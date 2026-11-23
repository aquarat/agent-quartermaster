package seal

// Seal format 2: per-credential buckets (docs/BUCKETS.md §3). Every context
// is T2(role, …): the format-1 framing with version 2, so no format-2 label
// can be read as a format-1 one. Callers pass the expected context; nothing
// here trusts bindings carried by a ciphertext.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"filippo.io/age"
)

var errBucket = errors.New("seal: invalid or unauthenticated bucket material")

// T2 frames a format-2 context: F("aqmas-seal") ‖ F(u64be(2)) ‖ F(role) ‖ F(field)…
func T2(role string, fields ...[]byte) []byte {
	b := frame(nil, []byte("aqmas-seal"))
	b = frame(b, number(2))
	b = frame(b, []byte(role))
	for _, f := range fields {
		b = frame(b, f)
	}
	return b
}

// Frames is F(p1) ‖ F(p2) ‖ …, the layout of the open packet's plaintext.
func Frames(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = frame(b, p)
	}
	return b
}

// ScopeInstallation is the scope of installation-wide buckets (the two CAs).
const ScopeInstallation = "installation"

var suiteKDF, suiteAEAD = hpke.HKDFSHA256(), hpke.AES128GCM()

// NewKeyPair returns a fresh P-256 scalar in a locked page and its public point.
// The ecdh library makes heap copies while generating; the page is the copy we keep.
func NewKeyPair() (*Key, []byte, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sk, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	b := k.Bytes()
	copy(sk.page, b)
	clear(b)
	return sk, k.PublicKey().Bytes(), nil
}

func (k *Key) ecdh() (*ecdh.PrivateKey, error) {
	if k == nil || k.page == nil {
		return nil, errBucket
	}
	return ecdh.P256().NewPrivateKey(k.page[:32])
}

// Public is the uncompressed point of a P-256 scalar key.
func (k *Key) Public() ([]byte, error) {
	p, err := k.ecdh()
	if err != nil {
		return nil, errBucket
	}
	return p.PublicKey().Bytes(), nil
}

// Matches reports whether the scalar's public point is pub.
func (k *Key) Matches(pub []byte) bool {
	p, err := k.Public()
	return err == nil && len(pub) == 65 && bytes.Equal(p, pub)
}

func publicKey(pub []byte) (hpke.PublicKey, error) {
	if len(pub) != 65 || pub[0] != 4 {
		return nil, errBucket
	}
	p, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, errBucket
	}
	return hpke.NewDHKEMPublicKey(p)
}
func (k *Key) hpke() (hpke.PrivateKey, error) {
	p, err := k.ecdh()
	if err != nil {
		return nil, errBucket
	}
	return hpke.NewDHKEMPrivateKey(p)
}

// ValidPublic checks an uncompressed P-256 point.
func ValidPublic(pub []byte) bool { _, err := publicKey(pub); return err == nil }

// sealTo is single-shot HPKE base mode with an empty AAD: enc(65) ‖ ct.
func sealTo(pub, info, plaintext []byte) ([]byte, error) {
	pk, err := publicKey(pub)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pk, suiteKDF, suiteAEAD, info, plaintext)
}
func (k *Key) openFrom(info, record []byte) ([]byte, error) {
	if len(record) < 65+16 || len(record) > maxPayload+65+16 {
		return nil, errBucket
	}
	sk, err := k.hpke()
	if err != nil {
		return nil, err
	}
	b, err := hpke.Open(sk, suiteKDF, suiteAEAD, info, record)
	if err != nil {
		return nil, errBucket
	}
	return b, nil
}

// scalarFrom moves an unwrapped scalar into a locked page and checks it opens pub.
func scalarFrom(b, pub []byte) (*Key, error) {
	defer clear(b)
	if len(b) != 32 {
		return nil, errBucket
	}
	k, err := importKey(b)
	if err != nil {
		return nil, err
	}
	if !k.Matches(pub) {
		k.Destroy()
		return nil, errBucket
	}
	return k, nil
}

// ---- scope keys and passkey wraps (§3.1) ----

// PasskeyScope names the PRF input of one passkey for one scope.
type PasskeyScope struct {
	Installation ID
	RPID         string
	RawID        []byte
	Scope        string
	Salt         ID
}

func (o PasskeyScope) valid() bool {
	return o.Installation != (ID{}) && len(o.RPID) > 0 && len(o.RPID) <= 253 && len(o.RawID) > 0 && len(o.RawID) <= 1023 && label(o.Scope) && o.Salt != (ID{})
}

// KEKInfo is the HKDF info the browser uses to derive this passkey's KEK for the scope.
func (o PasskeyScope) KEKInfo() []byte {
	return T2("scope-kek", o.Installation[:], []byte(o.RPID), o.RawID, []byte(o.Scope), o.Salt[:])
}

// DeriveKEK is the browser's derivation (web/src/buckets.ts), for tests and vectors.
func (o PasskeyScope) DeriveKEK(prf []byte) (*Key, error) {
	if !o.valid() || len(prf) != 32 {
		return nil, errBucket
	}
	b, err := hkdf.Key(sha256.New, prf, o.Installation[:], string(o.KEKInfo()), 32)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return importKey(b)
}

// ImportKEK copies 32 transported bytes into a locked page.
func ImportKEK(b []byte) (*Key, error) { return importKey(b) }

func (o PasskeyScope) aad(scopePublic []byte) []byte {
	return T2("scope-wrap", o.Installation[:], []byte(o.RPID), o.RawID, []byte(o.Scope), o.Salt[:], scopePublic)
}

// Wrap seals the scope scalar under this passkey's KEK (XChaCha20-Poly1305, fresh nonce).
func (o PasskeyScope) Wrap(kek, scope *Key, scopePublic []byte) ([]byte, error) {
	if !o.valid() || scope == nil || !scope.Matches(scopePublic) {
		return nil, errBucket
	}
	return kek.encrypt(scope.page[:32], o.aad(scopePublic))
}

// Unwrap opens the scope scalar and checks it against the scope's public key.
func (o PasskeyScope) Unwrap(kek *Key, wrap, scopePublic []byte) (*Key, error) {
	if !o.valid() || len(wrap) != 73 || len(scopePublic) != 65 {
		return nil, errBucket
	}
	b, err := kek.open(nil, wrap, o.aad(scopePublic))
	if err != nil {
		return nil, errBucket
	}
	return scalarFrom(b, scopePublic)
}

// ---- remembered browsers (docs/BUCKETS.md §13) ----

// BrowserScope names one remembered browser's wrap of a scope key for one
// passkey. The KEK is 32 random bytes made in that browser; the broker keeps
// the scope scalar wrapped under it (Wrap) and the KEK itself sealed to the
// browser key's public half (SealKEK). Without the browser's private key
// neither stored value opens anything.
type BrowserScope struct {
	Installation ID
	RPID         string
	RawID        []byte
	Scope        string
	WrapID       ID     // random, new for every wrap (the role a PRF salt has)
	Browser      []byte // the browser key's public half, uncompressed P-256
}

func (o BrowserScope) valid() bool {
	return o.Installation != (ID{}) && len(o.RPID) > 0 && len(o.RPID) <= 253 && len(o.RawID) > 0 && len(o.RawID) <= 1023 && label(o.Scope) && o.WrapID != (ID{}) && ValidPublic(o.Browser)
}

// KEKInfo is the HPKE info of the sealed KEK: it binds the installation, the
// passkey, the scope, the wrap and the browser key.
func (o BrowserScope) KEKInfo() []byte {
	return T2("browser-kek", o.Installation[:], []byte(o.RPID), o.RawID, []byte(o.Scope), o.WrapID[:], o.Browser)
}
func (o BrowserScope) aad(scopePublic []byte) []byte {
	return T2("scope-wrap-browser", o.Installation[:], []byte(o.RPID), o.RawID, []byte(o.Scope), o.WrapID[:], o.Browser, scopePublic)
}

// Wrap seals the scope scalar under the browser's KEK (XChaCha20-Poly1305, fresh nonce).
func (o BrowserScope) Wrap(kek, scope *Key, scopePublic []byte) ([]byte, error) {
	if !o.valid() || scope == nil || !scope.Matches(scopePublic) {
		return nil, errBucket
	}
	return kek.encrypt(scope.page[:32], o.aad(scopePublic))
}

// Unwrap opens the scope scalar and checks it against the scope's public key.
func (o BrowserScope) Unwrap(kek *Key, wrap, scopePublic []byte) (*Key, error) {
	if !o.valid() || len(wrap) != 73 || len(scopePublic) != 65 {
		return nil, errBucket
	}
	b, err := kek.open(nil, wrap, o.aad(scopePublic))
	if err != nil {
		return nil, errBucket
	}
	return scalarFrom(b, scopePublic)
}

// SealKEK encrypts the KEK to the browser key (HPKE, 113 bytes). Only that
// browser can open it; the broker stores it and hands it out inside a valid
// tap by the wrap's own passkey.
func (o BrowserScope) SealKEK(kek *Key) ([]byte, error) {
	if !o.valid() || kek == nil || kek.page == nil {
		return nil, errBucket
	}
	return sealTo(o.Browser, o.KEKInfo(), kek.page[:32])
}

// OpenKEK is the browser's half (web/src/browserKey.ts), for tests: the
// broker never holds a browser key's private half.
func (o BrowserScope) OpenKEK(browser *Key, sealed []byte) (*Key, error) {
	if !o.valid() || len(sealed) != 65+32+16 || !browser.Matches(o.Browser) {
		return nil, errBucket
	}
	b, err := browser.openFrom(o.KEKInfo(), sealed)
	if err != nil {
		return nil, errBucket
	}
	defer clear(b)
	return importKey(b)
}

// BrowserKeyID is a browser key's fingerprint: hex of the first 16 bytes of
// SHA-256(public half). It names the key in canonicals, the audit log and the UI.
func BrowserKeyID(public []byte) string {
	h := sha256.Sum256(public)
	return hex.EncodeToString(h[:16])
}

// Scope is a scope key's public description.
type Scope struct {
	Installation ID
	Name         string
	Public       []byte
}

func (s Scope) valid() bool { return s.Installation != (ID{}) && label(s.Name) && len(s.Public) == 65 }
func (s Scope) recoveryPrefix(recipient string) []byte {
	return T2("scope-recovery", s.Installation[:], []byte(s.Name), s.Public, []byte(recipient))
}

// RecoveryWrap encrypts the scope scalar to the canonical native age X25519 recipient.
func (s Scope) RecoveryWrap(recipient string, sk *Key) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if !s.valid() || err != nil || r.String() != recipient || sk == nil || !sk.Matches(s.Public) {
		return nil, errBucket
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	p := frame(s.recoveryPrefix(recipient), sk.page[:32])
	defer clear(p)
	if _, err = w.Write(p); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Recover opens a scope's recovery wrap with the owner's identity. Anyone with
// the public recipient can make such a file: the scalar must match Public.
func (s Scope) Recover(id *age.X25519Identity, recipient string, wrap []byte) (*Key, error) {
	if !s.valid() || id == nil || id.Recipient().String() != recipient || len(wrap) > 4096 {
		return nil, errBucket
	}
	r, err := age.Decrypt(bytes.NewReader(wrap), id)
	if err != nil {
		return nil, errBucket
	}
	prefix := s.recoveryPrefix(recipient)
	want := len(prefix) + 4 + 32
	p, err := io.ReadAll(io.LimitReader(r, int64(want+1)))
	defer clear(p)
	if err != nil || len(p) != want || !bytes.Equal(p[:len(prefix)], prefix) || !bytes.Equal(p[len(prefix):len(prefix)+4], []byte{0, 0, 0, 32}) {
		return nil, errBucket
	}
	return scalarFrom(bytes.Clone(p[len(prefix)+4:]), s.Public)
}

// ---- buckets (§3.2, §3.3) ----

// Bucket is the public description every wrap and record is bound to.
type Bucket struct {
	Installation ID
	ID           ID
	Scope, Kind  string
	Public       []byte
}

func (b Bucket) valid() bool {
	return b.Installation != (ID{}) && b.ID != (ID{}) && label(b.Scope) && label(b.Kind) && len(b.Public) == 65
}
func (b Bucket) wrapInfo(scopePublic []byte) []byte {
	return T2("bucket-wrap", b.Installation[:], b.ID[:], []byte(b.Scope), []byte(b.Kind), b.Public, scopePublic)
}

// WrapTo seals the bucket scalar to its scope's public key (no secret needed but the bucket's own).
func (b Bucket) WrapTo(scopePublic []byte, sk *Key) ([]byte, error) {
	if !b.valid() || sk == nil || !sk.Matches(b.Public) {
		return nil, errBucket
	}
	return sealTo(scopePublic, b.wrapInfo(scopePublic), sk.page[:32])
}

// UnwrapWith opens the bucket's wrap with the open scope scalar.
func (b Bucket) UnwrapWith(scope *Key, scopePublic, wrap []byte) (*Key, error) {
	if !b.valid() || len(wrap) != 65+32+16 {
		return nil, errBucket
	}
	s, err := scope.openFrom(b.wrapInfo(scopePublic), wrap)
	if err != nil {
		return nil, errBucket
	}
	return scalarFrom(s, b.Public)
}

// Record roles (§3.3) and the context fields each binds after the role.
const (
	RoleSSHCA      = "ssh-ca"
	RoleInternalCA = "internal-ca"
	RoleCFProxy    = "cf-proxy"
	RoleEnvEntry   = "env-entry"
	RoleSignerKey  = "signer-key"
)

var recordFields = map[string]int{RoleSSHCA: 0, RoleInternalCA: 0, RoleCFProxy: 5, RoleEnvEntry: 3, RoleSignerKey: 3}

func (b Bucket) recordInfo(role string, fields [][]byte) ([]byte, error) {
	n, ok := recordFields[role]
	if !b.valid() || !ok || len(fields) != n {
		return nil, errBucket
	}
	for _, f := range fields {
		if len(f) == 0 || len(f) > 4096 {
			return nil, errBucket
		}
	}
	return T2("bucket-record", append([][]byte{b.Installation[:], b.ID[:], []byte(role)}, fields...)...), nil
}

// Seal encrypts one value to the bucket's public key: no secret needed.
func (b Bucket) Seal(role string, fields [][]byte, plaintext []byte) ([]byte, error) {
	info, err := b.recordInfo(role, fields)
	if err != nil || len(plaintext) > maxPayload {
		return nil, errBucket
	}
	return sealTo(b.Public, info, plaintext)
}

// Open decrypts one record with the open bucket scalar. The caller clears the result.
func (b Bucket) Open(sk *Key, role string, fields [][]byte, record []byte) ([]byte, error) {
	info, err := b.recordInfo(role, fields)
	if err != nil {
		return nil, err
	}
	return sk.openFrom(info, record)
}

// ParseIdentity accepts exactly one native age X25519 identity (comments allowed).
func ParseIdentity(b []byte) (*age.X25519Identity, error) {
	var key *age.X25519Identity
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key != nil {
			return nil, errBucket
		}
		var err error
		if key, err = age.ParseX25519Identity(line); err != nil {
			return nil, errBucket
		}
	}
	if key == nil {
		return nil, errBucket
	}
	return key, nil
}

// OpenChallenge binds an open descriptor to an action canonical (§4.2).
func OpenChallenge(canonical, descriptor []byte) []byte {
	c, d := sha256.Sum256(canonical), sha256.Sum256(descriptor)
	h := sha256.Sum256(T2("open-challenge", c[:], d[:]))
	return h[:]
}

// OpenInfo and OpenAAD are the HPKE context of the browser's KEK packet (§4.3).
func OpenInfo(installation ID, purpose string) []byte {
	return T2("hpke-open", installation[:], []byte(purpose))
}
func OpenAAD(attempt, epoch ID, challenge, cred []byte) []byte {
	return T2("open-aad", attempt[:], epoch[:], challenge, cred)
}

// SplitKEKs parses F(KEK1) ‖ F(KEK2 or empty) into one or two locked keys.
// It clears the input.
func SplitKEKs(p []byte) ([]*Key, error) {
	defer clear(p)
	var out []*Key
	fail := func() ([]*Key, error) {
		for _, k := range out {
			k.Destroy()
		}
		return nil, errBucket
	}
	for i := 0; i < 2; i++ {
		if len(p) < 4 {
			return fail()
		}
		n := int(uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3]))
		p = p[4:]
		if n == 0 && i == 1 {
			continue
		}
		if n != 32 || len(p) < 32 {
			return fail()
		}
		k, err := importKey(p[:32])
		clear(p[:32])
		if err != nil {
			return fail()
		}
		out = append(out, k)
		p = p[32:]
	}
	if len(p) != 0 {
		return fail()
	}
	return out, nil
}

// Bytes lends the raw 32 bytes of a key for transport into a locked buffer
// elsewhere (tests and the recovery flow only). Never log or marshal it.
func (k *Key) Bytes() []byte {
	if k == nil || k.page == nil {
		return nil
	}
	return k.page[:32]
}
