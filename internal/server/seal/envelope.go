// Package seal implements suite 1 of the aqmas sealed store. All open
// operations take caller-supplied expected context, never bindings selected
// by the ciphertext. Keys returned to the caller must be destroyed.
package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxPayload = 1 << 20

var errRecord = errors.New("seal: invalid or unauthenticated record")

// Key owns exactly one locked page. Use by pointer; the owner must serialize
// destruction with use. Its contents must never be formatted or marshaled.
type Key struct{ page []byte }

func (*Key) String() string   { return "[sealed key]" }
func (*Key) GoString() string { return "[sealed key]" }
func (k *Key) Destroy() {
	if k != nil && k.page != nil {
		freePage(k.page)
		k.page = nil
	}
}
func newKey() (*Key, error) {
	p, err := keyPage()
	if err != nil {
		return nil, err
	}
	return &Key{p}, nil
}
func RandomKey() (*Key, error) {
	k, err := newKey()
	if err == nil {
		rand.Read(k.page[:32])
	}
	return k, err
}
func importKey(b []byte) (*Key, error) {
	if len(b) != 32 {
		return nil, errRecord
	}
	k, err := newKey()
	if err == nil {
		copy(k.page, b)
	}
	return k, err
}

type ID [32]byte

func (id ID) MarshalText() ([]byte, error) { return []byte(b64(id[:])), nil }
func (id *ID) UnmarshalText(text []byte) error {
	if len(text) != 43 {
		return errRecord
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(string(text))
	if err != nil || len(b) != 32 {
		return errRecord
	}
	copy(id[:], b)
	return nil
}

func RandomID() (id ID)      { rand.Read(id[:]); return }
func number(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
func frame(out, p []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
	return append(out, p...)
}
func tuple(role string, fields ...[]byte) []byte {
	b := frame(nil, []byte("aqmas-seal"))
	b = frame(b, number(1))
	b = frame(b, []byte(role))
	for _, f := range fields {
		b = frame(b, f)
	}
	return b
}

// Wire record: one suite octet || 24 random nonce bytes || ciphertext/tag.
// AAD also commits to suite 1. No caller-supplied nonce, even on a retry.
func (k *Key) encrypt(data, aad []byte) ([]byte, error) {
	if k == nil || k.page == nil || len(data) > maxPayload {
		return nil, errRecord
	}
	a, err := chacha20poly1305.NewX(k.page[:32])
	if err != nil {
		return nil, err
	}
	b := make([]byte, 25, 25+len(data)+a.Overhead())
	b[0] = 1
	rand.Read(b[1:])
	return a.Seal(b, b[1:25], data, aad), nil
}
func (k *Key) open(dst, record, aad []byte) ([]byte, error) {
	if k == nil || k.page == nil || len(record) < 41 || len(record) > maxPayload+41 || record[0] != 1 {
		return nil, errRecord
	}
	a, err := chacha20poly1305.NewX(k.page[:32])
	if err != nil {
		return nil, err
	}
	b, err := a.Open(dst, record[1:25], record[25:], aad)
	if err != nil {
		return nil, errRecord
	}
	return b, nil
}
func (k *Key) openKey(record, aad []byte) (*Key, error) {
	if len(record) != 73 {
		return nil, errRecord
	}
	out, err := newKey()
	if err != nil {
		return nil, err
	}
	if _, err = k.open(out.page[:0:32], record, aad); err != nil {
		out.Destroy()
		return nil, err
	}
	return out, nil
}

type Generation struct {
	Installation ID
	Version      uint64
}

func (g Generation) valid() bool { return g.Installation != (ID{}) && g.Version != 0 }

const marker = "aqmas installation master key check"

func (g Generation) CheckRecord(mk *Key) ([]byte, error) {
	if !g.valid() {
		return nil, errRecord
	}
	return mk.encrypt([]byte(marker), tuple("mk-check", g.Installation[:], number(g.Version)))
}
func (g Generation) Verify(mk *Key, record []byte) error {
	if !g.valid() || len(record) != 41+len(marker) {
		return errRecord
	}
	b, err := mk.open(nil, record, tuple("mk-check", g.Installation[:], number(g.Version)))
	if err != nil || !bytes.Equal(b, []byte(marker)) {
		return errRecord
	}
	return nil
}

type Credential struct {
	Generation
	RPID  string
	RawID []byte
	Salt  ID
}

func (c Credential) valid() bool {
	return c.Generation.valid() && len(c.RPID) > 0 && len(c.RPID) <= 253 && len(c.RawID) > 0 && len(c.RawID) <= 1023 && c.Salt != (ID{})
}
func (c Credential) context(role string) []byte {
	return tuple(role, c.Installation[:], []byte(c.RPID), c.RawID, number(c.Version), c.Salt[:])
}
func (c Credential) Wrap(kek, mk *Key) ([]byte, error) {
	if !c.valid() || mk == nil || mk.page == nil {
		return nil, errRecord
	}
	return kek.encrypt(mk.page[:32], c.context("mk-wrap"))
}
func (c Credential) Unwrap(kek *Key, wrap, check []byte) (*Key, error) {
	if !c.valid() {
		return nil, errRecord
	}
	mk, err := kek.openKey(wrap, c.context("mk-wrap"))
	if err != nil {
		return nil, err
	}
	if err = c.Verify(mk, check); err != nil {
		mk.Destroy()
		return nil, err
	}
	return mk, nil
}

// Object describes an immutable, independently authorised object. Global
// objects have a signer/notifier ID; scoped ones require all three path IDs.
type Object struct {
	Org, Service, Set, Global, Role string
	Revision                        uint64
	Blob                            ID
	Issuer, Account                 string
	ParentVersion                   uint64
}

func label(s string) bool { return len(s) > 0 && len(s) <= 256 && utf8.ValidString(s) }
func (o Object) fields(g Generation) ([][]byte, error) {
	if !g.valid() || o.Blob == (ID{}) || o.Revision == 0 {
		return nil, errRecord
	}
	f := [][]byte{g.Installation[:]}
	switch o.Role {
	case "ssh-ca", "internal-ca", "ntfy-topic":
		if !label(o.Global) || o.Org != "" || o.Service != "" || o.Set != "" {
			return nil, errRecord
		}
		f = append(f, []byte("global"), []byte(o.Global))
	case "cf-proxy", "cf-minter", "env-draft", "env-revision", "signer-key":
		if o.Global != "" || !label(o.Org) || !label(o.Service) || !label(o.Set) {
			return nil, errRecord
		}
		f = append(f, []byte("scoped"), []byte(o.Org), []byte(o.Service), []byte(o.Set))
	default:
		return nil, errRecord
	}
	f = append(f, []byte(o.Role), number(o.Revision), o.Blob[:])
	if o.Role == "cf-proxy" || o.Role == "cf-minter" {
		if !label(o.Issuer) || !label(o.Account) || o.ParentVersion == 0 {
			return nil, errRecord
		}
		f = append(f, []byte(o.Issuer), []byte(o.Account), number(o.ParentVersion))
	} else if o.Issuer != "" || o.Account != "" || o.ParentVersion != 0 {
		return nil, errRecord
	}
	return f, nil
}

type Envelope struct{ Payload, WrappedDEK []byte }

func (o Object) Encrypt(g Generation, mk *Key, data []byte) (Envelope, error) {
	var e Envelope
	f, err := o.fields(g)
	if err != nil {
		return e, err
	}
	dek, err := RandomKey()
	if err != nil {
		return e, err
	}
	defer dek.Destroy()
	e.Payload, err = dek.encrypt(data, tuple("payload", f...))
	if err != nil {
		return Envelope{}, err
	}
	e.WrappedDEK, err = mk.encrypt(dek.page[:32], tuple("dek-wrap", append(f, number(g.Version))...))
	if err != nil {
		return Envelope{}, err
	}
	return e, nil
}
func (o Object) Decrypt(g Generation, mk *Key, e Envelope) ([]byte, error) {
	f, err := o.fields(g)
	if err != nil {
		return nil, err
	}
	dek, err := mk.openKey(e.WrappedDEK, tuple("dek-wrap", append(f, number(g.Version))...))
	if err != nil {
		return nil, err
	}
	defer dek.Destroy()
	return dek.open(nil, e.Payload, tuple("payload", f...))
}
