// Package signer is the registry of signing schemes for `signer` credential
// sets, shared by aqmasd (which holds the key) and the aqmas CLI (which hashes
// locally and checks every signature it gets back). A key belongs to exactly
// one scheme for its whole life, so a signature made under one scheme can
// never be presented as another's. Adding a scheme is one entry in schemes.
package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// MaxMessage bounds an artifact that travels to the broker because the scheme
// signs the message itself. Larger artifacts need a digest scheme.
const MaxMessage = 4096

// MaxItems bounds one request or one call under a time-boxed grant.
const MaxItems = 16

// Scheme describes what the key signs and what comes back.
type Scheme struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Key is the key type: "ed25519" or "ecdsa-p256".
	Key string `json:"key"`
	// Input is what the broker needs: "message" (the artifact itself, at most
	// MaxMessage bytes), "sha256" or "sha512" (the artifact's digest only).
	Input string `json:"input"`
	// Signed says, for the approval card, exactly which bytes get signed.
	Signed string `json:"signed"`
	// Output describes the signature bytes; Check is an independent check.
	Output string `json:"output"`
	Check  string `json:"check"`
	// SSH marks the scheme of an SSH key: it signs SSH login requests only
	// (ssh.go) and is not offered for a signer set.
	SSH bool `json:"ssh,omitempty"`

	sign   func(priv []byte, it Item) ([]byte, error)
	verify func(pub []byte, it Item, sig []byte) bool
}

var schemes = []Scheme{
	{ID: "ed25519", Title: "Ed25519 (pure, RFC 8032)", Key: "ed25519", Input: "message",
		Signed: "the artifact's own bytes", Output: "64 raw bytes (R || S)",
		Check: "openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in FILE -sigfile FILE.sig",
		sign: func(priv []byte, it Item) ([]byte, error) {
			return ed25519.Sign(ed25519.NewKeyFromSeed(priv), it.Message), nil
		},
		verify: func(pub []byte, it Item, sig []byte) bool {
			return ed25519.Verify(pub, it.Message, sig)
		}},
	{ID: "ed25519-sha256", Title: "Ed25519 over the SHA-256 digest", Key: "ed25519", Input: "sha256",
		Signed: "the 32 raw bytes of the artifact's SHA-256 (pure Ed25519 over that digest)", Output: "64 raw bytes (R || S)",
		Check: "openssl dgst -sha256 -binary FILE > d && openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in d -sigfile FILE.sig",
		sign: func(priv []byte, it Item) ([]byte, error) {
			return ed25519.Sign(ed25519.NewKeyFromSeed(priv), mustHex(it.SHA256)), nil
		},
		verify: func(pub []byte, it Item, sig []byte) bool { return ed25519.Verify(pub, mustHex(it.SHA256), sig) }},
	{ID: "ed25519ph", Title: "Ed25519ph (RFC 8032 prehash, SHA-512)", Key: "ed25519", Input: "sha512",
		Signed: "the artifact's SHA-512, as Ed25519ph with an empty context", Output: "64 raw bytes (R || S)",
		Check: "an RFC 8032 Ed25519ph verifier (empty context) over FILE",
		sign: func(priv []byte, it Item) ([]byte, error) {
			return ed25519.NewKeyFromSeed(priv).Sign(nil, mustHex(it.SHA512), &ed25519.Options{Hash: crypto.SHA512})
		},
		verify: func(pub []byte, it Item, sig []byte) bool {
			return ed25519.VerifyWithOptions(pub, mustHex(it.SHA512), sig, &ed25519.Options{Hash: crypto.SHA512}) == nil
		}},
	{ID: "ecdsa-p256-sha256", Title: "ECDSA P-256 over SHA-256", Key: "ecdsa-p256", Input: "sha256",
		Signed: "the artifact's SHA-256 (ECDSA, NIST P-256)", Output: "ASN.1 DER (r, s)",
		Check: "openssl dgst -sha256 -verify pub.pem -signature FILE.sig FILE",
		sign: func(priv []byte, it Item) ([]byte, error) {
			k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), priv)
			if err != nil {
				return nil, err
			}
			return ecdsa.SignASN1(rand.Reader, k, mustHex(it.SHA256))
		},
		verify: func(pub []byte, it Item, sig []byte) bool {
			k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
			return err == nil && ecdsa.VerifyASN1(k, mustHex(it.SHA256), sig)
		}},
}

// All lists the schemes a signer set may be created with. The schemes of SSH
// keys are found by Lookup only.
func All() []Scheme { return append([]Scheme(nil), schemes...) }
func Lookup(id string) (Scheme, bool) {
	for _, list := range [][]Scheme{schemes, sshSchemes} {
		for _, s := range list {
			if s.ID == id {
				return s, true
			}
		}
	}
	return Scheme{}, false
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }
func lowerHex(s string, n int) bool {
	if len(s) != 2*n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Item is one artifact. Name is a label chosen by the requester (shown on the
// card, never trusted); Size is -1 when only a digest was supplied. SHA256 is
// always present and is what the card shows; SHA512 and Message are present
// exactly when the scheme signs them.
type Item struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	SHA512  string `json:"sha512,omitempty"`
	Message []byte `json:"message,omitempty"`
}

// ValidName accepts a short printable label without path separators.
func ValidName(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == '/' || c == '\\' || c >= 0x80 && c < 0xa0 || c == 0x2028 || c == 0x2029 || c >= 0x202a && c <= 0x202e || c >= 0x2066 && c <= 0x2069 {
			return false
		}
	}
	return true
}

// Valid checks an item is complete and unambiguous for this scheme: nothing
// the scheme would not sign may ride along, and what it signs must be there.
func (s Scheme) Valid(it Item) error {
	if s.sign == nil || !ValidName(it.Name) || it.Size < -1 || it.Size > 1<<40 || !lowerHex(it.SHA256, 32) {
		return errors.New("invalid signing item")
	}
	switch s.Input {
	case "message":
		sum := sha256.Sum256(it.Message)
		if it.SHA512 != "" || it.Size != int64(len(it.Message)) || len(it.Message) > MaxMessage || hex.EncodeToString(sum[:]) != it.SHA256 {
			return errors.New("this scheme signs the artifact itself: send it, at most 4096 bytes")
		}
		if s.SSH {
			if _, err := ParseUserAuth(it.Message); err != nil {
				return err
			}
		}
	case "sha256":
		if it.SHA512 != "" || it.Message != nil {
			return errors.New("this scheme signs a SHA-256 digest only")
		}
	case "sha512":
		if it.Message != nil || !lowerHex(it.SHA512, 64) {
			return errors.New("this scheme signs a SHA-512 digest")
		}
	default:
		return errors.New("unknown scheme input")
	}
	return nil
}
func (s Scheme) Sign(priv []byte, it Item) ([]byte, error) {
	if err := s.Valid(it); err != nil {
		return nil, err
	}
	if len(priv) != 32 {
		return nil, errors.New("invalid signer key")
	}
	return s.sign(priv, it)
}
func (s Scheme) Verify(pub []byte, it Item, sig []byte) bool {
	if s.Valid(it) != nil || len(pub) != s.publicLen() {
		return false
	}
	if s.SSH {
		if _, err := s.SSHLogin(pub, it); err != nil {
			return false
		}
	}
	return s.verify(pub, it, sig)
}
func (s Scheme) publicLen() int {
	if s.Key == "ed25519" {
		return ed25519.PublicKeySize
	}
	return 65
}

// Public derives the raw public key (Ed25519: 32 bytes; P-256: 65-byte
// uncompressed SEC1 point) from the 32-byte private seed or scalar.
func (s Scheme) Public(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("invalid signer key")
	}
	switch s.Key {
	case "ed25519":
		return bytes.Clone(ed25519.NewKeyFromSeed(priv)[32:]), nil
	case "ecdsa-p256":
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), priv)
		if err != nil {
			return nil, errors.New("invalid signer key")
		}
		return k.PublicKey.Bytes()
	}
	return nil, errors.New("unknown key type")
}

// Generate makes a new private key for the scheme.
func (s Scheme) Generate() (priv, pub []byte, err error) {
	switch s.Key {
	case "ed25519":
		priv = make([]byte, 32)
		rand.Read(priv)
	case "ecdsa-p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if priv, err = k.Bytes(); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, errors.New("unknown key type")
	}
	pub, err = s.Public(priv)
	return priv, pub, err
}

// ParsePrivate accepts what an owner is likely to hold: a hex seed/scalar
// (32 bytes; for Ed25519 also the 64-byte seed||public form), or an
// unencrypted PEM key (PKCS#8, SEC1 or OpenSSH). Errors never echo input.
func (s Scheme) ParsePrivate(text []byte) (priv, pub []byte, err error) {
	bad := errors.New("not an unencrypted " + s.Key + " private key (hex seed, PKCS#8, SEC1 or OpenSSH PEM)")
	t := bytes.TrimSpace(text)
	if len(t) == 0 || len(t) > 8192 {
		return nil, nil, bad
	}
	if !bytes.HasPrefix(t, []byte("-----")) {
		raw, e := hex.DecodeString(string(bytes.ToLower(t)))
		if e != nil {
			return nil, nil, bad
		}
		defer clear(raw)
		if s.Key == "ed25519" && len(raw) == 64 {
			if !bytes.Equal(ed25519.NewKeyFromSeed(raw[:32])[32:], raw[32:]) {
				return nil, nil, bad
			}
		} else if len(raw) != 32 {
			return nil, nil, bad
		}
		priv = bytes.Clone(raw[:32])
	} else {
		if blk, _ := pem.Decode(t); blk == nil || x509.IsEncryptedPEMBlock(blk) { //nolint:staticcheck // legacy header check only
			return nil, nil, bad
		}
		k, e := ssh.ParseRawPrivateKey(t)
		if e != nil {
			return nil, nil, bad
		}
		switch k := k.(type) {
		case *ed25519.PrivateKey:
			if s.Key != "ed25519" {
				return nil, nil, bad
			}
			priv = bytes.Clone(k.Seed())
		case ed25519.PrivateKey:
			if s.Key != "ed25519" {
				return nil, nil, bad
			}
			priv = bytes.Clone(k.Seed())
		case *ecdsa.PrivateKey:
			if s.Key != "ecdsa-p256" || k.Curve != elliptic.P256() {
				return nil, nil, bad
			}
			if priv, e = k.Bytes(); e != nil {
				return nil, nil, bad
			}
		default:
			return nil, nil, bad
		}
	}
	if pub, err = s.Public(priv); err != nil {
		clear(priv)
		return nil, nil, bad
	}
	return priv, pub, nil
}

// PublicPEM is the SubjectPublicKeyInfo PEM that openssl and most verifiers read.
func (s Scheme) PublicPEM(pub []byte) (string, error) {
	var key any
	switch {
	case s.Key == "ed25519" && len(pub) == 32:
		key = ed25519.PublicKey(pub)
	case s.Key == "ecdsa-p256":
		k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
		if err != nil {
			return "", err
		}
		key = k
	default:
		return "", errors.New("invalid public key")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// Fingerprint identifies a key on cards and in the audit log.
func Fingerprint(pub []byte) string { h := sha256.Sum256(pub); return hex.EncodeToString(h[:]) }
