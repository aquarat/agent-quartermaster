package seal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
)

// Vault transport: one HPKE base-mode message per fresh key pair, in either
// direction, with the same suite as the unlock finish (DHKEM(P-256,
// HKDF-SHA256), HKDF-SHA256, AES-128-GCM). The edge between the browser and
// the broker sees ciphertext only.

var errTransport = errors.New("seal: invalid transport packet")

// Tuple frames a context for vault transport info and AAD strings.
func Tuple(role string, fields ...[]byte) []byte { return tuple(role, fields...) }

// Recipient is a single-use private key held in memory by the broker.
type Recipient struct{ key hpke.PrivateKey }

func NewRecipient() (*Recipient, error) {
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Recipient{k}, nil
}

// Public is the uncompressed SEC1 P-256 point (65 bytes).
func (r *Recipient) Public() []byte { return r.key.PublicKey().Bytes() }
func (r *Recipient) Open(info, aad, enc, ciphertext []byte) ([]byte, error) {
	if r == nil || r.key == nil || len(enc) != 65 || len(ciphertext) < 16 {
		return nil, errTransport
	}
	x, err := hpke.NewRecipient(enc, r.key, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		return nil, errTransport
	}
	b, err := x.Open(aad, ciphertext)
	if err != nil {
		return nil, errTransport
	}
	return b, nil
}

// SealTo encrypts one message to a caller-supplied public key (a browser's
// ephemeral reveal key). The key must be a valid uncompressed P-256 point.
func SealTo(public, info, aad, plaintext []byte) (enc, ciphertext []byte, err error) {
	if len(public) != 65 || public[0] != 4 {
		return nil, nil, errTransport
	}
	p, err := ecdh.P256().NewPublicKey(public)
	if err != nil {
		return nil, nil, errTransport
	}
	pk, err := hpke.NewDHKEMPublicKey(p)
	if err != nil {
		return nil, nil, errTransport
	}
	enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		return nil, nil, errTransport
	}
	ciphertext, err = s.Seal(aad, plaintext)
	return enc, ciphertext, err
}

// RecipientFromScalar rebuilds a recipient from a raw P-256 scalar (test vectors).
func RecipientFromScalar(scalar []byte) (*Recipient, error) {
	k, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	p, err := hpke.NewDHKEMPrivateKey(k)
	return &Recipient{p}, err
}
