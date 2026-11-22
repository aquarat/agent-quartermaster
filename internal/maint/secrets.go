package maint

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

// Pasted secrets never reach aqmasd, its logs or the tunnel in the clear: the browser seals
// them to a key only the root runner holds (HPKE base mode, DHKEM(P-256, HKDF-SHA256),
// HKDF-SHA256, AES-128-GCM; packet = enc || ciphertext, base64url). The signed canonical
// commits to SHA-256(packet), so a request cannot be paired with other secrets.
var kem = hpke.DHKEM(ecdh.P256())

const maxPacket = 8 << 10

// SecretsInfo is the HPKE info string for a task's secrets packet.
func SecretsInfo(task string) []byte { return []byte("aqmas-setup-secrets-v1\x00" + task) }

// NewKey generates a recipient key; Bytes() is what the runner stores (root only).
func NewKey() (hpke.PrivateKey, error) { return kem.GenerateKey() }

// LoadKey parses a stored recipient key.
func LoadKey(b []byte) (hpke.PrivateKey, error) { return kem.NewPrivateKey(b) }

// PublicKey returns the base64url public half shown to browsers.
func PublicKey(k hpke.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// PacketHash returns the value a canonical binds for a packet ("" for no packet).
func PacketHash(packet string) (string, error) {
	if packet == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(packet)
	if err != nil || len(raw) < 65+16 || len(raw) > maxPacket {
		return "", errors.New("invalid secrets packet")
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

// OpenPacket decrypts a base64url enc||ciphertext packet. The caller clears the result.
func OpenPacket(k hpke.PrivateKey, info []byte, packet string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(packet)
	if err != nil || len(raw) < 65+16 || len(raw) > maxPacket {
		return nil, errors.New("invalid secrets packet")
	}
	b, err := hpke.Open(k, hpke.HKDFSHA256(), hpke.AES128GCM(), info, raw)
	if err != nil {
		return nil, errors.New("secrets packet could not be opened")
	}
	return b, nil
}

// SealPacket is what the browser does (tests and tools).
func SealPacket(public string, info, plaintext []byte) (string, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(public)
	if err != nil {
		return "", err
	}
	pk, err := kem.NewPublicKey(raw)
	if err != nil {
		return "", err
	}
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES128GCM(), info, plaintext)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// OpenSecrets returns exactly the secrets the task and its signed parameters call for.
func OpenSecrets(k hpke.PrivateKey, task string, params any, packet string) (map[string]string, error) {
	want := SecretNames(task, params)
	if len(want) == 0 {
		if packet != "" {
			return nil, errors.New("this task takes no secrets")
		}
		return map[string]string{}, nil
	}
	if packet == "" || k == nil {
		return nil, errors.New("secrets required")
	}
	b, err := OpenPacket(k, SecretsInfo(task), packet)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	var m map[string]string
	if json.Unmarshal(b, &m) != nil || len(m) != len(want) {
		return nil, errors.New("unexpected secrets")
	}
	for name, v := range m {
		if !slices.Contains(want, name) || !validSecret(name, v) {
			return nil, errors.New("unexpected or malformed secret: " + name)
		}
	}
	return m, nil
}
