// Package canon builds the canonical action text that a per-action WebAuthn challenge commits
// to (docs/API.md, "Approval challenge"). The challenge is SHA-256(canonical); on decide the
// server re-parses the stored canonical text and applies exactly the action it describes.
package canon

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Version is the canonical format version ("v").
const Version = 1

// Actions.
const (
	ActionApprove  = "approve"
	ActionDeny     = "deny"
	ActionRevoke   = "revoke"
	ActionRegister = "register" // add another passkey
)

// Objects.
const (
	ObjectRequest    = "request"
	ObjectEnrollment = "enrollment"
	ObjectStanding   = "standing"
	ObjectGrant      = "grant"
	ObjectPasskey    = "passkey"
)

// Action is everything the owner approves with one passkey assertion. Fields that do not apply
// to an object are empty / zero but always present in the canonical text.
type Action struct {
	Action         string `json:"action"`
	Object         string `json:"object"`
	ID             string `json:"id"`
	RequestingHost string `json:"requesting_host"`
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	LoginUser      string `json:"login_user"`
	KeyFingerprint string `json:"key_fingerprint"`
	TTLSeconds     int    `json:"ttl_seconds"`
	StandingHours  int    `json:"standing_hours"`
}

// Signed is a parsed canonical text: the action plus the challenge metadata.
type Signed struct {
	Action
	V        int       `json:"v"`
	Nonce    string    `json:"nonce"`
	IssuedAt time.Time `json:"issued_at"`
}

// NewNonce returns 32 random bytes, base64url without padding.
func NewNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Build returns the canonical UTF-8 JSON text for a: keys sorted, no insignificant whitespace,
// no HTML escaping.
func Build(a Action, nonce string, issuedAt time.Time) (string, error) {
	if a.Action == "" || a.Object == "" || a.ID == "" {
		return "", errors.New("canon: action, object and id are required")
	}
	if nonce == "" {
		return "", errors.New("canon: nonce required")
	}
	m := map[string]any{
		"v":               Version,
		"action":          a.Action,
		"object":          a.Object,
		"id":              a.ID,
		"requesting_host": a.RequestingHost,
		"kind":            a.Kind,
		"target":          a.Target,
		"login_user":      a.LoginUser,
		"key_fingerprint": a.KeyFingerprint,
		"ttl_seconds":     a.TTLSeconds,
		"standing_hours":  a.StandingHours,
		"nonce":           nonce,
		"issued_at":       issuedAt.UTC().Format(time.RFC3339),
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil { // encoding/json sorts map keys
		return "", err
	}
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

// Challenge returns SHA-256(canonical), the WebAuthn challenge bytes.
func Challenge(canonical string) []byte {
	h := sha256.Sum256([]byte(canonical))
	return h[:]
}

// Parse decodes canonical text produced by Build and checks it round-trips byte for byte,
// so the parsed action is exactly what the challenge committed to.
func Parse(canonical string) (Signed, error) {
	var s Signed
	dec := json.NewDecoder(bytes.NewReader([]byte(canonical)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Signed{}, fmt.Errorf("canon: %w", err)
	}
	if s.V != Version {
		return Signed{}, fmt.Errorf("canon: unsupported version %d", s.V)
	}
	again, err := Build(s.Action, s.Nonce, s.IssuedAt)
	if err != nil {
		return Signed{}, err
	}
	if again != canonical {
		return Signed{}, errors.New("canon: text is not canonical")
	}
	return s, nil
}
