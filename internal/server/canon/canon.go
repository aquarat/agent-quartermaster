// Package canon builds the canonical action text that a per-action WebAuthn challenge commits
// to (docs/API.md, "Approval challenge"). The challenge is SHA-256(canonical); on decide the
// server re-parses the stored canonical text and applies exactly the action it describes.
//
// Each object has a fixed key set (the web UI refuses to sign text with any other key):
//
//	common:     v, action, object, id, nonce, issued_at
//	request:    + requesting_host, kind, target, login_user, key_fingerprint, ttl_seconds, standing_hours
//	enrollment: + requesting_host, kind, key_fingerprint, replaces, ttl_seconds, standing_hours
//	standing:   + requesting_host, kind, target, login_user, ttl_seconds, standing_hours
//	grant:      + requesting_host, kind, target, login_user, ttl_seconds, standing_hours
//	passkey:    + nickname, new_nickname
//
// For passkey "add" the id is "new" and both nicknames are ""; for "rename" and "remove" the
// id is the passkey's id (hex of the first 16 bytes of SHA-256 of the credential ID),
// nickname its current nickname and new_nickname the new one (rename) or "" (remove).
package canon

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Version is the canonical format version ("v").
const Version = 1

// Actions.
const (
	ActionApprove = "approve"
	ActionDeny    = "deny"
	ActionRevoke  = "revoke"
	ActionAdd     = "add"    // add another passkey
	ActionRename  = "rename" // rename a passkey
	ActionRemove  = "remove" // remove a passkey
)

// Objects.
const (
	ObjectRequest    = "request"
	ObjectEnrollment = "enrollment"
	ObjectStanding   = "standing"
	ObjectGrant      = "grant"
	ObjectPasskey    = "passkey"
)

var commonKeys = []string{"v", "action", "object", "id", "nonce", "issued_at"}

// objectKeys are the keys each object carries besides the common ones.
var objectKeys = map[string][]string{
	ObjectRequest:    {"requesting_host", "kind", "target", "login_user", "key_fingerprint", "ttl_seconds", "standing_hours"},
	ObjectEnrollment: {"requesting_host", "kind", "key_fingerprint", "replaces", "ttl_seconds", "standing_hours"},
	ObjectStanding:   {"requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"},
	ObjectGrant:      {"requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"},
	ObjectPasskey:    {"nickname", "new_nickname"},
}

var objectActions = map[string][]string{
	ObjectRequest:    {ActionApprove, ActionDeny},
	ObjectEnrollment: {ActionApprove, ActionDeny},
	ObjectStanding:   {ActionRevoke},
	ObjectGrant:      {ActionRevoke},
	ObjectPasskey:    {ActionAdd, ActionRename, ActionRemove},
}

// Action is everything the owner approves with one passkey assertion.
type Action struct {
	Action         string `json:"action"`
	Object         string `json:"object"`
	ID             string `json:"id"`
	RequestingHost string `json:"requesting_host"`
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	LoginUser      string `json:"login_user"`
	KeyFingerprint string `json:"key_fingerprint"`
	Replaces       bool   `json:"replaces"` // enrollment: approving revokes an existing host
	TTLSeconds     int    `json:"ttl_seconds"`
	StandingHours  int    `json:"standing_hours"`
	Nickname       string `json:"nickname"`     // passkey: its current nickname
	NewNickname    string `json:"new_nickname"` // passkey rename: the new nickname
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

func (a Action) values() map[string]any {
	return map[string]any{
		"requesting_host": a.RequestingHost,
		"kind":            a.Kind,
		"target":          a.Target,
		"login_user":      a.LoginUser,
		"key_fingerprint": a.KeyFingerprint,
		"replaces":        a.Replaces,
		"ttl_seconds":     a.TTLSeconds,
		"standing_hours":  a.StandingHours,
		"nickname":        a.Nickname,
		"new_nickname":    a.NewNickname,
	}
}

func isZero(v any) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case int:
		return x == 0
	case bool:
		return !x
	}
	return false
}

// Build returns the canonical UTF-8 JSON text for a: the object's fixed key set, keys sorted
// (encoding/json sorts map keys bytewise; all keys are ASCII), no insignificant whitespace, no
// HTML escaping. A field set on an object that does not carry it is an error, so nothing the
// server acts on can be left out of what the owner signs.
func Build(a Action, nonce string, issuedAt time.Time) (string, error) {
	if a.Action == "" || a.ID == "" {
		return "", errors.New("canon: action and id are required")
	}
	keys, ok := objectKeys[a.Object]
	if !ok {
		return "", fmt.Errorf("canon: unknown object %q", a.Object)
	}
	if !slices.Contains(objectActions[a.Object], a.Action) {
		return "", fmt.Errorf("canon: action %q not valid for %s", a.Action, a.Object)
	}
	if nonce == "" {
		return "", errors.New("canon: nonce required")
	}
	if a.TTLSeconds < 0 || a.StandingHours < 0 {
		return "", errors.New("canon: negative ttl or standing hours")
	}
	m := map[string]any{
		"v":         Version,
		"action":    a.Action,
		"object":    a.Object,
		"id":        a.ID,
		"nonce":     nonce,
		"issued_at": issuedAt.UTC().Format(time.RFC3339),
	}
	for k, v := range a.values() {
		if slices.Contains(keys, k) {
			m[k] = v
		} else if !isZero(v) {
			return "", fmt.Errorf("canon: %s does not carry %s", a.Object, k)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

// Challenge returns SHA-256(canonical), the WebAuthn challenge bytes.
func Challenge(canonical string) []byte {
	h := sha256.Sum256([]byte(canonical))
	return h[:]
}

// Parse decodes canonical text produced by Build: it must have exactly the object's key set and
// round-trip byte for byte, so the parsed action is exactly what the challenge committed to.
func Parse(canonical string) (Signed, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(canonical), &raw); err != nil {
		return Signed{}, fmt.Errorf("canon: %w", err)
	}
	var obj string
	if err := json.Unmarshal(raw["object"], &obj); err != nil {
		return Signed{}, errors.New("canon: no object")
	}
	keys, ok := objectKeys[obj]
	if !ok {
		return Signed{}, fmt.Errorf("canon: unknown object %q", obj)
	}
	want := append(slices.Clone(commonKeys), keys...)
	if len(raw) != len(want) {
		return Signed{}, errors.New("canon: wrong key set")
	}
	for _, k := range want {
		if _, ok := raw[k]; !ok {
			return Signed{}, fmt.Errorf("canon: missing %s", k)
		}
	}
	var s Signed
	if err := json.Unmarshal([]byte(canonical), &s); err != nil {
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
