package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"testing"
)

// uiCheck applies the web UI's pre-signing checks (web/src/canonical.ts parseCanonical and
// challengeCommitsTo on ws/web) to a challenge response, so every challenge the tests obtain is
// one the real UI would agree to sign.
func uiCheck(t *testing.T, cr challengeResp) map[string]any {
	t.Helper()
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader([]byte(cr.Canonical)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("ui: canonical not JSON: %v", err)
	}
	// Re-serialise sorted, no whitespace (JS JSON.stringify of each value).
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kj, _ := json.Marshal(k)
		b.Write(kj)
		b.WriteByte(':')
		switch x := v[k].(type) {
		case json.Number:
			b.WriteString(x.String())
		default:
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			enc.Encode(x)
			b.Truncate(b.Len() - 1)
		}
	}
	b.WriteByte('}')
	if b.String() != cr.Canonical {
		t.Fatalf("ui: not canonical form:\n%s\n%s", cr.Canonical, b.String())
	}
	if v["v"] != json.Number("1") {
		t.Fatalf("ui: version %v", v["v"])
	}
	common := []string{"v", "action", "object", "id", "nonce", "issued_at"}
	allowed := map[string][]string{
		"request":    append(slices.Clone(common), "requesting_host", "kind", "target", "login_user", "key_fingerprint", "ttl_seconds", "standing_hours"),
		"enrollment": append(slices.Clone(common), "requesting_host", "kind", "key_fingerprint", "replaces", "ttl_seconds", "standing_hours"),
		"standing":   append(slices.Clone(common), "requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"),
		"grant":      append(slices.Clone(common), "requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"),
		"passkey":    append(slices.Clone(common), "nickname", "new_nickname"),
	}
	actions := map[string][]string{"request": {"approve", "deny"}, "enrollment": {"approve", "deny"}, "standing": {"revoke"}, "grant": {"revoke"}, "passkey": {"add", "rename", "remove"}}
	obj, _ := v["object"].(string)
	al, ok := allowed[obj]
	if !ok {
		t.Fatalf("ui: unknown object %q", obj)
	}
	if act, _ := v["action"].(string); !slices.Contains(actions[obj], act) {
		t.Fatalf("ui: action %q for %s", act, obj)
	}
	for _, k := range keys {
		if !slices.Contains(al, k) {
			t.Fatalf("ui: field %s not allowed for %s", k, obj)
		}
	}
	if r, ok := v["replaces"]; ok {
		if _, isBool := r.(bool); !isBool {
			t.Fatal("ui: replaces not a boolean")
		}
	}
	// public_key: go-webauthn wrapper or bare options; challenge == SHA-256(canonical).
	var pk map[string]json.RawMessage
	json.Unmarshal(cr.PublicKey, &pk)
	if inner, ok := pk["publicKey"]; ok {
		pk = nil
		json.Unmarshal(inner, &pk)
	}
	var ch string
	json.Unmarshal(pk["challenge"], &ch)
	got, err := b64url(ch)
	sum := sha256.Sum256([]byte(cr.Canonical))
	if err != nil || !bytes.Equal(got, sum[:]) {
		t.Fatal("ui: challenge is not SHA-256(canonical)")
	}
	var uv string
	json.Unmarshal(pk["userVerification"], &uv)
	if uv != "required" {
		t.Fatalf("ui: userVerification %q", uv)
	}
	var timeout int
	json.Unmarshal(pk["timeout"], &timeout)
	if timeout <= 0 || timeout > 120000 {
		t.Fatalf("ui: timeout %d", timeout)
	}
	return v
}

var _ = fmt.Sprint
