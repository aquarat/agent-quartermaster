package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestBuildIsCanonical(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.FixedZone("x", 3600))
	a := Action{Action: "approve", Object: "request", ID: "01ABC", RequestingHost: "build-box", Kind: "ssh",
		Target: "db-1", LoginUser: "alice", KeyFingerprint: "SHA256:abc<>&", TTLSeconds: 1800, StandingHours: 2}
	got, err := Build(a, "NONCE", at)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"approve","id":"01ABC","issued_at":"2026-11-20T11:00:00Z","key_fingerprint":"SHA256:abc<>&","kind":"ssh","login_user":"alice","nonce":"NONCE","object":"request","requesting_host":"build-box","standing_hours":2,"target":"db-1","ttl_seconds":1800,"v":1}`
	if got != want {
		t.Fatalf("canonical\n got %s\nwant %s", got, want)
	}
	if strings.ContainsAny(got, " \n\t") {
		t.Fatal("whitespace in canonical text")
	}
	ch := Challenge(got)
	h := sha256.Sum256([]byte(want))
	if !bytes.Equal(ch, h[:]) {
		t.Fatal("challenge is not SHA-256(canonical)")
	}
}

func TestParseRoundTripAndTamper(t *testing.T) {
	a := Action{Action: "deny", Object: "request", ID: "X", Kind: "ssh"}
	n := NewNonce()
	if b, err := base64.RawURLEncoding.DecodeString(n); err != nil || len(b) != 32 {
		t.Fatalf("nonce %q", n)
	}
	text, _ := Build(a, n, time.Now())
	s, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if s.Action != a || s.Nonce != n || s.V != 1 {
		t.Fatalf("round trip %+v", s)
	}
	for _, bad := range []string{
		strings.Replace(text, `"deny"`, `"approve"`, 1) + " ",            // trailing data
		strings.Replace(text, `{"action"`, `{ "action"`, 1),              // whitespace
		strings.Replace(text, `"v":1`, `"v":2`, 1),                       // version
		strings.Replace(text, `"action":"deny",`, ``, 1),                 // missing key
		strings.Replace(text, `"id":"X"`, `"id":"X","extra":1`, 1),       // unknown key
		strings.Replace(text, `"ttl_seconds":0`, `"ttl_seconds":0.0`, 1), // non-canonical number
	} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("accepted non-canonical text %s", bad)
		}
	}
	// Different nonces give different challenges for the same action.
	t2, _ := Build(a, NewNonce(), time.Now())
	if bytes.Equal(Challenge(text), Challenge(t2)) {
		t.Fatal("same challenge for different nonces")
	}
	if _, err := Build(Action{Action: "approve"}, n, time.Now()); err == nil {
		t.Fatal("built without object/id")
	}
}

func TestPerObjectKeySets(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	en, err := Build(Action{Action: "approve", Object: "enrollment", ID: "E", RequestingHost: "h", Kind: "enrollment", KeyFingerprint: "SHA256:x", Replaces: true}, "N", at)
	if err != nil {
		t.Fatal(err)
	}
	if en != `{"action":"approve","id":"E","issued_at":"2026-11-20T12:00:00Z","key_fingerprint":"SHA256:x","kind":"enrollment","nonce":"N","object":"enrollment","replaces":true,"requesting_host":"h","standing_hours":0,"ttl_seconds":0,"v":1}` {
		t.Fatal(en)
	}
	pk, _ := Build(Action{Action: "add", Object: "passkey", ID: "new"}, "N", at)
	if pk != `{"action":"add","id":"new","issued_at":"2026-11-20T12:00:00Z","new_nickname":"","nickname":"","nonce":"N","object":"passkey","v":1}` {
		t.Fatal(pk)
	}
	rn, err := Build(Action{Action: "rename", Object: "passkey", ID: "0123abcd", Nickname: "Bitwarden", NewNickname: "Phone <&>"}, "N", at)
	if err != nil {
		t.Fatal(err)
	}
	if rn != `{"action":"rename","id":"0123abcd","issued_at":"2026-11-20T12:00:00Z","new_nickname":"Phone <&>","nickname":"Bitwarden","nonce":"N","object":"passkey","v":1}` {
		t.Fatal(rn)
	}
	if s, err := Parse(rn); err != nil || s.NewNickname != "Phone <&>" || s.Nickname != "Bitwarden" || s.Action.Action != ActionRename {
		t.Fatalf("parse rename: %+v %v", s, err)
	}
	if _, err := Build(Action{Action: "remove", Object: "passkey", ID: "0123abcd", Nickname: "Bitwarden"}, "N", at); err != nil {
		t.Fatal(err)
	}
	if s, err := Parse(en); err != nil || !s.Replaces {
		t.Fatalf("parse enrollment: %v", err)
	}
	// Fields an object doesn't carry can't be set (they would be acted on but not signed).
	for _, a := range []Action{
		{Action: "approve", Object: "enrollment", ID: "E", Target: "db-1"},
		{Action: "revoke", Object: "grant", ID: "G", KeyFingerprint: "x"},
		{Action: "add", Object: "passkey", ID: "new", Kind: "passkey"},
		{Action: "approve", Object: "request", ID: "R", Replaces: true},
		{Action: "approve", Object: "grant", ID: "G"},
		{Action: "register", Object: "passkey", ID: "new"},
		{Action: "approve", Object: "request", ID: "R", Nickname: "x"},
		{Action: "revoke", Object: "grant", ID: "G", NewNickname: "x"},
	} {
		if _, err := Build(a, "N", at); err == nil {
			t.Errorf("built %+v", a)
		}
	}
	// A request text with an enrollment-only key, or missing one, is refused.
	req, _ := Build(Action{Action: "deny", Object: "request", ID: "R"}, "N", at)
	if _, err := Parse(strings.Replace(req, `"requesting_host":""`, `"replaces":false,"requesting_host":""`, 1)); err == nil {
		t.Fatal("extra key accepted")
	}
	if _, err := Parse(strings.Replace(pk, `"object":"passkey"`, `"object":"passkey","object":"request"`, 1)); err == nil {
		t.Fatal("duplicate key accepted")
	}
}
