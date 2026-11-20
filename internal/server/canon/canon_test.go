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
	if pk != `{"action":"add","id":"new","issued_at":"2026-11-20T12:00:00Z","nonce":"N","object":"passkey","v":1}` {
		t.Fatal(pk)
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

func TestCloudflareKeySets(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		a    Action
		want string
	}{
		{Action{Action: "approve", Object: "request", ID: "R", RequestingHost: "hosta", Kind: "cloudflare", Scope: "cf.dns.edit",
			ScopeParams: "name=*.example.com;zone=example.com", Mode: "proxy", TTLSeconds: 7200, StandingHours: 4},
			`{"action":"approve","id":"R","ip_condition":"","issued_at":"2026-11-20T12:00:00Z","kind":"cloudflare","mode":"proxy","nonce":"N","object":"request","requesting_host":"hosta","scope":"cf.dns.edit","scope_params":"name=*.example.com;zone=example.com","standing_hours":4,"ttl_seconds":7200,"v":1}`},
		{Action{Action: "approve", Object: "request", ID: "R", RequestingHost: "hosta", Kind: "cloudflare", Scope: "cf.pages",
			ScopeParams: "project=blog", Mode: "token", IPCondition: "198.51.100.0/24,203.0.113.7/32", TTLSeconds: 900},
			`{"action":"approve","id":"R","ip_condition":"198.51.100.0/24,203.0.113.7/32","issued_at":"2026-11-20T12:00:00Z","kind":"cloudflare","mode":"token","nonce":"N","object":"request","requesting_host":"hosta","scope":"cf.pages","scope_params":"project=blog","standing_hours":0,"ttl_seconds":900,"v":1}`},
		{Action{Action: "deny", Object: "request", ID: "R", RequestingHost: "hosta", Kind: "cloudflare", Scope: "cf.admin", Mode: "proxy"},
			`{"action":"deny","id":"R","ip_condition":"","issued_at":"2026-11-20T12:00:00Z","kind":"cloudflare","mode":"proxy","nonce":"N","object":"request","requesting_host":"hosta","scope":"cf.admin","scope_params":"","standing_hours":0,"ttl_seconds":0,"v":1}`},
		{Action{Action: "revoke", Object: "standing", ID: "S", RequestingHost: "hosta", Kind: "cloudflare", Scope: "cf.dns.edit",
			ScopeParams: "zone=example.com", Mode: "proxy", TTLSeconds: 3600},
			`{"action":"revoke","id":"S","issued_at":"2026-11-20T12:00:00Z","kind":"cloudflare","mode":"proxy","nonce":"N","object":"standing","requesting_host":"hosta","scope":"cf.dns.edit","scope_params":"zone=example.com","standing_hours":0,"ttl_seconds":3600,"v":1}`},
		{Action{Action: "revoke", Object: "grant", ID: "G", RequestingHost: "hosta", Kind: "cloudflare", Scope: "cf.read", Mode: "proxy"},
			`{"action":"revoke","id":"G","issued_at":"2026-11-20T12:00:00Z","kind":"cloudflare","mode":"proxy","nonce":"N","object":"grant","requesting_host":"hosta","scope":"cf.read","scope_params":"","standing_hours":0,"ttl_seconds":0,"v":1}`},
	} {
		got, err := Build(tc.a, "N", at)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("canonical\n got %s\nwant %s", got, tc.want)
		}
		s, err := Parse(got)
		if err != nil {
			t.Fatalf("parse %s: %v", got, err)
		}
		if s.Action != tc.a {
			t.Fatalf("round trip %+v != %+v", s.Action, tc.a)
		}
	}
	// Fields a (object, kind) does not carry cannot be built.
	for _, a := range []Action{
		{Action: "approve", Object: "request", ID: "R", Kind: "cloudflare", Target: "db-1"},
		{Action: "approve", Object: "request", ID: "R", Kind: "cloudflare", KeyFingerprint: "SHA256:x"},
		{Action: "approve", Object: "request", ID: "R", Kind: "ssh", Scope: "cf.read"},
		{Action: "approve", Object: "request", ID: "R", Kind: "ssh", Mode: "proxy"},
		{Action: "revoke", Object: "standing", ID: "S", Kind: "cloudflare", IPCondition: "1.2.3.4/32"},
		{Action: "revoke", Object: "grant", ID: "G", Kind: "cloudflare", IPCondition: "1.2.3.4/32"},
		{Action: "revoke", Object: "grant", ID: "G", Kind: "cloudflare", LoginUser: "root"},
		{Action: "approve", Object: "enrollment", ID: "E", Kind: "enrollment", Scope: "cf.read"},
		{Action: "add", Object: "passkey", ID: "new", Mode: "proxy"},
	} {
		if _, err := Build(a, "N", at); err == nil {
			t.Errorf("built %+v", a)
		}
	}
	// Parse picks the key set from (object, kind): an ssh key set under kind "cloudflare" (or
	// the reverse) is refused.
	cf, _ := Build(Action{Action: "deny", Object: "request", ID: "R", Kind: "cloudflare", Mode: "proxy"}, "N", at)
	ssh, _ := Build(Action{Action: "deny", Object: "request", ID: "R", Kind: "ssh"}, "N", at)
	for _, bad := range []string{
		strings.Replace(cf, `"kind":"cloudflare"`, `"kind":"ssh"`, 1),
		strings.Replace(ssh, `"kind":"ssh"`, `"kind":"cloudflare"`, 1),
		strings.Replace(cf, `"ip_condition":"",`, ``, 1),
		strings.Replace(cf, `"id":"R",`, `"id":"R","target":"",`, 1),
		strings.Replace(cf, `"kind":"cloudflare"`, `"kind":1`, 1),
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// The M1 ssh text is unchanged by the new fields.
	if ssh != `{"action":"deny","id":"R","issued_at":"2026-11-20T12:00:00Z","key_fingerprint":"","kind":"ssh","login_user":"","nonce":"N","object":"request","requesting_host":"","standing_hours":0,"target":"","ttl_seconds":0,"v":1}` {
		t.Fatal(ssh)
	}
}
