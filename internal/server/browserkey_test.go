//go:build linux

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// Remembered browsers (docs/BUCKETS.md §13). testBrowser plays one browser
// profile: it holds the private half of a browser key (the broker never sees
// it) and remembers every KEK it made or opened, for the leak checks.
type testBrowser struct {
	key  *seal.Key
	pub  []byte
	keks [][]byte
}

func newTestBrowser(t *testing.T) *testBrowser {
	t.Helper()
	k, pub, err := seal.NewKeyPair()
	requireNoError(t, err)
	t.Cleanup(k.Destroy)
	return &testBrowser{key: k, pub: pub}
}
func (b *testBrowser) id() string { return seal.BrowserKeyID(b.pub) }

type releaseResp struct {
	Wraps []struct {
		Scope     string `json:"scope"`
		ID        string `json:"id"`
		SealedKEK string `json:"sealed_kek"`
	} `json:"wraps"`
}

func (v *vaultEnv) release(r tapResp, as json.RawMessage, pub []byte, out any) int {
	return v.web("POST", "/api/ui/seal/browser/release", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "browser_key": encodeID(pub)}, out)
}

// tapBrowser plays the page of a remembered browser for a tap by a (a passkey
// without PRF): sign, ask for the sealed KEKs with that assertion, open them
// with the browser key and seal the KEKs to the descriptor's recipient. An
// enrol tap makes fresh KEKs instead; a rekey adds one.
func (v *vaultEnv) tapBrowser(a *vauth.Authenticator, b *testBrowser, r tapResp) (json.RawMessage, *api.OpenPacket, int) {
	v.t.Helper()
	if r.Open == nil {
		v.t.Fatal("no open offered")
	}
	challenge := seal.OpenChallenge([]byte(r.Canonical), []byte(r.Open.Descriptor))
	as := a.Assert(challenge)
	var d struct {
		descriptor
		Browser string `json:"browser_key"`
	}
	requireNoError(v.t, json.Unmarshal([]byte(r.Open.Descriptor), &d))
	var frames [][]byte
	fresh := func() {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		b.keks = append(b.keks, k)
		frames = append(frames, bytes.Clone(k))
	}
	if d.Object == "scope-enrol" && d.Purpose == "enrol" {
		if d.Browser != encodeID(b.pub) {
			v.t.Fatalf("enrol descriptor names browser key %q", d.Browser)
		}
		for range d.Scopes {
			fresh()
		}
	} else {
		var rel releaseResp
		if st := v.release(r, as, b.pub, &rel); st != 200 {
			return as, nil, st
		}
		if len(rel.Wraps) != len(d.Scopes) {
			v.t.Fatalf("release returned %d wraps for %d scopes", len(rel.Wraps), len(d.Scopes))
		}
		for i, w := range rel.Wraps {
			id, _ := b64url(w.ID)
			sealed, _ := b64url(w.SealedKEK)
			bs := seal.BrowserScope{Installation: v.fix.inst, RPID: v.s.rpID, RawID: a.CredID, Scope: d.Scopes[i], Browser: b.pub}
			copy(bs.WrapID[:], id)
			if w.Scope != d.Scopes[i] {
				v.t.Fatal("release out of scope order")
			}
			kek, err := bs.OpenKEK(b.key, sealed)
			requireNoError(v.t, err)
			b.keks = append(b.keks, bytes.Clone(kek.Bytes()))
			frames = append(frames, bytes.Clone(kek.Bytes()))
			kek.Destroy()
		}
		if d.RekeySalt != "" {
			fresh()
		}
	}
	if len(frames) == 1 {
		frames = append(frames, nil)
	}
	attempt, _ := b64url(d.Attempt)
	epoch, _ := b64url(d.Epoch)
	pub, _ := b64url(d.Recipient)
	var at, ep seal.ID
	copy(at[:], attempt)
	copy(ep[:], epoch)
	enc, ct, err := seal.SealTo(pub, seal.OpenInfo(v.fix.inst, d.Purpose), seal.OpenAAD(at, ep, challenge, a.CredID), seal.Frames(frames...))
	requireNoError(v.t, err)
	return as, &api.OpenPacket{AttemptID: d.Attempt, Enc: encodeID(enc), Ciphertext: encodeID(ct)}, 200
}

// nickOf names the passkeys registerSpare2 added (registerSpare's is "spare").
var nickOf sync.Map

func rememberBody(spare *vauth.Authenticator, b *testBrowser, action string, scopes []string) map[string]any {
	nick := "spare"
	if n, ok := nickOf.Load(string(spare.CredID)); ok {
		nick = n.(string)
	}
	m := map[string]any{"action": action, "nickname": nick, "capability": "unlock", "credential_id": encodeID(spare.CredID), "scopes": scopes, "browser_key": encodeID(b.pub)}
	if action == "remember" {
		m["browser_label"] = "Test browser"
	}
	return m
}

// remember runs the whole enable for a passkey without PRF: signer approves
// (and opens the scope keys with tap), the target taps to create its wraps,
// then tests them.
func (v *vaultEnv) remember(spare *vauth.Authenticator, b *testBrowser, scopes []string, tap func(tapResp) (json.RawMessage, *api.OpenPacket)) {
	v.t.Helper()
	var r tapResp
	mustStatus(v.t, "remember challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", rememberBody(spare, b, "remember", scopes), &r), 200)
	if !strings.Contains(r.Canonical, `"browser_key_id":"`+b.id()+`"`) || !strings.Contains(r.Canonical, `"credential_id":"`+encodeID(spare.CredID)+`"`) || !strings.Contains(r.Canonical, `"browser_label":"Test browser"`) {
		v.t.Fatalf("the canonical does not name the passkey and the browser key: %s", r.Canonical)
	}
	as, pkt := tap(r)
	var auth struct {
		Registration string `json:"registration_id"`
	}
	mustStatus(v.t, "remember authorize", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &auth), 200)
	var e tapResp
	mustStatus(v.t, "evaluate", v.web("POST", "/api/ui/seal/passkeys/evaluate", map[string]any{"registration_id": auth.Registration}, &e), 200)
	if !strings.Contains(e.Canonical, `"browser_key_id":"`+b.id()+`"`) {
		v.t.Fatalf("the enrol canonical does not name the browser key: %s", e.Canonical)
	}
	as, pkt, _ = v.tapBrowser(spare, b, e)
	mustStatus(v.t, "remember finish", v.web("POST", "/api/ui/seal/passkeys/finish", map[string]any{"registration_id": auth.Registration, "challenge_id": e.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
	v.testBrowser(spare, b, scopes)
}
func (v *vaultEnv) ownerTap(r tapResp) (json.RawMessage, *api.OpenPacket) {
	return v.fix.tapWith(v.t, v.s, v.auth, r)
}
func (v *vaultEnv) testBrowser(spare *vauth.Authenticator, b *testBrowser, scopes []string) {
	v.t.Helper()
	var r tapResp
	mustStatus(v.t, "test challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", rememberBody(spare, b, "test", scopes), &r), 200)
	as, pkt, st := v.tapBrowser(spare, b, r)
	mustStatus(v.t, "test release", st, 200)
	var res struct{ OK bool }
	mustStatus(v.t, "test", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &res), 200)
	if !res.OK {
		v.t.Fatal("browser test failed")
	}
}
func (v *vaultEnv) browserWraps(a *vauth.Authenticator) []store.BrowserWrapRow {
	all, err := v.s.store.Q().BrowserWraps(v.t.Context(), 0)
	requireNoError(v.t, err)
	var out []store.BrowserWrapRow
	for _, w := range all {
		if bytes.Equal(w.RawID, a.CredID) {
			out = append(out, w)
		}
	}
	return out
}

// decideBrowser runs challenge + decide for a request with a remembered-browser tap.
func (v *vaultEnv) decideBrowser(a *vauth.Authenticator, b *testBrowser, id string) int {
	v.t.Helper()
	var r tapResp
	if st := v.web("POST", "/api/ui/requests/"+id+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r); st != 200 {
		return st
	}
	as, pkt, st := v.tapBrowser(a, b, r)
	if st != 200 {
		// As the page does: no packet, and the broker says why.
		return v.web("POST", "/api/ui/requests/"+id+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as}, nil)
	}
	return v.web("POST", "/api/ui/requests/"+id+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil)
}

type statusPasskey struct {
	ID     string
	Name   string
	PRF    bool
	Mode   string
	Opens  int
	Scopes []struct {
		Scope  string
		Tested bool
	}
	Browsers []struct {
		ID, Label string
		Created   string `json:"created_at"`
		LastUsed  string `json:"last_used_at"`
		Scopes    []struct {
			Scope  string
			Tested bool
		}
	}
}

func (v *vaultEnv) statusOf(a *vauth.Authenticator) statusPasskey {
	v.t.Helper()
	var st struct{ Passkeys []statusPasskey }
	mustStatus(v.t, "status", v.web("GET", "/api/ui/seal/status", nil, &st), 200)
	for _, p := range st.Passkeys {
		if p.ID == passkeyID(a.CredID) {
			return p
		}
	}
	v.t.Fatal("passkey not in status")
	return statusPasskey{}
}

func TestBrowserKeyEnableOpenForget(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "v1"}}}, nil)
	spare := v.registerSpare("approve-only", []string{}, nil)
	b := newTestBrowser(t)
	rc := ownerOnlySSH(t, v)
	mustStatus(t, "not remembered yet", v.decideBrowser(spare, b, rc.ID), 423)
	if p := v.statusOf(spare); p.Mode != "" || p.PRF || len(p.Browsers) != 0 {
		t.Fatalf("status before: %+v", p)
	}

	v.remember(spare, b, []string{"installation", v.org}, v.ownerTap)
	w := v.browserWraps(spare)
	if len(w) != 2 || w[0].Tested == nil || w[1].Tested == nil || len(v.wraps(spare)) != 0 {
		t.Fatalf("wraps after remember: %+v", w)
	}
	if !v.audited("passkey_remember_browser", `"browser_key_id":"`+b.id()+`"`) || !v.audited("passkey_remember_browser", `"credential_id":"`+encodeID(spare.CredID)+`"`) {
		t.Fatal("the audit log does not name the passkey and the browser key")
	}
	p := v.statusOf(spare)
	if p.Mode != "browser" || p.PRF || len(p.Browsers) != 1 || p.Browsers[0].ID != b.id() || p.Browsers[0].Label != "Test browser" || p.Browsers[0].LastUsed == "" || p.Browsers[0].Created == "" || len(p.Scopes) != 2 || !p.Scopes[0].Tested || p.Opens != 3 {
		t.Fatalf("status after remember: %+v", p)
	}
	if o := v.statusOf(v.auth); o.Mode != "prf" || !o.PRF || len(o.Browsers) != 0 {
		t.Fatalf("the PRF passkey's status changed: %+v", o)
	}

	// The offer lists the pair; the tap opens the SSH CA.
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", "/api/ui/requests/"+rc.ID+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r), 200)
	if r.Open == nil || len(r.Open.Browsers) != 1 || r.Open.Browsers[0].CredentialID != encodeID(spare.CredID) || r.Open.Browsers[0].KeyID != b.id() || r.Open.Browsers[0].Label != "Test browser" {
		t.Fatalf("offer: %+v", r.Open)
	}
	if strings.Contains(r.Open.Descriptor, "sealed") || strings.Contains(string(r.PublicKey), encodeID(w[0].SealedKEK)) {
		t.Fatal("the challenge carries a sealed KEK before any assertion")
	}
	mustStatus(t, "approve from the remembered browser", v.decideBrowser(spare, b, rc.ID), 200)

	// Reveal in the vault (the organisation's scope).
	rv, k, st := v.revealChallenge([]string{"APP_TOKEN"})
	mustStatus(t, "reveal challenge", st, 200)
	as, pkt, st := v.tapBrowser(spare, b, rv.tap())
	mustStatus(t, "reveal release", st, 200)
	var out struct{ Enc, Ciphertext string }
	mustStatus(t, "reveal", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": rv.ChallengeID, "assertion": as, "open": pkt}, &out), 200)
	if got, err := v.openReveal(rv, k, out.Enc, out.Ciphertext); err != nil || got[0].Value != "v1" {
		t.Fatal("reveal from the remembered browser")
	}

	// A browser-key passkey approves and opens for enabling another passkey.
	third := v.registerSpare2("third")
	v.fix.prf[string(third.CredID)] = []byte("third-prf-secret")
	body := map[string]any{"action": "enable", "nickname": "third", "capability": "unlock", "credential_id": encodeID(third.CredID), "scopes": []string{"installation"}}
	mustStatus(t, "enable challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", body, &r), 200)
	as, pkt, st = v.tapBrowser(spare, b, r)
	mustStatus(t, "enable release", st, 200)
	var auth struct {
		Registration string `json:"registration_id"`
	}
	mustStatus(t, "enable approved by a browser-key passkey", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &auth), 200)
	v.enrolFinish(third, auth.Registration)
	if len(v.wraps(third)) != 1 {
		t.Fatal("the browser-key passkey did not enable another passkey")
	}

	// Nothing that unwraps is stored or sent: not a KEK, not the browser key.
	for _, kek := range b.keks {
		if where := v.leaked(kek); where != "" {
			t.Fatalf("a browser KEK is readable in %s", where)
		}
	}
	if where := v.leaked(b.key.Bytes()); where != "" {
		t.Fatalf("the browser key's private half is in %s", where)
	}
	// What is stored opens only with the browser's private key.
	other := newTestBrowser(t)
	bs := v.s.browserScope(w[0])
	if _, err := bs.OpenKEK(other.key, w[0].SealedKEK); err == nil {
		t.Fatal("a sealed KEK opened without its browser key")
	}
	bs.Browser = other.pub
	if _, err := bs.OpenKEK(other.key, w[0].SealedKEK); err == nil {
		t.Fatal("a sealed KEK opened for another browser key")
	}

	// Forget: a signed action naming the passkey and the browser key; the wraps go.
	rc2 := ownerOnlySSH(t, v)
	r = tapResp{}
	mustStatus(t, "forget challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", rememberBody(spare, b, "forget", []string{}), &r), 200)
	if r.Open != nil || !strings.Contains(r.Canonical, `"browser_key_id":"`+b.id()+`"`) || !strings.Contains(r.Canonical, `"action":"forget"`) {
		t.Fatalf("forget canonical: %s", r.Canonical)
	}
	as, _ = v.ownerTap(r)
	mustStatus(t, "forget", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as}, nil), 200)
	var n int
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT (SELECT count(*) FROM browser_keys)+(SELECT count(*) FROM browser_wraps)`).Scan(&n))
	if n != 0 || !v.audited("passkey_forget_browser", b.id()) {
		t.Fatal("forget left rows, or was not audited")
	}
	mustStatus(t, "forgotten browser is refused", v.decideBrowser(spare, b, rc2.ID), 423)
	if p := v.statusOf(spare); p.Mode != "" || len(p.Browsers) != 0 || p.Opens != 0 {
		t.Fatalf("status after forget: %+v", p)
	}
}

// registerSpare2 adds another approve-only passkey with its own nickname.
func (v *vaultEnv) registerSpare2(name string) *vauth.Authenticator {
	v.t.Helper()
	var r tapResp
	mustStatus(v.t, "register challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", map[string]any{"action": "register", "nickname": name, "capability": "approve-only", "credential_id": "", "scopes": []string{}}, &r), 200)
	as, pkt := v.fix.tapWith(v.t, v.s, v.auth, r)
	var auth struct {
		Registration string          `json:"registration_id"`
		PublicKey    json.RawMessage `json:"public_key"`
	}
	mustStatus(v.t, "authorize", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &auth), 200)
	a := vauth.New(testBase)
	cred, err := a.Register(auth.PublicKey)
	requireNoError(v.t, err)
	mustStatus(v.t, "create", v.web("POST", "/api/ui/seal/passkeys/create", map[string]any{"registration_id": auth.Registration, "credential": cred}, nil), 200)
	nickOf.Store(string(a.CredID), name)
	return a
}

// The sealed KEKs leave the broker only inside a valid tap by the wrap's own
// passkey, once, and never for another passkey or another browser key.
func TestBrowserKeyReleaseBinding(t *testing.T) {
	v := newVault(t)
	spare := v.registerSpare("approve-only", []string{}, nil)
	b := newTestBrowser(t)
	v.remember(spare, b, []string{"installation"}, v.ownerTap)
	other := v.registerSpare2("other")
	ob := newTestBrowser(t)
	rc := ownerOnlySSH(t, v)
	challenge := func() tapResp {
		var r tapResp
		mustStatus(t, "challenge", v.web("POST", "/api/ui/requests/"+rc.ID+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r), 200)
		return r
	}
	bound := func(r tapResp) []byte { return seal.OpenChallenge([]byte(r.Canonical), []byte(r.Open.Descriptor)) }
	sealed := encodeID(v.browserWraps(spare)[0].SealedKEK)
	from := v.seen.Len() // the enable's own test tap released it, legitimately
	noWrap := func(what string) {
		t.Helper()
		if strings.Contains(v.seen.String()[from:], sealed) {
			t.Fatalf("%s: the sealed KEK was handed out", what)
		}
	}
	// No assertion, an assertion over another challenge, an unbound assertion.
	r := challenge()
	mustStatus(t, "release without an assertion", v.release(r, nil, b.pub, nil), 400)
	r2 := challenge()
	mustStatus(t, "assertion of another tap", v.release(r, spare.Assert(bound(r2)), b.pub, nil), 403)
	mustStatus(t, "assertion over the canonical alone", v.release(r, spare.Assert(sha256Bytes(r.Canonical)), b.pub, nil), 403)
	noWrap("bad assertions")
	// Passkey B's valid assertion does not release passkey A's wrap, whether B
	// is approve-only, a PRF passkey, or remembered for a browser of its own.
	r = challenge()
	mustStatus(t, "another passkey, A's browser key", v.release(r, other.Assert(bound(r)), b.pub, nil), 423)
	r = challenge()
	mustStatus(t, "the PRF passkey, A's browser key", v.release(r, v.auth.Assert(bound(r)), b.pub, nil), 423)
	v.remember(other, ob, []string{"installation"}, v.ownerTap)
	r = challenge()
	mustStatus(t, "B remembered elsewhere, A's browser key", v.release(r, other.Assert(bound(r)), b.pub, nil), 423)
	r = challenge()
	mustStatus(t, "A, B's browser key", v.release(r, spare.Assert(bound(r)), ob.pub, nil), 423)
	noWrap("another passkey or browser key")
	// A's release cannot be finished by B: the packet is bound to the signer.
	r = challenge()
	_, pkt, st := v.tapBrowser(spare, b, r)
	mustStatus(t, "release", st, 200)
	mustStatus(t, "another passkey finishes A's release", v.web("POST", "/api/ui/requests/"+rc.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: other.Assert(bound(r)), Open: pkt}, nil), 403)
	if v.s.seal.pool.count() != 0 {
		t.Fatal("a refused finish opened a bucket")
	}
	// One release per tap; none after the tap is finished (replay).
	r = challenge()
	as, pkt, st := v.tapBrowser(spare, b, r)
	mustStatus(t, "release", st, 200)
	mustStatus(t, "second release of one tap", v.release(r, as, b.pub, nil), 409)
	mustStatus(t, "approve", v.web("POST", "/api/ui/requests/"+rc.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil), 200)
	mustStatus(t, "release replayed after the finish", v.release(r, as, b.pub, nil), 409)
	if st := v.web("POST", "/api/ui/requests/"+rc.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil); st == 200 {
		t.Fatal("replayed tap accepted")
	}
	// A browser tap without the release step opens nothing.
	rc = ownerOnlySSH(t, v)
	r = challenge()
	kek := b.keks[len(b.keks)-1]
	var d descriptor
	requireNoError(t, json.Unmarshal([]byte(r.Open.Descriptor), &d))
	attempt, _ := b64url(d.Attempt)
	epoch, _ := b64url(d.Epoch)
	pub, _ := b64url(d.Recipient)
	var at, ep seal.ID
	copy(at[:], attempt)
	copy(ep[:], epoch)
	enc, ct, err := seal.SealTo(pub, seal.OpenInfo(v.fix.inst, d.Purpose), seal.OpenAAD(at, ep, bound(r), spare.CredID), seal.Frames(kek, nil))
	requireNoError(t, err)
	mustStatus(t, "KEK without a release", v.web("POST", "/api/ui/requests/"+rc.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: spare.Assert(bound(r)), Open: &api.OpenPacket{AttemptID: d.Attempt, Enc: encodeID(enc), Ciphertext: encodeID(ct)}}, nil), 423)
	if v.s.seal.pool.count() != 0 {
		t.Fatal("a tap without a release opened a bucket")
	}
	// The release recorded nothing: the passkey's sign count is the finish's.
	if !strings.Contains(v.logs.String(), "sealed keys released to a remembered browser") {
		t.Fatal("release not logged")
	}
}

// A passkey opens buckets one way: PRF, or remembered browsers. A PRF passkey
// is never moved to the browser path, and the other way round.
func TestBrowserKeyOnlyWithoutPRF(t *testing.T) {
	v := newVault(t)
	b := newTestBrowser(t)
	owner := map[string]any{"action": "remember", "nickname": "test", "capability": "unlock", "credential_id": encodeID(v.auth.CredID), "scopes": []string{"installation"}, "browser_key": encodeID(b.pub), "browser_label": "Test browser"}
	mustStatus(t, "remember a PRF passkey", v.web("POST", "/api/ui/seal/passkeys/challenge", owner, nil), 409)
	spare := v.registerSpare("approve-only", []string{}, nil)
	v.remember(spare, b, []string{"installation"}, v.ownerTap)
	enable := map[string]any{"action": "enable", "nickname": "spare", "capability": "unlock", "credential_id": encodeID(spare.CredID), "scopes": []string{v.org}}
	mustStatus(t, "PRF-enable a browser-key passkey", v.web("POST", "/api/ui/seal/passkeys/challenge", enable, nil), 409)
	// Malformed intents.
	for what, m := range map[string]map[string]any{
		"no browser key":   {"browser_key": ""},
		"not a point":      {"browser_key": encodeID(bytes.Repeat([]byte{4}, 65))},
		"no label":         {"browser_label": ""},
		"untrimmed label":  {"browser_label": " x "},
		"approve-only":     {"capability": "approve-only", "scopes": []string{}},
		"control in label": {"browser_label": "a\u0007b"},
	} {
		body := rememberBody(spare, b, "remember", []string{v.org})
		for k, x := range m {
			body[k] = x
		}
		mustStatus(t, what, v.web("POST", "/api/ui/seal/passkeys/challenge", body, nil), 400)
	}
	extra := map[string]any{"action": "enable", "nickname": "spare", "capability": "unlock", "credential_id": encodeID(spare.CredID), "scopes": []string{v.org}, "browser_key": encodeID(b.pub)}
	mustStatus(t, "enable with a browser key", v.web("POST", "/api/ui/seal/passkeys/challenge", extra, nil), 400)
	// A tested browser wrap is never replaced.
	mustStatus(t, "remember again (tested)", v.web("POST", "/api/ui/seal/passkeys/challenge", rememberBody(spare, b, "remember", []string{"installation"}), nil), 409)
	// The enrol step refuses a packet of another tap's attempt and a missing one.
	var r tapResp
	mustStatus(t, "remember challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", rememberBody(spare, b, "remember", []string{v.org}), &r), 200)
	as, pkt := v.ownerTap(r)
	var auth struct {
		Registration string `json:"registration_id"`
	}
	mustStatus(t, "authorize", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &auth), 200)
	var e tapResp
	mustStatus(t, "evaluate", v.web("POST", "/api/ui/seal/passkeys/evaluate", map[string]any{"registration_id": auth.Registration}, &e), 200)
	as, _, _ = v.tapBrowser(spare, b, e)
	mustStatus(t, "enrol without keys", v.web("POST", "/api/ui/seal/passkeys/finish", map[string]any{"registration_id": auth.Registration, "challenge_id": e.ChallengeID, "assertion": as}, nil), 409)
	if len(v.browserWraps(spare)) != 1 {
		t.Fatal("a refused enrol wrote a wrap")
	}
}

// The new actions rebuild their canonical at finish: a stored canonical with
// a changed field is refused even with a valid assertion over the change.
func TestBrowserKeyCanonicalBinding(t *testing.T) {
	v := newVault(t)
	spare := v.registerSpare("approve-only", []string{}, nil)
	b, b2 := newTestBrowser(t), newTestBrowser(t)
	tamper := func(what string, body map[string]any, from, to string) {
		t.Helper()
		var r tapResp
		mustStatus(t, what+" challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", body, &r), 200)
		changed := strings.Replace(r.Canonical, from, to, 1)
		if changed == r.Canonical {
			t.Fatalf("%s: %q not in %s", what, from, r.Canonical)
		}
		_, err := v.s.store.DB().Exec(`UPDATE challenges SET canonical=? WHERE id=?`, changed, r.ChallengeID)
		requireNoError(t, err)
		ch := sha256Bytes(changed)
		if r.Open != nil {
			ch = seal.OpenChallenge([]byte(changed), []byte(r.Open.Descriptor))
		}
		if st := v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": v.auth.Assert(ch)}, nil); st/100 == 2 {
			t.Fatalf("%s: changed canonical accepted", what)
		}
	}
	rem := rememberBody(spare, b, "remember", []string{"installation"})
	tamper("remember: fingerprint", rem, b.id(), b2.id())
	tamper("remember: key", rem, encodeID(b.pub), encodeID(b2.pub))
	tamper("remember: label", rem, `"browser_label":"Test browser"`, `"browser_label":"Other browser"`)
	tamper("remember: passkey", rem, encodeID(spare.CredID), encodeID(v.auth.CredID))
	tamper("remember: action", rem, `"action":"remember"`, `"action":"enable"`)
	if len(v.browserWraps(spare)) != 0 {
		t.Fatal("a refused remember wrote a wrap")
	}
	v.remember(spare, b, []string{"installation"}, v.ownerTap)
	v.remember(spare, b2, []string{"installation"}, v.ownerTap)
	forget := rememberBody(spare, b, "forget", []string{})
	tamper("forget: fingerprint", forget, b.id(), b2.id())
	tamper("forget: key", forget, encodeID(b.pub), encodeID(b2.pub))
	if len(v.browserWraps(spare)) != 2 {
		t.Fatal("a refused forget removed a wrap")
	}
}

func TestBrowserKeyRekeyAndRemoval(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "kept-across-rekey"}}}, nil)
	spare := v.registerSpare("approve-only", []string{}, nil)
	b, b2 := newTestBrowser(t), newTestBrowser(t)
	v.remember(spare, b, []string{"installation", v.org}, v.ownerTap)
	v.remember(spare, b2, []string{v.org}, v.ownerTap)
	before := v.browserWraps(spare)
	// The remembered browser rekeys the organisation's scope.
	var r tapResp
	mustStatus(t, "rekey challenge", v.web("POST", "/api/ui/seal/control/challenge", map[string]any{"action": "rekey", "scope": v.org}, &r), 200)
	as, pkt, st := v.tapBrowser(spare, b, r)
	mustStatus(t, "rekey release", st, 200)
	var d descriptor
	requireNoError(t, json.Unmarshal([]byte(r.Open.Descriptor), &d))
	var res struct {
		OK      bool
		Buckets int
	}
	mustStatus(t, "rekey", v.web("POST", "/api/ui/seal/control/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &res), 200)
	var mine *store.BrowserWrapRow
	after := v.browserWraps(spare)
	for i, w := range after {
		if w.Scope == v.org {
			if mine != nil {
				t.Fatal("another browser's wrap survived the rekey")
			}
			mine = &after[i]
		}
	}
	if !res.OK || mine == nil || !bytes.Equal(mine.Public, b.pub) || encodeID(mine.ID) != d.RekeySalt || mine.Tested != nil {
		t.Fatalf("the rekeying browser's wrap: %+v", mine)
	}
	for _, w := range before {
		if w.Scope == v.org && (bytes.Equal(w.Wrap, mine.Wrap) || bytes.Equal(w.SealedKEK, mine.SealedKEK)) {
			t.Fatal("the rekey kept an old ciphertext")
		}
	}
	for _, w := range v.wraps(v.auth) {
		if w.Scope == v.org {
			t.Fatal("a PRF wrap survived a rekey by a remembered browser")
		}
	}
	// The new wrap opens (test), and the values are still there.
	v.testBrowser(spare, b, []string{v.org})
	rv, k, st := v.revealChallenge([]string{"APP_TOKEN"})
	mustStatus(t, "reveal challenge", st, 200)
	as, pkt, st = v.tapBrowser(spare, b, rv.tap())
	mustStatus(t, "reveal release", st, 200)
	var out struct{ Enc, Ciphertext string }
	mustStatus(t, "reveal after rekey", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": rv.ChallengeID, "assertion": as, "open": pkt}, &out), 200)
	if got, err := v.openReveal(rv, k, out.Enc, out.Ciphertext); err != nil || got[0].Value != "kept-across-rekey" {
		t.Fatal("value unreadable after a rekey by a remembered browser")
	}
	requireNoError(t, v.drill())
	// The other browser lost the scope and says so.
	mustStatus(t, "test challenge of a browser the rekey dropped", v.web("POST", "/api/ui/seal/passkeys/challenge", rememberBody(spare, b2, "test", []string{v.org}), nil), 409)
	// A rekey by the PRF passkey drops every remembered browser's wrap of the scope.
	mustStatus(t, "rekey by the PRF passkey", v.control(map[string]any{"action": "rekey", "scope": "installation"}, &res), 200)
	for _, w := range v.browserWraps(spare) {
		if w.Scope == "installation" {
			t.Fatal("a browser wrap survived a rekey by another passkey")
		}
	}
	rc := ownerOnlySSH(t, v)
	mustStatus(t, "the browser no longer opens the rekeyed scope", v.decideBrowser(spare, b, rc.ID), 423)
	// The scope's only opener is now the remembered browser: forgetting it, or
	// removing the passkey, would leave only the recovery key.
	mustStatus(t, "forget the only opener", v.web("POST", "/api/ui/seal/passkeys/challenge", rememberBody(spare, b, "forget", []string{}), nil), 409)
	mustStatus(t, "remove the only opener", v.web("POST", "/api/ui/passkeys/"+passkeyID(spare.CredID)+"/challenge", api.ChallengeRequest{Action: "remove"}, nil), 409)
	if _, err := v.s.store.DB().Exec(`DELETE FROM passkeys WHERE credential_id=?`, spare.CredID); err == nil {
		t.Fatal("the trigger let the last opener of a scope go")
	}
	// Enable the owner again from the remembered browser, then remove the passkey:
	// its browser keys and wraps go with it.
	body := map[string]any{"action": "enable", "nickname": "test", "capability": "unlock", "credential_id": encodeID(v.auth.CredID), "scopes": []string{v.org}}
	mustStatus(t, "enable challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", body, &r), 200)
	as, pkt, st = v.tapBrowser(spare, b, r)
	mustStatus(t, "enable release", st, 200)
	var auth struct {
		Registration string `json:"registration_id"`
	}
	mustStatus(t, "enable", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &auth), 200)
	v.enrolFinish(v.auth, auth.Registration)
	body["action"] = "test"
	mustStatus(t, "test the owner", v.capability(v.auth, body, nil), 200)
	cr, st := v.challenge("/api/ui/passkeys/"+passkeyID(spare.CredID), api.ChallengeRequest{Action: "remove"})
	mustStatus(t, "remove challenge", st, 200)
	mustStatus(t, "remove", v.decide("/api/ui/passkeys/"+passkeyID(spare.CredID), "remove", cr, nil), 200)
	var n int
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT (SELECT count(*) FROM browser_keys)+(SELECT count(*) FROM browser_wraps)`).Scan(&n))
	if n != 0 {
		t.Fatal("removing the passkey left its browser keys or wraps")
	}
}

// Enrolling from the recovery key works for a passkey without PRF: the wraps
// are made for the browser the owner is using.
func TestBrowserKeyRecoveryEnrol(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "x"}}}, nil)
	spare := v.registerSpare("approve-only", []string{}, nil)
	b := newTestBrowser(t)
	attempt, packet, digest := v.sealIdentity()
	body := map[string]any{"mode": "enrol", "attempt_id": attempt, "packet_sha256": digest, "credential_id": encodeID(spare.CredID), "scopes": []string{v.org}, "browser_key": encodeID(b.pub), "browser_label": "Test browser"}
	var r tapResp
	mustStatus(t, "enrol challenge", v.web("POST", "/api/ui/seal/recovery/challenge", body, &r), 200)
	if !strings.Contains(r.Canonical, `"browser_key_id":"`+b.id()+`"`) {
		t.Fatalf("recovery canonical: %s", r.Canonical)
	}
	as, pkt, _ := v.tapBrowser(spare, b, r)
	mustStatus(t, "enrol", v.web("POST", "/api/ui/seal/recovery/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "packet": packet, "open": pkt}, nil), 200)
	if w := v.browserWraps(spare); len(w) != 1 || w[0].Scope != v.org || len(v.wraps(spare)) != 0 {
		t.Fatalf("wraps after recovery enrol: %+v", w)
	}
	v.testBrowser(spare, b, []string{v.org})
	// The PRF passkey is not offered this path, and a browser-key passkey not the PRF one.
	attempt, _, digest = v.sealIdentity()
	body["attempt_id"], body["packet_sha256"], body["credential_id"] = attempt, digest, encodeID(v.auth.CredID)
	mustStatus(t, "recovery-enrol a PRF passkey for a browser", v.web("POST", "/api/ui/seal/recovery/challenge", body, nil), 409)
	delete(body, "browser_key")
	delete(body, "browser_label")
	body["credential_id"] = encodeID(spare.CredID)
	mustStatus(t, "recovery-enrol a browser-key passkey with PRF", v.web("POST", "/api/ui/seal/recovery/challenge", body, nil), 409)
	if strings.Contains(v.logs.String(), v.fix.identity.String()) || strings.Contains(v.seen.String(), v.fix.identity.String()) {
		t.Fatal("the recovery identity leaked")
	}
}

// A store made before remembered browsers existed starts unchanged: the new
// tables appear empty, nothing is enabled, and PRF taps work as before.
func TestBrowserKeyExistingStoreStartsUnchanged(t *testing.T) {
	v := newVault(t)
	_, err := v.s.store.DB().Exec(`DROP TRIGGER keep_one_scope_passkey; DROP VIEW scope_openers; DROP TABLE browser_wraps; DROP TABLE browser_keys;`)
	requireNoError(t, err)
	var before, after string
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT group_concat(passkey||scope||hex(salt)||hex(wrap)||coalesce(tested_at,''),'|') FROM scope_wraps`).Scan(&before))
	v.restart(v.logs)
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT group_concat(passkey||scope||hex(salt)||hex(wrap)||coalesce(tested_at,''),'|') FROM scope_wraps`).Scan(&after))
	var n, ver int
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT (SELECT count(*) FROM browser_keys)+(SELECT count(*) FROM browser_wraps)`).Scan(&n))
	requireNoError(t, v.s.store.DB().QueryRow(`PRAGMA user_version`).Scan(&ver))
	if n != 0 || before != after || ver != store.SchemaBuckets {
		t.Fatalf("an existing store changed at boot: rows=%d version=%d", n, ver)
	}
	v.login()
	if p := v.statusOf(v.auth); p.Mode != "prf" || len(p.Browsers) != 0 {
		t.Fatalf("status: %+v", p)
	}
	rc := ownerOnlySSH(t, v)
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", "/api/ui/requests/"+rc.ID+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r), 200)
	if r.Open == nil || r.Open.Browsers != nil {
		t.Fatalf("offer: %+v", r.Open)
	}
	as, pkt := v.ownerTap(r)
	mustStatus(t, "the PRF path is unchanged", v.web("POST", "/api/ui/requests/"+rc.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil), 200)
}

// Every kind of tap that opens a bucket works from a remembered browser, with
// the passkey without PRF signed in: an approval window, a signing approval,
// an env release, a reopen.
func TestBrowserKeyEveryKindOfTap(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "v1"}}}, nil)
	f := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", "")
	spare := v.registerSpare("approve-only", []string{}, nil)
	b := newTestBrowser(t)
	v.remember(spare, b, []string{"installation", v.org}, v.ownerTap)
	v.auth = spare
	v.login()
	s, ctx := v.s, t.Context()
	sess := ids.Hash(v.sess)
	browserTap := func(r tapResp) (json.RawMessage, *api.OpenPacket) {
		t.Helper()
		as, pkt, st := v.tapBrowser(spare, b, r)
		mustStatus(t, "release", st, 200)
		return as, pkt
	}
	// An approval window that holds the SSH CA open.
	pk, err := s.store.Q().SessionPasskeyID(ctx, sess)
	requireNoError(t, err)
	actx := withAccess(ctx, s, sess)
	profiles, err := s.windowProfiles(actx, s.store.Q(), sess, pk)
	requireNoError(t, err)
	var org string
	for _, p := range profiles {
		if p.Personal {
			org = p.Org
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public, _ := key.PublicKey.Bytes()
	res, err := s.windowOpenBegin(actx, jsonReq(windowOpen{org, 300, encodeID(public), encodeID(spare.CredID)}), sess)
	requireNoError(t, err)
	cr := res.(api.ChallengeResponse)
	opts, _ := json.Marshal(cr.PublicKey)
	restoreAccess(s, sess) // the release goes over HTTP, as the page sends it
	as, pkt := browserTap(tapResp{ChallengeID: cr.ChallengeID, Canonical: cr.Canonical, PublicKey: opts, Open: cr.Open})
	actx = withAccess(ctx, s, sess)
	_, err = s.windowOpenFinish(actx, jsonReq(api.DecideRequest{ChallengeID: cr.ChallengeID, Assertion: as, Open: pkt}), sess)
	requireNoError(t, err)
	restoreAccess(s, sess)
	if ob := openBuckets(t, s); len(ob) != 1 || ob["ssh-ca:installation"].Holds[0].Kind != "window" {
		t.Fatalf("window from a remembered browser: %+v", ob)
	}
	v.lock()
	// A signing approval: the signer's bucket opens and signs.
	req, _ := v.askSign(v.agent, f, 0, 0, signItemFor(f.scheme, "a", []byte("a")))
	sr, st := v.signChallenge(f, req, "sign-approve", 0, 1)
	mustStatus(t, "sign challenge", st, 200)
	as, pkt = browserTap(sr.tap())
	mustStatus(t, "sign approve", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": sr.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
	var got signer.Request
	mustStatus(t, "approved status", v.host(v.agent, "GET", "/v2/sign/requests/"+req.ID, nil, &got), 200)
	if _, st := v.sign(v.agent, got.Grant, signItemFor(f.scheme, "a", []byte("a"))); st != 200 {
		t.Fatal("signing after an approval from a remembered browser")
	}
	// An env release, then Close all and a Reopen of the paused bucket.
	rel := v.envRelease()
	var er tapResp
	mustStatus(t, "env challenge", v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": rel.ID, "action": "approve", "ttl_seconds": 600}, &er), 200)
	as, pkt = browserTap(er)
	mustStatus(t, "env approve", v.web("POST", "/api/ui/seal/env/finish", map[string]any{"challenge_id": er.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
	if len(openBuckets(t, s)) != 1 {
		t.Fatal("env release from a remembered browser opened nothing")
	}
	v.lock()
	var status struct {
		Buckets []struct {
			ID     string
			Paused []struct{ Ref string }
		}
	}
	mustStatus(t, "status", v.web("GET", "/api/ui/seal/status", nil, &status), 200)
	var paused []string
	for _, x := range status.Buckets {
		if len(x.Paused) > 0 {
			paused = append(paused, x.ID)
		}
	}
	var rr tapResp
	mustStatus(t, "reopen challenge", v.web("POST", "/api/ui/seal/control/challenge", map[string]any{"action": "reopen", "buckets": paused}, &rr), 200)
	as, pkt = browserTap(rr)
	mustStatus(t, "reopen", v.web("POST", "/api/ui/seal/control/finish", map[string]any{"challenge_id": rr.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
	if len(paused) != 1 || len(openBuckets(t, s)) != 1 {
		t.Fatalf("reopen from a remembered browser: paused=%v open=%v", paused, openBuckets(t, s))
	}
	if p := v.statusOf(spare); p.Mode != "browser" || p.Browsers[0].LastUsed == "" {
		t.Fatalf("status: %+v", p)
	}
}

// A passkey that opens only from a remembered browser creates a new
// organisation's scope key (Security → Buckets → Create): no key exists, so
// the approving tap opens nothing; the enrol tap makes the first wrap.
func TestBrowserKeyCreatesAScope(t *testing.T) {
	v := newVault(t)
	spare := v.registerSpare("approve-only", []string{}, nil)
	b := newTestBrowser(t)
	v.remember(spare, b, []string{"installation"}, v.ownerTap)
	const org = "0123456789abcdef0123456789abcdef"
	for _, q := range []string{
		`INSERT INTO organisations(id,slug,title,revision) VALUES('` + org + `','client-b','Client B',1)`,
		`INSERT INTO org_policies VALUES('` + org + `',1,3600,86400,1,3600,86400,1)`,
		`INSERT INTO org_approvers SELECT '` + org + `',id,'approver',1 FROM people WHERE owner=1`,
	} {
		_, err := v.s.store.DB().Exec(q)
		requireNoError(t, err)
	}
	if _, err := v.s.store.Q().Scope(t.Context(), org); err == nil {
		t.Fatal("the new organisation already has a scope key")
	}
	// The passkey approves its own remember: a plain signature (nothing to open).
	v.remember(spare, b, []string{org}, func(r tapResp) (json.RawMessage, *api.OpenPacket) {
		if r.Open != nil {
			t.Fatal("creating a scope offered an open")
		}
		return spare.Assert(sha256Bytes(r.Canonical)), nil
	})
	sc, err := v.s.store.Q().Scope(t.Context(), org)
	requireNoError(t, err)
	if ok, _ := v.s.store.Q().ScopeTested(t.Context(), org); !ok {
		t.Fatal("the new scope is not tested after the browser's test tap")
	}
	// The recovery key opens it too.
	k, err := seal.Scope{Installation: v.fix.inst, Name: org, Public: sc.Public}.Recover(v.fix.identity, v.fix.recipient, sc.Recovery)
	requireNoError(t, err)
	k.Destroy()
	var n int
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT count(*) FROM scope_wraps WHERE scope=?`, org).Scan(&n))
	if n != 0 || len(v.browserWraps(spare)) != 2 {
		t.Fatal("the new scope's only wrap should be the remembered browser's")
	}
}
