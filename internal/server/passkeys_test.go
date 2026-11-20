package server

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
)

var (
	aaguidBitwarden = mustHex("d548826e79b4db40a3d811116f7e8349")
	aaguidYubiKey   = mustHex("a4e9fc6d4cbe4758b8ba37598bb5bbaa") // Security Key NFC by Yubico
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// addPasskey signs "passkey add" (with nickname name, "" = server's choice) with the current
// e.auth, registers a with that name, and returns the result.
func (e *env) addPasskey(a *vauth.Authenticator, name string) api.RegisterResult {
	e.t.Helper()
	cr, st := e.challenge("/api/ui/passkeys", api.ChallengeRequest{Action: "add", Nickname: name})
	mustStatus(e.t, "passkey add challenge", st, 200)
	return e.finishAdd(cr, a, name, 200)
}

// finishAdd signs an add challenge, creates a's credential and sends register/finish with name.
func (e *env) finishAdd(cr challengeResp, a *vauth.Authenticator, name string, want int) api.RegisterResult {
	e.t.Helper()
	as, err := e.auth.AssertOptions(cr.PublicKey)
	if err != nil {
		e.t.Fatal(err)
	}
	var begin struct {
		ChallengeID string          `json:"challenge_id"`
		PublicKey   json.RawMessage `json:"public_key"`
	}
	mustStatus(e.t, "register begin", e.webDo("POST", "/api/ui/passkeys/register/begin", api.RegisterBegin{ChallengeID: cr.ChallengeID, Assertion: as}, &begin), 200)
	cred, err := a.Register(begin.PublicKey)
	if err != nil {
		e.t.Fatal(err)
	}
	var res api.RegisterResult
	mustStatus(e.t, "register finish", e.webDo("POST", "/api/ui/passkeys/register/finish", api.RegisterFinish{ChallengeID: begin.ChallengeID, Credential: cred, Name: name}, &res), want)
	if want == 200 && (!res.OK || res.Passkey == nil) {
		e.t.Fatalf("register result %+v", res)
	}
	return res
}

func (e *env) state() api.UIState {
	e.t.Helper()
	var s api.UIState
	mustStatus(e.t, "state", e.webDo("GET", "/api/ui/state", nil, &s), 200)
	return s
}

func passkeyByName(t *testing.T, s api.UIState, name string) api.PasskeyInfo {
	t.Helper()
	for _, p := range s.Passkeys {
		if p.Nickname == name {
			return p
		}
	}
	t.Fatalf("no passkey %q in %+v", name, s.Passkeys)
	return api.PasskeyInfo{}
}

// passkeyAction runs challenge + apply for a passkey rename/remove; returns both statuses.
func (e *env) passkeyAction(id string, req api.ChallengeRequest, verb string) (int, int, api.PasskeyChange) {
	e.t.Helper()
	cr, st := e.challenge("/api/ui/passkeys/"+id, req)
	if st != 200 {
		return st, 0, api.PasskeyChange{}
	}
	var out api.PasskeyChange
	return st, e.decide("/api/ui/passkeys/"+id, verb, cr, &out), out
}

func auditActions(t *testing.T, s api.UIState) map[string][]api.AuditEntry {
	t.Helper()
	m := map[string][]api.AuditEntry{}
	for _, a := range s.Recent {
		m[a.Action] = append(m[a.Action], a)
	}
	return m
}

func TestPasskeyListAddRenameRemove(t *testing.T) {
	e := newEnv(t)
	e.setupOwner() // "test", zero AAGUID, device-bound
	first := e.auth
	s := e.state()
	if len(s.Passkeys) != 1 || s.Owner.Passkeys != 1 {
		t.Fatalf("passkeys %+v", s.Passkeys)
	}
	p1 := s.Passkeys[0]
	if p1.Nickname != "test" || p1.Authenticator != "Unknown authenticator" || p1.Icon != "unknown" || p1.AAGUID != "" ||
		!p1.Current || p1.BackupEligible || p1.LastUsedAt == nil || len(p1.ID) != 32 || p1.SignCount == 0 ||
		len(p1.Transports) != 1 || p1.Transports[0] != "internal" {
		t.Fatalf("first passkey %+v", p1)
	}

	// Second: synced Bitwarden, no nickname given -> named after the authenticator.
	bw := vauth.New(testBase)
	bw.AAGUID, bw.Synced, bw.Transports = aaguidBitwarden, true, []string{"hybrid", "internal"}
	res := e.addPasskey(bw, "")
	if res.Passkey.Nickname != "Bitwarden" || res.Passkey.Authenticator != "Bitwarden" || res.Passkey.Icon != "bitwarden" ||
		!res.Passkey.BackupEligible || !res.Passkey.BackupState || res.Passkey.AAGUID != "d548826e-79b4-db40-a3d8-11116f7e8349" {
		t.Fatalf("bitwarden %+v", res.Passkey)
	}
	// Third: another Bitwarden -> "Bitwarden 2"; a hardware key with a chosen name.
	bw2 := vauth.New(testBase)
	bw2.AAGUID, bw2.Synced = aaguidBitwarden, true
	if r := e.addPasskey(bw2, ""); r.Passkey.Nickname != "Bitwarden 2" {
		t.Fatalf("duplicate default name %q", r.Passkey.Nickname)
	}
	// A chosen nickname is signed with the add action: a taken one is refused up front, one
	// differing at register/finish is refused, the signed one is stored exactly.
	if _, st := e.challenge("/api/ui/passkeys", api.ChallengeRequest{Action: "add", Nickname: "  BITWARDEN  "}); st != 409 {
		t.Fatalf("add with a taken nickname: %d, want 409", st)
	}
	cr, st := e.challenge("/api/ui/passkeys", api.ChallengeRequest{Action: "add", Nickname: "Key\u00a0on  keyring"})
	mustStatus(t, "add challenge", st, 200)
	if c := uiCheck(t, cr); c["new_nickname"] != "Key on keyring" || c["nickname"] != "" {
		t.Fatalf("add canonical %s", cr.Canonical)
	}
	e.finishAdd(cr, vauth.New(testBase), "Something else", 400)
	yk := vauth.New(testBase)
	yk.AAGUID, yk.Transports = aaguidYubiKey, []string{"nfc", "usb", "constructor-Is-Not-A-Transport!"}
	cr, _ = e.challenge("/api/ui/passkeys", api.ChallengeRequest{Action: "add", Nickname: "Key on keyring"})
	if r := e.finishAdd(cr, yk, "", 200); r.Passkey.Nickname != "Key on keyring" || r.Passkey.Authenticator != "Security Key NFC by Yubico" ||
		r.Passkey.BackupEligible || r.Passkey.Icon != "yubikey" || len(r.Passkey.Transports) != 2 {
		t.Fatalf("signed name / yubikey: %+v", r.Passkey)
	}
	s = e.state()
	if len(s.Passkeys) != 4 || s.Owner.Passkeys != 4 {
		t.Fatalf("want 4 passkeys, got %d", len(s.Passkeys))
	}
	if cur := passkeyByName(t, s, "test"); !cur.Current {
		t.Fatal("session's passkey not marked current")
	}
	if passkeyByName(t, s, "Bitwarden").Current {
		t.Fatal("other passkey marked current")
	}

	// Rename: the canonical names the passkey by its current nickname and the new one.
	bwInfo := passkeyByName(t, s, "Bitwarden")
	cr, st = e.challenge("/api/ui/passkeys/"+bwInfo.ID, api.ChallengeRequest{Action: "rename", Nickname: "  Phone <img src=x onerror=alert(1)>  "})
	mustStatus(t, "rename challenge", st, 200)
	c := uiCheck(t, cr)
	if c["object"] != "passkey" || c["action"] != "rename" || c["id"] != bwInfo.ID || c["nickname"] != "Bitwarden" ||
		c["new_nickname"] != "Phone <img src=x onerror=alert(1)>" {
		t.Fatalf("rename canonical %s", cr.Canonical)
	}
	if !strings.Contains(cr.Canonical, `"new_nickname":"Phone <img src=x onerror=alert(1)>"`) {
		t.Fatalf("canonical escaped the nickname: %s", cr.Canonical)
	}
	var ch api.PasskeyChange
	mustStatus(t, "rename", e.decide("/api/ui/passkeys/"+bwInfo.ID, "rename", cr, &ch), 200)
	if !ch.OK || ch.Action != "rename" || ch.Nickname != "Phone <img src=x onerror=alert(1)>" || ch.SignedOut {
		t.Fatalf("rename result %+v", ch)
	}
	s = e.state()
	passkeyByName(t, s, "Phone <img src=x onerror=alert(1)>")

	// Remove one that isn't this session's: stays signed in.
	b2 := passkeyByName(t, s, "Bitwarden 2")
	cs, ds, out := e.passkeyAction(b2.ID, api.ChallengeRequest{Action: "remove"}, "remove")
	if cs != 200 || ds != 200 || out.SignedOut || out.Nickname != "Bitwarden 2" {
		t.Fatalf("remove: %d %d %+v", cs, ds, out)
	}
	s = e.state()
	if len(s.Passkeys) != 3 {
		t.Fatalf("after remove: %d passkeys", len(s.Passkeys))
	}
	acts := auditActions(t, s)
	if len(acts["passkey_register"]) != 4 || len(acts["passkey_rename"]) != 1 || len(acts["passkey_remove"]) != 1 {
		t.Fatalf("audit %+v", s.Recent)
	}
	if a := acts["passkey_remove"][0]; a.Object != "passkey:"+b2.ID || a.Actor != "owner" || !strings.Contains(a.Detail, `nickname="Bitwarden 2"`) {
		t.Fatalf("remove audit %+v", a)
	}
	if a := acts["passkey_rename"][0]; a.Object != "passkey:"+bwInfo.ID || !strings.Contains(a.Detail, `from "Bitwarden" to "Phone <img src=x onerror=alert(1)>"`) {
		t.Fatalf("rename audit %+v", a)
	}

	// A removed passkey can't sign in any more.
	e.auth = bw2
	var begin struct {
		ChallengeID string          `json:"challenge_id"`
		PublicKey   json.RawMessage `json:"public_key"`
	}
	e.webDo("POST", "/api/ui/login/begin", map[string]any{}, &begin)
	as, _ := bw2.AssertOptions(begin.PublicKey)
	if st := e.webDo("POST", "/api/ui/login/finish", map[string]any{"challenge_id": begin.ChallengeID, "assertion": as}, nil); st != 403 {
		t.Fatalf("removed passkey signed in: %d", st)
	}
	e.auth = first
}

func TestPasskeyCanonicalBinding(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	a := vauth.New(testBase)
	e.addPasskey(a, "A")
	e.addPasskey(vauth.New(testBase), "B")
	s := e.state()
	pa, pb := passkeyByName(t, s, "A"), passkeyByName(t, s, "B")

	// An assertion for "rename A" can't remove B (different object) ...
	cr, _ := e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "rename", Nickname: "A2"})
	if st := e.decide("/api/ui/passkeys/"+pb.ID, "remove", cr, nil); st == 200 {
		t.Fatal("rename-A assertion removed B")
	}
	// ... nor rename B, nor remove A (verb must be the signed action).
	cr, _ = e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "rename", Nickname: "A2"})
	if st := e.decide("/api/ui/passkeys/"+pb.ID, "rename", cr, nil); st == 200 {
		t.Fatal("rename-A assertion renamed B")
	}
	cr, _ = e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "rename", Nickname: "A2"})
	if st := e.decide("/api/ui/passkeys/"+pa.ID, "remove", cr, nil); st != 400 {
		t.Fatalf("rename-A assertion at remove-A: %d, want 400", st)
	}
	// The challenge was consumed by that attempt: it can't be replayed at the right endpoint.
	if st := e.decide("/api/ui/passkeys/"+pa.ID, "rename", cr, nil); st != 409 {
		t.Fatalf("replayed challenge: %d, want 409", st)
	}
	// A "remove B" challenge can't remove A; a request/grant challenge can't touch a passkey.
	cr, _ = e.challenge("/api/ui/passkeys/"+pb.ID, api.ChallengeRequest{Action: "remove"})
	if st := e.decide("/api/ui/passkeys/"+pa.ID, "remove", cr, nil); st == 200 {
		t.Fatal("remove-B assertion removed A")
	}
	// "add" (id "new") can't be used as rename/remove, even at /passkeys/new/...
	cr, _ = e.challenge("/api/ui/passkeys", api.ChallengeRequest{Action: "add"})
	if st := e.decide("/api/ui/passkeys/new", "remove", cr, nil); st == 200 {
		t.Fatal("add challenge applied as remove")
	}
	// A rename challenge can't unlock passkey registration.
	cr, _ = e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "rename", Nickname: "A3"})
	as, _ := e.auth.AssertOptions(cr.PublicKey)
	if st := e.webDo("POST", "/api/ui/passkeys/register/begin", api.RegisterBegin{ChallengeID: cr.ChallengeID, Assertion: as}, nil); st == 200 {
		t.Fatal("rename challenge unlocked registration")
	}
	// Renamed in between: the signed nickname no longer matches, refused.
	cr, _ = e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "remove"})
	if cs, ds, _ := e.passkeyAction(pa.ID, api.ChallengeRequest{Action: "rename", Nickname: "A-renamed"}, "rename"); cs != 200 || ds != 200 {
		t.Fatalf("rename A: %d %d", cs, ds)
	}
	if st := e.decide("/api/ui/passkeys/"+pa.ID, "remove", cr, nil); st != 409 {
		t.Fatalf("stale remove after rename: %d, want 409", st)
	}
	s = e.state()
	if len(s.Passkeys) != 3 {
		t.Fatalf("passkeys changed: %+v", s.Passkeys)
	}
	passkeyByName(t, s, "A-renamed")
	passkeyByName(t, s, "B")

	// Nickname rules.
	for _, c := range []struct {
		name string
		want int
	}{
		{"", 400}, {"   ", 400}, {"a\u202eb", 400}, {"zero\u200bwidth", 400}, {"tab\tname", 400}, {"Cafe\u0301", 400},
		{"b\u00a0", 409}, {"\u3000B", 409}, {"Cafe\u0301", 400},
		{"b\u00a0", 409}, {"\u3000B", 409},
		{strings.Repeat("x", 65), 400}, {"A-renamed", 400}, {"b", 409}, {"TEST", 409},
	} {
		if _, st := e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "rename", Nickname: c.name}); st != c.want {
			t.Errorf("rename to %q: %d, want %d", c.name, st, c.want)
		}
	}
	if _, st := e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "remove", Nickname: "x"}); st != 400 {
		t.Errorf("remove with nickname: %d", st)
	}
	if _, st := e.challenge("/api/ui/passkeys/"+pa.ID, api.ChallengeRequest{Action: "approve"}); st != 400 {
		t.Errorf("approve passkey: %d", st)
	}
	if _, st := e.challenge("/api/ui/passkeys/0123456789abcdef0123456789abcdef", api.ChallengeRequest{Action: "remove"}); st != 404 {
		t.Errorf("unknown passkey: %d", st)
	}
}

func TestPasskeyLastOneAndCurrentSession(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	first := e.auth
	second := vauth.New(testBase)
	e.addPasskey(second, "second")
	s := e.state()
	p1, p2 := passkeyByName(t, s, "test"), passkeyByName(t, s, "second")

	// Two remove challenges while two exist; applying both would leave none: the second is
	// refused inside the transaction.
	cr1, st1 := e.challenge("/api/ui/passkeys/"+p2.ID, api.ChallengeRequest{Action: "remove"})
	cr2, st2 := e.challenge("/api/ui/passkeys/"+p1.ID, api.ChallengeRequest{Action: "remove"})
	mustStatus(t, "challenge 1", st1, 200)
	mustStatus(t, "challenge 2", st2, 200)
	mustStatus(t, "remove second", e.decide("/api/ui/passkeys/"+p2.ID, "remove", cr1, nil), 200)
	if st := e.decide("/api/ui/passkeys/"+p1.ID, "remove", cr2, nil); st != 409 {
		t.Fatalf("removed the last passkey: %d", st)
	}
	// And no challenge is issued for it.
	if _, st := e.challenge("/api/ui/passkeys/"+p1.ID, api.ChallengeRequest{Action: "remove"}); st != 409 {
		t.Fatalf("last passkey remove challenge: %d, want 409", st)
	}
	if s := e.state(); len(s.Passkeys) != 1 {
		t.Fatalf("passkeys %+v", s.Passkeys)
	}

	// Removing the passkey this session signed in with (signed by another one) ends the session.
	third := vauth.New(testBase)
	e.addPasskey(third, "third")
	e.auth = third
	cs, ds, out := e.passkeyAction(p1.ID, api.ChallengeRequest{Action: "remove"}, "remove")
	if cs != 200 || ds != 200 || !out.SignedOut {
		t.Fatalf("remove current: %d %d %+v", cs, ds, out)
	}
	if st := e.webDo("GET", "/api/ui/state", nil, nil); st != 401 {
		t.Fatalf("session survived removing its passkey: %d", st)
	}
	_ = first
	e.login() // with third
	s = e.state()
	if len(s.Passkeys) != 1 || !s.Passkeys[0].Current || s.Passkeys[0].Nickname != "third" {
		t.Fatalf("after: %+v", s.Passkeys)
	}
	if a := auditActions(t, s)["passkey_remove"]; len(a) != 2 || !strings.Contains(a[0].Detail, "sessions_ended=1") {
		t.Fatalf("remove audit %+v", a)
	}
}
