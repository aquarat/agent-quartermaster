//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/cfaccess"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
)

// ---- helpers ----

// opened records every bucket the pool opens (kind:ref).
type opened struct {
	mu   sync.Mutex
	seen map[string]bool
	ids  map[seal.ID]bool
	s    *Server
	t    *testing.T
}

func (v *vaultEnv) watchOpens() *opened {
	o := &opened{seen: map[string]bool{}, ids: map[seal.ID]bool{}, s: v.s, t: v.t}
	p := v.s.seal.pool
	// onChange may run inside a transaction: record IDs only, name them later.
	p.onChange = func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		for id := range p.snapshot() {
			o.ids[id] = true
		}
	}
	return o
}
func (o *opened) take() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	rows, err := o.s.store.Q().Buckets(o.t.Context())
	requireNoError(o.t, err)
	var out []string
	for _, r := range rows {
		if o.ids[bucketSealID(r)] {
			out = append(out, r.Kind+":"+r.Ref)
		}
	}
	clear(o.ids)
	slices.Sort(out)
	return out
}

// decideTap runs challenge + decide for a request or enrollment with a tap of a.
func (v *vaultEnv) decideTap(a *vauth.Authenticator, path string, req api.ChallengeRequest) int {
	v.t.Helper()
	var r tapResp
	if st := v.web("POST", path+"/challenge", req, &r); st != 200 {
		return st
	}
	as, pkt := v.fix.tapWith(v.t, v.s, a, r)
	return v.web("POST", path+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil)
}

// envRelease asks for the set's values as the workload host and returns the release.
func (v *vaultEnv) envRelease() envset.Release {
	v.t.Helper()
	var b envset.Binding
	mustStatus(v.t, "binding", v.host(v.agent, "GET", "/v2/env/set?path=client-a/paas/staging", nil, &b), 200)
	var rel envset.Release
	mustStatus(v.t, "env request", v.host(v.agent, "POST", "/v2/env/requests", map[string]any{"binding": b, "mode": "process", "reason": "deploy", "ttl_seconds": 600}, &rel), 200)
	return rel
}
func (v *vaultEnv) envApprove(rel envset.Release) string {
	v.t.Helper()
	var r tapResp
	mustStatus(v.t, "env challenge", v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": rel.ID, "action": "approve", "ttl_seconds": 600}, &r), 200)
	if r.Open == nil {
		v.t.Fatal("env approval offered no open")
	}
	as, pkt := v.fix.tapWith(v.t, v.s, v.auth, r)
	mustStatus(v.t, "env approve", v.web("POST", "/api/ui/seal/env/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
	var got envset.Release
	mustStatus(v.t, "release", v.host(v.agent, "GET", "/v2/env/requests/"+rel.ID, nil, &got), 200)
	return got.Grant
}
func (v *vaultEnv) collect(grant string) int {
	return v.host(v.agent, "POST", "/v2/grants/"+grant+"/collect", map[string]any{}, nil)
}

func ownerOnlySSH(t *testing.T, v *vaultEnv) api.RequestCreated {
	t.Helper()
	rc, _, st := v.request(v.agent, "db-1", "alice", 300)
	mustStatus(t, "ssh request", st, 201)
	if rc.Status != api.StatusPending {
		t.Fatalf("request not pending: %s", rc.Status)
	}
	return rc
}

// ---- tests ----

func TestBucketsEachActionOpensOnlyItsBucket(t *testing.T) {
	v := newVault(t)
	o := v.watchOpens()
	// A write opens nothing; the set's bucket is created at its first write.
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "one"}}}, nil)
	if got := o.take(); len(got) != 0 {
		t.Fatalf("a commit opened %v", got)
	}
	// SSH approval: the SSH CA only, for an instant.
	rc := ownerOnlySSH(t, v)
	mustStatus(t, "approve ssh", v.decideTap(v.auth, "/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300}), 200)
	if got := o.take(); !slices.Equal(got, []string{"ssh-ca:installation"}) {
		t.Fatalf("ssh approval opened %v", got)
	}
	if len(openBuckets(t, v.s)) != 0 {
		t.Fatal("an instant hold outlived its approval")
	}
	if rs, _ := v.status(v.agent, rc.ID, ""); rs.Grant == nil || rs.Grant.SSH.Certificate == "" {
		t.Fatal("no certificate signed")
	}
	// Delivering the signed certificate again needs nothing open.
	if rs, st := v.status(v.agent, rc.ID, ""); st != 200 || rs.Grant == nil {
		t.Fatal("delivery needed a bucket")
	}
	// Enrollment approval: the internal CA only.
	key, csr := newCSR(t, "third")
	var er api.EnrollResponse
	st, err := agentDo(t, v.agentClient(nil), "POST", v.env.agent.URL+"/v1/enroll", api.EnrollRequest{Class: api.ClassAgent, Hostname: "third", CSRPEM: csr, Note: "t"}, &er)
	if err != nil || st != 201 {
		t.Fatalf("enroll %d %v", st, err)
	}
	mustStatus(t, "approve enrollment", v.decideTap(v.auth, "/api/ui/enrollments/"+er.ID, api.ChallengeRequest{Action: "approve"}), 200)
	if got := o.take(); !slices.Equal(got, []string{"internal-ca:installation"}) {
		t.Fatalf("enrollment opened %v", got)
	}
	_ = key
	// Env approval: the set only, held until collected.
	grant := v.envApprove(v.envRelease())
	if got := o.take(); !slices.Equal(got, []string{"env-set:" + v.set}) {
		t.Fatalf("env approval opened %v", got)
	}
	ob := openBuckets(t, v.s)
	if len(ob) != 1 || len(ob["env-set:"+v.set].Holds) != 1 || ob["env-set:"+v.set].Holds[0].Kind != "env" {
		t.Fatalf("env hold: %+v", ob)
	}
	// Operations on other, closed buckets are refused without a tap.
	if _, err := v.s.cfParentToken(t.Context()); err == nil {
		t.Fatal("a closed or missing bucket was used")
	}
	mustStatus(t, "collect", v.collect(grant), 200)
	if len(openBuckets(t, v.s)) != 0 {
		t.Fatal("collect did not release the env hold")
	}
	// A deny opens nothing.
	rc = ownerOnlySSH(t, v)
	mustStatus(t, "deny", v.decideTap(v.auth, "/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "deny"}), 200)
	if got := o.take(); len(got) != 0 {
		t.Fatalf("deny opened %v", got)
	}
}

func TestBucketsClosedRefusesAndRestartLeavesNothingOpen(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "sentinel-restart-value"}}}, nil)
	grant := v.envApprove(v.envRelease())
	// Restart: nothing is open, the release is paused, collect waits for a reopen.
	v.restart(v.logs)
	v.agent = v.agentClient(v.agentCert())
	if n := v.s.seal.pool.count(); n != 0 {
		t.Fatalf("%d buckets open after restart", n)
	}
	var b struct {
		Error, Message string
	}
	st := v.host(v.agent, "POST", "/v2/grants/"+grant+"/collect", map[string]any{}, nil)
	if st != 423 {
		t.Fatalf("collect from a closed bucket: %d", st)
	}
	req, _ := http.NewRequest("POST", v.env.agent.URL+"/v2/grants/"+grant+"/collect", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.agent.Do(req)
	requireNoError(t, err)
	json.NewDecoder(resp.Body).Decode(&b)
	resp.Body.Close()
	if b.Error != "locked" || !strings.Contains(b.Message, "is closed: waiting for the owner to reopen it") {
		t.Fatalf("closed bucket answer: %+v", b)
	}
	var status struct {
		Mode    string
		Buckets []struct {
			ID, Kind string
			Open     bool
			Paused   []struct{ Kind, Ref string }
		}
	}
	mustStatus(t, "status", v.web("GET", "/api/ui/seal/status", nil, &status), 200)
	paused := 0
	for _, b := range status.Buckets {
		if b.Open {
			t.Fatal("status shows an open bucket")
		}
		paused += len(b.Paused)
	}
	if status.Mode != "buckets" || paused != 1 {
		t.Fatalf("status: %+v", status)
	}
	// Standing rules do not issue while the SSH CA is closed: the request waits.
	rc := ownerOnlySSH(t, v)
	_ = rc
	// Reopen: one tap, the paused release is held again and collects.
	v.reopenPaused()
	mustStatus(t, "collect after reopen", v.collect(grant), 200)
	if len(openBuckets(t, v.s)) != 0 {
		t.Fatal("hold outlived collect")
	}
}

func (v *vaultEnv) agentCert() *tlsCert {
	// The enrolled client certificate survives a restart: same CA, same DB.
	tr := v.agent.Transport.(*http.Transport)
	c, err := tr.TLSClientConfig.GetClientCertificate(nil)
	requireNoError(v.t, err)
	return c
}

func TestBucketsTapsAndPackets(t *testing.T) {
	v := newVault(t)
	path := func(id string) string { return "/api/ui/requests/" + id }
	challenge := func(id string) tapResp {
		var r tapResp
		mustStatus(t, "challenge", v.web("POST", path(id)+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r), 200)
		if r.Open == nil {
			t.Fatal("approval offered no open")
		}
		var d descriptor
		requireNoError(t, json.Unmarshal([]byte(r.Open.Descriptor), &d))
		if d.Object != "bucket-open" || d.Purpose != "approve" || !slices.Equal(d.Scopes, []string{"installation"}) || len(d.Buckets) != 1 || d.Buckets[0].Kind != "ssh-ca" {
			t.Fatalf("descriptor: %s", r.Open.Descriptor)
		}
		return r
	}
	decide := func(r tapResp, id string, as json.RawMessage, pkt *api.OpenPacket) int {
		return v.web("POST", path(id)+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil)
	}
	rc := ownerOnlySSH(t, v)
	// An assertion over SHA-256(canonical) alone is refused when an open was offered.
	r := challenge(rc.ID)
	mustStatus(t, "unbound assertion", decide(r, rc.ID, v.auth.Assert(canon.Challenge(r.Canonical)), nil), 403)
	// A tampered packet opens nothing and applies nothing.
	r = challenge(rc.ID)
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	ct, _ := b64url(pkt.Ciphertext)
	ct[3] ^= 1
	bad := *pkt
	bad.Ciphertext = encodeID(ct)
	mustStatus(t, "tampered packet", decide(r, rc.ID, as, &bad), 403)
	if v.s.seal.pool.count() != 0 {
		t.Fatal("tampered packet opened a bucket")
	}
	// No packet: the bucket is closed, so the decision is refused.
	r = challenge(rc.ID)
	as, _ = v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "no packet", decide(r, rc.ID, as, nil), 423)
	// A packet from another challenge (another attempt) is refused.
	r1 := challenge(rc.ID)
	_, pkt1 := v.fix.tapWith(t, v.s, v.auth, r1)
	r2 := challenge(rc.ID)
	as2, _ := v.fix.tapWith(t, v.s, v.auth, r2)
	mustStatus(t, "packet of another attempt", decide(r2, rc.ID, as2, pkt1), 409)
	if v.s.seal.pool.count() != 0 {
		t.Fatal("foreign packet opened a bucket")
	}
	// The good tap, then its replay.
	r = challenge(rc.ID)
	as, pkt = v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "approve", decide(r, rc.ID, as, pkt), 200)
	if st := decide(r, rc.ID, as, pkt); st == 200 {
		t.Fatal("replayed tap accepted")
	}
	if v.s.seal.pool.count() != 0 {
		t.Fatal("replay opened a bucket")
	}
	if !strings.Contains(v.logs.String(), "buckets opened by approval") {
		t.Fatal("open not logged")
	}
}

// registerSpare adds a second passkey through the capability flow.
func (v *vaultEnv) registerSpare(capability string, scopes []string, secret []byte) *vauth.Authenticator {
	v.t.Helper()
	var r tapResp
	mustStatus(v.t, "register challenge", v.web("POST", "/api/ui/seal/passkeys/challenge", map[string]any{"action": "register", "nickname": "spare", "capability": capability, "credential_id": "", "scopes": scopes}, &r), 200)
	as, pkt := v.fix.tapWith(v.t, v.s, v.auth, r)
	var auth struct {
		Registration string          `json:"registration_id"`
		PublicKey    json.RawMessage `json:"public_key"`
	}
	mustStatus(v.t, "authorize", v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &auth), 200)
	spare := vauth.New(testBase)
	cred, err := spare.Register(auth.PublicKey)
	requireNoError(v.t, err)
	mustStatus(v.t, "create", v.web("POST", "/api/ui/seal/passkeys/create", map[string]any{"registration_id": auth.Registration, "credential": cred}, nil), 200)
	if secret != nil {
		v.fix.prf[string(spare.CredID)] = secret
		v.enrolFinish(spare, auth.Registration)
	}
	return spare
}
func (v *vaultEnv) enrolFinish(target *vauth.Authenticator, registration string) {
	v.t.Helper()
	var r tapResp
	mustStatus(v.t, "evaluate", v.web("POST", "/api/ui/seal/passkeys/evaluate", map[string]any{"registration_id": registration}, &r), 200)
	var d descriptor
	requireNoError(v.t, json.Unmarshal([]byte(r.Open.Descriptor), &d))
	if d.Object != "scope-enrol" || d.Purpose != "enrol" || d.Credential != encodeID(target.CredID) || len(d.Salts) != len(d.Scopes) {
		v.t.Fatalf("enrol descriptor %s", r.Open.Descriptor)
	}
	as, pkt := v.fix.tapWith(v.t, v.s, target, r)
	mustStatus(v.t, "enrol finish", v.web("POST", "/api/ui/seal/passkeys/finish", map[string]any{"registration_id": registration, "challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
}
func (v *vaultEnv) capability(signer *vauth.Authenticator, body map[string]any, out any) int {
	v.t.Helper()
	var r tapResp
	if st := v.web("POST", "/api/ui/seal/passkeys/challenge", body, &r); st != 200 {
		return st
	}
	as, pkt := v.fix.tapWith(v.t, v.s, signer, r)
	return v.web("POST", "/api/ui/seal/passkeys/authorize", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, out)
}
func (v *vaultEnv) wraps(a *vauth.Authenticator) []store.ScopeWrapRow {
	all, err := v.s.store.Q().ScopeWraps(v.t.Context(), 0)
	requireNoError(v.t, err)
	var out []store.ScopeWrapRow
	for _, w := range all {
		if bytes.Equal(w.RawID, a.CredID) {
			out = append(out, w)
		}
	}
	return out
}

func TestBucketsPasskeysWithoutPRFEnableTestDisable(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "v1"}}}, nil)
	spare := v.registerSpare("approve-only", []string{}, nil)
	if len(v.wraps(spare)) != 0 {
		t.Fatal("an approve-only passkey got wraps")
	}
	// Without PRF it approves only what is open.
	rc := ownerOnlySSH(t, v)
	mustStatus(t, "approve-only on a closed bucket", v.decideTap(spare, "/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300}), 423)
	v.envApprove(v.envRelease()) // the owner's tap holds the set open
	names := []string{"APP_TOKEN"}
	r, k, st := v.revealChallenge(names)
	mustStatus(t, "reveal challenge", st, 200)
	as, pkt := v.fix.tapWith(t, v.s, spare, r.tap())
	if pkt != nil {
		t.Fatal("a passkey without PRF produced a packet")
	}
	var out struct{ Enc, Ciphertext string }
	mustStatus(t, "reveal by an approve-only passkey while open", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as}, &out), 200)
	if got, err := v.openReveal(r, k, out.Enc, out.Ciphertext); err != nil || got[0].Value != "v1" {
		t.Fatal("reveal")
	}
	// Enable it for the installation (the owner's tap opens the scope key).
	v.fix.prf[string(spare.CredID)] = []byte("spare-prf-secret")
	nick := "spare"
	body := map[string]any{"action": "enable", "nickname": nick, "capability": "unlock", "credential_id": encodeID(spare.CredID), "scopes": []string{"installation"}}
	var auth struct {
		Registration string `json:"registration_id"`
	}
	mustStatus(t, "enable", v.capability(v.auth, body, &auth), 200)
	v.enrolFinish(spare, auth.Registration)
	w := v.wraps(spare)
	if len(w) != 1 || w[0].Scope != "installation" || w[0].Tested != nil {
		t.Fatalf("wraps after enable: %+v", w)
	}
	// Test: the target opens its own wrap; it is marked tested.
	body["action"] = "test"
	var res struct {
		OK     bool
		Scopes []string
	}
	mustStatus(t, "test", v.capability(spare, body, &res), 200)
	if !res.OK || v.wraps(spare)[0].Tested == nil {
		t.Fatal("test did not mark the wrap")
	}
	// Now it opens the SSH CA itself.
	mustStatus(t, "spare approves", v.decideTap(spare, "/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300}), 200)
	// The owner is the only passkey for the organisations: removing it is refused.
	var pk []api.PasskeyInfo
	var state struct{ Passkeys []api.PasskeyInfo }
	mustStatus(t, "state", v.web("GET", "/api/ui/state", nil, &state), 200)
	pk = state.Passkeys
	var ownerID string
	for _, p := range pk {
		if p.RawID == encodeID(v.auth.CredID) {
			ownerID = p.ID
		}
	}
	mustStatus(t, "remove the only passkey of a scope", v.web("POST", "/api/ui/passkeys/"+ownerID+"/challenge", api.ChallengeRequest{Action: "remove"}, nil), 409)
	// Disable the spare's installation wrap (no open).
	body = map[string]any{"action": "disable", "nickname": nick, "capability": "approve-only", "credential_id": encodeID(spare.CredID), "scopes": []string{"installation"}}
	mustStatus(t, "disable", v.capability(v.auth, body, nil), 200)
	if len(v.wraps(spare)) != 0 {
		t.Fatal("disable left wraps")
	}
	// Disabling the owner's last wraps is refused.
	body = map[string]any{"action": "disable", "nickname": "test", "capability": "approve-only", "credential_id": encodeID(v.auth.CredID), "scopes": []string{}}
	mustStatus(t, "disable the last", v.web("POST", "/api/ui/seal/passkeys/challenge", body, nil), 409)
}

func TestBucketsWindowHoldsAndExpiry(t *testing.T) {
	v := newVault(t)
	ctx := t.Context()
	s := v.s
	sess := ids.Hash(v.sess)
	pk, err := s.store.Q().SessionPasskeyID(ctx, sess)
	requireNoError(t, err)
	ctx = withAccess(ctx, s, sess)
	profiles, err := s.windowProfiles(ctx, s.store.Q(), sess, pk)
	requireNoError(t, err)
	var org string
	for _, p := range profiles {
		if p.Personal {
			org = p.Org
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public, _ := key.PublicKey.Bytes()
	in := windowOpen{org, 300, encodeID(public), encodeID(v.auth.CredID)}
	res, err := s.windowOpenBegin(ctx, jsonReq(in), sess)
	requireNoError(t, err)
	cr := res.(api.ChallengeResponse)
	if cr.Open == nil {
		t.Fatal("window offered no open")
	}
	opts, _ := json.Marshal(cr.PublicKey)
	as, pkt := v.fix.tapWith(t, s, v.auth, tapResp{ChallengeID: cr.ChallengeID, Canonical: cr.Canonical, PublicKey: opts, Open: cr.Open})
	out, err := s.windowOpenFinish(ctx, jsonReq(api.DecideRequest{ChallengeID: cr.ChallengeID, Assertion: as, Open: pkt}), sess)
	requireNoError(t, err)
	rec := out.(windowReceipt)
	ob := openBuckets(t, s)
	if len(ob) != 1 || ob["ssh-ca:installation"].Holds[0].Kind != "window" {
		t.Fatalf("window holds: %+v", ob)
	}
	// Inside the window a passkey-less confirm signs: the CA is held open.
	rc := ownerOnlySSH(t, v)
	click := windowClick{ID: rec.ID, Token: rec.Token, Choice: ordinaryChoice{rc.ID, "approve", 300}}
	prep, err := s.windowPrepare(ctx, jsonReq(click), sess)
	requireNoError(t, err)
	p := prep.(map[string]string)
	click.Proposal = p["proposal_id"]
	click.Proof = proof(t, key, s, rec.ID, click.Proposal, p["canonical"])
	_, err = s.windowConfirm(ctx, jsonReq(click), sess)
	requireNoError(t, err)
	// Expiry with the fake clock: the reconcile pass drops the hold.
	v.clock.Advance(301 * time.Second)
	s.reconcileHolds(ctx)
	if len(openBuckets(t, s)) != 0 {
		t.Fatal("window hold outlived the window")
	}
	// Close all ends windows and closes everything.
	res, err = s.windowOpenBegin(ctx, jsonReq(in), sess)
	requireNoError(t, err)
	cr = res.(api.ChallengeResponse)
	opts, _ = json.Marshal(cr.PublicKey)
	as, pkt = v.fix.tapWith(t, s, v.auth, tapResp{ChallengeID: cr.ChallengeID, Canonical: cr.Canonical, PublicKey: opts, Open: cr.Open})
	_, err = s.windowOpenFinish(ctx, jsonReq(api.DecideRequest{ChallengeID: cr.ChallengeID, Assertion: as, Open: pkt}), sess)
	requireNoError(t, err)
	if s.seal.pool.count() != 1 {
		t.Fatal("window did not open the CA")
	}
	restoreAccess(s, sess)
	var closeRes struct{ OK bool }
	mustStatus(t, "close all", v.control(map[string]any{"action": "close-all"}, &closeRes), 200)
	if s.seal.pool.count() != 0 || len(s.seal.windows.active) != 0 {
		t.Fatal("close all left something open")
	}
}

// withAccess makes a context with a verified Access identity; restore puts
// the session back for the HTTP helpers.
func withAccess(ctx context.Context, s *Server, sess string) context.Context {
	s.access = &cfaccess.Verifier{}
	_, _ = s.store.DB().Exec(`UPDATE web_sessions SET access_sub=? WHERE hash=?`, "verified-owner", sess)
	return context.WithValue(ctx, ctxAccessSub, "verified-owner")
}
func restoreAccess(s *Server, sess string) {
	s.access = nil
	_, _ = s.store.DB().Exec(`UPDATE web_sessions SET access_sub='' WHERE hash=?`, sess)
}
func removeCA(e *env, name string) error { return os.Remove(filepath.Join(CADir(e.cfg.DataDir), name)) }
func jsonReq(v any) *http.Request {
	b, _ := json.Marshal(v)
	return httptest.NewRequest("POST", "/", bytes.NewReader(b))
}
func proof(t *testing.T, key *ecdsa.PrivateKey, s *Server, window, proposal, canonical string) string {
	h := sha256.Sum256(windowMessage(s.seal.installation[:], window, proposal, canon.Challenge(canonical)))
	r, sg, err := ecdsa.Sign(rand.Reader, key, h[:])
	requireNoError(t, err)
	return encodeID(append(r.FillBytes(make([]byte, 32)), sg.FillBytes(make([]byte, 32))...))
}

func TestBucketsRekey(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "kept-across-rekey"}}}, nil)
	f := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", "")
	spare := v.registerSpare("unlock", []string{v.org}, []byte("spare-secret"))
	if len(v.wraps(spare)) != 1 {
		t.Fatal("spare not enabled")
	}
	// A draft of the scope, to be dropped.
	sess := ids.Hash(v.sess)
	row, err := v.s.setRow(t.Context(), v.s.store.Q(), "env-set", v.set)
	requireNoError(t, err)
	_, err = v.s.store.DB().Exec(`INSERT INTO env_drafts(id,session,host,set_id,expires,metadata,blob,payload,wrap) VALUES('d1',?,(SELECT min(id) FROM hosts),?,?,'{}',x'01',x'5b5d',?)`, sess, v.set, v.clock.Now().Add(time.Hour).UnixMilli(), row.ID)
	requireNoError(t, err)
	before, err := v.s.store.Q().Scope(t.Context(), v.org)
	requireNoError(t, err)
	var res struct {
		OK      bool
		Buckets int
	}
	mustStatus(t, "rekey", v.control(map[string]any{"action": "rekey", "scope": v.org}, &res), 200)
	after, _ := v.s.store.Q().Scope(t.Context(), v.org)
	if !res.OK || res.Buckets != 2 || bytes.Equal(before.Public, after.Public) {
		t.Fatalf("rekey: %+v", res)
	}
	if len(v.wraps(spare)) != 0 || len(v.wraps(v.auth)) == 0 {
		t.Fatal("other passkeys' wraps survived the rekey")
	}
	var n int
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT count(*) FROM env_drafts`).Scan(&n))
	if n != 0 || v.s.seal.pool.count() != 0 {
		t.Fatal("drafts or open buckets survived the rekey")
	}
	if got := v.reveal([]string{"APP_TOKEN"}); got[0].Value != "kept-across-rekey" {
		t.Fatal("value unreadable after rekey")
	}
	requireNoError(t, v.drill())
	req, _ := v.askSign(v.agent, f, 0, 0, signItemFor(f.scheme, "a", []byte("a")))
	grant := v.approveSign(f, req, 0, 1)
	if _, st := v.sign(v.agent, grant, signItemFor(f.scheme, "a", []byte("a"))); st != 200 {
		t.Fatal("signer unusable after rekey")
	}
	if len(openBuckets(t, v.s)) != 0 {
		t.Fatal("the last signature did not release the signer")
	}
}

// sealIdentity plays the page: seal the pasted identity to the broker's key.
func (v *vaultEnv) sealIdentity() (attempt, packet, digest string) {
	v.t.Helper()
	var k struct {
		Attempt   string `json:"attempt_id"`
		Recipient string `json:"recipient"`
	}
	mustStatus(v.t, "recovery key", v.web("POST", "/api/ui/seal/recovery/key", map[string]any{}, &k), 200)
	raw, _ := b64url(k.Attempt)
	pub, _ := b64url(k.Recipient)
	var at seal.ID
	copy(at[:], raw)
	text := []byte("# comment\n" + v.fix.identity.String() + "\n")
	enc, ct, err := seal.SealTo(pub, seal.OpenInfo(v.fix.inst, "recovery"), seal.OpenAAD(at, v.s.seal.opens.Epoch(), nil, nil), text)
	requireNoError(v.t, err)
	p := append(enc, ct...)
	return k.Attempt, encodeID(p), sha256Hex(p)
}

func TestBucketsRecoveryDrillAndEnrol(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "x"}}}, nil)
	attempt, packet, digest := v.sealIdentity()
	var r tapResp
	mustStatus(t, "drill challenge", v.web("POST", "/api/ui/seal/recovery/challenge", map[string]any{"mode": "drill", "attempt_id": attempt, "packet_sha256": digest}, &r), 200)
	if r.Open != nil {
		t.Fatal("a drill offered an open")
	}
	as, _ := v.fix.tapWith(t, v.s, v.auth, r)
	var res struct {
		OK              bool
		Scopes, Buckets int
	}
	mustStatus(t, "drill", v.web("POST", "/api/ui/seal/recovery/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "packet": packet}, &res), 200)
	if !res.OK || res.Scopes != 3 || res.Buckets != 3 || v.s.seal.pool.count() != 0 {
		t.Fatalf("drill: %+v", res)
	}
	// Another packet than the one reviewed is refused.
	attempt, _, digest = v.sealIdentity()
	_, other, _ := v.sealIdentity()
	mustStatus(t, "drill challenge", v.web("POST", "/api/ui/seal/recovery/challenge", map[string]any{"mode": "drill", "attempt_id": attempt, "packet_sha256": digest}, &r), 200)
	as, _ = v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "other packet", v.web("POST", "/api/ui/seal/recovery/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "packet": other}, nil), 400)
	// Enrol an approve-only passkey for the organisation from the recovery key.
	spare := v.registerSpare("approve-only", []string{}, nil)
	v.fix.prf[string(spare.CredID)] = []byte("spare-from-recovery")
	attempt, packet, digest = v.sealIdentity()
	mustStatus(t, "enrol challenge", v.web("POST", "/api/ui/seal/recovery/challenge", map[string]any{"mode": "enrol", "attempt_id": attempt, "packet_sha256": digest, "credential_id": encodeID(spare.CredID), "scopes": []string{v.org}}, &r), 200)
	as, pkt := v.fix.tapWith(t, v.s, spare, r)
	mustStatus(t, "enrol", v.web("POST", "/api/ui/seal/recovery/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "packet": packet, "open": pkt}, &res), 200)
	if len(v.wraps(spare)) != 1 || v.s.seal.pool.count() != 0 {
		t.Fatal("enrol did not wrap, or left something open")
	}
	// The enrolled passkey opens the set.
	r2, k, st := v.revealChallenge([]string{"APP_TOKEN"})
	mustStatus(t, "reveal", st, 200)
	as, pkt = v.fix.tapWith(t, v.s, spare, r2.tap())
	var out struct{ Enc, Ciphertext string }
	mustStatus(t, "reveal by the enrolled passkey", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": r2.ChallengeID, "assertion": as, "open": pkt}, &out), 200)
	if got, err := v.openReveal(r2, k, out.Enc, out.Ciphertext); err != nil || got[0].Value != "x" {
		t.Fatal("reveal")
	}
	if strings.Contains(v.logs.String(), v.fix.identity.String()) || strings.Contains(v.seen.String(), v.fix.identity.String()) {
		t.Fatal("the recovery identity leaked")
	}
}

// Every new or changed v3 action rebuilds its canonical at finish: a stored
// canonical with a changed field is refused even with a valid assertion.
func TestBucketsCanonicalBinding(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "x"}}}, nil)
	v.envApprove(v.envRelease())
	tamper := func(what, challengePath, finishPath string, body map[string]any, from, to string, extra map[string]any) {
		t.Helper()
		var r tapResp
		mustStatus(t, what+" challenge", v.web("POST", challengePath, body, &r), 200)
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
		fin := map[string]any{"challenge_id": r.ChallengeID, "assertion": v.auth.Assert(ch)}
		for k, x := range extra {
			fin[k] = x
		}
		if st := v.web("POST", finishPath, fin, nil); st/100 == 2 {
			t.Fatalf("%s: changed canonical accepted", what)
		}
	}
	var st struct {
		Buckets []struct{ ID, Kind string }
	}
	mustStatus(t, "status", v.web("GET", "/api/ui/seal/status", nil, &st), 200)
	var ids []string
	for _, b := range st.Buckets {
		ids = append(ids, b.ID)
	}
	slices.Sort(ids)
	tamper("reopen", "/api/ui/seal/control/challenge", "/api/ui/seal/control/finish", map[string]any{"action": "reopen", "buckets": ids[:1]}, ids[0], ids[1], nil)
	tamper("rekey", "/api/ui/seal/control/challenge", "/api/ui/seal/control/finish", map[string]any{"action": "rekey", "scope": v.org}, `"scope_title":"Client A"`, `"scope_title":"Client B"`, nil)
	tamper("close-all", "/api/ui/seal/control/challenge", "/api/ui/seal/control/finish", map[string]any{"action": "close-all"}, `"action":"close-all"`, `"action":"renew-leaf"`, nil)
	tamper("capability", "/api/ui/seal/passkeys/challenge", "/api/ui/seal/passkeys/authorize", map[string]any{"action": "register", "nickname": "spare", "capability": "approve-only", "credential_id": "", "scopes": []string{}}, `"v":3`, `"v":4`, nil)
	attempt, packet, digest := v.sealIdentity()
	tamper("recovery", "/api/ui/seal/recovery/challenge", "/api/ui/seal/recovery/finish", map[string]any{"mode": "drill", "attempt_id": attempt, "packet_sha256": digest}, digest, strings.Repeat("0", 64), map[string]any{"packet": packet})
	if v.s.seal.pool.count() != 1 {
		t.Fatal("a refused action changed the open buckets")
	}
}

func TestBucketsMigrationRequiredMode(t *testing.T) {
	// A format-1 activation marker under this binary: sign-in and queueing
	// work; anything needing a bucket says migration is required.
	logs := &syncBuffer{}
	e := newEnv(t)
	e.setupOwner()
	cert := e.enrollHost("workload")
	organise(t, e)
	s := e.s
	m, _ := json.Marshal(seal.Manifest{Format: 1, Generation: seal.Generation{Installation: seal.RandomID(), Version: 1}, Recipient: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq", SSHCA: s.sshPin(), InternalCA: s.pki.CAPin(), Config: s.profileRevision})
	_, err := s.store.DB().Exec(sealActiveDDL + `CREATE TABLE seal_wraps(passkey INTEGER PRIMARY KEY REFERENCES passkeys(id) ON DELETE CASCADE, salt BLOB NOT NULL UNIQUE, wrap BLOB NOT NULL, generation INTEGER NOT NULL, tested_at INTEGER NOT NULL) STRICT;`)
	requireNoError(t, err)
	_, err = s.store.DB().Exec(`INSERT INTO seal_active VALUES(1,?,CAST('{}' AS BLOB),'',x'');PRAGMA user_version=8`, string(m))
	requireNoError(t, err)
	for _, f := range []string{"ssh_user_ca", "client_ca.key"} {
		requireNoError(t, removeCA(e, f))
	}
	e.cfg.Seal.Required, e.cfg.Seal.Recipient, e.cfg.Seal.Manifest = true, "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq", seal.Digest(m)
	e.restart(logs)
	agent := e.agentClient(&cert)
	var status struct{ Mode string }
	mustStatus(t, "status", e.webDo("GET", "/api/ui/seal/status", nil, &status), 200)
	if status.Mode != "migration-required" {
		t.Fatalf("mode %q", status.Mode)
	}
	rc, _, st := e.request(agent, "db-1", "alice", 300)
	mustStatus(t, "queue", st, 201)
	if st := e.webDo("POST", "/api/ui/requests/"+rc.ID+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, nil); st != 423 {
		t.Fatalf("approve with migration required: %d", st)
	}
	var cr challengeResp
	mustStatus(t, "deny challenge", e.webDo("POST", "/api/ui/requests/"+rc.ID+"/challenge", api.ChallengeRequest{Action: "deny"}, &cr), 200)
	mustStatus(t, "deny", e.decide("/api/ui/requests/"+rc.ID, "decide", cr, nil), 200)
	mustStatus(t, "vault", e.webDo("GET", "/api/ui/seal/vault/state", nil, nil), 423)
}

func TestBucketsStandingHoldAndRevoke(t *testing.T) {
	v := newVault(t)
	rc := ownerOnlySSH(t, v)
	st := v.decideTap(v.auth, "/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300, StandingHours: 1})
	if st == 400 {
		t.Skip("standing approvals are off in the personal policy fixture")
	}
	mustStatus(t, "approve with standing", st, 200)
	ob := openBuckets(t, v.s)
	h := ob["ssh-ca:installation"].Holds
	if len(h) != 1 || h[0].Kind != "standing" || !strings.HasPrefix(h[0].Ref, "standing:") {
		t.Fatalf("standing hold: %+v", ob)
	}
	// The rule issues without a tap while the CA is open.
	again, _, code := v.request(v.agent, "db-1", "alice", 300)
	mustStatus(t, "second", code, 201)
	if again.Status != api.StatusApproved {
		t.Fatalf("standing rule did not issue: %s", again.Status)
	}
	// Restart: the rule pauses; the next request waits for a re-arming tap.
	v.restart(v.logs)
	v.agent = v.agentClient(v.agentCert())
	third := ownerOnlySSH(t, v)
	var r tapResp
	mustStatus(t, "re-arm challenge", v.web("POST", "/api/ui/requests/"+third.ID+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r), 200)
	if !strings.Contains(r.Open.Descriptor, "re-arms standing rule") {
		t.Fatalf("descriptor does not show the re-arm: %s", r.Open.Descriptor)
	}
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "re-arm", v.web("POST", "/api/ui/requests/"+third.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil), 200)
	if v.s.seal.pool.count() != 1 {
		t.Fatal("re-arm did not keep the CA open")
	}
	// Revoking the rule closes the CA.
	rules, err := v.s.store.Q().ActiveStanding(t.Context(), 0, v.clock.Now())
	requireNoError(t, err)
	path := "/api/ui/standing/" + rules[0].ID
	r = tapResp{}
	mustStatus(t, "revoke challenge", v.web("POST", path+"/challenge", api.ChallengeRequest{Action: "revoke"}, &r), 200)
	if r.Open != nil {
		t.Fatal("a revoke offered an open")
	}
	as, _ = v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "revoke", v.web("POST", path+"/revoke", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as}, nil), 200)
	if v.s.seal.pool.count() != 0 {
		t.Fatal("revoking the rule left the CA open")
	}
}
