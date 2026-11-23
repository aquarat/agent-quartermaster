//go:build linux

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Findings of the independent review of seal format 2 (stage holds, guards,
// rekey salts, auto holds, snapshot gate, migration and recovery).

// H1: an abandoned passkey enable does not keep its opened scope keys: the
// reconcile pass wipes the stage at its deadline, and the stage has a timer.
func TestReviewAbandonedEnableIsWiped(t *testing.T) {
	v := newVault(t)
	spare := v.registerSpare("approve-only", []string{}, nil)
	body := map[string]any{"action": "enable", "nickname": "spare", "capability": "unlock", "credential_id": encodeID(spare.CredID), "scopes": []string{"installation"}}
	var auth struct {
		Registration string `json:"registration_id"`
	}
	mustStatus(t, "enable", v.capability(v.auth, body, &auth), 200)
	pool := &v.s.seal.capabilities
	pool.Lock()
	st := pool.entries[auth.Registration]
	keys, timer := len(st.keys), st.timer
	pool.Unlock()
	if keys != 1 || timer == nil {
		t.Fatalf("stage holds %d scope keys, timer %v", keys, timer)
	}
	// Before the deadline the pass keeps it.
	v.s.reconcileHolds(t.Context())
	pool.Lock()
	_, kept := pool.entries[auth.Registration]
	pool.Unlock()
	if !kept {
		t.Fatal("a live stage was dropped")
	}
	v.clock.Advance(RegisterTTL + time.Second)
	v.s.reconcileHolds(t.Context())
	pool.Lock()
	_, left := pool.entries[auth.Registration]
	n := len(st.keys)
	pool.Unlock()
	if left || n != 0 {
		t.Fatal("the reconcile pass left an expired stage or its scope keys")
	}
	if timer.Stop() {
		t.Fatal("the wiped stage's timer was still armed")
	}
	mustStatus(t, "evaluate after expiry", v.web("POST", "/api/ui/seal/passkeys/evaluate", map[string]any{"registration_id": auth.Registration}, nil), 409)
	// The timer's own path wipes too.
	mustStatus(t, "enable again", v.capability(v.auth, body, &auth), 200)
	pool.Lock()
	st = pool.entries[auth.Registration]
	pool.Unlock()
	pool.drop(st)
	if len(st.keys) != 0 || pool.entries[auth.Registration] != nil {
		t.Fatal("drop left the stage")
	}
}

// H2: a tested wrap is never overwritten; the last-passkey guard (query and
// trigger) is per scope and counts only tested wraps; boot recreates the trigger.
func TestReviewScopeWrapGuards(t *testing.T) {
	v := newVault(t)
	ctx := t.Context()
	q := v.s.store.Q()
	db := v.s.store.DB()
	owner := v.wraps(v.auth)[0].Passkey
	// A tested wrap is kept: no page-supplied KEK replaces it.
	before, err := q.ScopeWrap(ctx, owner, seal.ScopeInstallation)
	requireNoError(t, err)
	salt := seal.RandomID()
	if err := q.PutScopeWrap(ctx, store.ScopeWrapRow{Passkey: owner, Scope: seal.ScopeInstallation, Salt: salt[:], Wrap: bytes.Repeat([]byte{1}, 73), Created: v.clock.Now()}); !errors.Is(err, store.ErrTestedWrap) {
		t.Fatalf("a tested wrap was overwritten: %v", err)
	}
	after, _ := q.ScopeWrap(ctx, owner, seal.ScopeInstallation)
	if !bytes.Equal(after.Wrap, before.Wrap) || after.Tested == nil {
		t.Fatal("the tested wrap changed")
	}
	// After a rekey the wrap is untested, and recovery enrol (PutScopeWrap) may
	// replace it: the way back in when the rekeying passkey's test fails.
	salt2 := seal.RandomID()
	requireNoError(t, q.RekeyScopeWrap(ctx, store.ScopeWrapRow{Passkey: owner, Scope: seal.ScopeInstallation, Salt: salt2[:], Wrap: bytes.Repeat([]byte{2}, 73), Created: v.clock.Now()}))
	if w, _ := q.ScopeWrap(ctx, owner, seal.ScopeInstallation); w.Tested != nil {
		t.Fatal("a rekeyed wrap reads as tested")
	}
	requireNoError(t, q.PutScopeWrap(ctx, store.ScopeWrapRow{Passkey: owner, Scope: seal.ScopeInstallation, Salt: before.Salt, Wrap: before.Wrap, Created: v.clock.Now()}))
	requireNoError(t, q.MarkScopeWrapTested(ctx, before.ID, v.clock.Now()))
	if w, _ := q.ScopeWrap(ctx, owner, seal.ScopeInstallation); !bytes.Equal(w.Wrap, before.Wrap) || w.Tested == nil {
		t.Fatal("recovery enrol did not replace the untested wrap")
	}
	// An untested wrap of the organisation (enable, not yet tested).
	spare := v.registerSpare("unlock", []string{v.org}, []byte("spare-secret"))
	sw := v.wraps(spare)
	if len(sw) != 1 || sw[0].Tested != nil {
		t.Fatalf("spare wraps %+v", sw)
	}
	row := sw[0].Passkey
	// Enabling a passkey for a scope it already opens (tested) is refused.
	mustStatus(t, "enable over a tested wrap", v.capability(v.auth, map[string]any{"action": "enable", "nickname": "test", "capability": "unlock", "credential_id": encodeID(v.auth.CredID), "scopes": []string{"installation"}}, nil), 409)
	// The spare gets tested wraps of every other scope (the guard reads only the table).
	scopes, err := q.Scopes(ctx)
	requireNoError(t, err)
	for _, x := range scopes {
		if x.Scope != v.org {
			_, err := db.Exec(`INSERT INTO scope_wraps(passkey,scope,salt,wrap,created,tested_at) VALUES(?,?,randomblob(32),randomblob(73),0,1)`, row, x.Scope)
			requireNoError(t, err)
		}
	}
	// Its untested wrap of the organisation does not count: the owner stays the last.
	if o, err := q.OrphanedScopes(ctx, owner); err != nil || !slices.Equal(o, []string{v.org}) {
		t.Fatalf("orphaned scopes %v %v", o, err)
	}
	// Removal says to test the other passkey, not to enable one.
	if err := v.s.keepUnlock(ctx, q, owner); err == nil || !strings.Contains(err.Error(), "test passkey") {
		t.Fatalf("removal refusal text: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM passkeys WHERE id=?`, owner); err == nil || !strings.Contains(err.Error(), "last passkey") {
		t.Fatalf("the trigger let the last tested passkey of a scope go: %v", err)
	}
	// Once tested it counts, per scope.
	_, err = db.Exec(`UPDATE scope_wraps SET tested_at=1 WHERE passkey=?`, row)
	requireNoError(t, err)
	if o, err := q.OrphanedScopes(ctx, owner); err != nil || len(o) != 0 {
		t.Fatalf("orphaned scopes after the test %v %v", o, err)
	}
	// A store made by an earlier build of schema 9 gets the current trigger at boot.
	_, err = db.Exec(`DROP TRIGGER keep_one_scope_passkey; CREATE TRIGGER keep_one_scope_passkey BEFORE DELETE ON passkeys WHEN 0 BEGIN SELECT 1; END;`)
	requireNoError(t, err)
	v.restart(v.logs)
	var text string
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='keep_one_scope_passkey'`).Scan(&text))
	if !strings.Contains(text, "tested_at IS NOT NULL") {
		t.Fatal("boot kept an old trigger: " + text)
	}
}

// M6: nothing is written into a new organisation scope until a passkey has
// opened it once; the test tap lifts the refusal.
func TestReviewNewScopeNeedsTest(t *testing.T) {
	v := newVault(t)
	ctx := t.Context()
	const org, service, set = "ffffffffffffffffffffffffffffffff", "99999999999999999999999999999999", "88888888888888888888888888888888"
	for _, x := range []string{
		`INSERT INTO organisations(id,slug,title,revision) VALUES('` + org + `','club','Club',1)`,
		`INSERT INTO org_policies VALUES('` + org + `',1,3600,86400,1,3600,86400,1)`,
		`INSERT INTO org_approvers SELECT '` + org + `',id,'approver',1 FROM people WHERE owner=1`,
		`INSERT INTO services(id,org_id,slug,title,provider,revision) VALUES('` + service + `','` + org + `','app','App','application',1)`,
		`INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES('` + set + `','` + service + `','application','prod','Prod env','env-set',0)`,
	} {
		_, err := v.s.store.DB().Exec(x)
		requireNoError(t, err)
	}
	create := func() error {
		return v.s.store.Tx(ctx, func(q *store.Q) error {
			_, err := v.s.ensureSetBucket(ctx, q, "env-set", set, org)
			return err
		})
	}
	if err := create(); err == nil || !strings.Contains(err.Error(), "create the scope first") {
		t.Fatalf("a bucket in a scope without a key: %v", err)
	}
	// Create the scope: an enable of the owner's passkey for it.
	body := map[string]any{"action": "enable", "nickname": "test", "capability": "unlock", "credential_id": encodeID(v.auth.CredID), "scopes": []string{org}}
	var auth struct {
		Registration string `json:"registration_id"`
	}
	mustStatus(t, "create scope", v.capability(v.auth, body, &auth), 200)
	v.enrolFinish(v.auth, auth.Registration)
	if _, err := v.s.store.Q().Scope(ctx, org); err != nil {
		t.Fatal("scope not created")
	}
	if err := create(); err == nil || !strings.Contains(err.Error(), "test the new scope first") {
		t.Fatalf("a bucket before the new scope was tested: %v", err)
	}
	body["action"] = "test"
	mustStatus(t, "test", v.capability(v.auth, body, nil), 200)
	requireNoError(t, create())
}

// M1: rekey wraps the new scope key under a fresh salt (the tap's second PRF
// evaluation), not under the passkey's old salt; the wrap is tested at its next open.
func TestReviewRekeyUsesFreshSalt(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "v"}}}, nil)
	var old store.ScopeWrapRow
	for _, w := range v.wraps(v.auth) {
		if w.Scope == v.org {
			old = w
		}
	}
	var r tapResp
	mustStatus(t, "rekey challenge", v.web("POST", "/api/ui/seal/control/challenge", map[string]any{"action": "rekey", "scope": v.org}, &r), 200)
	var d descriptor
	requireNoError(t, unmarshalJSON(r.Open.Descriptor, &d))
	if d.RekeySalt == "" || len(d.Scopes) != 1 {
		t.Fatalf("rekey descriptor without a fresh salt: %s", r.Open.Descriptor)
	}
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "rekey", v.web("POST", "/api/ui/seal/control/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
	var now store.ScopeWrapRow
	for _, w := range v.wraps(v.auth) {
		if w.Scope == v.org {
			now = w
		}
	}
	if bytes.Equal(now.Salt, old.Salt) || encodeID(now.Salt) != d.RekeySalt || now.Tested != nil {
		t.Fatal("the new scope key is not wrapped at the descriptor's fresh salt, untested")
	}
	// A packet without the second KEK is refused (nothing changes).
	mustStatus(t, "rekey challenge", v.web("POST", "/api/ui/seal/control/challenge", map[string]any{"action": "rekey", "scope": v.org}, &r), 200)
	d = descriptor{}
	requireNoError(t, unmarshalJSON(r.Open.Descriptor, &d))
	as, pkt = v.fix.tapWith(t, v.s, v.auth, stripRekey(t, r))
	mustStatus(t, "rekey with one KEK", v.web("POST", "/api/ui/seal/control/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, nil), 403)
	// The next open (a reveal) proves the new wrap and marks it tested.
	if got := v.reveal([]string{"APP_TOKEN"}); got[0].Value != "v" {
		t.Fatal("value after rekey")
	}
	for _, w := range v.wraps(v.auth) {
		if w.Scope == v.org && w.Tested == nil {
			t.Fatal("the new wrap was not marked tested by its first open")
		}
	}
}

// stripRekey makes tapWith seal only the first KEK (a page that ignores the fresh salt).
func stripRekey(t *testing.T, r tapResp) tapResp {
	t.Helper()
	r.oneKEK = true
	return r
}

// L1: a packet sent with a tap that needed nothing closed consumes only that
// tap's own attempt, so another pending tap can still open its bucket.
func TestReviewOpenTapLeavesOtherAttempts(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "kept"}}}, nil)
	grant := v.envApprove(v.envRelease()) // the set is open until collected
	ra, ka, st := v.revealChallenge([]string{"APP_TOKEN"})
	mustStatus(t, "reveal A", st, 200)
	rb, kb, st := v.revealChallenge([]string{"APP_TOKEN"})
	mustStatus(t, "reveal B", st, 200)
	asA, _ := v.fix.tapWith(t, v.s, v.auth, ra.tap())
	asB, pktB := v.fix.tapWith(t, v.s, v.auth, rb.tap())
	var out struct{ Enc, Ciphertext string }
	// A carries B's packet: nothing was closed, so A succeeds and B's attempt is untouched.
	mustStatus(t, "reveal A with B's packet", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": ra.ChallengeID, "assertion": asA, "open": pktB}, &out), 200)
	if got, err := v.openReveal(ra, ka, out.Enc, out.Ciphertext); err != nil || got[0].Value != "kept" {
		t.Fatal("reveal A")
	}
	mustStatus(t, "collect", v.collect(grant), 200)
	if v.s.seal.pool.count() != 0 {
		t.Fatal("the set stayed open after collect")
	}
	mustStatus(t, "reveal B opens the set with its own packet", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": rb.ChallengeID, "assertion": asB, "open": pktB}, &out), 200)
	if got, err := v.openReveal(rb, kb, out.Enc, out.Ciphertext); err != nil || got[0].Value != "kept" {
		t.Fatal("reveal B")
	}
}

// L2: a bucket rekeyed between the review and the tap is never installed with
// its old key: the tap re-reads the row and refuses.
func TestReviewOpenTapRereadsBucket(t *testing.T) {
	v := newVault(t)
	ctx := t.Context()
	rc := ownerOnlySSH(t, v)
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", "/api/ui/requests/"+rc.ID+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r), 200)
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	// The SSH CA bucket gets a new key pair (as a rekey does) after the review.
	q := v.s.store.Q()
	sc, err := q.Scope(ctx, seal.ScopeInstallation)
	requireNoError(t, err)
	k, err := seal.Scope{Installation: v.fix.inst, Name: sc.Scope, Public: sc.Public}.Recover(v.fix.identity, v.fix.recipient, sc.Recovery)
	requireNoError(t, err)
	defer k.Destroy()
	requireNoError(t, v.s.store.Tx(ctx, func(q *store.Q) error {
		row, err := v.s.caRow(ctx, q, seal.RoleSSHCA)
		if err != nil {
			return err
		}
		return v.s.rekeyBucket(ctx, q, row, k, sc.Public, sc.Public)
	}))
	mark := v.seen.Len()
	mustStatus(t, "decide after the bucket changed", v.web("POST", "/api/ui/requests/"+rc.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil), 409)
	if !strings.Contains(v.seen.String()[mark:], "changed since the review") || v.s.seal.pool.count() != 0 {
		t.Fatal("a key from before the change was installed")
	}
	// A fresh review opens the new key.
	mustStatus(t, "approve", v.decideTap(v.auth, "/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300}), 200)
}

// L6: any failure of the open-legacy tap after the format-1 key opened leaves
// nothing staged; the tap can be repeated.
func TestReviewOpenLegacyFailureResets(t *testing.T) {
	v, f := newFormat1(t)
	v.startMode(Options{BucketMigrate: true})
	stageAfterLegacy = func() error { return errConflict("injected") }
	t.Cleanup(func() { stageAfterLegacy = nil })
	if code := v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}); code != 409 {
		t.Fatalf("injected failure: %d", code)
	}
	st := v.s.seal.stage
	st.mu.Lock()
	built, scopes, buckets := st.built, len(st.scopes), len(st.buckets)
	st.mu.Unlock()
	if built || scopes != 0 || buckets != 0 || v.stageState().Stage.LegacyUnlocked {
		t.Fatal("a failed open-legacy tap left the stage built")
	}
	stageAfterLegacy = nil
	mustStatus(t, "open-legacy again", v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}), 200)
}

// M2, M3: the "auto" hold is added only by a tap whose card says it re-arms
// auto-approval, and ends when the policy stops auto-approving; snapshots are
// served only while the proxy parent is open.
func TestReviewCloudflareAutoHoldAndSnapshots(t *testing.T) {
	v, _ := migratedVault(t)
	ctx := t.Context()
	set, err := v.s.store.Q().CFProxySet(ctx)
	requireNoError(t, err)
	key := seal.RoleCFProxy + ":" + set
	snapshots := func() int { return v.host(v.agent, "GET", "/v1/cf/snapshots", nil, nil) }
	if st := snapshots(); st != 423 {
		t.Fatalf("snapshots with the proxy parent closed: %d", st)
	}
	kinds := func() []string {
		var out []string
		for _, h := range openBuckets(t, v.s)[key].Holds {
			out = append(out, h.Kind)
		}
		slices.Sort(out)
		return out
	}
	// Closed: cf.read waits for a tap whose card re-arms auto-approval.
	rc, st := v.cfRequest(v.agent, "cf.read", nil, "", 0)
	mustStatus(t, "cf.read", st, 201)
	if rc.Status != api.StatusPending {
		t.Fatalf("auto-approved with the parent closed: %s", rc.Status)
	}
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", "/api/ui/requests/"+rc.ID+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 300}, &r), 200)
	if r.Open == nil || !strings.Contains(r.Open.Descriptor, "re-arms Cloudflare auto-approval") {
		t.Fatalf("the card does not say it re-arms auto-approval: %+v", r.Open)
	}
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "approve", v.web("POST", "/api/ui/requests/"+rc.ID+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil), 200)
	if got := kinds(); !slices.Equal(got, []string{"auto", "grant"}) {
		t.Fatalf("holds after the re-arming tap: %v", got)
	}
	if st := snapshots(); st != 200 {
		t.Fatalf("snapshots with the parent open: %d", st)
	}
	// The policy stops auto-approving: the auto hold ends at the next pass.
	_, err = v.s.store.DB().Exec(`UPDATE set_policies SET auto=0 WHERE set_id=?`, set)
	requireNoError(t, err)
	v.s.reconcileHolds(ctx)
	if got := kinds(); !slices.Equal(got, []string{"grant"}) {
		t.Fatalf("holds after auto-approval was turned off: %v", got)
	}
	_, err = v.s.store.DB().Exec(`UPDATE set_policies SET auto=1 WHERE set_id=? AND scope IN ('cf.read','cf.cache.purge')`, set)
	requireNoError(t, err)
	// While open, auto-approval issues without a tap but adds no auto hold.
	rc, st = v.cfRequest(v.agent, "cf.read", nil, "", 0)
	mustStatus(t, "cf.read while open", st, 201)
	if rc.Status != api.StatusApproved {
		t.Fatalf("not auto-approved while open: %s", rc.Status)
	}
	if got := kinds(); !slices.Equal(got, []string{"grant", "grant"}) {
		t.Fatalf("holds after an auto-approval: %v", got)
	}
	v.s.closeAll()
	if st := snapshots(); st != 423 {
		t.Fatalf("snapshots after Close all: %d", st)
	}
}

// migratedVault is a format-1 store moved to buckets and served (Cloudflare on).
func migratedVault(t *testing.T) (*vaultEnv, *f1) {
	t.Helper()
	v, f := newFormat1(t)
	v.startMode(Options{BucketMigrate: true})
	mustStatus(t, "open-legacy", v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}), 200)
	v.stageAll(f)
	manifest := v.activate()
	v.s.Close()
	v.cfg.Seal.Manifest = seal.Digest([]byte(manifest))
	v.startMode(Options{})
	v.fix = &bucketFix{inst: f.inst, identity: f.identity, recipient: f.recipient, prf: map[string][]byte{string(v.auth.CredID): f.secret}}
	return v, f
}

func unmarshalJSON(s string, out any) error { return json.Unmarshal([]byte(s), out) }
