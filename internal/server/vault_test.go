//go:build linux

package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// vaultEnv is a format-2, organisation-scoped broker with one client
// organisation, an env set and two admitted hosts. Its helpers play the page:
// they seal to the broker's attempt key, rebuild every canonical from what the
// owner chose, open buckets with the software PRF and open reveals with a key
// of their own.
type vaultEnv struct {
	*env
	logs       *syncBuffer
	seen       bytes.Buffer // every response body, web and agent
	org        string
	service    string
	set        string
	agent      *http.Client
	other      *http.Client
	fix        *bucketFix
	target     map[string]any
	recipient  string // of the last upload attempt
	lastReveal map[string]any
}
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

const (
	vOrg, vService, vSet = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"
)

// organise activates organisations on an unsealed env (as the cutover does).
func organise(t *testing.T, e *env) {
	t.Helper()
	ctx := t.Context()
	s := e.s
	now := s.now()
	tx, err := s.store.DB().BeginTx(ctx, nil)
	requireNoError(t, err)
	plan, err := organisations.Inventory(ctx, tx, s.cfg, s.sshPin(), s.pki.CAPin(), now)
	requireNoError(t, err)
	raw, _ := json.Marshal(plan)
	requireNoError(t, organisations.Backfill(ctx, tx, s.cfg, s.sshPin(), s.pki.CAPin(), now, string(raw)))
	requireNoError(t, tx.Commit())
	s.store.Close()
	s.store, err = store.Open(DBPath(s.cfg.DataDir))
	requireNoError(t, err)
	requireNoError(t, s.verifyPersonalConfig())
	requireNoError(t, s.store.InitWindows(ctx))
}

func newVault(t *testing.T) *vaultEnv {
	t.Helper()
	logs := &syncBuffer{}
	e := newEnvWith(t, testConfig(t.TempDir()), func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	e.setupOwner()
	a, b := e.enrollHost("workload"), e.enrollHost("other")
	organise(t, e)
	for _, q := range []string{
		`INSERT INTO organisations(id,slug,title,revision) VALUES('` + vOrg + `','client-a','Client A',1)`,
		`INSERT INTO org_policies VALUES('` + vOrg + `',1,3600,86400,1,3600,86400,1)`,
		`INSERT INTO org_approvers SELECT '` + vOrg + `',id,'approver',1 FROM people WHERE owner=1`,
		`INSERT INTO services(id,org_id,slug,title,provider,revision) VALUES('` + vService + `','` + vOrg + `','paas','PaaS','application',1)`,
		`INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES('` + vSet + `','` + vService + `','application','staging','Staging env','env-set',0)`,
		`INSERT INTO org_hosts SELECT '` + vOrg + `',id,1,1 FROM hosts`,
	} {
		_, err := e.s.store.DB().Exec(q)
		requireNoError(t, err)
	}
	fix := sealBuckets(t, e, logs)
	v := &vaultEnv{env: e, logs: logs, org: vOrg, service: vService, set: vSet, agent: e.agentClient(&a), other: e.agentClient(&b), fix: fix}
	v.target = map[string]any{"org_id": vOrg, "org_slug": "client-a", "org_title": "Client A", "service_id": vService, "service_slug": "paas", "service_title": "PaaS", "set_id": vSet, "set_slug": "staging", "set_title": "Staging env", "kind": "env-set"}
	return v
}

// lock closes every bucket (format 2 has no lock: this is Close all).
func (v *vaultEnv) lock() { v.s.closeAll() }

func (v *vaultEnv) web(method, path string, body, out any) int {
	v.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, v.env.web.URL+path, rd)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Aqmas", "1")
		req.Header.Set("Origin", testBase)
	}
	req.Header.Set("Cookie", sessionCookie+"="+v.sess)
	resp, err := http.DefaultClient.Do(req)
	requireNoError(v.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	v.seen.Write(b)
	if out != nil && resp.StatusCode/100 == 2 {
		requireNoError(v.t, json.Unmarshal(b, out))
	}
	if resp.StatusCode/100 != 2 && testing.Verbose() {
		v.t.Logf("%s %s -> %d %s", method, path, resp.StatusCode, b)
	}
	return resp.StatusCode
}
func (v *vaultEnv) host(c *http.Client, method, path string, body, out any) int {
	v.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, v.env.agent.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	requireNoError(v.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	v.seen.Write(b)
	if out != nil && resp.StatusCode/100 == 2 {
		requireNoError(v.t, json.Unmarshal(b, out))
	}
	if resp.StatusCode/100 != 2 && testing.Verbose() {
		v.t.Logf("%s %s -> %d %s", method, path, resp.StatusCode, b)
	}
	return resp.StatusCode
}

type vaultReviewResp struct {
	Canonical   string          `json:"canonical"`
	ChallengeID string          `json:"challenge_id"`
	PublicKey   json.RawMessage `json:"public_key"`
	Open        *api.OpenOffer  `json:"open"`
	Facts       map[string]any  `json:"facts"`
}

func (r vaultReviewResp) tap() tapResp {
	return tapResp{ChallengeID: r.ChallengeID, Canonical: r.Canonical, PublicKey: r.PublicKey, Open: r.Open}
}

// expect rebuilds the canonical from the owner's side and requires the
// broker's to be byte-identical, as web/src/vault.ts does before any tap.
func (v *vaultEnv) expect(r vaultReviewResp, action, id string, meta map[string]any) {
	v.t.Helper()
	var c struct {
		IssuedAt string `json:"issued_at"`
		Nonce    string `json:"nonce"`
	}
	requireNoError(v.t, json.Unmarshal([]byte(r.Canonical), &c))
	m, _ := reviewJSON(meta)
	want, _ := reviewJSON(map[string]any{"v": 3, "object": "vault", "action": action, "id": id, "installation": v.fix.inst, "epoch": v.s.seal.opens.Epoch(), "issued_at": c.IssuedAt, "nonce": c.Nonce, "metadata": m})
	if want != r.Canonical {
		v.t.Fatalf("canonical is not what the owner chose:\n got %s\nwant %s", r.Canonical, want)
	}
}
func (v *vaultEnv) tap(r vaultReviewResp, out any) int {
	v.t.Helper()
	as, pkt := v.fix.tapWith(v.t, v.s, v.auth, r.tap())
	return v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, out)
}
func with(base map[string]any, kv ...any) map[string]any {
	m := map[string]any{}
	for k, x := range base {
		m[k] = x
	}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}
func (v *vaultEnv) revision() int {
	var n int
	requireNoError(v.t, v.s.store.DB().QueryRow(`SELECT revision FROM credential_sets WHERE id=?`, v.set).Scan(&n))
	return n
}

// sealUpload plays the browser: one attempt, one packet.
func (v *vaultEnv) sealUpload(purpose, set string, plain []byte) (attempt, enc, ct string) {
	v.t.Helper()
	var a struct {
		ID        string `json:"attempt_id"`
		Recipient string `json:"recipient"`
	}
	mustStatus(v.t, "attempt", v.web("POST", "/api/ui/seal/vault/attempt", map[string]any{}, &a), 200)
	pub, _ := b64url(a.Recipient)
	raw, _ := b64url(a.ID)
	epoch := v.s.seal.opens.Epoch()
	e, c, err := seal.SealTo(pub, seal.Tuple("hpke-vault", v.fix.inst[:], []byte(purpose)), seal.Tuple("hpke-vault-aad", raw, epoch[:], []byte(set)), plain)
	requireNoError(v.t, err)
	v.recipient = a.Recipient
	return a.ID, encodeID(e), encodeID(c)
}

// commitChallenge uploads an edit and returns the review, already checked.
func (v *vaultEnv) commitChallenge(edit envset.Edit, oldNames []string) (vaultReviewResp, int) {
	v.t.Helper()
	rev := v.revision()
	edit.Salt = bytes.Repeat([]byte{byte(rev + 1)}, 32)
	plain, _ := json.Marshal(edit)
	commit, err := edit.Commit(envset.Binding{Org: v.org, Service: v.service, Set: v.set, Revision: rev})
	requireNoError(v.t, err)
	attempt, enc, ct := v.sealUpload("edit", v.set, plain)
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "commit", "id": v.set, "attempt_id": attempt, "enc": enc, "ciphertext": ct, "commitment": commit}, &r)
	if st == 200 {
		changes, _ := edit.Changes(oldNames)
		v.expect(r, "commit", v.set, with(v.target, "revision", rev, "attempt_id", attempt, "operation", edit.Op, "changes", changes, "commitment", commit, "result_revision", rev+1, "recipient", v.recipient))
	}
	return r, st
}
func (v *vaultEnv) commit(edit envset.Edit, oldNames []string) {
	v.t.Helper()
	r, st := v.commitChallenge(edit, oldNames)
	mustStatus(v.t, "commit challenge", st, 200)
	mustStatus(v.t, "commit finish", v.tap(r, nil), 200)
}

// revealChallenge asks for names with a fresh browser key.
func (v *vaultEnv) revealChallenge(names []string) (vaultReviewResp, *seal.Recipient, int) {
	v.t.Helper()
	k, err := seal.NewRecipient()
	requireNoError(v.t, err)
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "reveal", "id": v.set, "names": names, "recipient": encodeID(k.Public())}, &r)
	if st == 200 {
		v.expect(r, "reveal", v.set, with(v.target, "revision", v.revision(), "names", names, "recipient", encodeID(k.Public())))
	}
	return r, k, st
}
func (v *vaultEnv) openReveal(r vaultReviewResp, k *seal.Recipient, enc, ct string) ([]envset.Entry, error) {
	e, _ := b64url(enc)
	c, _ := b64url(ct)
	epoch := v.s.seal.opens.Epoch()
	b, err := k.Open(seal.Tuple("hpke-vault", v.fix.inst[:], []byte("reveal")), seal.Tuple("hpke-vault-aad", canon.Challenge(r.Canonical), epoch[:], []byte(v.set)), e, c)
	if err != nil {
		return nil, err
	}
	var out struct {
		Entries []envset.Entry `json:"entries"`
	}
	return out.Entries, json.Unmarshal(b, &out)
}
func (v *vaultEnv) reveal(names []string) []envset.Entry {
	v.t.Helper()
	r, k, st := v.revealChallenge(names)
	mustStatus(v.t, "reveal challenge", st, 200)
	var out struct{ Enc, Ciphertext string }
	mustStatus(v.t, "reveal finish", v.tap(r, &out), 200)
	entries, err := v.openReveal(r, k, out.Enc, out.Ciphertext)
	requireNoError(v.t, err)
	return entries
}

// leaked reports where any encoding of secret appears outside the sealed store.
func (v *vaultEnv) leaked(secret []byte) string {
	v.t.Helper()
	forms := [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret))}
	if j, err := json.Marshal(string(secret)); err == nil {
		forms = append(forms, j[1:len(j)-1])
	}
	places := map[string][]byte{"logs": []byte(v.logs.String()), "responses": v.seen.Bytes()}
	_, err := v.s.store.DB().Exec(`PRAGMA wal_checkpoint`)
	requireNoError(v.t, err)
	for _, name := range []string{"aqmas.db", "aqmas.db-wal"} {
		b, err := os.ReadFile(filepath.Join(v.cfg.DataDir, name))
		if err == nil {
			places[name] = b
		}
	}
	rows, err := v.s.store.DB().Query(`SELECT actor||' '||action||' '||object||' '||detail FROM audit`)
	requireNoError(v.t, err)
	defer rows.Close()
	var audit bytes.Buffer
	for rows.Next() {
		var s string
		requireNoError(v.t, rows.Scan(&s))
		audit.WriteString(s + "\n")
	}
	places["audit"] = audit.Bytes()
	for where, b := range places {
		for _, f := range forms {
			if bytes.Contains(b, f) {
				return where
			}
		}
	}
	return ""
}
func (v *vaultEnv) audited(action, fragment string) bool {
	var n int
	requireNoError(v.t, v.s.store.DB().QueryRow(`SELECT count(*) FROM audit WHERE action=? AND instr(detail,?)>0`, action, fragment).Scan(&n))
	return n > 0
}

const vaultPEM = "-----BEGIN PRIVATE KEY-----\nc2VudGluZWwtbXVsdGlsaW5lLXZhbHVlLTAwMDE=\nline 'three' \"quoted\" $HOME `id`\n-----END PRIVATE KEY-----\n"

func TestVaultFormAndReveal(t *testing.T) {
	v := newVault(t)
	const sentinel = "sentinel-form-value-7c1d4e"
	// Typed and pasted values, one of them multi-line, in one signed revision.
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: sentinel}, {Name: "APP_KEY", Value: vaultPEM}, {Name: "DB_URL", Value: "postgres://app@192.0.2.10/app"}}}, nil)
	if v.revision() != 1 || !v.audited("vault_commit", "client-a/paas/staging revision=1 operation=merge changes=APP_KEY:add,APP_TOKEN:add,DB_URL:add") {
		t.Fatal("first revision not recorded")
	}
	// Replace one, remove one, keep one untouched and unseen.
	names := []string{"APP_KEY", "APP_TOKEN", "DB_URL"}
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: sentinel + "-2"}}, Remove: []string{"DB_URL"}}, names)
	got := v.reveal([]string{"APP_KEY", "APP_TOKEN"})
	if len(got) != 2 || got[0] != (envset.Entry{Name: "APP_KEY", Value: vaultPEM}) || got[1].Value != sentinel+"-2" {
		t.Fatalf("reveal did not round-trip: %q", got)
	}
	if one := v.reveal([]string{"APP_KEY"}); len(one) != 1 || one[0].Value != vaultPEM {
		t.Fatal("per-key reveal returned something else")
	}
	if !v.audited("vault_reveal", "client-a/paas/staging revision=2 names=APP_KEY,APP_TOKEN") {
		t.Fatal("reveal not audited with its key names")
	}
	// A .env import replaces the whole set.
	v.commit(envset.Edit{Op: "import", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: sentinel}, {Name: "APP_KEY", Value: vaultPEM}}}, []string{"APP_KEY", "APP_TOKEN"})
	var state struct {
		Sets []struct {
			SetID       string `json:"set_id"`
			Kind        string
			Revision    int
			Names       []string
			AllowReveal bool `json:"allow_reveal"`
		}
	}
	mustStatus(t, "state", v.web("GET", "/api/ui/seal/vault/state", nil, &state), 200)
	if len(state.Sets) != 1 || state.Sets[0].Revision != 3 || strings.Join(state.Sets[0].Names, ",") != "APP_KEY,APP_TOKEN" || !state.Sets[0].AllowReveal {
		t.Fatalf("state: %+v", state)
	}
	// The existing delivery path hands an admitted host exactly what the form stored.
	var b envset.Binding
	mustStatus(t, "binding", v.host(v.agent, "GET", "/v2/env/set?path=client-a/paas/staging", nil, &b), 200)
	if b.Revision != 3 {
		t.Fatal("agent sees another revision")
	}
	for _, where := range []string{v.leaked([]byte(sentinel)), v.leaked([]byte(vaultPEM)), v.leaked([]byte("c2VudGluZWwtbXVsdGlsaW5lLXZhbHVlLTAwMDE="))} {
		if where != "" {
			t.Fatalf("a value reached %s in the clear", where)
		}
	}
}

func TestVaultRevealIsAlwaysAFreshTap(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "value-one"}, {Name: "APP_SECRET", Value: "value-two"}}}, nil)
	names := []string{"APP_SECRET", "APP_TOKEN"}
	r, k, st := v.revealChallenge(names)
	mustStatus(t, "challenge", st, 200)
	finish := func(body map[string]any) int { return v.web("POST", "/api/ui/seal/vault/finish", body, nil) }
	// No assertion, an assertion over another challenge, a window-style proof: all refused, and each spends the challenge.
	mustStatus(t, "no assertion", finish(map[string]any{"challenge_id": r.ChallengeID}), 400)
	r, k, _ = v.revealChallenge(names)
	mustStatus(t, "foreign assertion", finish(map[string]any{"challenge_id": r.ChallengeID, "assertion": v.auth.Assert(canon.Challenge(r.Canonical + " "))}), 403)
	r, k, _ = v.revealChallenge(names)
	mustStatus(t, "window proof", finish(map[string]any{"challenge_id": r.ChallengeID, "id": "window", "token": "x", "proposal_id": "y", "proof": "z"}), 400)
	// The window routes know nothing of vault actions.
	req := func(x any) *http.Request {
		b, _ := json.Marshal(x)
		rq, _ := http.NewRequest("POST", "/", bytes.NewReader(b))
		return rq
	}
	sess := ids.Hash(v.sess)
	if _, err := v.s.windowPrepare(t.Context(), req(windowClick{ID: "w", Token: "t", Choice: ordinaryChoice{v.set, "reveal", 0}}), sess); err == nil {
		t.Fatal("a window prepared a reveal")
	}
	if _, err := v.s.batchBegin(t.Context(), req(map[string]any{"items": []ordinaryChoice{{v.set, "reveal", 0}}}), sess); err == nil {
		t.Fatal("a batch accepted a reveal")
	}
	// A good tap works once; the same challenge and assertion do not work again.
	r, k, _ = v.revealChallenge(names)
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r.tap())
	var out struct{ Enc, Ciphertext string }
	mustStatus(t, "reveal", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, &out), 200)
	mustStatus(t, "replay", finish(map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}), 409)
	if _, err := v.openReveal(r, k, out.Enc, out.Ciphertext); err != nil {
		t.Fatal(err)
	}
	// Only the key named in the signed canonical opens it; not another key, another canonical or another set.
	other, _ := seal.NewRecipient()
	if _, err := v.openReveal(r, other, out.Enc, out.Ciphertext); err == nil {
		t.Fatal("another key opened the reveal")
	}
	r2 := r
	r2.Canonical += " "
	if _, err := v.openReveal(r2, k, out.Enc, out.Ciphertext); err == nil {
		t.Fatal("the reveal opened under another canonical")
	}
	// Bad requests: unsorted or duplicate or unknown names, an invalid point.
	bad := func(names []string, recipient string) int {
		return v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "reveal", "id": v.set, "names": names, "recipient": recipient}, nil)
	}
	good := encodeID(k.Public())
	for _, c := range []struct {
		names []string
		rcpt  string
		want  int
	}{{[]string{"APP_TOKEN", "APP_SECRET"}, good, 400}, {[]string{"APP_TOKEN", "APP_TOKEN"}, good, 400}, {nil, good, 400}, {[]string{"NOT_THERE_KEY"}, good, 409}, {names, encodeID(make([]byte, 65)), 400}, {names, encodeID(append([]byte{4}, make([]byte, 64)...)), 400}, {names, "", 400}} {
		mustStatus(t, "bad reveal", bad(c.names, c.rcpt), c.want)
	}
	// The set changing between review and tap invalidates the review.
	r, _, _ = v.revealChallenge(names)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_ID", Value: "3"}}}, names)
	mustStatus(t, "stale reveal", v.tap(r, nil), 409)
	// Close all: a review made before it is void; a new review's tap opens the set
	// for an instant only, and uploads need nothing open.
	r, _, _ = v.revealChallenge(names)
	v.lock()
	mustStatus(t, "review from before Close all", v.tap(r, nil), 400)
	if len(v.reveal(names2(v))) != 3 || len(openBuckets(t, v.s)) != 0 {
		t.Fatal("a reveal left its bucket open")
	}
	mustStatus(t, "attempt with everything closed", v.web("POST", "/api/ui/seal/vault/attempt", map[string]any{}, nil), 200)
	// Organisation policy: off refuses, and turning it back on needs an unlocked broker.
	policy := func(allow bool) (vaultReviewResp, int) {
		var r vaultReviewResp
		st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "policy", "id": v.org, "allow_reveal": allow}, &r)
		if st == 200 {
			v.expect(r, "policy", v.org, map[string]any{"org_id": v.org, "org_slug": "client-a", "org_title": "Client A", "old_allow_reveal": !allow, "allow_reveal": allow})
		}
		return r, st
	}
	if _, st := policy(true); st != 409 {
		t.Fatal("no-op policy accepted")
	}
	p, st := policy(false)
	mustStatus(t, "policy off", st, 200)
	stale, _, _ := v.revealChallenge(names2(v))
	mustStatus(t, "policy tap", v.tap(p, nil), 200)
	mustStatus(t, "reveal reviewed before the switch", v.tap(stale, nil), 403)
	mustStatus(t, "reveal with policy off", bad(names2(v), good), 403)
	p, _ = policy(true)
	mustStatus(t, "policy on", v.tap(p, nil), 200)
	if len(v.reveal(names2(v))) != 3 {
		t.Fatal("reveal after re-enabling")
	}
	// Another session cannot finish this session's review.
	r, _, _ = v.revealChallenge(names2(v))
	as, pkt = v.fix.tapWith(t, v.s, v.auth, r.tap())
	v.login()
	mustStatus(t, "other session", v.web("POST", "/api/ui/seal/vault/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, nil), 409)
	if len(openBuckets(t, v.s)) != 0 {
		t.Fatal("another session's packet opened a bucket")
	}
}
func names2(v *vaultEnv) []string { return []string{"APP_ID", "APP_SECRET", "APP_TOKEN"} }

func TestVaultCommitBinding(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "one"}}}, nil)
	old := []string{"APP_TOKEN"}
	edit := envset.Edit{Op: "merge", Salt: bytes.Repeat([]byte{5}, 32), Entries: []envset.Entry{{Name: "APP_SECRET", Value: "two"}}}
	plain, _ := json.Marshal(edit)
	commit, _ := edit.Commit(envset.Binding{Org: v.org, Service: v.service, Set: v.set, Revision: 1})
	challenge := func(attempt, enc, ct, commitment, set string) int {
		return v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "commit", "id": set, "attempt_id": attempt, "enc": enc, "ciphertext": ct, "commitment": commitment}, nil)
	}
	// A commitment that is not over these exact bytes, a packet sealed for another purpose or set, a reused attempt.
	a, e, c := v.sealUpload("edit", v.set, plain)
	mustStatus(t, "wrong commitment", challenge(a, e, c, strings.Repeat("0", 64), v.set), 400)
	mustStatus(t, "attempt reuse", challenge(a, e, c, commit, v.set), 409)
	a, e, c = v.sealUpload("signer-import", v.set, plain)
	mustStatus(t, "wrong purpose", challenge(a, e, c, commit, v.set), 400)
	a, e, c = v.sealUpload("edit", vService, plain)
	mustStatus(t, "sealed for another set", challenge(a, e, c, commit, v.set), 400)
	mustStatus(t, "unknown attempt", challenge(encodeID(bytes.Repeat([]byte{1}, 32)), e, c, commit, v.set), 409)
	mustStatus(t, "unknown set", func() int {
		a, e, c := v.sealUpload("edit", "dddddddddddddddddddddddddddddddd", plain)
		return challenge(a, e, c, commit, "dddddddddddddddddddddddddddddddd")
	}(), 404)
	// Removing a key that is not there, an unsafe name, an old CLI operation.
	for _, bad := range []envset.Edit{{Op: "merge", Remove: []string{"MISSING_KEY"}}, {Op: "merge", Entries: []envset.Entry{{Name: "LD_PRELOAD", Value: "x"}}}, {Op: "put", Entries: []envset.Entry{{Name: "APP_ID", Value: "x"}}}, {Op: "merge", Entries: []envset.Entry{{Name: "APP_ID", Value: "a\x00b"}}}} {
		bad.Salt = edit.Salt
		p, _ := json.Marshal(bad)
		cm, _ := bad.Commit(envset.Binding{Org: v.org, Service: v.service, Set: v.set, Revision: 1})
		if cm == "" {
			cm = commit
		}
		a, e, c := v.sealUpload("edit", v.set, p)
		mustStatus(t, "bad edit "+bad.Op, challenge(a, e, c, cm, v.set), 400)
	}
	// Two reviews of the same base revision: the second tap is stale and changes nothing.
	first, st := v.commitChallenge(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_SECRET", Value: "two"}}}, old)
	mustStatus(t, "first", st, 200)
	second, st := v.commitChallenge(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_SECRET", Value: "three"}}}, old)
	mustStatus(t, "second", st, 200)
	mustStatus(t, "first tap", v.tap(first, nil), 200)
	mustStatus(t, "stale tap", v.tap(second, nil), 409)
	if got := v.reveal([]string{"APP_SECRET"}); got[0].Value != "two" || v.revision() != 2 {
		t.Fatal("stale commit applied")
	}
	// A review cannot be finished twice, and its attempt is gone afterwards.
	mustStatus(t, "replayed commit", v.tap(first, nil), 409)
	// Writes are tapless: a commit needs no open bucket and opens none.
	third, _ := v.commitChallenge(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_ID", Value: "4"}}}, []string{"APP_SECRET", "APP_TOKEN"})
	v.lock()
	if third.Open != nil {
		t.Fatal("a commit offered an open")
	}
	mustStatus(t, "commit with everything closed", v.tap(third, nil), 200)
	if v.revision() != 3 || len(openBuckets(t, v.s)) != 0 {
		t.Fatal("commit not applied, or it opened a bucket")
	}
	// Limits are those of an env set.
	big := envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_KEY", Value: strings.Repeat("k", 8193)}}}
	big.Salt = edit.Salt
	p, _ := json.Marshal(big)
	a, e, c = v.sealUpload("edit", v.set, p)
	mustStatus(t, "oversize value", challenge(a, e, c, commit, v.set), 400)
}

type signerFixture struct {
	id, path string
	pub      []byte
	scheme   signer.Scheme
}

// createSigner makes a signer set, generated or imported, checking the canonical.
func (v *vaultEnv) createSigner(id, slug, scheme, private string) signerFixture {
	v.t.Helper()
	choice := map[string]any{"action": "signer-create", "id": id, "service_id": v.service, "set_slug": slug, "set_title": "Release key", "scheme": scheme, "source": "generate"}
	recipient := ""
	if private != "" {
		plain, _ := json.Marshal(map[string]string{"private_key": private})
		a, e, c := v.sealUpload("signer-import", id, plain)
		choice["source"], choice["attempt_id"], choice["enc"], choice["ciphertext"] = "import", a, e, c
		recipient = v.recipient
	}
	var r vaultReviewResp
	mustStatus(v.t, "signer challenge", v.web("POST", "/api/ui/seal/vault/challenge", choice, &r), 200)
	pub, _ := b64url(r.Facts["public_key"].(string))
	if r.Facts["fingerprint"] != signer.Fingerprint(pub) {
		v.t.Fatal("fingerprint is not of the public key")
	}
	v.expect(r, "signer-create", id, with(v.target, "set_id", id, "set_slug", slug, "set_title", "Release key", "kind", "signer", "revision", 0, "scheme", scheme, "source", choice["source"], "attempt_id", r.Facts["attempt_id"], "public_key", r.Facts["public_key"], "fingerprint", r.Facts["fingerprint"], "result_revision", 0, "recipient", recipient))
	var out struct {
		Path      string
		PublicKey string `json:"public_key"`
	}
	mustStatus(v.t, "signer finish", v.tap(r, &out), 200)
	sc, _ := signer.Lookup(scheme)
	if out.PublicKey != r.Facts["public_key"] || out.Path != "client-a/paas/"+slug {
		v.t.Fatal("created another key than the one signed for")
	}
	return signerFixture{id, out.Path, pub, sc}
}
func signItemFor(sc signer.Scheme, name string, msg []byte) signer.Item {
	a := sha256.Sum256(msg)
	it := signer.Item{Name: name, Size: int64(len(msg)), SHA256: hex.EncodeToString(a[:])}
	switch sc.Input {
	case "message":
		it.Message = msg
	case "sha512":
		b := sha512.Sum512(msg)
		it.SHA512 = hex.EncodeToString(b[:])
	}
	return it
}
func publicItems(items []signer.Item) []map[string]any {
	out := make([]map[string]any, len(items))
	for i, it := range items {
		out[i] = map[string]any{"name": it.Name, "size": it.Size, "sha256": it.SHA256}
		if it.SHA512 != "" {
			out[i]["sha512"] = it.SHA512
		}
	}
	return out
}

// askSign files a request as a host; decideSign reviews it as the owner.
func (v *vaultEnv) askSign(c *http.Client, f signerFixture, ttl, max int, items ...signer.Item) (signer.Request, int) {
	v.t.Helper()
	var b signer.Binding
	if st := v.host(c, "GET", "/v2/sign/key?path="+f.path, nil, &b); st != 200 {
		return signer.Request{}, st
	}
	var r signer.Request
	st := v.host(c, "POST", "/v2/sign/requests", map[string]any{"binding": b, "reason": "release build", "ttl_seconds": ttl, "max_signatures": max, "items": items}, &r)
	return r, st
}
func (v *vaultEnv) signChallenge(f signerFixture, req signer.Request, action string, ttl, max int) (vaultReviewResp, int) {
	v.t.Helper()
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": action, "id": req.ID, "ttl_seconds": ttl, "max_signatures": max}, &r)
	if st == 200 {
		v.expect(r, action, req.ID, with(v.target, "set_id", f.id, "set_slug", strings.TrimPrefix(f.path, "client-a/paas/"), "set_title", "Release key", "kind", "signer", "revision", 0,
			"request_id", req.ID, "host", req.Host, "enrollment", req.Enrollment, "address", "127.0.0.1", "scheme", f.scheme.ID, "fingerprint", signer.Fingerprint(f.pub), "items", publicItems(req.Items),
			"requested_ttl_seconds", req.TTL, "requested_max_signatures", req.Max, "ttl_seconds", ttl, "max_signatures", max,
			"admission_generation", req.Generation, "policy_revision", req.PolicyRevision, "service_revision", req.ServiceRevision, "soft_cap_seconds", req.Soft, "beyond_soft_cap", ttl > req.Soft))
	}
	return r, st
}
func (v *vaultEnv) approveSign(f signerFixture, req signer.Request, ttl, max int) string {
	v.t.Helper()
	r, st := v.signChallenge(f, req, "sign-approve", ttl, max)
	mustStatus(v.t, "sign challenge", st, 200)
	mustStatus(v.t, "sign approve", v.tap(r, nil), 200)
	var got signer.Request
	mustStatus(v.t, "approved status", v.host(v.agent, "GET", "/v2/sign/requests/"+req.ID, nil, &got), 200)
	if got.Status != "approved" || got.Grant == "" {
		v.t.Fatalf("not approved: %+v", got)
	}
	return got.Grant
}
func (v *vaultEnv) sign(c *http.Client, grant string, items ...signer.Item) (signer.Signed, int) {
	var out signer.Signed
	st := v.host(c, "POST", "/v2/sign/grants/"+grant+"/sign", map[string]any{"items": items}, &out)
	return out, st
}

func TestSignerSingleUse(t *testing.T) {
	v := newVault(t)
	seed := bytes.Repeat([]byte{0x5e}, 32)
	seed[0], seed[31] = 0xa7, 0x13
	f := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", hex.EncodeToString(seed))
	if !bytes.Equal(f.pub, ed25519.NewKeyFromSeed(seed)[32:]) {
		t.Fatal("imported key has another public half")
	}
	manifest := bytes.Repeat([]byte("manifest"), 18)[:140]
	a, b := signItemFor(f.scheme, "manifest.bin", manifest), signItemFor(f.scheme, "notes.txt", []byte("release notes"))
	req, st := v.askSign(v.agent, f, 0, 0, a, b)
	mustStatus(t, "request", st, 200)
	if req.Status != "pending" || req.Max != 2 || req.TTL != 0 {
		t.Fatalf("request: %+v", req)
	}
	// Nothing is signed before approval; no grant exists.
	if _, st := v.sign(v.agent, req.ID, a, b); st != 404 {
		t.Fatal("signed with a request ID")
	}
	// The owner may not widen a request.
	if _, st := v.signChallenge(f, req, "sign-approve", 600, 2); st != 400 {
		t.Fatal("single-use request approved as a time-boxed grant")
	}
	if _, st := v.signChallenge(f, req, "sign-approve", 0, 3); st != 400 {
		t.Fatal("count above the artifacts shown")
	}
	grant := v.approveSign(f, req, 0, 2)
	// Exactly the approved artifacts: not a subset, another file, another order or another host.
	other := signItemFor(f.scheme, "manifest.bin", append([]byte{1}, manifest[1:]...))
	for name, items := range map[string][]signer.Item{"subset": {a}, "substitute": {other, b}, "reordered": {b, a}, "renamed": {{Name: "x.bin", Size: a.Size, SHA256: a.SHA256, Message: a.Message}, b}} {
		if _, st := v.sign(v.agent, grant, items...); st != 409 {
			t.Fatalf("%s signed under a single-use grant (%d)", name, st)
		}
	}
	if _, st := v.sign(v.other, grant, a, b); st != 404 {
		t.Fatal("another host used the grant")
	}
	v.lock()
	if _, st := v.sign(v.agent, grant, a, b); st != 423 {
		t.Fatal("signed with the signer closed")
	}
	v.reopenPaused()
	out, st := v.sign(v.agent, grant, a, b)
	mustStatus(t, "sign", st, 200)
	if len(out.Signatures) != 2 || !ed25519.Verify(f.pub, manifest, out.Signatures[0].Signature) || !ed25519.Verify(f.pub, []byte("release notes"), out.Signatures[1].Signature) || out.Request.Used != 2 {
		t.Fatal("signatures do not verify with the standard library")
	}
	if _, st := v.sign(v.agent, grant, a, b); st != 409 {
		t.Fatal("single-use grant signed twice")
	}
	if !v.audited("sign", "client-a/paas/release-key scheme=ed25519 sha256="+a.SHA256) || !v.audited("sign", "sha256="+b.SHA256) || !v.audited("vault_sign_approve", "items="+a.SHA256+","+b.SHA256) {
		t.Fatal("signatures not audited by digest")
	}
	// Limits of a request: a grant shorter than a minute, more artifact bytes than one call carries.
	if _, st := v.askSign(v.agent, f, 30, 5, a); st != 400 {
		t.Fatal("sub-minute grant accepted")
	}
	var many []signer.Item
	for i := 0; i < 11; i++ {
		many = append(many, signItemFor(f.scheme, "part.bin", bytes.Repeat([]byte{byte(i)}, signer.MaxMessage)))
	}
	if _, st := v.askSign(v.agent, f, 0, 0, many...); st != 400 {
		t.Fatal("more artifact bytes than a call may carry")
	}
	// A host cannot flood the owner with requests by cancelling each one.
	last := 0
	for i := 0; i < signer.MaxRequestsPerHour+1; i++ {
		var req signer.Request
		if req, last = v.askSign(v.other, f, 0, 0, signItemFor(f.scheme, "n.bin", []byte{byte(i)})); last != 200 {
			break
		}
		mustStatus(t, "cancel", v.host(v.other, "POST", "/v2/sign/requests/"+req.ID+"/cancel", map[string]any{}, nil), 200)
	}
	if last != 429 {
		t.Fatalf("request flood not limited (%d)", last)
	}
	v.clock.Advance(61 * time.Minute)
	if _, st := v.askSign(v.other, f, 0, 0, a); st != 200 {
		t.Fatal("rate limit did not clear after an hour")
	}
	// The private key is nowhere but the sealed record: no response, log, audit row or database page.
	if where := v.leaked(seed); where != "" {
		t.Fatalf("signer key reached %s", where)
	}
	// It cannot be revealed, edited as an env set, or delivered.
	k, _ := seal.NewRecipient()
	mustStatus(t, "reveal a signer", v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "reveal", "id": f.id, "names": []string{"APP_KEY"}, "recipient": encodeID(k.Public())}, nil), 403)
	edit := envset.Edit{Op: "merge", Salt: bytes.Repeat([]byte{1}, 32), Entries: []envset.Entry{{Name: "APP_KEY", Value: "x"}}}
	plain, _ := json.Marshal(edit)
	cm, _ := edit.Commit(envset.Binding{Org: v.org, Service: v.service, Set: f.id, Revision: 0})
	at, e, c := v.sealUpload("edit", f.id, plain)
	mustStatus(t, "edit a signer", v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "commit", "id": f.id, "attempt_id": at, "enc": e, "ciphertext": c, "commitment": cm}, nil), 400)
	mustStatus(t, "env binding of a signer", v.host(v.agent, "GET", "/v2/env/set?path="+f.path, nil, nil), 404)
	mustStatus(t, "sign binding of an env set", v.host(v.agent, "GET", "/v2/sign/key?path=client-a/paas/staging", nil, nil), 404)
	var cat struct {
		Organisations []struct {
			Slug     string
			Services []struct {
				Sets []struct{ Slug, Kind string }
			}
		}
	}
	mustStatus(t, "catalogue", v.web("GET", "/api/ui/catalogue", nil, &cat), 200)
	kinds := map[string]string{}
	for _, o := range cat.Organisations {
		for _, sv := range o.Services {
			for _, s := range sv.Sets {
				kinds[o.Slug+"/"+s.Slug] = s.Kind
			}
		}
	}
	if kinds["client-a/release-key"] != "signer" || kinds["client-a/staging"] != "env-set" {
		t.Fatalf("catalogue kinds: %v", kinds)
	}
}

func TestSignerGrantsAndSchemes(t *testing.T) {
	v := newVault(t)
	ed := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "image-key", "ed25519-sha256", "")
	ec := v.createSigner("ffffffffffffffffffffffffffffffff", "ecdsa-key", "ecdsa-p256-sha256", "")
	ph := v.createSigner("99999999999999999999999999999999", "ph-key", "ed25519ph", "")
	image := bytes.Repeat([]byte{0xfe}, 300000)
	first := signItemFor(ed.scheme, "firmware.bin", image)
	// Scheme confusion: an item shaped for another scheme is refused before it reaches the owner.
	for name, it := range map[string]signer.Item{
		"message for a digest key": {Name: "m", Size: 3, SHA256: first.SHA256, Message: []byte("abc")},
		"sha512 for a sha256 key":  {Name: "m", Size: 3, SHA256: first.SHA256, SHA512: strings.Repeat("a", 128)},
		"upper-case digest":        {Name: "m", Size: 3, SHA256: strings.ToUpper(first.SHA256)},
		"path in name":             {Name: "../m", Size: 3, SHA256: first.SHA256},
	} {
		if _, st := v.askSign(v.agent, ed, 0, 0, it); st != 400 {
			t.Fatalf("%s accepted (%d)", name, st)
		}
	}
	if _, st := v.askSign(v.agent, ph, 0, 0, signItemFor(ed.scheme, "f", image)); st != 400 {
		t.Fatal("ed25519ph request without its SHA-512")
	}
	// Cross-key: a binding for one key cannot be filed against another's path.
	var b signer.Binding
	mustStatus(t, "binding", v.host(v.agent, "GET", "/v2/sign/key?path="+ed.path, nil, &b), 200)
	swapped := b
	swapped.Path = ec.path
	mustStatus(t, "cross-key binding", v.host(v.agent, "POST", "/v2/sign/requests", map[string]any{"binding": swapped, "reason": "x", "items": []signer.Item{first}}, nil), 409)
	mustStatus(t, "no reason", v.host(v.agent, "POST", "/v2/sign/requests", map[string]any{"binding": b, "reason": " ", "items": []signer.Item{first}}, nil), 400)
	// A time-boxed grant: the owner lowers both numbers; the canonical carries what was asked and what was given.
	req, st := v.askSign(v.agent, ed, 7200, 50, first)
	mustStatus(t, "timed request", st, 200)
	if _, st := v.signChallenge(ed, req, "sign-approve", 7201, 3); st != 400 {
		t.Fatal("duration above the request")
	}
	if _, st := v.signChallenge(ed, req, "sign-approve", 600, 51); st != 400 {
		t.Fatal("count above the request")
	}
	grant := v.approveSign(ed, req, 600, 3)
	out, st := v.sign(v.agent, grant, first)
	mustStatus(t, "first signature", st, 200)
	digest := sha256.Sum256(image)
	if !ed25519.Verify(ed.pub, digest[:], out.Signatures[0].Signature) {
		t.Fatal("ed25519-sha256 signature is not pure Ed25519 over the digest")
	}
	second, third, fourth := signItemFor(ed.scheme, "b.bin", []byte("b")), signItemFor(ed.scheme, "c.bin", []byte("c")), signItemFor(ed.scheme, "d.bin", []byte("d"))
	if _, st := v.sign(v.agent, grant, second, third, fourth); st != 409 {
		t.Fatal("more signatures than the grant has left")
	}
	if out, st := v.sign(v.agent, grant, second, third); st != 200 || out.Request.Used != 3 {
		t.Fatal("grant did not sign up to its count")
	}
	if _, st := v.sign(v.agent, grant, fourth); st != 409 {
		t.Fatal("grant signed beyond its count")
	}
	// A grant for one key signs nothing under another, and expires.
	req, _ = v.askSign(v.agent, ec, 600, 5, signItemFor(ec.scheme, "app.tar", image))
	grantEC := v.approveSign(ec, req, 600, 5)
	outEC, st := v.sign(v.agent, grantEC, signItemFor(ec.scheme, "app.tar", image))
	mustStatus(t, "ecdsa", st, 200)
	if !ec.scheme.Verify(ec.pub, signItemFor(ec.scheme, "app.tar", image), outEC.Signatures[0].Signature) || ed.scheme.Verify(ed.pub, first, outEC.Signatures[0].Signature) {
		t.Fatal("ecdsa signature")
	}
	v.clock.Advance(601 * time.Second)
	if _, st := v.sign(v.agent, grantEC, signItemFor(ec.scheme, "late.tar", []byte("late"))); st != 409 && st != 404 {
		t.Fatalf("expired grant signed (%d)", st)
	}
	// Deny opens nothing.
	req, _ = v.askSign(v.agent, ph, 600, 5, signItemFor(ph.scheme, "p.bin", image))
	v.lock()
	r, st := v.signChallenge(ph, req, "sign-deny", 0, 0)
	mustStatus(t, "deny challenge", st, 200)
	if r.Open != nil {
		t.Fatal("deny offered an open")
	}
	mustStatus(t, "deny", v.tap(r, nil), 200)
	req, _ = v.askSign(v.agent, ph, 600, 5, signItemFor(ph.scheme, "p.bin", image))
	grantPH := v.approveSign(ph, req, 600, 5)
	outPH, st := v.sign(v.agent, grantPH, signItemFor(ph.scheme, "p.bin", image))
	mustStatus(t, "ed25519ph", st, 200)
	if !ph.scheme.Verify(ph.pub, signItemFor(ph.scheme, "p.bin", image), outPH.Signatures[0].Signature) {
		t.Fatal("ed25519ph signature")
	}
	r, st = v.signChallenge(ph, signer.Request{Binding: req.Binding, ID: req.ID, Items: req.Items, TTL: req.TTL, Max: req.Max}, "sign-revoke", 0, 0)
	mustStatus(t, "revoke challenge", st, 200)
	mustStatus(t, "revoke", v.tap(r, nil), 200)
	if _, st := v.sign(v.agent, grantPH, signItemFor(ph.scheme, "q.bin", []byte("q"))); st != 409 {
		t.Fatal("revoked grant signed")
	}
	// Removing the host's admission ends its requests and grants; another organisation's host never sees the key.
	req, _ = v.askSign(v.agent, ed, 600, 5, first)
	grant = v.approveSign(ed, req, 600, 5)
	_, err := v.s.store.DB().Exec(`UPDATE org_hosts SET active=0,generation=generation+1 WHERE org_id=? AND host_id=(SELECT id FROM hosts WHERE name='workload')`, v.org)
	requireNoError(t, err)
	if _, st := v.sign(v.agent, grant, first); st != 404 {
		t.Fatal("grant survived the end of admission")
	}
	mustStatus(t, "unadmitted host", v.host(v.agent, "GET", "/v2/sign/key?path="+ed.path, nil, nil), 404)
	// Pending requests are capped per host with every other kind.
	for i := 0; i < MaxPendingPerHost; i++ {
		if _, st := v.askSign(v.other, ed, 0, 0, signItemFor(ed.scheme, "n.bin", []byte{byte(i)})); st != 200 {
			t.Fatalf("request %d: %d", i, st)
		}
	}
	if _, st := v.askSign(v.other, ed, 0, 0, first); st != 429 {
		t.Fatal("pending cap not applied")
	}
}

func TestSignerCreateBinding(t *testing.T) {
	v := newVault(t)
	seed := bytes.Repeat([]byte{0x42}, 32)
	id := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	challenge := func(kv ...any) (vaultReviewResp, int) {
		var r vaultReviewResp
		st := v.web("POST", "/api/ui/seal/vault/challenge", with(map[string]any{"action": "signer-create", "id": id, "service_id": v.service, "set_slug": "release-key", "set_title": "Release key", "scheme": "ed25519", "source": "generate"}, kv...), &r)
		return r, st
	}
	for name, kv := range map[string][]any{"unknown scheme": {"scheme", "rsa"}, "bad id": {"id", "EEEE"}, "existing slug": {"set_slug", "staging"}, "bad slug": {"set_slug", "Bad Slug"}, "upload with generate": {"attempt_id", "x"}, "no source": {"source", ""}} {
		want := 400
		if name == "existing slug" {
			want = 409
		}
		if _, st := challenge(kv...); st != want {
			t.Fatalf("%s: %d", name, st)
		}
	}
	if _, st := challenge("service_id", "dddddddddddddddddddddddddddddddd"); st != 404 {
		t.Fatal("unknown service")
	}
	// Wrong key type for the scheme, an encrypted or malformed key: refused without echo.
	for _, key := range []string{"sentinel-not-a-key", hex.EncodeToString(seed) + "ff", "-----BEGIN PRIVATE KEY-----\nsentinel\n-----END PRIVATE KEY-----"} {
		plain, _ := json.Marshal(map[string]string{"private_key": key})
		a, e, c := v.sealUpload("signer-import", id, plain)
		if _, st := challenge("source", "import", "attempt_id", a, "enc", e, "ciphertext", c); st != 400 {
			t.Fatal("bad key accepted")
		}
	}
	if strings.Contains(v.seen.String(), "sentinel") {
		t.Fatal("an error echoed key input")
	}
	// A packet sealed for another new set ID does not open as this one.
	plain, _ := json.Marshal(map[string]string{"private_key": hex.EncodeToString(seed)})
	a, e, c := v.sealUpload("signer-import", "ffffffffffffffffffffffffffffffff", plain)
	if _, st := challenge("source", "import", "attempt_id", a, "enc", e, "ciphertext", c); st != 400 {
		t.Fatal("key packet accepted for another set")
	}
	// An abandoned upload or generated key is dropped on its own timer, with no further vault call.
	v.s.seal.vault.ttl = 50 * time.Millisecond
	v.sealUpload("edit", v.set, plain)
	if _, st := challenge("id", "ffffffffffffffffffffffffffffffff", "set_slug", "abandoned"); st != 200 {
		t.Fatal("generate challenge")
	}
	for i := 0; ; i++ {
		v.s.seal.vault.mu.Lock()
		n := len(v.s.seal.vault.m)
		v.s.seal.vault.mu.Unlock()
		if n == 0 {
			break
		}
		if i > 1000 {
			t.Fatalf("%d pending secrets outlived their timer", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	v.s.seal.vault.ttl = 0
	// Two generate reviews: each has its own key; the one tapped is the one created; the other dies with a conflict.
	one, st := challenge()
	mustStatus(t, "generate", st, 200)
	two, _ := challenge()
	if one.Facts["public_key"] == two.Facts["public_key"] {
		t.Fatal("two reviews share a key")
	}
	var out struct {
		PublicKey string `json:"public_key"`
	}
	mustStatus(t, "create", v.tap(two, &out), 200)
	if out.PublicKey != two.Facts["public_key"] {
		t.Fatal("created a key other than the one shown")
	}
	mustStatus(t, "second create with the same id", v.tap(one, nil), 409)
	// The key row cannot be rewritten in place.
	if _, err := v.s.store.DB().Exec(`UPDATE signer_keys SET scheme='ed25519ph' WHERE set_id=?`, id); err == nil {
		t.Fatal("signer scheme changed in place")
	}
	// A sealed record moved to another set, or relabelled with another scheme, fails authentication.
	f := v.createSigner("ffffffffffffffffffffffffffffffff", "second-key", "ed25519", "")
	requireNoError(t, v.drill())
	_, err := v.s.store.DB().Exec(`UPDATE signer_keys SET payload=(SELECT payload FROM signer_keys WHERE set_id=?) WHERE set_id=?`, id, f.id)
	requireNoError(t, err)
	if v.drill() == nil {
		t.Fatal("a signer record opened under another set's binding")
	}
}

// A previous binary sees a signer set as an empty application set: nothing to
// request or deliver, and nothing for its recovery inventory to check. This
// binary's recovery inventory opens every signer key instead.
func TestSignerRowsAreInertForEnv(t *testing.T) {
	v := newVault(t)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "one"}}}, nil)
	f := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", "")
	var kind string
	var rev, envRows int
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT kind,revision,(SELECT count(*) FROM env_revisions WHERE set_id=s.id) FROM credential_sets s WHERE id=?`, f.id).Scan(&kind, &rev, &envRows))
	if kind != "env-set" || rev != 0 || envRows != 0 {
		t.Fatalf("stored as kind=%s revision=%d env rows=%d", kind, rev, envRows)
	}
	// The v0.3.3 recovery inventory query, verbatim: it must select only real env revisions.
	var n int
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT count(*) FROM credential_sets s JOIN services v ON v.id=s.service_id JOIN organisations o ON o.id=v.org_id LEFT JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision WHERE s.kind='env-set' AND s.revision>0 AND r.names IS NULL`).Scan(&n))
	if n != 0 {
		t.Fatal("a previous binary's recovery inventory would trip over a signer set")
	}
	// v0.3.3 accepts a request only for a set with a revision and names: a signer has neither.
	requireNoError(t, v.s.store.InitVault(t.Context())) // idempotent on restart
	requireNoError(t, v.drill())
	// A damaged signer record fails the drill (the trigger forbids in-place edits, so swap the row).
	_, err := v.s.store.DB().Exec(`DROP TRIGGER signer_key_immutable; UPDATE signer_keys SET public_key=zeroblob(32) WHERE set_id=?`, f.id)
	requireNoError(t, err)
	if v.drill() == nil {
		t.Fatal("drill accepted a signer whose key does not match its public half")
	}
}

// drill opens every scope from its recovery wrap and authenticates every record.
func (v *vaultEnv) drill() error {
	ctx := v.t.Context()
	q := v.s.store.Q()
	scopes, err := q.Scopes(ctx)
	requireNoError(v.t, err)
	for _, x := range scopes {
		k, err := seal.Scope{Installation: v.fix.inst, Name: x.Scope, Public: x.Public}.Recover(v.fix.identity, v.fix.recipient, x.Recovery)
		if err != nil {
			return err
		}
		_, err = v.s.drillScope(ctx, q, x, k)
		k.Destroy()
		if err != nil {
			return err
		}
	}
	return nil
}

// reopenPaused reopens, in one tap, every bucket with paused users.
func (v *vaultEnv) reopenPaused() {
	v.t.Helper()
	var st struct {
		Buckets []struct {
			ID     string
			Paused []struct{ Ref string }
		}
	}
	mustStatus(v.t, "status", v.web("GET", "/api/ui/seal/status", nil, &st), 200)
	var ids []string
	for _, b := range st.Buckets {
		if len(b.Paused) > 0 {
			ids = append(ids, b.ID)
		}
	}
	slices.Sort(ids)
	mustStatus(v.t, "reopen", v.control(map[string]any{"action": "reopen", "buckets": ids}, nil), 200)
}

// control runs one seal-control ceremony with the owner's passkey.
func (v *vaultEnv) control(choice map[string]any, out any) int {
	v.t.Helper()
	var r tapResp
	if st := v.web("POST", "/api/ui/seal/control/challenge", choice, &r); st != 200 {
		return st
	}
	as, pkt := v.fix.tapWith(v.t, v.s, v.auth, r)
	return v.web("POST", "/api/ui/seal/control/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, out)
}
