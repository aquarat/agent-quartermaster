//go:build linux

package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

const propPath = "client-a/paas/staging"

func hex32(t *testing.T) string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	requireNoError(t, err)
	return hex.EncodeToString(b)
}

// proposeRaw plays the CLI: resolve the binding (for create, the base of the
// new set and fresh IDs), compute the commitment, post. mutate may spoil the
// request first.
func (v *vaultEnv) proposeRaw(c *http.Client, path, op string, entries []envset.Entry, create bool, mutate func(*envset.ProposalRequest)) (envset.Proposal, int, string) {
	v.t.Helper()
	var b envset.Binding
	q := "/v2/env/set?path=" + url.QueryEscape(path)
	if create {
		q += "&create=1"
	}
	mustStatus(v.t, "binding", v.host(c, "GET", q, nil, &b), 200)
	in := envset.ProposalRequest{Path: path, Reason: "rotate the staging values", Edit: envset.Edit{Op: op, Salt: make([]byte, 32), Entries: entries}}
	_, err := rand.Read(in.Edit.Salt)
	requireNoError(v.t, err)
	if create && b.Set == "" {
		in.Create = &envset.ProposalCreate{SetID: hex32(v.t)}
		if b.Service == "" {
			in.Create.ServiceID = hex32(v.t)
			b.Service = in.Create.ServiceID
		}
		b.Set = in.Create.SetID
	}
	in.Commitment, err = in.Edit.Commit(b)
	requireNoError(v.t, err)
	if mutate != nil {
		mutate(&in)
	}
	raw, _ := json.Marshal(in)
	resp, err := c.Post(v.env.agent.URL+"/v2/env/proposals", "application/json", bytes.NewReader(raw))
	requireNoError(v.t, err)
	defer resp.Body.Close()
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	v.seen.Write(body.Bytes())
	var p envset.Proposal
	if resp.StatusCode == 200 {
		requireNoError(v.t, json.Unmarshal(body.Bytes(), &p))
		if p.Status != "pending" || p.Commitment != in.Commitment || p.Reason != in.Reason || p.Ref != ref(p.ID) || len(p.Ref) != 6 || p.Expires-p.Created != ProposalTTL.Milliseconds() || p.Names == nil {
			v.t.Fatalf("proposal as created: %+v", p)
		}
	}
	return p, resp.StatusCode, body.String()
}
func (v *vaultEnv) propose(c *http.Client, path, op string, entries []envset.Entry, create bool) envset.Proposal {
	v.t.Helper()
	p, st, body := v.proposeRaw(c, path, op, entries, create, nil)
	if st != 200 {
		v.t.Fatalf("propose %s %s: %d %s", op, path, st, body)
	}
	return p
}
func (v *vaultEnv) proposal(c *http.Client, id string) (envset.Proposal, int) {
	v.t.Helper()
	var p envset.Proposal
	st := v.host(c, "GET", "/v2/env/proposals/"+id, nil, &p)
	return p, st
}
func (v *vaultEnv) proposalStatus(id string) string {
	v.t.Helper()
	p, st := v.proposal(v.agent, id)
	mustStatus(v.t, "proposal", st, 200)
	return p.Status
}
func (v *vaultEnv) ownerProposals() []envset.Proposal {
	v.t.Helper()
	var s struct {
		Proposals []envset.Proposal `json:"proposals"`
	}
	mustStatus(v.t, "env state", v.web("GET", "/api/ui/seal/env/state", nil, &s), 200)
	if s.Proposals == nil {
		v.t.Fatal("env state has no proposals list")
	}
	return s.Proposals
}
func (v *vaultEnv) decideProposal(id, action string) int {
	v.t.Helper()
	_, st := v.envDecide(map[string]any{"id": id, "action": "proposal-" + action, "ttl_seconds": 0})
	return st
}

// nothingKept: an ended proposal holds no sealed record and no bucket material.
func (v *vaultEnv) nothingKept() {
	v.t.Helper()
	if n := v.count(`SELECT count(*) FROM env_proposals WHERE status!='pending' AND (payload IS NOT NULL OR bucket IS NOT NULL)`); n != 0 {
		v.t.Fatalf("%d ended proposals still hold sealed records", n)
	}
}
func (v *vaultEnv) valuesOf(c *http.Client, path string) []envset.Entry {
	v.t.Helper()
	rel, st := v.ask(c, path, "process")
	mustStatus(v.t, "release", st, 200)
	out, _ := v.deliver(c, rel)
	return out.Entries
}

var proposalKeys = []string{"path", "title", "org", "service", "set", "revision", "service_revision", "policy_revision", "admission_generation", "enrollment", "host", "class", "names", "default_seconds", "soft_cap_seconds", "offers_indefinite",
	"id", "ref", "operation", "commitment", "changes", "reason", "address", "new_service", "new_set", "status", "created_at", "expires_at", "result_revision"}

func TestEnvProposalCommit(t *testing.T) {
	v := newVault(t)
	secret := []byte("sentinel-proposal-value-7f3a9c")
	p := v.propose(v.agent, propPath, "import", []envset.Entry{{Name: "APP_TOKEN", Value: string(secret)}, {Name: "APP_URL", Value: "https://example.com/a b"}}, false)
	if p.Changes != "APP_TOKEN:add,APP_URL:add" || p.Operation != "import" || p.NewSet || p.NewService || p.Revision != 0 || p.Set != vSet || p.Host != "workload" || p.Peer != "127.0.0.1" || p.Result != 0 {
		t.Fatalf("proposal: %+v", p)
	}
	// The set had no bucket and gets none until the owner commits.
	if n := v.count(`SELECT count(*) FROM buckets WHERE ref=?`, vSet); n != 0 {
		t.Fatal("a proposal created the set's bucket")
	}
	if !v.audited("env_proposal", propPath+" operation=import") {
		t.Fatal("proposal not audited")
	}
	// Only the proposing host sees it.
	if _, st := v.proposal(v.other, p.ID); st != 404 {
		t.Fatalf("another host read the proposal: %d", st)
	}
	mustStatus(t, "another host cancels", v.host(v.other, "POST", "/v2/env/proposals/"+p.ID+"/cancel", map[string]any{}, nil), 404)
	list := v.ownerProposals()
	if len(list) != 1 || list[0].ID != p.ID || list[0].Reason != p.Reason {
		t.Fatalf("owner state: %+v", list)
	}
	// A commit or discard with a duration, or an unknown proposal, is refused.
	if st := v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": p.ID, "action": "proposal-commit", "ttl_seconds": 300}, nil); st != 400 {
		t.Fatalf("commit with a duration: %d", st)
	}
	if st := v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": "nope", "action": "proposal-commit", "ttl_seconds": 0}, nil); st != 404 {
		t.Fatalf("unknown proposal: %d", st)
	}
	// What the owner signs: the whole proposal, the 29 keys in the documented
	// order, the host's reason blank, nothing else.
	canonical, st := v.envDecide(map[string]any{"id": p.ID, "action": "proposal-commit", "ttl_seconds": 0})
	mustStatus(t, "commit", st, 200)
	var c struct {
		Object, Action, ID, Metadata string
		TTL                          *int `json:"ttl_seconds"`
	}
	requireNoError(t, json.Unmarshal([]byte(canonical), &c))
	signed := p
	signed.Reason = ""
	want, _ := reviewJSON(signed)
	if c.Object != "env" || c.Action != "proposal-commit" || c.ID != p.ID || c.TTL == nil || *c.TTL != 0 || c.Metadata != want || strings.Contains(canonical, "standing_seconds") {
		t.Fatalf("signed text:\n%s\nwant metadata %s", canonical, want)
	}
	var keys []string
	for _, m := range regexp.MustCompile(`"([a-z_]+)":`).FindAllStringSubmatch(c.Metadata, -1) {
		keys = append(keys, m[1])
	}
	if !slices.Equal(keys, proposalKeys) || !strings.Contains(c.Metadata, `"names":[]`) || !strings.Contains(c.Metadata, `"reason":""`) {
		t.Fatalf("signed keys: %v\n%s", keys, c.Metadata)
	}
	// Proposed, listed, reviewed, committed: the value is in no response, log,
	// audit row or database page (the host has not collected anything yet).
	if where := v.leaked(secret); where != "" {
		t.Fatalf("value leaked into %s", where)
	}
	got, st := v.proposal(v.agent, p.ID)
	if st != 200 || got.Status != "committed" || got.Result != 1 || v.revision() != 1 {
		t.Fatalf("after commit: %+v revision %d", got, v.revision())
	}
	if !v.audited("env_proposal_commit", `\"set\":\"`+vSet+`\"`) || !v.audited("env_proposal_commit", "passkey=") {
		t.Fatal("commit not audited with passkey and canonical")
	}
	if len(v.ownerProposals()) != 0 {
		t.Fatal("a committed proposal is still listed")
	}
	// A second decision on it is refused.
	if st := v.decideProposal(p.ID, "discard"); st != 409 {
		t.Fatalf("discard after commit: %d", st)
	}
	entries := v.valuesOf(v.agent, propPath)
	if len(entries) != 2 || entries[0].Value != string(secret) || entries[1].Value != "https://example.com/a b" {
		t.Fatalf("collected: %d entries", len(entries))
	}
	// put replaces one key, unset removes one; an import replaces the set.
	p = v.propose(v.other, propPath, "put", []envset.Entry{{Name: "APP_URL", Value: "https://example.com/b"}}, false)
	if p.Changes != "APP_URL:replace" || p.Revision != 1 || p.Host != "other" {
		t.Fatalf("put: %+v", p)
	}
	mustStatus(t, "commit put", v.decideProposal(p.ID, "commit"), 200)
	p = v.propose(v.agent, propPath, "unset", []envset.Entry{{Name: "APP_TOKEN"}}, false)
	mustStatus(t, "commit unset", v.decideProposal(p.ID, "commit"), 200)
	entries = v.valuesOf(v.agent, propPath)
	if len(entries) != 1 || entries[0].Name != "APP_URL" || entries[0].Value != "https://example.com/b" || v.revision() != 3 {
		t.Fatalf("after put and unset: %v revision %d", envset.Names(entries), v.revision())
	}
	p = v.propose(v.agent, propPath, "import", []envset.Entry{{Name: "APP_ID", Value: "x"}}, false)
	if p.Changes != "APP_ID:add,APP_URL:remove" {
		t.Fatalf("import changes: %s", p.Changes)
	}
	mustStatus(t, "commit import", v.decideProposal(p.ID, "commit"), 200)
	v.nothingKept()
	// The value was never stored or logged in the clear. (Collection returned
	// it to the host, so the recorded responses are not scanned here.)
	v.seen.Reset()
	if where := v.leaked(secret); where != "" {
		t.Fatalf("value leaked into %s", where)
	}
}

func TestEnvProposalRefusals(t *testing.T) {
	v := newVault(t)
	one := []envset.Entry{{Name: "APP_TOKEN", Value: "v"}}
	for name, c := range map[string]struct {
		op      string
		entries []envset.Entry
		create  bool
		mutate  func(*envset.ProposalRequest)
		want    int
	}{
		"wrong commitment":      {"import", one, false, func(r *envset.ProposalRequest) { r.Commitment = strings.Repeat("0", 64) }, 400},
		"commitment of another": {"import", one, false, func(r *envset.ProposalRequest) { r.Edit.Entries[0].Value = "w" }, 400},
		"no reason":             {"import", one, false, func(r *envset.ProposalRequest) { r.Reason = " " }, 400},
		"two-line reason":       {"import", one, false, func(r *envset.ProposalRequest) { r.Reason = "a\nb" }, 400},
		"long reason":           {"import", one, false, func(r *envset.ProposalRequest) { r.Reason = strings.Repeat("x", 501) }, 400},
		"merge":                 {"import", one, false, func(r *envset.ProposalRequest) { r.Edit.Op = "merge" }, 400},
		"unsafe name":           {"import", one, false, func(r *envset.ProposalRequest) { r.Edit.Entries[0].Name = "LD_PRELOAD" }, 400},
		"unset a missing key":   {"unset", []envset.Entry{{Name: "APP_TOKEN"}}, false, nil, 400},
		"empty import":          {"import", nil, false, nil, 400},
		"unknown path":          {"import", one, false, func(r *envset.ProposalRequest) { r.Path = "client-a/paas/nope" }, 404},
		"unknown organisation":  {"import", one, false, func(r *envset.ProposalRequest) { r.Path = "client-z/paas/staging" }, 404},
		"bad path":              {"import", one, false, func(r *envset.ProposalRequest) { r.Path = "client-a/paas" }, 400},
		"create on a set":       {"import", one, false, func(r *envset.ProposalRequest) { r.Create = &envset.ProposalCreate{SetID: strings.Repeat("d", 32)} }, 409},
		"create by unset": {"put", one, true, func(r *envset.ProposalRequest) {
			r.Path, r.Edit.Op, r.Create = "client-a/paas/new", "unset", &envset.ProposalCreate{SetID: strings.Repeat("d", 32)}
		}, 400},
	} {
		if _, st, body := v.proposeRaw(v.agent, propPath, c.op, slices.Clone(c.entries), c.create, c.mutate); st != c.want {
			t.Errorf("%s: %d %s", name, st, body)
		}
	}
	// A secret is replaced in the Vault.
	v.createSecret(strings.Repeat("e", 32), "api-key", "API key", "APP_KEY", "secret-value", "", "")
	if _, st, body := v.proposeRaw(v.agent, "client-a/paas/api-key", "put", []envset.Entry{{Name: "APP_KEY", Value: "x"}}, false, nil); st != 400 || !strings.Contains(body, "a secret is replaced in the Vault") {
		t.Fatalf("secret: %d %s", st, body)
	}
	// A host that is not admitted to the organisation sees nothing of it.
	_, err := v.s.store.DB().Exec(`UPDATE org_hosts SET active=0,generation=generation+1 WHERE host_id=(SELECT id FROM hosts WHERE name='other')`)
	requireNoError(t, err)
	if st, _ := v.rawGet(v.other, "/v2/env/set?create=1&path=client-a/paas/new"); st != 404 {
		t.Fatalf("base for an unadmitted host: %d", st)
	}
	if n := v.count(`SELECT count(*) FROM env_proposals`); n != 0 {
		t.Fatalf("%d refused proposals stored", n)
	}
}

func TestEnvProposalDiscardCancelExpire(t *testing.T) {
	v := newVault(t)
	secret := []byte("sentinel-never-committed-91b2")
	entries := func() []envset.Entry { return []envset.Entry{{Name: "APP_TOKEN", Value: string(secret)}} }
	gone := func(what string) {
		t.Helper()
		v.nothingKept()
		if n := v.count(`SELECT count(*) FROM buckets WHERE kind='env-set'`) + v.count(`SELECT count(*) FROM env_revisions`); n != 0 || v.revision() != 0 {
			t.Fatalf("%s left a bucket or a revision behind", what)
		}
		if where := v.leaked(secret); where != "" {
			t.Fatalf("%s: value in %s", what, where)
		}
	}
	// Discard, while the host is waiting in a long poll.
	p := v.propose(v.agent, propPath, "import", entries(), false)
	done := make(chan envset.Proposal, 1)
	go func() {
		var got envset.Proposal
		v.host(v.agent, "GET", "/v2/env/proposals/"+p.ID+"?wait=25", nil, &got)
		done <- got
	}()
	mustStatus(t, "discard", v.decideProposal(p.ID, "discard"), 200)
	select {
	case got := <-done:
		if got.Status != "discarded" || got.Result != 0 {
			t.Fatalf("long poll: %+v", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the long poll did not return after the decision")
	}
	if !v.audited("env_proposal_discard", "passkey=") {
		t.Fatal("discard not audited")
	}
	if st := v.decideProposal(p.ID, "commit"); st != 409 {
		t.Fatalf("commit after discard: %d", st)
	}
	gone("discard")
	// Cancel, by the host; only once.
	p = v.propose(v.agent, propPath, "import", entries(), false)
	var got envset.Proposal
	mustStatus(t, "cancel", v.host(v.agent, "POST", "/v2/env/proposals/"+p.ID+"/cancel", map[string]any{}, &got), 200)
	if got.Status != "cancelled" || v.proposalStatus(p.ID) != "cancelled" || !v.audited("env_proposal_cancel", propPath) {
		t.Fatalf("cancel: %+v", got)
	}
	mustStatus(t, "cancel again", v.host(v.agent, "POST", "/v2/env/proposals/"+p.ID+"/cancel", map[string]any{}, nil), 409)
	if st := v.decideProposal(p.ID, "commit"); st != 409 {
		t.Fatalf("commit after cancel: %d", st)
	}
	gone("cancel")
	// Expire: ten minutes without a decision. A challenge made before the
	// deadline cannot be finished after it.
	p = v.propose(v.agent, propPath, "import", entries(), false)
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": p.ID, "action": "proposal-commit", "ttl_seconds": 0}, &r), 200)
	v.clock.Advance(ProposalTTL - time.Second)
	if v.proposalStatus(p.ID) != "pending" {
		t.Fatal("expired early")
	}
	v.clock.Advance(2 * time.Second)
	v.login()
	if v.proposalStatus(p.ID) != "expired" || len(v.ownerProposals()) != 0 || !v.audited("env_proposal_expire", propPath+" host=workload") {
		t.Fatal("not expired after ten minutes")
	}
	if st := v.decideProposal(p.ID, "commit"); st != 409 {
		t.Fatalf("commit after expiry: %d", st)
	}
	gone("expiry")
	// Ended proposals are forgotten a day later.
	v.clock.Advance(25 * time.Hour)
	requireNoError(t, v.s.store.Tx(t.Context(), func(q *store.Q) error { return q.SweepEnv(t.Context(), v.s.now()) }))
	if n := v.count(`SELECT count(*) FROM env_proposals`); n != 0 {
		t.Fatalf("%d old proposals kept", n)
	}
}

func TestEnvProposalSuperseded(t *testing.T) {
	v := newVault(t)
	entries := func() []envset.Entry { return []envset.Entry{{Name: "APP_TOKEN", Value: "proposed"}} }
	superseded := func(what string, c *http.Client, p envset.Proposal) {
		t.Helper()
		if got, st := v.proposal(c, p.ID); st != 200 || got.Status != "superseded" || got.Result != 0 {
			t.Fatalf("%s: proposal is %d %s", what, st, got.Status)
		}
		if st := v.decideProposal(p.ID, "commit"); st != 409 {
			t.Fatalf("%s: commit of a superseded proposal: %d", what, st)
		}
		v.nothingKept()
	}
	// The set's revision changes (the owner saves the Vault form).
	p := v.propose(v.agent, propPath, "import", entries(), false)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_ID", Value: "form"}}}, nil)
	superseded("revision", v.agent, p)
	// Committing one proposal supersedes the others of the set.
	a := v.propose(v.agent, propPath, "put", entries(), false)
	b := v.propose(v.other, propPath, "put", []envset.Entry{{Name: "APP_TOKEN", Value: "other"}}, false)
	mustStatus(t, "commit", v.decideProposal(a.ID, "commit"), 200)
	superseded("another commit", v.other, b)
	p = v.propose(v.agent, propPath, "put", entries(), false)
	keep := v.propose(v.other, propPath, "put", entries(), false)
	// The host's admission changes (removed here, then admitted again).
	_, err := v.s.store.DB().Exec(`UPDATE org_hosts SET active=0,generation=generation+1 WHERE host_id=(SELECT id FROM hosts WHERE name='workload')`)
	requireNoError(t, err)
	superseded("admission", v.agent, p)
	_, err = v.s.store.DB().Exec(`UPDATE org_hosts SET active=1,generation=generation+1 WHERE host_id=(SELECT id FROM hosts WHERE name='workload')`)
	requireNoError(t, err)
	if _, st := v.proposal(v.other, keep.ID); st != 200 {
		t.Fatal("another host's proposal ended with this host's admission")
	}
	// The organisation's policy is replaced.
	mustStatus(t, "policy", v.setPolicy("client-a", func(p *api.DurationPolicy) { p.Default = 1800 }), 200)
	p2, st := v.proposal(v.other, keep.ID)
	if st != 200 || p2.Status != "superseded" {
		t.Fatalf("policy: %d %+v", st, p2)
	}
	v.nothingKept()
	if entries := v.valuesOf(v.agent, propPath); len(entries) != 2 || entries[1].Value != "proposed" {
		t.Fatalf("the set is not what the one commit made it: %v", envset.Names(entries))
	}
	// A change between the owner's review and the tap: the finish is refused.
	p = v.propose(v.agent, propPath, "put", entries(), false)
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": p.ID, "action": "proposal-commit", "ttl_seconds": 0}, &r), 200)
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_URL", Value: "https://example.com"}}}, []string{"APP_ID", "APP_TOKEN"})
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	if st := v.web("POST", "/api/ui/seal/env/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, nil); st != 409 {
		t.Fatalf("finish after the revision changed: %d", st)
	}
	// A scope rekey ends what was sealed under the old keys.
	p = v.propose(v.agent, propPath, "put", entries(), false)
	mustStatus(t, "rekey", v.control(map[string]any{"action": "rekey", "scope": v.org}, nil), 200)
	superseded("rekey", v.agent, p)
}

func TestEnvProposalCreate(t *testing.T) {
	v := newVault(t)
	secret := []byte("sentinel-new-set-value-55aa")
	entries := func() []envset.Entry { return []envset.Entry{{Name: "APP_TOKEN", Value: string(secret)}} }
	rows := func() int {
		return v.count(`SELECT count(*) FROM services`) + v.count(`SELECT count(*) FROM credential_sets`) + v.count(`SELECT count(*) FROM buckets`)
	}
	before := rows()
	// Without create a missing path is not found, whatever is missing.
	if _, st, _ := v.proposeRaw(v.agent, propPath, "import", entries(), false, func(r *envset.ProposalRequest) { r.Path = "client-a/paas/prod" }); st != 404 {
		t.Fatalf("missing set without create: %d", st)
	}
	// The base of a new set: the organisation's and service's IDs, no set.
	var base envset.Binding
	mustStatus(t, "base", v.host(v.agent, "GET", "/v2/env/set?create=1&path=client-a/paas/prod", nil, &base), 200)
	if base.Org != vOrg || base.Service != vService || base.Set != "" || base.Revision != 0 || base.Names == nil || len(base.Names) != 0 || base.Host != "workload" {
		t.Fatalf("base: %+v", base)
	}
	mustStatus(t, "base of a new service", v.host(v.agent, "GET", "/v2/env/set?create=1&path=client-a/billing/prod", nil, &base), 200)
	if base.Service != "" || base.ServiceRevision != 0 {
		t.Fatalf("base of a new service: %+v", base)
	}
	// With create=1 an existing set answers as without.
	mustStatus(t, "base of an existing set", v.host(v.agent, "GET", "/v2/env/set?create=1&path="+propPath, nil, &base), 200)
	if base.Set != vSet {
		t.Fatalf("existing set: %+v", base)
	}
	// Bad IDs, titles and names.
	for name, mutate := range map[string]func(*envset.ProposalRequest){
		"set id":             func(r *envset.ProposalRequest) { r.Create.SetID = "XYZ" },
		"title":              func(r *envset.ProposalRequest) { r.Create.Title = " padded" },
		"markup title":       func(r *envset.ProposalRequest) { r.Create.Title = "<b>prod</b>" },
		"no create":          func(r *envset.ProposalRequest) { r.Create = nil },
		"service id present": func(r *envset.ProposalRequest) { r.Create.ServiceID = strings.Repeat("9", 32) },
		"taken set id":       func(r *envset.ProposalRequest) { r.Create.SetID = vSet },
	} {
		_, st, body := v.proposeRaw(v.agent, "client-a/paas/prod", "import", entries(), true, mutate)
		want := 400
		if name == "no create" {
			want = 404
		} else if name == "service id present" || name == "taken set id" {
			want = 409
		}
		if st != want {
			t.Errorf("%s: %d %s", name, st, body)
		}
	}
	if _, st, body := v.proposeRaw(v.agent, "client-a/billing/prod", "import", entries(), true, func(r *envset.ProposalRequest) { r.Create.ServiceID = "" }); st != 400 {
		t.Errorf("new service without an ID: %d %s", st, body)
	}
	if _, st, body := v.proposeRaw(v.agent, "client-a/billing/prod", "import", entries(), true, func(r *envset.ProposalRequest) { r.Create.ServiceID = vService }); st != 409 {
		t.Errorf("taken service ID: %d %s", st, body)
	}
	// A new organisation is never proposed.
	if st, _ := v.rawGet(v.agent, "/v2/env/set?create=1&path=client-new/paas/prod"); st != 404 {
		t.Fatalf("base in an unknown organisation: %d", st)
	}
	// A new set in an existing service: discarded, nothing stays.
	p := v.propose(v.agent, "client-a/paas/prod", "import", entries(), true)
	if !p.NewSet || p.NewService || p.Service != vService || p.Revision != 0 || len(p.Names) != 0 || p.Title != "Client A / PaaS / prod" || p.Changes != "APP_TOKEN:add" {
		t.Fatalf("new set: %+v", p)
	}
	mustStatus(t, "discard", v.decideProposal(p.ID, "discard"), 200)
	v.nothingKept()
	if rows() != before {
		t.Fatal("a discarded proposal left a service, set or bucket")
	}
	if where := v.leaked(secret); where != "" {
		t.Fatalf("discarded value in %s", where)
	}
	// Two hosts propose the same new path: the first commit creates it, the
	// other is superseded.
	p = v.propose(v.agent, "client-a/paas/prod", "import", entries(), true)
	var titled envset.Proposal
	if x, st, body := v.proposeRaw(v.other, "client-a/paas/prod", "put", entries(), true, func(r *envset.ProposalRequest) { r.Create.Title = "Production env" }); st != 200 || x.Title != "Client A / PaaS / Production env" {
		t.Fatalf("titled: %d %s", st, body)
	} else {
		titled = x
	}
	mustStatus(t, "commit", v.decideProposal(p.ID, "commit"), 200)
	got, _ := v.proposal(v.agent, p.ID)
	if got.Status != "committed" || got.Result != 1 {
		t.Fatalf("committed: %+v", got)
	}
	if n := v.count(`SELECT count(*) FROM credential_sets WHERE id=? AND service_id=? AND slug='prod' AND title='prod' AND kind='env-set' AND revision=1 AND NOT archived`, p.Set, vService); n != 1 {
		t.Fatal("the set was not created as proposed")
	}
	if n := v.count(`SELECT count(*) FROM buckets WHERE kind='env-set' AND ref=? AND scope=?`, p.Set, vOrg); n != 1 {
		t.Fatal("the set has no bucket in its organisation's scope")
	}
	if x, st := v.proposal(v.other, titled.ID); st != 200 || x.Status != "superseded" {
		t.Fatalf("the second proposal for the path: %d %+v", st, x)
	}
	if st := v.decideProposal(titled.ID, "commit"); st != 409 {
		t.Fatalf("commit of the superseded create: %d", st)
	}
	if entries := v.valuesOf(v.other, "client-a/paas/prod"); len(entries) != 1 || entries[0].Value != string(secret) {
		t.Fatal("the new set does not deliver the proposed value")
	}
	// Now the path exists: create is refused, a plain proposal is fine.
	if _, st, _ := v.proposeRaw(v.agent, "client-a/paas/prod", "import", entries(), false, func(r *envset.ProposalRequest) { r.Create = &envset.ProposalCreate{SetID: strings.Repeat("d", 32)} }); st != 409 {
		t.Fatalf("create of an existing path: %d", st)
	}
	// A new service and set, with a title for the set; the service takes its slug.
	p, st, body := v.proposeRaw(v.agent, "client-a/billing/live", "put", entries(), true, func(r *envset.ProposalRequest) { r.Create.Title = "Live env" })
	if st != 200 || !p.NewService || !p.NewSet || p.ServiceRevision != 0 || p.Title != "Client A / billing / Live env" {
		t.Fatalf("new service: %d %s", st, body)
	}
	if n := v.count(`SELECT count(*) FROM services WHERE slug='billing'`); n != 0 {
		t.Fatal("the service exists before the commit")
	}
	// The path is taken between the proposal and the tap: superseded.
	late := v.propose(v.other, "client-a/billing/live", "put", entries(), true)
	mustStatus(t, "commit", v.decideProposal(p.ID, "commit"), 200)
	if n := v.count(`SELECT count(*) FROM services WHERE id=? AND org_id=? AND slug='billing' AND title='billing' AND provider='application' AND revision=1`, p.Service, vOrg); n != 1 {
		t.Fatal("the service was not created as proposed")
	}
	if n := v.count(`SELECT count(*) FROM credential_sets WHERE id=? AND service_id=? AND slug='live' AND title='Live env' AND revision=1`, p.Set, p.Service); n != 1 {
		t.Fatal("the set of the new service was not created as proposed")
	}
	if x, _ := v.proposal(v.other, late.ID); x.Status != "superseded" {
		t.Fatalf("late create: %+v", x)
	}
	if entries := v.valuesOf(v.agent, "client-a/billing/live"); len(entries) != 1 || entries[0].Value != string(secret) {
		t.Fatal("the new service's set does not deliver the proposed value")
	}
	v.nothingKept()
	if !v.audited("env_proposal", "client-a/billing/live operation=put set="+p.Set+" new_service=true new_set=true") {
		t.Fatal("create not audited")
	}
	// An organisation without a scope key cannot take a first write.
	for _, q := range []string{
		`INSERT INTO organisations(id,slug,title,revision) VALUES('` + strings.Repeat("7", 32) + `','client-b','Client B',1)`,
		`INSERT INTO org_policies VALUES('` + strings.Repeat("7", 32) + `',1,3600,86400,1,3600,86400,1)`,
		`INSERT INTO org_hosts SELECT '` + strings.Repeat("7", 32) + `',id,1,1 FROM hosts`,
	} {
		_, err := v.s.store.DB().Exec(q)
		requireNoError(t, err)
	}
	if _, st, body := v.proposeRaw(v.agent, "client-b/app/prod", "import", entries(), true, nil); st != 409 || !strings.Contains(body, "no scope key") {
		t.Fatalf("organisation without a scope: %d %s", st, body)
	}
}

func TestEnvProposalLimitsAndIndividualTap(t *testing.T) {
	v := newVault(t)
	var ps []envset.Proposal
	for i := 0; i < MaxPendingPerHost; i++ {
		ps = append(ps, v.propose(v.agent, propPath, "import", []envset.Entry{{Name: "APP_TOKEN", Value: "v"}}, false))
	}
	if _, st, body := v.proposeRaw(v.agent, propPath, "import", []envset.Entry{{Name: "APP_TOKEN", Value: "v"}}, false, nil); st != 429 || !strings.Contains(body, "rate_limited") {
		t.Fatalf("sixth proposal: %d %s", st, body)
	}
	// Another host has its own count.
	other := v.propose(v.other, propPath, "import", []envset.Entry{{Name: "APP_TOKEN", Value: "v"}}, false)
	mustStatus(t, "cancel", v.host(v.other, "POST", "/v2/env/proposals/"+other.ID+"/cancel", map[string]any{}, nil), 200)
	// Proposals count with the host's other pending requests.
	mustStatus(t, "commit", v.decideProposal(ps[0].ID, "commit"), 200) // supersedes the other four
	for _, p := range ps[1:] {
		if got := v.proposalStatus(p.ID); got != "superseded" {
			t.Fatalf("proposal %s is %s", p.Ref, got)
		}
	}
	for i := 0; i < MaxPendingPerHost-1; i++ {
		if _, st := v.ask(v.agent, propPath, "process"); st != 200 {
			t.Fatalf("release %d: %d", i, st)
		}
	}
	p := v.propose(v.agent, propPath, "put", []envset.Entry{{Name: "APP_URL", Value: "u"}}, false)
	if _, st := v.ask(v.agent, propPath, "process"); st != 429 {
		t.Fatalf("a release beyond the limit, with a proposal pending: %d", st)
	}
	// No batch and no approval window decides a proposal: both go through the
	// ordinary-request path, which knows only /v1 requests.
	for _, action := range []string{"approve", "deny"} {
		ttl := 0
		if action == "approve" {
			ttl = 300
		}
		if st := v.web("POST", "/api/ui/seal/batch/challenge", map[string]any{"items": []ordinaryChoice{{p.ID, action, ttl}}}, nil); st/100 == 2 {
			t.Fatalf("a batch took a proposal (%s)", action)
		}
		if st := v.web("POST", "/api/ui/seal/windows/prepare", map[string]any{"id": p.ID, "action": action, "ttl_seconds": ttl}, nil); st/100 == 2 {
			t.Fatalf("a window took a proposal (%s)", action)
		}
		sess := mustSessionHash(v.env)
		err := v.s.store.Tx(t.Context(), func(q *store.Q) error {
			pk, err := q.SessionPasskeyID(t.Context(), sess)
			if err != nil {
				return err
			}
			_, err = v.s.ordinary(t.Context(), q, sess, pk, ordinaryChoice{p.ID, action, ttl})
			return err
		})
		if err == nil {
			t.Fatalf("the batch and window path accepted a proposal (%s)", action)
		}
	}
	// The env actions for releases do not reach it either.
	for _, action := range []string{"approve", "deny", "revoke", "commit", "discard", "standing-revoke"} {
		if st := v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": p.ID, "action": action, "ttl_seconds": 0}, nil); st/100 == 2 {
			t.Fatalf("env action %s took a proposal", action)
		}
	}
	// "Don't ask again" does not ride a proposal decision.
	if st := v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": p.ID, "action": "proposal-commit", "ttl_seconds": 0, "standing_seconds": 3600}, nil); st != 400 {
		t.Fatalf("standing on a proposal: %d", st)
	}
	// One challenge, one decision: the tap cannot be replayed.
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": p.ID, "action": "proposal-commit", "ttl_seconds": 0}, &r), 200)
	if r.Open != nil {
		t.Fatal("committing a proposal offered to open a bucket")
	}
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	finish := map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}
	mustStatus(t, "finish", v.web("POST", "/api/ui/seal/env/finish", finish, nil), 200)
	if st := v.web("POST", "/api/ui/seal/env/finish", finish, nil); st/100 == 2 {
		t.Fatal("a proposal tap was replayed")
	}
	if got := v.proposalStatus(p.ID); got != "committed" {
		t.Fatalf("proposal is %s", got)
	}
	if len(openBuckets(t, v.s)) != 0 {
		t.Fatal("a proposal commit left a bucket open")
	}
}

// What ends a host ends what it proposed; what would not commit is refused
// before the owner's tap, and what would not fit is refused when proposed.
func TestEnvProposalReviewFixes(t *testing.T) {
	v := newVault(t)
	// An empty value is not stored by a proposal.
	if _, st, body := v.proposeRaw(v.agent, propPath, "put", []envset.Entry{{Name: "APP_TOKEN", Value: ""}}, false, nil); st != 400 || !strings.Contains(body, "the value is empty") {
		t.Fatalf("empty put: %d %s", st, body)
	}
	// A pending proposal past its time reads as expired at once, without a sweep.
	p := v.propose(v.agent, propPath, "put", []envset.Entry{{Name: "APP_TOKEN", Value: "v"}}, false)
	v.clock.Advance(ProposalTTL + time.Second)
	if got, st := v.proposal(v.agent, p.ID); st != 200 || got.Status != "expired" {
		t.Fatalf("read after expiry: %d %s", st, got.Status)
	}
	if n := v.count(`SELECT count(*) FROM env_proposals WHERE id=? AND status='pending'`, p.ID); n != 1 {
		t.Fatal("a poll wrote to the store")
	}
	v.login()
	// The set got its key while a proposal carried one for it: no commit challenge.
	p = v.propose(v.agent, propPath, "put", []envset.Entry{{Name: "APP_TOKEN", Value: "v"}}, false)
	requireNoError(t, v.s.store.Tx(t.Context(), func(q *store.Q) error {
		_, err := v.s.ensureSetBucket(t.Context(), q, "env-set", vSet, vOrg)
		return err
	}))
	var body struct{ Message string }
	challenge := func(id string) (int, string) {
		t.Helper()
		before := v.seen.Len()
		st := v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": id, "action": "proposal-commit", "ttl_seconds": 0}, nil)
		_ = json.Unmarshal(v.seen.Bytes()[before:], &body)
		return st, body.Message
	}
	if st, msg := challenge(p.ID); st != 409 || !strings.Contains(msg, "got its key") {
		t.Fatalf("commit challenge after the set got a bucket: %d %s", st, msg)
	}
	mustStatus(t, "discard still works", v.decideProposal(p.ID, "discard"), 200)
	// The merged result must fit an env set: a put onto a full set is refused when proposed.
	full := make([]envset.Entry, 64)
	for i := range full {
		full[i] = envset.Entry{Name: "APP_K" + string(rune('A'+i/26)) + string(rune('A'+i%26)), Value: "v"}
	}
	p = v.propose(v.agent, propPath, "import", full, false)
	// ... and a second proposal made before the first was committed is refused at review.
	extra := v.propose(v.other, propPath, "put", []envset.Entry{{Name: "APP_EXTRA", Value: "v"}}, false)
	mustStatus(t, "commit the full set", v.decideProposal(p.ID, "commit"), 200)
	if got, _ := v.proposal(v.other, extra.ID); got.Status != "superseded" {
		t.Fatalf("the other proposal: %s", got.Status)
	}
	if _, st, body := v.proposeRaw(v.agent, propPath, "put", []envset.Entry{{Name: "APP_EXTRA", Value: "v"}}, false, nil); st != 400 || !strings.Contains(body, "too many keys") {
		t.Fatalf("put onto a full set: %d %s", st, body)
	}
	big := strings.Repeat("x", 8000)
	if _, st, body := v.proposeRaw(v.agent, propPath, "put", []envset.Entry{{Name: "APP_KAA", Value: big}}, false, nil); st != 200 {
		t.Fatalf("a large value that fits: %d %s", st, body)
	}
	// Revoking a host ends its pending proposals and erases what they sealed.
	p = v.propose(v.other, propPath, "put", []envset.Entry{{Name: "APP_KAB", Value: "from-other"}}, false)
	otherID := int64(v.count(`SELECT id FROM hosts WHERE name='other'`))
	requireNoError(t, v.s.store.Tx(t.Context(), func(q *store.Q) error { return q.RevokeHost(t.Context(), otherID, v.s.now()) }))
	if n := v.count(`SELECT count(*) FROM env_proposals WHERE id=? AND status='superseded' AND payload IS NULL AND bucket IS NULL`, p.ID); n != 1 {
		t.Fatal("a revoked host's proposal is still pending")
	}
	if n := v.count(`SELECT count(*) FROM env_proposals WHERE status='pending'`); n != 1 {
		t.Fatalf("%d pending: revoking one host ended another's proposal, or not its own", n)
	}
	if st, _ := challenge(p.ID); st != 409 {
		t.Fatalf("commit challenge for a revoked host's proposal: %d", st)
	}
	v.nothingKept()
}
