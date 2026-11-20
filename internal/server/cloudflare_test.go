package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/aquarat/agent-quartermaster/internal/server/cfproxy"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Fake credentials only: none of these is a real Cloudflare token.
const (
	testAcct        = "0123456789abcdef0123456789abcdef"
	testZoneID      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testProxyToken  = "FAKE-proxy-parent-token-not-real-0001"
	testMinterToken = "FAKE-minter-parent-token-not-real-0002"
)

// ---- fakes ----

type fakeProxy struct {
	mu      sync.Mutex
	opts    cfproxy.Options
	callers []cfproxy.Caller
	paths   []string // escaped request paths seen by Serve
	methods []string
	bodies  []int64
	snaps   []string // "list" or snapshot ids
	prunes  int
}

func (f *fakeProxy) Serve(w http.ResponseWriter, r *http.Request, c cfproxy.Caller) {
	n, _ := io.Copy(io.Discard, r.Body)
	f.mu.Lock()
	f.callers = append(f.callers, c)
	f.paths = append(f.paths, r.URL.EscapedPath())
	f.methods = append(f.methods, r.Method)
	f.bodies = append(f.bodies, n)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":null}`))
}

func (f *fakeProxy) ServeSnapshotList(w http.ResponseWriter, r *http.Request, c cfproxy.Caller) {
	f.mu.Lock()
	f.callers = append(f.callers, c)
	f.snaps = append(f.snaps, "list")
	f.mu.Unlock()
	writeJSON(w, 200, api.CFSnapshotList{Snapshots: []api.CFSnapshot{}})
}

func (f *fakeProxy) ServeSnapshotGet(w http.ResponseWriter, r *http.Request, c cfproxy.Caller, id string) {
	f.mu.Lock()
	f.callers = append(f.callers, c)
	f.snaps = append(f.snaps, id)
	f.mu.Unlock()
	writeJSON(w, 200, api.CFSnapshot{ID: id})
}

func (f *fakeProxy) Prune(ctx context.Context, now time.Time) error {
	f.mu.Lock()
	f.prunes++
	f.mu.Unlock()
	return nil
}

type fakeMinter struct {
	mu        sync.Mutex
	fail      error
	deleteErr error
	n         int
	mints     []cfproxy.MintRequest
	values    []string
	live      map[string]cfproxy.UpstreamToken
	deleted   []string
}

func newFakeMinter() *fakeMinter { return &fakeMinter{live: map[string]cfproxy.UpstreamToken{}} }

func (m *fakeMinter) Mint(ctx context.Context, req cfproxy.MintRequest) (*cfproxy.Minted, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return nil, m.fail
	}
	m.n++
	id := fmt.Sprintf("tok%04d", m.n)
	v := "FAKE-child-token-value-" + id
	m.mints = append(m.mints, req)
	m.values = append(m.values, v)
	m.live[id] = cfproxy.UpstreamToken{ID: id, Name: req.Name, ExpiresOn: req.ExpiresOn, Status: "active"}
	return &cfproxy.Minted{ID: id, Value: v}, nil
}

func (m *fakeMinter) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deleted = append(m.deleted, id)
	delete(m.live, id) // a missing token counts as deleted (404 = success)
	return nil
}

func (m *fakeMinter) ListAqmas(ctx context.Context) ([]cfproxy.UpstreamToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []cfproxy.UpstreamToken
	for _, t := range m.live {
		if strings.HasPrefix(t.Name, "aqmas:") {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b cfproxy.UpstreamToken) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (m *fakeMinter) set(f func(*fakeMinter)) { m.mu.Lock(); defer m.mu.Unlock(); f(m) }

func (m *fakeMinter) wasDeleted(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.deleted, id)
}

// lockedBuf collects log output from server goroutines.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// ---- env ----

func writeSecret(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// cfConfig is testConfig with Cloudflare enabled (fake ids and token files).
func cfConfig(t *testing.T, withMinter bool) *config.Config {
	t.Helper()
	cfg := testConfig(t.TempDir())
	tok := t.TempDir()
	cfg.Cloudflare = config.Cloudflare{
		Enabled: true, AccountID: testAcct,
		ProxyTokenFile:   writeSecret(t, tok, "proxy", testProxyToken+"\n", 0o600),
		TokenIPCondition: []string{"203.0.113.7/32", "198.51.100.0/24"},
		Zones:            []config.CFObject{{Name: "example.net", ID: testZoneID}},
		Tunnels:          []config.CFObject{{Name: "home", ID: "7e570b05-0000-4000-8000-000000000000"}},
		D1Databases:      []config.CFObject{{Name: "billing", ID: "11111111-2222-4333-8444-555555555555"}},
		Scopes:           map[string]config.CFScopeOverride{},
	}
	if withMinter {
		cfg.Cloudflare.MinterTokenFile = writeSecret(t, tok, "minter", "  "+testMinterToken+"\n", 0o400)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

type cfEnv struct {
	*env
	proxy  *fakeProxy
	minter *fakeMinter
	logs   *lockedBuf
	pushes *pushLog
}

type pushLog struct {
	mu     sync.Mutex
	bodies []string
}

func (p *pushLog) all() string { p.mu.Lock(); defer p.mu.Unlock(); return strings.Join(p.bodies, "\n") }

// waitFor polls the push log for want (notifications are sent asynchronously).
func (p *pushLog) waitFor(t *testing.T, want string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if strings.Contains(p.all(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no push %q; got:\n%s", want, p.all())
}

func newCFEnv(t *testing.T, cfg *config.Config) *cfEnv {
	t.Helper()
	ce := &cfEnv{proxy: &fakeProxy{}, minter: newFakeMinter(), logs: &lockedBuf{}, pushes: &pushLog{}}
	ce.env = newEnvWith(t, cfg, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(ce.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		o.newCFProxy = func(po cfproxy.Options) (cfProxy, error) {
			ce.proxy.opts = po
			return ce.proxy, nil
		}
	})
	if ce.s.cf.minter != nil {
		ce.s.cf.minter = ce.minter
	}
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ce.pushes.mu.Lock()
		ce.pushes.bodies = append(ce.pushes.bodies, string(b))
		ce.pushes.mu.Unlock()
	}))
	t.Cleanup(ntfy.Close)
	ce.s.notify.TopicURL = ntfy.URL + "/topic"
	t.Cleanup(func() {
		// No secret may ever reach the log.
		logs := ce.logs.String()
		for _, secret := range append([]string{testProxyToken, testMinterToken}, ce.minter.values...) {
			if strings.Contains(logs, secret) {
				t.Errorf("log contains a token value")
			}
		}
	})
	return ce
}

func (e *env) cfRequest(c *http.Client, scope string, params map[string]string, mode string, ttl int) (api.RequestCreated, int) {
	e.t.Helper()
	var rc api.RequestCreated
	st, err := agentDo(e.t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{
		Kind: "cloudflare", Cloudflare: &api.CloudflareRequest{Scope: scope, Params: params, Mode: mode},
		Reason: "test", TTLSeconds: ttl, Requester: api.Requester{Tool: "other", User: "alice"},
	}, &rc)
	if err != nil {
		e.t.Fatal(err)
	}
	return rc, st
}

func (e *env) item(id string) api.PendingItem {
	e.t.Helper()
	var it api.PendingItem
	mustStatus(e.t, "request item", e.webDo("GET", "/api/ui/requests/"+id, nil, &it), 200)
	return it
}

func (e *env) audited(action, object string) *api.AuditEntry {
	e.t.Helper()
	for _, en := range e.state().Recent {
		if en.Action == action && en.Object == object {
			return &en
		}
	}
	return nil
}

// dbContains reports whether any text or blob value in the database contains needle.
func dbContains(t *testing.T, db *sql.DB, needle string) bool {
	t.Helper()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	for _, tb := range tables {
		rs, err := db.Query("SELECT * FROM " + tb)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rs.Columns()
		for rs.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rs.Scan(ptrs...)
			for _, v := range vals {
				switch x := v.(type) {
				case string:
					if strings.Contains(x, needle) {
						rs.Close()
						return true
					}
				case []byte:
					if bytes.Contains(x, []byte(needle)) {
						rs.Close()
						return true
					}
				}
			}
		}
		rs.Close()
	}
	return false
}

// ---- tests ----

func TestCFDisabled(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	_, st := e.cfRequest(c, "cf.read", nil, "", 0)
	mustStatus(t, "cloudflare request while disabled", st, 400)
	for _, p := range []string{"/v1/cf/catalogue", "/v1/cf/snapshots", "/v1/cf/snapshots/x", "/cf/client/v4/zones"} {
		st, _ := agentDo(t, c, "GET", e.agent.URL+p, nil, nil)
		mustStatus(t, p, st, 404)
	}
	// An ssh request carrying a cloudflare object is malformed.
	_, line := newSSHKey(t)
	st, _ = agentDo(t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{Kind: "ssh",
		SSH:        &api.SSHRequest{TargetHost: "db-1", LoginUser: "alice", PublicKey: line},
		Cloudflare: &api.CloudflareRequest{Scope: "cf.read"}, Reason: "x", Requester: api.Requester{Tool: "other", User: "u"}}, nil)
	mustStatus(t, "ssh with cloudflare object", st, 400)
}

func TestCFRequestValidationAndTTL(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, true))
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	zone := map[string]string{"zone": "example.net"}
	for name, tc := range map[string]struct {
		scope  string
		params map[string]string
		mode   string
	}{
		"unknown scope":        {"cf.nope", nil, ""},
		"missing param":        {"cf.dns.edit", nil, ""},
		"unconfigured zone":    {"cf.dns.edit", map[string]string{"zone": "example.com"}, ""},
		"extra param":          {"cf.read", zone, ""},
		"name outside zone":    {"cf.dns.edit", map[string]string{"zone": "example.net", "name": "x.example.com"}, ""},
		"bad mode":             {"cf.dns.edit", zone, "both"},
		"token for proxy-only": {"cf.tunnel.config", map[string]string{"tunnel": "home"}, "token"},
		"bad value":            {"cf.d1", map[string]string{"db": "billing", "access": "drop"}, ""},
	} {
		if _, st := e.cfRequest(c, tc.scope, tc.params, tc.mode, 0); st != 400 {
			t.Errorf("%s: HTTP %d, want 400", name, st)
		}
	}
	st, _ := agentDo(t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{Kind: "cloudflare", Reason: "x",
		Requester: api.Requester{Tool: "other", User: "u"}}, nil)
	mustStatus(t, "no cloudflare object", st, 400)
	st, _ = agentDo(t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{Kind: "cloudflare", Reason: "x\x1b[31m",
		Cloudflare: &api.CloudflareRequest{Scope: "cf.read"}, Requester: api.Requester{Tool: "other", User: "u"}}, nil)
	mustStatus(t, "control characters in reason", st, 400)

	// TTL: 0 = the scope default, clamped into [ttl.min_seconds, scope max].
	for _, tc := range []struct {
		scope    string
		params   map[string]string
		ttl, max int
	}{
		{"cf.dns.edit", zone, 0, 7200},
		{"cf.dns.edit", zone, 10, 60},
		{"cf.dns.edit", zone, 99999, 28800},
		{"cf.zone-settings", zone, 0, 3600},
		{"cf.admin", nil, 0, 3600},
		{"cf.admin", nil, 28800, 3600},
		{"cf.read.private", nil, 28800, 7200},
	} {
		rc, st := e.cfRequest(c, tc.scope, tc.params, "", tc.ttl)
		mustStatus(t, "create "+tc.scope, st, 201)
		if it := e.item(rc.ID); it.TTLRequested != tc.max || it.TTLMax != tc.max {
			t.Errorf("%s ttl %d: ttl_requested %d ttl_max %d, want %d", tc.scope, tc.ttl, it.TTLRequested, it.TTLMax, tc.max)
		}
		agentDo(t, c, "POST", e.agent.URL+"/v1/requests/"+rc.ID+"/cancel", map[string]any{}, nil) // stay below the pending cap
	}

	// Token mode without a minter token is refused at request time.
	e2 := newCFEnv(t, cfConfig(t, false))
	e2.setupOwner()
	c2 := e2.agentClient(ptr(e2.enrollHost("hosta")))
	if _, st := e2.cfRequest(c2, "cf.dns.edit", zone, "token", 0); st != 400 {
		t.Fatalf("token mode without minter: HTTP %d", st)
	}
	var cat api.CFCatalogue
	st, _ = agentDo(t, c2, "GET", e2.agent.URL+"/v1/cf/catalogue", nil, &cat)
	mustStatus(t, "catalogue", st, 200)
	if cat.AccountID != testAcct || len(cat.Zones) != 1 || cat.Zones[0].ID != testZoneID || len(cat.Scopes) == 0 {
		t.Fatalf("catalogue %+v", cat)
	}
}

func TestCFAutoApprove(t *testing.T) {
	cfg := cfConfig(t, true)
	e := newCFEnv(t, cfg)
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))

	rc, st := e.cfRequest(c, "cf.read", nil, "", 0)
	mustStatus(t, "cf.read", st, 201)
	if rc.Status != "approved" {
		t.Fatalf("cf.read not auto-approved: %s", rc.Status)
	}
	rs, st := e.status(c, rc.ID, "")
	mustStatus(t, "status", st, 200)
	g := rs.Grant
	if g == nil || g.Kind != "cloudflare" || g.SSH != nil || g.Cloudflare == nil {
		t.Fatalf("grant %+v", g)
	}
	cg := g.Cloudflare
	if cg.Scope != "cf.read" || cg.ScopeParams != "" || cg.Mode != "proxy" || cg.AccountID != testAcct || cg.ProxyPath != "/cf/client/v4" ||
		cg.Token != "" || cg.TokenID != "" || len(cg.IPCondition) != 0 {
		t.Fatalf("cloudflare grant %+v", cg)
	}
	if got := g.NotAfter.Sub(g.NotBefore); got != 8*time.Hour {
		t.Fatalf("cf.read validity %v", got)
	}
	if e.audited("cf_auto_approve", "request:"+rc.ID) == nil {
		t.Fatal("auto-approval not audited")
	}

	// Auto-approval is capped per host, scope and params (the CLI reuses an active grant).
	for i := 1; i < MaxAutoCFGrants; i++ {
		if rc, st := e.cfRequest(c, "cf.read", nil, "", 0); st != 201 || rc.Status != "approved" {
			t.Fatalf("cf.read #%d: %d %s", i+1, st, rc.Status)
		}
	}
	if _, st := e.cfRequest(c, "cf.read", nil, "", 0); st != 429 {
		t.Fatalf("auto-approval beyond the cap answered %d, want 429", st)
	}

	rc, _ = e.cfRequest(c, "cf.cache.purge", map[string]string{"zone": "example.net"}, "proxy", 0)
	if rc.Status != "approved" {
		t.Fatalf("cf.cache.purge proxy not auto-approved: %s", rc.Status)
	}
	if rs, _ := e.status(c, rc.ID, ""); rs.Grant.Cloudflare.Params["zone"] != "example.net" || rs.Grant.Cloudflare.ScopeParams != "zone=example.net" {
		t.Fatalf("purge grant %+v", rs.Grant.Cloudflare)
	}
	// Token mode is never auto-approved.
	rc, _ = e.cfRequest(c, "cf.cache.purge", map[string]string{"zone": "example.net"}, "token", 0)
	if rc.Status != "pending" {
		t.Fatalf("token-mode purge: %s", rc.Status)
	}
	// Other scopes are never auto-approved.
	rc, _ = e.cfRequest(c, "cf.dns.edit", map[string]string{"zone": "example.net"}, "", 0)
	if rc.Status != "pending" {
		t.Fatalf("dns.edit: %s", rc.Status)
	}
	e.pushes.waitFor(t, "aqmas: hosta wants cf.dns.edit zone=example.net (2h)")
	e.pushes.waitFor(t, "aqmas: hosta wants a Cloudflare token cf.cache.purge zone=example.net (1h)")
	if strings.Contains(e.pushes.all(), "cf.read") {
		t.Fatal("auto-approval was pushed")
	}
	// The agent's grant list carries the scope fields.
	var gl api.GrantList
	agentDo(t, c, "GET", e.agent.URL+"/v1/grants?active=1", nil, &gl)
	if len(gl.Grants) != 1+MaxAutoCFGrants || gl.Grants[0].Scope != "cf.cache.purge" || gl.Grants[0].ScopeParams != "zone=example.net" ||
		gl.Grants[0].Mode != "proxy" || gl.Grants[1].Scope != "cf.read" || gl.Grants[0].TargetHost != "" || gl.Grants[0].RequestingHost != "" {
		t.Fatalf("grants %+v", gl.Grants)
	}

	// Config can turn auto-approval off.
	cfg2 := cfConfig(t, false)
	cfg2.Cloudflare.Scopes["cf.read"] = config.CFScopeOverride{NoAutoApprove: true}
	e2 := newCFEnv(t, cfg2)
	e2.setupOwner()
	c2 := e2.agentClient(ptr(e2.enrollHost("hosta")))
	if rc, _ := e2.cfRequest(c2, "cf.read", nil, "", 0); rc.Status != "pending" {
		t.Fatalf("no_auto_approve ignored: %s", rc.Status)
	}
}

func TestCFApproveStandingAndRevoke(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, true))
	e.setupOwner()
	a := e.agentClient(ptr(e.enrollHost("hosta")))
	b := e.agentClient(ptr(e.enrollHost("hostb")))
	params := map[string]string{"zone": "Example.net", "name": "*.example.net"}
	const sp = "name=*.example.net;zone=example.net"

	rc, st := e.cfRequest(a, "cf.dns.edit", params, "", 0)
	mustStatus(t, "create", st, 201)
	if rc.Status != "pending" {
		t.Fatal(rc.Status)
	}
	// The card.
	st0 := e.state()
	if len(st0.Pending) != 1 {
		t.Fatalf("pending %+v", st0.Pending)
	}
	it := st0.Pending[0]
	pc := it.Cloudflare
	if it.Kind != "cloudflare" || it.SSH != nil || pc == nil || pc.Scope != "cf.dns.edit" || pc.ScopeParams != sp ||
		pc.Params["zone"] != "example.net" || pc.Params["name"] != "*.example.net" || pc.Mode != "proxy" || pc.IPCondition != "" ||
		pc.Title == "" || pc.Description == "" || pc.Risk != "high" || !pc.StandingAllowed || len(pc.Permissions) != 0 ||
		it.Risk != "high" || it.TTLMax != 7200 || it.SimilarRecent != 0 || it.RequestingAddress != "127.0.0.1" {
		t.Fatalf("card %+v / %+v", it, pc)
	}

	// Approve with "similar for 2 hours".
	cr, st := e.challenge("/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 3600, StandingHours: 2})
	mustStatus(t, "challenge", st, 200)
	cv := uiCheck(t, cr)
	for k, want := range map[string]any{"action": "approve", "object": "request", "kind": "cloudflare", "requesting_host": "hosta",
		"scope": "cf.dns.edit", "scope_params": sp, "mode": "proxy", "ip_condition": ""} {
		if cv[k] != want {
			t.Fatalf("canonical %s = %v, want %v (%s)", k, cv[k], want, cr.Canonical)
		}
	}
	if cv["ttl_seconds"] != json.Number("3600") || cv["standing_hours"] != json.Number("2") {
		t.Fatalf("canonical %s", cr.Canonical)
	}
	var decided api.RequestStatus
	mustStatus(t, "decide", e.decide("/api/ui/requests/"+rc.ID, "decide", cr, &decided), 200)
	if decided.Status != "approved" || decided.Grant != nil {
		t.Fatalf("decide %+v", decided)
	}
	e.pushes.waitFor(t, "aqmas: approve cloudflare cf.dns.edit "+sp+" (proxy) for hosta, ttl 3600s, standing 2h [ref "+ref(rc.ID)+"]")
	rs, _ := e.status(a, rc.ID, "")
	if rs.Grant == nil || rs.Grant.Cloudflare.ScopeParams != sp || rs.Grant.NotAfter.Sub(rs.Grant.NotBefore) != time.Hour {
		t.Fatalf("grant %+v", rs.Grant)
	}
	gid := rs.Grant.ID

	st1 := e.state()
	if len(st1.Standing) != 1 || st1.Standing[0].Scope != "cf.dns.edit" || st1.Standing[0].ScopeParams != sp || st1.Standing[0].Mode != "proxy" ||
		st1.Standing[0].MaxTTLSeconds != 3600 || st1.Standing[0].TargetHost != "" || st1.Standing[0].Kind != "cloudflare" {
		t.Fatalf("standing %+v", st1.Standing)
	}
	if len(st1.Grants) != 1 || st1.Grants[0].Scope != "cf.dns.edit" || st1.Grants[0].RequestingHost != "hosta" {
		t.Fatalf("grants %+v", st1.Grants)
	}
	sid := st1.Standing[0].ID

	// Standing match: identical scope_params, same host and address, proxy, ttl within max.
	r1, _ := e.cfRequest(a, "cf.dns.edit", map[string]string{"zone": "example.net", "name": "*.example.net"}, "proxy", 3600)
	if r1.Status != "approved" {
		t.Fatalf("matching request: %s", r1.Status)
	}
	if e.audited("auto_approve", "request:"+r1.ID) == nil {
		t.Fatal("standing auto-approval not audited")
	}
	for name, tc := range map[string]struct {
		c      *http.Client
		scope  string
		params map[string]string
		mode   string
		ttl    int
	}{
		"other params": {a, "cf.dns.edit", map[string]string{"zone": "example.net"}, "", 3600},
		"other name":   {a, "cf.dns.edit", map[string]string{"zone": "example.net", "name": "x.example.net"}, "", 3600},
		"token mode":   {a, "cf.dns.edit", params, "token", 3600},
		"other scope":  {a, "cf.rulesets", map[string]string{"zone": "example.net"}, "", 3600},
		"longer ttl":   {a, "cf.dns.edit", params, "", 3601},
		"default ttl":  {a, "cf.dns.edit", params, "", 0}, // 7200 > 3600
		"other host":   {b, "cf.dns.edit", params, "", 3600},
	} {
		if rc, st := e.cfRequest(tc.c, tc.scope, tc.params, tc.mode, tc.ttl); st != 201 || rc.Status != "pending" {
			t.Errorf("%s: HTTP %d status %s", name, st, rc.Status)
		}
		e.s.Store().DB().Exec("UPDATE requests SET status = 'cancelled' WHERE status = 'pending'") // pending cap
	}
	// Bound to the address of the request the owner approved.
	e.s.Store().DB().Exec("UPDATE standing SET peer_address = '192.0.2.9' WHERE id = ?", sid)
	if rc, _ := e.cfRequest(a, "cf.dns.edit", params, "", 3600); rc.Status != "pending" {
		t.Fatal("standing approval matched from another address")
	}
	e.s.Store().DB().Exec("UPDATE standing SET peer_address = '127.0.0.1' WHERE id = ?", sid)
	e.s.Store().DB().Exec("UPDATE requests SET status = 'cancelled' WHERE status = 'pending'")
	// similar_recent counts the host's approved requests for the scope (rc and r1).
	r9, _ := e.cfRequest(a, "cf.dns.edit", map[string]string{"zone": "example.net"}, "", 0)
	if it := e.item(r9.ID); it.SimilarRecent != 2 {
		t.Fatalf("similar_recent %d, want 2", it.SimilarRecent)
	}

	// Revoking the standing approval: canonical text per API.md 5.4.
	cr, st = e.challenge("/api/ui/standing/"+sid, api.ChallengeRequest{Action: "revoke"})
	mustStatus(t, "standing challenge", st, 200)
	cv = uiCheck(t, cr)
	if cv["scope"] != "cf.dns.edit" || cv["scope_params"] != sp || cv["mode"] != "proxy" || cv["ttl_seconds"] != json.Number("3600") || cv["standing_hours"] != json.Number("0") {
		t.Fatalf("standing canonical %s", cr.Canonical)
	}
	mustStatus(t, "revoke standing", e.decide("/api/ui/standing/"+sid, "revoke", cr, nil), 200)
	if rc, _ := e.cfRequest(a, "cf.dns.edit", params, "", 3600); rc.Status != "pending" {
		t.Fatal("revoked standing still used")
	}

	// Grant revoke: the proxy stops accepting it at once.
	src := cfGrantSource{e.s}
	ha, _ := e.s.Store().Q().ActiveHostByName(context.Background(), "hosta")
	if gs, _ := src.ProxyGrants(context.Background(), ha.ID, []string{gid}, e.clock.Now()); len(gs) == 0 {
		t.Fatalf("grant %s not active before revoke", gid)
	}
	cr, st = e.challenge("/api/ui/grants/"+gid, api.ChallengeRequest{Action: "revoke"})
	mustStatus(t, "grant challenge", st, 200)
	cv = uiCheck(t, cr)
	if cv["kind"] != "cloudflare" || cv["scope"] != "cf.dns.edit" || cv["ttl_seconds"] != json.Number("0") || cv["standing_hours"] != json.Number("0") {
		t.Fatalf("grant canonical %s", cr.Canonical)
	}
	mustStatus(t, "revoke grant", e.decide("/api/ui/grants/"+gid, "revoke", cr, nil), 200)
	e.pushes.waitFor(t, "aqmas: revoke grant cloudflare cf.dns.edit "+sp+" (proxy) for hosta [ref "+ref(gid)+"]")
	if gs, _ := src.ProxyGrants(context.Background(), ha.ID, []string{gid}, e.clock.Now()); len(gs) != 0 {
		t.Fatal("revoked grant still offered to the proxy")
	}
	if rs, _ := e.status(a, rc.ID, ""); rs.Status != "revoked" || rs.Grant != nil {
		t.Fatalf("after revoke %+v", rs)
	}

	// Deny.
	rd, _ := e.cfRequest(a, "cf.access.apps", nil, "", 0)
	cr, st = e.challenge("/api/ui/requests/"+rd.ID, api.ChallengeRequest{Action: "deny"})
	mustStatus(t, "deny challenge", st, 200)
	uiCheck(t, cr)
	mustStatus(t, "deny", e.decide("/api/ui/requests/"+rd.ID, "decide", cr, nil), 200)
	if rs, _ := e.status(a, rd.ID, ""); rs.Status != "denied" {
		t.Fatal(rs.Status)
	}
	e.pushes.waitFor(t, "aqmas: deny cloudflare cf.access.apps (proxy) for hosta, ttl 0s, standing 0h")
}

func TestCFStandingRefusedAndAdminCap(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, true))
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	zone := map[string]string{"zone": "example.net"}

	adm, _ := e.cfRequest(c, "cf.admin", nil, "", 28800)
	e.pushes.waitFor(t, "aqmas: BREAK-GLASS cf.admin for hosta")
	it := e.item(adm.ID)
	if it.TTLMax != 3600 || it.Risk != "high" || it.Cloudflare.Risk != "admin" || it.Cloudflare.StandingAllowed {
		t.Fatalf("admin card %+v %+v", it, it.Cloudflare)
	}
	priv, _ := e.cfRequest(c, "cf.read.private", nil, "", 0)
	tok, _ := e.cfRequest(c, "cf.dns.edit", zone, "token", 0)
	if it := e.item(tok.ID); it.Cloudflare.StandingAllowed {
		t.Fatal("token mode card offers standing")
	}
	for name, id := range map[string]string{"cf.admin": adm.ID, "cf.read.private": priv.ID, "token mode": tok.ID} {
		if _, st := e.challenge("/api/ui/requests/"+id, api.ChallengeRequest{Action: "approve", StandingHours: 1}); st != 400 {
			t.Errorf("%s: standing challenge HTTP %d, want 400", name, st)
		}
	}
	if _, st := e.challenge("/api/ui/requests/"+adm.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 3601}); st != 400 {
		t.Fatalf("cf.admin ttl above cap: HTTP %d", st)
	}
	if _, st := e.challenge("/api/ui/requests/"+adm.ID, api.ChallengeRequest{Action: "deny", TTLSeconds: 60}); st != 400 {
		t.Fatalf("deny with ttl: HTTP %d", st)
	}
	mustStatus(t, "approve cf.admin", e.approve("/api/ui/requests/"+adm.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
	if rs, _ := e.status(c, adm.ID, ""); rs.Grant.NotAfter.Sub(rs.Grant.NotBefore) != time.Hour {
		t.Fatalf("cf.admin validity %v", rs.Grant.NotAfter.Sub(rs.Grant.NotBefore))
	}

	// The config changed between challenge and decision: 409, nothing approved.
	dns, _ := e.cfRequest(c, "cf.dns.edit", zone, "", 0)
	cr, st := e.challenge("/api/ui/requests/"+dns.ID, api.ChallengeRequest{Action: "approve", StandingHours: 1})
	mustStatus(t, "challenge", st, 200)
	zones := e.s.cfg.Cloudflare.Zones
	e.s.cfg.Cloudflare.Zones = nil
	mustStatus(t, "decide after zone removal", e.decide("/api/ui/requests/"+dns.ID, "decide", cr, nil), 409)
	if _, st := e.challenge("/api/ui/requests/"+dns.ID, api.ChallengeRequest{Action: "approve"}); st != 409 {
		t.Fatalf("challenge for an unconfigured zone: HTTP %d", st)
	}
	if it := e.item(dns.ID); it.Status != "pending" || len(it.Cloudflare.Notes) == 0 {
		t.Fatalf("card after zone removal %+v", it.Cloudflare)
	}
	e.s.cfg.Cloudflare.Zones = zones

	// Token mode: the IP condition the owner signs must still be the configured one.
	cr, st = e.challenge("/api/ui/requests/"+tok.ID, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "token challenge", st, 200)
	ipc := e.s.cfg.Cloudflare.TokenIPCondition
	e.s.cfg.Cloudflare.TokenIPCondition = []string{"192.0.2.1/32"}
	mustStatus(t, "decide after ip change", e.decide("/api/ui/requests/"+tok.ID, "decide", cr, nil), 409)
	e.s.cfg.Cloudflare.TokenIPCondition = ipc
}

func TestCFTokenMintOnDelivery(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, true))
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	other := e.agentClient(ptr(e.enrollHost("hostb")))
	rc, _ := e.cfRequest(c, "cf.dns.edit", map[string]string{"zone": "example.net"}, "token", 1800)
	pc := e.item(rc.ID).Cloudflare
	const ipc = "198.51.100.0/24,203.0.113.7/32" // sorted
	if pc.Mode != "token" || pc.IPCondition != ipc || !slices.Equal(pc.Permissions, []string{"DNS Write (zone example.net)", "Zone Read (zone example.net)"}) || len(pc.Notes) == 0 {
		t.Fatalf("token card %+v", pc)
	}
	cr, st := e.challenge("/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 900})
	mustStatus(t, "challenge", st, 200)
	if cv := uiCheck(t, cr); cv["mode"] != "token" || cv["ip_condition"] != ipc {
		t.Fatalf("canonical %s", cr.Canonical)
	}
	mustStatus(t, "decide", e.decide("/api/ui/requests/"+rc.ID, "decide", cr, nil), 200)
	e.pushes.waitFor(t, "(token) for hosta, ttl 900s, standing 0h")

	// Another host cannot collect it.
	if _, st := e.status(other, rc.ID, ""); st != 404 {
		t.Fatalf("other host: HTTP %d", st)
	}
	// A failed mint answers 502 and leaves the delivery open.
	e.minter.set(func(m *fakeMinter) { m.fail = errors.New("upstream says no") })
	if _, st := e.status(c, rc.ID, ""); st != 502 {
		t.Fatalf("failed mint: HTTP %d", st)
	}
	e.minter.set(func(m *fakeMinter) { m.fail = nil })
	rs, st := e.status(c, rc.ID, "")
	mustStatus(t, "mint", st, 200)
	cg := rs.Grant.Cloudflare
	if cg.Token == "" || cg.Token != e.minter.values[0] || cg.TokenID != "tok0001" || !cg.TokenDelivered ||
		!slices.Equal(cg.IPCondition, []string{"198.51.100.0/24", "203.0.113.7/32"}) || len(cg.Permissions) != 2 || cg.ProxyPath != "/cf/client/v4" {
		t.Fatalf("token grant %+v", cg)
	}
	value := cg.Token
	if len(e.minter.mints) != 1 {
		t.Fatalf("%d mints", len(e.minter.mints))
	}
	m := e.minter.mints[0]
	if m.Name != "aqmas:"+rs.Grant.ID+":hosta" || !m.ExpiresOn.Equal(rs.Grant.NotAfter) || !slices.Equal(m.IPIn, cg.IPCondition) ||
		m.Resolved == nil || m.Resolved.IDs["zone"] != testZoneID || m.Resolved.Mode != "token" || rs.Grant.NotAfter.Sub(rs.Grant.NotBefore) != 900*time.Second {
		t.Fatalf("mint request %+v", m)
	}
	// Later polls: id and delivered flag, never the value again.
	rs, _ = e.status(c, rc.ID, "")
	if cg := rs.Grant.Cloudflare; cg.Token != "" || cg.TokenID != "tok0001" || !cg.TokenDelivered {
		t.Fatalf("second poll %+v", cg)
	}
	if len(e.minter.mints) != 1 {
		t.Fatal("minted twice")
	}
	en := e.audited("cf_token_mint", "grant:"+rs.Grant.ID)
	if en == nil || !strings.Contains(en.Detail, "tok0001") {
		t.Fatalf("mint audit %+v", en)
	}
	// The value is nowhere in aqmasd's database (or its log: checked at cleanup).
	if dbContains(t, e.s.Store().DB(), value) {
		t.Fatal("token value stored")
	}
	if !dbContains(t, e.s.Store().DB(), "tok0001") {
		t.Fatal("dbContains is broken")
	}

	// Revoking the grant deletes the token upstream at once.
	mustStatus(t, "revoke", e.approve("/api/ui/grants/"+rs.Grant.ID, "revoke", api.ChallengeRequest{Action: "revoke"}), 200)
	if !e.minter.wasDeleted("tok0001") {
		t.Fatal("revoked grant's token not deleted")
	}
	if e.audited("cf_token_delete", "grant:"+rs.Grant.ID) == nil {
		t.Fatal("token delete not audited")
	}
	g, _ := e.s.Store().Q().GetGrant(context.Background(), rs.Grant.ID)
	if g.TokenDeletedAt == nil {
		t.Fatal("token deletion not recorded")
	}
	// The sweeper has nothing left to do for it.
	e.minter.set(func(m *fakeMinter) { m.deleted = nil })
	e.s.sweepTokens(context.Background())
	if len(e.minter.deleted) != 0 {
		t.Fatal("deleted twice")
	}
}

func TestCFTokenRevokeDeleteFailureIsRetried(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, true))
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	rc, _ := e.cfRequest(c, "cf.pages", map[string]string{"project": "blog"}, "token", 0)
	mustStatus(t, "approve", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
	rs, _ := e.status(c, rc.ID, "")
	if rs.Grant.Cloudflare.Token == "" {
		t.Fatal("no token")
	}
	e.minter.set(func(m *fakeMinter) { m.deleteErr = errors.New("cloudflare down") })
	mustStatus(t, "revoke", e.approve("/api/ui/grants/"+rs.Grant.ID, "revoke", api.ChallengeRequest{Action: "revoke"}), 200)
	if g, _ := e.s.Store().Q().GetGrant(context.Background(), rs.Grant.ID); g.TokenDeletedAt != nil || g.RevokedAt == nil {
		t.Fatal("state after failed delete")
	}
	e.minter.set(func(m *fakeMinter) { m.deleteErr = nil })
	e.s.sweepTokens(context.Background())
	if !e.minter.wasDeleted(rs.Grant.Cloudflare.TokenID) {
		t.Fatal("sweeper did not retry")
	}
}

func TestCFSweeper(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, true))
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	mint := func(ttl int) *api.Grant {
		rc, _ := e.cfRequest(c, "cf.workers.deploy", map[string]string{"script": "api"}, "token", ttl)
		mustStatus(t, "approve", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
		rs, _ := e.status(c, rc.ID, "")
		if rs.Grant.Cloudflare.Token == "" {
			t.Fatal("no token")
		}
		return rs.Grant
	}
	short := mint(600)
	long := mint(7200)

	// Expired token grants are deleted.
	e.clock.Advance(601 * time.Second)
	e.login()
	e.s.sweepTokens(context.Background())
	if !e.minter.wasDeleted(short.Cloudflare.TokenID) || e.minter.wasDeleted(long.Cloudflare.TokenID) {
		t.Fatalf("deleted %v", e.minter.deleted)
	}
	if en := e.audited("cf_token_delete", "grant:"+short.ID); en == nil || !strings.Contains(en.Detail, "expired") {
		t.Fatalf("delete audit %+v", en)
	}

	// Orphans: unknown names, superseded tokens of a live grant, upstream-expired tokens.
	now := e.clock.Now()
	e.minter.mu.Lock()
	e.minter.live["x1"] = cfproxy.UpstreamToken{ID: "x1", Name: "aqmas:01ZZZZZZZZZZZZZZZZZZZZZZZZ:hosta", ExpiresOn: now.Add(time.Hour)}
	e.minter.live["x2"] = cfproxy.UpstreamToken{ID: "x2", Name: "aqmas:" + long.ID + ":hosta", ExpiresOn: now.Add(time.Hour)} // not the recorded id
	e.minter.live["x3"] = cfproxy.UpstreamToken{ID: "x3", Name: "aqmas:" + long.ID + ":hostb", ExpiresOn: now.Add(time.Hour)} // wrong host
	e.minter.live["x4"] = cfproxy.UpstreamToken{ID: "x4", Name: "aqmas:01ZZZZZZZZZZZZZZZZZZZZZZZY:hosta", ExpiresOn: now.Add(-time.Minute)}
	e.minter.live["x6"] = cfproxy.UpstreamToken{ID: "x6", Name: "aqmas:junk", ExpiresOn: now.Add(-time.Minute)} // not aqmasd's form: left alone
	e.minter.live["x7"] = cfproxy.UpstreamToken{ID: "x7", Name: "aqmas: proxy parent", ExpiresOn: time.Time{}}  // the owner's parent tokens
	e.minter.live["x5"] = cfproxy.UpstreamToken{ID: "x5", Name: "someone-else", ExpiresOn: now.Add(time.Hour)}  // not ours: never listed
	e.minter.mu.Unlock()
	e.s.sweepOrphans(context.Background())
	for _, id := range []string{"x1", "x2", "x3", "x4"} {
		if !e.minter.wasDeleted(id) {
			t.Errorf("orphan %s kept", id)
		}
	}
	if e.minter.wasDeleted(long.Cloudflare.TokenID) || e.minter.wasDeleted("x5") || e.minter.wasDeleted("x6") || e.minter.wasDeleted("x7") {
		t.Fatal("live or foreign token deleted")
	}
	if e.audited("cf_token_orphan", "token:x1") == nil || e.audited("cf_token_orphan", "grant:"+long.ID) == nil {
		t.Fatal("orphan deletes not audited")
	}
	e.pushes.waitFor(t, "aqmas: deleted Cloudflare token aqmas:01ZZZZZZZZZZZZZZZZZZZZZZZZ:hosta (unknown to aqmasd)")

	// A grant whose token is being minted right now is left alone.
	rc, _ := e.cfRequest(c, "cf.workers.deploy", map[string]string{"script": "api"}, "token", 0)
	mustStatus(t, "approve", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
	g, _ := e.s.Store().Q().GrantByRequest(context.Background(), rc.ID)
	if ok, _ := e.s.Store().Q().MarkTokenDelivering(context.Background(), g.ID, e.clock.Now()); !ok {
		t.Fatal("claim failed")
	}
	e.minter.mu.Lock()
	e.minter.live["x6"] = cfproxy.UpstreamToken{ID: "x6", Name: tokenName(g), ExpiresOn: g.NotAfter}
	e.minter.mu.Unlock()
	e.s.sweepOrphans(context.Background())
	if e.minter.wasDeleted("x6") {
		t.Fatal("in-flight mint deleted")
	}

	// cfSweep schedules: everything due at first, then nothing until the periods pass.
	e.minter.set(func(m *fakeMinter) { m.deleted = nil })
	e.s.cfSweep(context.Background())
	if e.proxy.prunes != 1 {
		t.Fatalf("prunes %d", e.proxy.prunes)
	}
	e.s.cfSweep(context.Background())
	if e.proxy.prunes != 1 {
		t.Fatal("pruned twice within the hour")
	}
	e.clock.Advance(2 * time.Hour)
	e.s.cfSweep(context.Background())
	if e.proxy.prunes != 2 {
		t.Fatal("hourly prune missing")
	}
	// long expired meanwhile: the per-minute token sweep deleted it.
	if !e.minter.wasDeleted(long.Cloudflare.TokenID) {
		t.Fatal("token sweep not run by cfSweep")
	}
}

func TestCFParentTokenFiles(t *testing.T) {
	dir := t.TempDir()
	const secret = "FAKE-secret-0123456789"
	ok := writeSecret(t, dir, "ok", "\n  "+secret+"  \n", 0o600)
	if v, err := loadParentToken("proxy", "", ok); err != nil || v != secret {
		t.Fatalf("0600 file: %q %v", v, err)
	}
	ro := writeSecret(t, dir, "ro", secret, 0o400)
	if v, err := loadParentToken("proxy", "", ro); err != nil || v != secret {
		t.Fatalf("0400 file: %v", err)
	}
	for name, p := range map[string]string{
		"group readable": writeSecret(t, dir, "g", secret, 0o640),
		"world readable": writeSecret(t, dir, "w", secret, 0o644),
		"executable":     writeSecret(t, dir, "x", secret, 0o700),
		"empty":          writeSecret(t, dir, "e", " \n", 0o600),
		"two words":      writeSecret(t, dir, "two", secret+" "+secret, 0o600),
		"missing":        filepath.Join(dir, "nope"),
		"directory":      dir,
	} {
		_, err := loadParentToken("proxy", "", p)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error reveals the token", name)
		}
	}
	if os.Getuid() == 0 {
		p := writeSecret(t, dir, "foreign", secret, 0o600)
		os.Chown(p, 4242, 4242)
		if _, err := loadParentToken("proxy", "", p); err == nil {
			t.Error("file of another uid accepted")
		}
	}
	// systemd credentials.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := loadParentToken("proxy", "cf-proxy-token", ""); err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Fatalf("no credentials dir: %v", err)
	}
	cred := t.TempDir()
	writeSecret(t, cred, "cf-proxy-token", secret+"\n", 0o400)
	t.Setenv("CREDENTIALS_DIRECTORY", cred)
	if v, err := loadParentToken("proxy", "cf-proxy-token", ""); err != nil || v != secret {
		t.Fatalf("credential: %v", err)
	}
	if _, err := loadParentToken("minter", "cf-minter-token", ""); err == nil {
		t.Fatal("missing credential accepted")
	}

	// aqmasd refuses to start with a loosely protected token file, without printing it.
	cfg := cfConfig(t, false)
	os.Chmod(cfg.Cloudflare.ProxyTokenFile, 0o644)
	_, err := New(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		newCFProxy: func(cfproxy.Options) (cfProxy, error) { return &fakeProxy{}, nil }})
	if err == nil || strings.Contains(err.Error(), testProxyToken) {
		t.Fatalf("New with a 0644 token file: %v", err)
	}
	// ... and when the proxy cannot be built.
	cfg = cfConfig(t, false)
	_, err = New(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		newCFProxy: func(cfproxy.Options) (cfProxy, error) { return nil, cfproxy.ErrNotImplemented }})
	if !errors.Is(err, cfproxy.ErrNotImplemented) {
		t.Fatalf("New with a failing proxy: %v", err)
	}
}

func TestCFProxyOptionsAndMount(t *testing.T) {
	cfg := cfConfig(t, true)
	e := newCFEnv(t, cfg)
	if o := e.proxy.opts; o.ProxyToken != testProxyToken || o.Catalogue == nil || o.Grants == nil || o.Config != &e.s.cfg.Cloudflare ||
		o.SnapshotDir != filepath.Join(cfg.DataDir, "cf-snapshots") || o.Now == nil || o.Notify == nil {
		t.Fatalf("proxy options %+v", o)
	}
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	anon := e.agentClient(nil)

	resp, err := anon.Get(e.agent.URL + "/cf/client/v4/zones")
	if err != nil {
		t.Fatal(err)
	}
	var cfErr struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	json.NewDecoder(resp.Body).Decode(&cfErr)
	resp.Body.Close()
	if resp.StatusCode != 401 || cfErr.Success || len(cfErr.Errors) != 1 || cfErr.Errors[0].Code != api.CFErrorNumeric ||
		!strings.HasPrefix(cfErr.Errors[0].Message, "aqmas unauthenticated: ") {
		t.Fatalf("proxy without client cert: %d %+v", resp.StatusCode, cfErr)
	}
	if len(e.proxy.callers) != 0 {
		t.Fatal("unauthenticated call reached the proxy")
	}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/cf/client/v4/zones"},
		{"PUT", "/cf/client/v4/accounts/" + testAcct + "/cfd_tunnel/x/configurations"},
		{"DELETE", "/cf/client/v4/zones/" + testZoneID + "/dns_records/abc"},
		{"PATCH", "/cf/client/v4//zones/../x"}, // not cleaned or redirected: the proxy rejects it itself
		{"POST", "/cf/client/v4/accounts/" + testAcct + "/r2/buckets/b/objects/a%2Fb"},
	} {
		req, _ := http.NewRequest(tc.method, e.agent.URL+tc.path, strings.NewReader("{}"))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: HTTP %d", tc.method, tc.path, resp.StatusCode)
		}
		n := len(e.proxy.paths)
		if e.proxy.paths[n-1] != tc.path || e.proxy.methods[n-1] != tc.method {
			t.Fatalf("proxy saw %s %s, want %s %s", e.proxy.methods[n-1], e.proxy.paths[n-1], tc.method, tc.path)
		}
		if cl := e.proxy.callers[len(e.proxy.callers)-1]; cl.HostName != "hosta" || cl.HostID == 0 || cl.PeerAddress != "127.0.0.1" {
			t.Fatalf("caller %+v", cl)
		}
	}
	// A percent-encoded prefix is not the proxy.
	before := len(e.proxy.paths)
	st, _ := agentDo(t, c, "GET", e.agent.URL+"/cf%2Fclient/v4/zones", nil, nil)
	if st == 200 || len(e.proxy.paths) != before {
		t.Fatalf("encoded prefix reached the proxy (HTTP %d)", st)
	}

	// Snapshots need an active Cloudflare grant.
	st, _ = agentDo(t, c, "GET", e.agent.URL+"/v1/cf/snapshots", nil, nil)
	mustStatus(t, "snapshots without grant", st, 403)
	rc, _ := e.cfRequest(c, "cf.read", nil, "", 0)
	if rc.Status != "approved" {
		t.Fatal(rc.Status)
	}
	var sl api.CFSnapshotList
	st, _ = agentDo(t, c, "GET", e.agent.URL+"/v1/cf/snapshots?object=x", nil, &sl)
	mustStatus(t, "snapshots", st, 200)
	var sn api.CFSnapshot
	st, _ = agentDo(t, c, "GET", e.agent.URL+"/v1/cf/snapshots/01SNAP", nil, &sn)
	mustStatus(t, "snapshot", st, 200)
	if !slices.Equal(e.proxy.snaps, []string{"list", "01SNAP"}) || sn.ID != "01SNAP" {
		t.Fatalf("snapshot calls %v", e.proxy.snaps)
	}
	// Grants expire: snapshots are closed again.
	e.clock.Advance(8*time.Hour + time.Second)
	st, _ = agentDo(t, c, "GET", e.agent.URL+"/v1/cf/snapshots", nil, nil)
	mustStatus(t, "snapshots after expiry", st, 403)
}

// TestCFProxyLongUpload: the proxy route outlives the agent API's short read/write timeouts
// (100 MiB uploads), the rest of the API does not.
func TestCFProxyLongUpload(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, false))
	e.setupOwner()
	cert := e.enrollHost("hosta")
	srv := httptest.NewUnstartedServer(e.s.AgentHandler())
	srv.TLS = e.s.PKI().TLSConfig()
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.StartTLS()
	defer srv.Close()
	c := e.agentClient(&cert)
	post := func(method, path string) (int, error) {
		pr, pw := io.Pipe()
		go func() {
			for i := 0; i < 8; i++ {
				time.Sleep(100 * time.Millisecond)
				pw.Write(bytes.Repeat([]byte("x"), 1024))
			}
			pw.Close()
		}()
		req, _ := http.NewRequest(method, srv.URL+path, pr)
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}
	st, err := post("PUT", "/cf/client/v4/accounts/"+testAcct+"/r2/buckets/b/objects/big")
	if err != nil || st != 200 {
		t.Fatalf("slow upload through the proxy: %d %v", st, err)
	}
	if got := e.proxy.bodies[len(e.proxy.bodies)-1]; got != 8*1024 {
		t.Fatalf("proxy read %d bytes", got)
	}
	// The same slow body on the plain API runs into its 300 ms timeouts: aqmasd gives up on it
	// long before the 800 ms body ends (the connection is cut, or the 400 "unreadable body"
	// gets out first: both deadlines expire together, so either can win).
	start := time.Now()
	st, err = post("POST", "/v1/requests")
	if err == nil && (st != http.StatusBadRequest || time.Since(start) > 700*time.Millisecond) {
		t.Fatalf("slow body on the plain API was not cut off (HTTP %d after %v)", st, time.Since(start))
	}
}

func TestCFGrantSource(t *testing.T) {
	e := newCFEnv(t, cfConfig(t, true))
	e.setupOwner()
	a := e.agentClient(ptr(e.enrollHost("hosta")))
	b := e.agentClient(ptr(e.enrollHost("hostb")))
	ctx := context.Background()
	q := e.s.Store().Q()
	ha, _ := q.ActiveHostByName(ctx, "hosta")
	hb, _ := q.ActiveHostByName(ctx, "hostb")
	grantOf := func(c *http.Client, scope string, params map[string]string, mode string, ttl int) string {
		rc, _ := e.cfRequest(c, scope, params, mode, ttl)
		if rc.Status == "pending" {
			mustStatus(t, "approve", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
		}
		g, err := q.GrantByRequest(ctx, rc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return g.ID
	}
	a1 := grantOf(a, "cf.read", nil, "", 0)
	a2 := grantOf(a, "cf.cache.purge", map[string]string{"zone": "example.net"}, "", 0)
	aShort := grantOf(a, "cf.zone-settings", map[string]string{"zone": "example.net"}, "", 60)
	aTok := grantOf(a, "cf.pages", map[string]string{"project": "blog"}, "token", 0)
	aRev := grantOf(a, "cf.r2.admin", nil, "", 0)
	mustStatus(t, "revoke", e.approve("/api/ui/grants/"+aRev, "revoke", api.ChallengeRequest{Action: "revoke"}), 200)
	b1 := grantOf(b, "cf.read", nil, "", 0)
	rc, _, _ := e.request(a, "db-1", "alice", 600)
	mustStatus(t, "approve ssh", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
	sshG, _ := q.GrantByRequest(ctx, rc.ID)

	src := cfGrantSource{e.s}
	now := e.clock.Now()
	gs, err := src.ProxyGrants(ctx, ha.ID, []string{b1, "nope", aRev, aTok, sshG.ID, a2, a1, a2, aShort}, now)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range gs {
		got = append(got, g.ID)
		if g.HostID != ha.ID || g.HostName != "hosta" || g.PeerAddress != "127.0.0.1" || g.Mode != "proxy" || g.NotAfter.IsZero() {
			t.Fatalf("grant %+v", g)
		}
	}
	if !slices.Equal(got, []string{a2, a1, aShort}) {
		t.Fatalf("ProxyGrants = %v, want %v", got, []string{a2, a1, aShort})
	}
	if gs[0].Scope != "cf.cache.purge" || gs[0].ScopeParams != "zone=example.net" {
		t.Fatalf("grant fields %+v", gs[0])
	}
	if gs, _ := src.ProxyGrants(ctx, hb.ID, []string{a1, b1}, now); len(gs) != 1 || gs[0].ID != b1 {
		t.Fatalf("host b sees %+v", gs)
	}
	// Expired grants are excluded.
	if gs, _ := src.ProxyGrants(ctx, ha.ID, []string{aShort}, now.Add(61*time.Second)); len(gs) != 0 {
		t.Fatal("expired grant offered")
	}
	if ok, _ := src.HasActiveGrant(ctx, ha.ID, now); !ok {
		t.Fatal("HasActiveGrant false")
	}
	if ok, _ := src.HasActiveGrant(ctx, ha.ID, now.Add(9*time.Hour)); ok {
		t.Fatal("HasActiveGrant true after every grant expired")
	}
	if err := src.Audit(ctx, "host:hosta", "cf_write", "grant:"+a1, "PUT /x 200"); err != nil {
		t.Fatal(err)
	}
	if e.audited("cf_write", "grant:"+a1) == nil {
		t.Fatal("proxy audit not stored")
	}
}

// TestCFRealProxy runs the real cfproxy behind core once the cf-proxy workstream has
// implemented it (skipped while cfproxy.New returns ErrNotImplemented).
func TestCFRealProxy(t *testing.T) {
	var mu sync.Mutex
	var auth []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[]}`))
	}))
	defer upstream.Close()
	cfg := cfConfig(t, false)
	cfg.Cloudflare.APIBase = upstream.URL + "/client/v4"
	cfg.Cloudflare.AllowInsecureAPIBase = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	probe := *cfg
	probe.DataDir = t.TempDir()
	s, err := New(Options{Config: &probe, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HTTPClient: upstream.Client()})
	if errors.Is(err, cfproxy.ErrNotImplemented) {
		t.Skip("cfproxy not implemented yet")
	}
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	e := newEnvWith(t, cfg, func(o *Options) { o.HTTPClient = upstream.Client() })
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	rc, _ := e.cfRequest(c, "cf.read", nil, "", 0)
	rs, _ := e.status(c, rc.ID, "")
	call := func(path, grant string) (*http.Response, []byte) {
		req, _ := http.NewRequest("GET", e.agent.URL+path, nil)
		if grant != "" {
			req.Header.Set(api.CFGrantHeader, grant)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, body := call("/cf/client/v4/user/tokens/verify", rs.Grant.ID)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "aqmas:"+rs.Grant.ID) {
		t.Fatalf("verify: %d %s", resp.StatusCode, body)
	}
	resp, _ = call("/cf/client/v4/zones/"+testZoneID+"/dns_records", "")
	if resp.StatusCode != 403 || resp.Header.Get(api.CFErrorHeader) != api.CFErrNoGrant {
		t.Fatalf("no grant: %d %q", resp.StatusCode, resp.Header.Get(api.CFErrorHeader))
	}
	resp, body = call("/cf/client/v4/zones/"+testZoneID+"/dns_records", rs.Grant.ID)
	if resp.StatusCode != 200 || resp.Header.Get(api.CFGrantUsedHeader) != rs.Grant.ID {
		t.Fatalf("dns read: %d %s", resp.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(auth) == 0 || auth[len(auth)-1] != "Bearer "+testProxyToken {
		t.Fatal("upstream did not get the proxy parent token")
	}
	var sl api.CFSnapshotList
	if st, _ := agentDo(t, c, "GET", e.agent.URL+"/v1/cf/snapshots", nil, &sl); st != 200 {
		t.Fatalf("snapshots: HTTP %d", st)
	}
}
