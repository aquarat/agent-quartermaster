package cfproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

const (
	fakeParent = "FAKE-PARENT-TOKEN-do-not-leak-0001"
	acct       = "0123456789abcdef0123456789abcdef"
	zoneA      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	zoneB      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	zoneX      = "cccccccccccccccccccccccccccccccc" // not configured
	tunHome    = "0b1c2d3e-0000-4000-8000-000000000000"
	dbTT       = "11111111-2222-4333-8444-555555555555"
	peer       = "192.0.2.10"
)

// ---- fake Cloudflare ----

type upReq struct {
	Method, URI, Auth, UA, CT, Cookie, XAuth string
	Body                                     []byte
}

type fakeCF struct {
	t    *testing.T
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []upReq
	// routes: "METHOD /path" (path below /client/v4, no query) -> handler
	routes map[string]http.HandlerFunc
}

func newFakeCF(t *testing.T) *fakeCF {
	f := &fakeCF{t: t, routes: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, upReq{Method: r.Method, URI: r.RequestURI, Auth: r.Header.Get("Authorization"), UA: r.Header.Get("User-Agent"),
			CT: r.Header.Get("Content-Type"), Cookie: r.Header.Get("Cookie"), XAuth: r.Header.Get("X-Auth-Key"), Body: b})
		h := f.routes[r.Method+" "+strings.TrimPrefix(r.URL.EscapedPath(), "/client/v4")]
		f.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b))
		if h == nil {
			cfJSON(w, 200, map[string]any{"ok": true})
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCF) on(methodPath string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[methodPath] = h
}

// result answers {"success":true,"result":v}.
func (f *fakeCF) result(methodPath string, v any) {
	f.on(methodPath, func(w http.ResponseWriter, r *http.Request) { cfJSON(w, 200, v) })
}

func (f *fakeCF) requests() []upReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]upReq(nil), f.reqs...)
}

func (f *fakeCF) count(method, pathPrefix string) int {
	n := 0
	for _, r := range f.requests() {
		if r.Method == method && strings.HasPrefix(r.URI, "/client/v4"+pathPrefix) {
			n++
		}
	}
	return n
}

func cfJSON(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cf-Ray", "abc123-LHR")
	w.Header().Set("Set-Cookie", "__cf=x")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": status < 300, "errors": []any{}, "messages": []any{}, "result": result})
}

// ---- fake core ----

type auditRow struct{ Actor, Action, Object, Detail string }

type fakeGrants struct {
	mu     sync.Mutex
	grants map[string]Grant
	audits []auditRow
	active bool
	scopes []string // ActiveScopes
}

func (g *fakeGrants) ActiveScopes(context.Context, int64, time.Time) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.scopes...), nil
}

func (g *fakeGrants) ProxyGrants(_ context.Context, hostID int64, ids []string, now time.Time) ([]Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Grant
	for _, id := range ids {
		if gr, ok := g.grants[id]; ok && gr.HostID == hostID && now.Before(gr.NotAfter) {
			out = append(out, gr)
		}
	}
	return out, nil
}

func (g *fakeGrants) HasActiveGrant(context.Context, int64, time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active, nil
}

func (g *fakeGrants) Audit(_ context.Context, actor, action, object, detail string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audits = append(g.audits, auditRow{actor, action, object, detail})
	return nil
}

func (g *fakeGrants) last(action string) *auditRow {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := len(g.audits) - 1; i >= 0; i-- {
		if g.audits[i].Action == action {
			a := g.audits[i]
			return &a
		}
	}
	return nil
}

// ---- the harness ----

type harness struct {
	t      *testing.T
	cf     *fakeCF
	cfg    *config.Cloudflare
	cat    *cfscope.Catalogue
	p      *Proxy
	grants *fakeGrants
	logs   *bytes.Buffer
	pushes []string
	pmu    sync.Mutex
	now    time.Time
	caller Caller
}

func testConfig(apiBase string) *config.Cloudflare {
	return &config.Cloudflare{
		Enabled: true, APIBase: apiBase, AllowInsecureAPIBase: true, AccountID: acct,
		Zones:                    []config.CFObject{{Name: "example.com", ID: zoneA}, {Name: "example.org", ID: zoneB}},
		Tunnels:                  []config.CFObject{{Name: "home", ID: tunHome}},
		D1Databases:              []config.CFObject{{Name: "app-db", ID: dbTT}},
		TokenIPCondition:         []string{"203.0.113.7/32"},
		RatePerMinute:            600,
		WriteRatePerMinute:       60,
		MaxBodyBytes:             2 << 20,
		UploadMaxBodyBytes:       4 << 20,
		SnapshotRetentionDays:    7,
		ProtectedAccessHostnames: []string{"id.example.com"},
		TraefikOrigin:            "https://192.0.2.10:8443",
		TraefikPlainOrigins:      []string{"http://192.0.2.10", "http://192.0.2.10:80"},
		ProtectedDNSNames:        []string{"id.example.com"},
		Scopes:                   map[string]config.CFScopeOverride{},
	}
}

func newHarness(t *testing.T, mod ...func(*config.Cloudflare)) *harness {
	t.Helper()
	cf := newFakeCF(t)
	cfg := testConfig(cf.srv.URL + "/client/v4")
	for _, m := range mod {
		m(cfg)
	}
	cat, err := cfscope.NewCatalogue(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, cf: cf, cfg: cfg, cat: cat, grants: &fakeGrants{grants: map[string]Grant{}, active: true},
		logs: &bytes.Buffer{}, now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC),
		caller: Caller{HostID: 1, HostName: "hosta", PeerAddress: peer}}
	p, err := New(Options{Config: cfg, Catalogue: cat, Grants: h.grants, ProxyToken: fakeParent, SnapshotDir: t.TempDir(),
		Notify: func(title, text string) {
			h.pmu.Lock()
			h.pushes = append(h.pushes, text)
			h.pmu.Unlock()
		},
		Log: slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now: func() time.Time { return h.now }, HTTPClient: cf.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	h.p = p
	t.Cleanup(h.checkNoLeak)
	return h
}

// checkNoLeak: the parent token never appears in logs, audits or pushes.
func (h *harness) checkNoLeak() {
	if strings.Contains(h.logs.String(), fakeParent) {
		h.t.Error("parent token in logs")
	}
	for _, a := range h.grants.audits {
		if strings.Contains(a.Detail+a.Object, fakeParent) {
			h.t.Error("parent token in audit")
		}
	}
	for _, p := range h.pushes {
		if strings.Contains(p, fakeParent) {
			h.t.Error("parent token in push")
		}
	}
}

// grant adds a grant for the caller.
func (h *harness) grant(id, scope string, params map[string]string) {
	h.t.Helper()
	sp := cfscope.CanonicalParams(params)
	if _, err := h.cat.Reparse(scope, sp, api.CFModeProxy); err != nil {
		h.t.Fatal(err)
	}
	h.grants.grants[id] = Grant{ID: id, HostID: 1, HostName: "hosta", PeerAddress: peer, Scope: scope, ScopeParams: sp,
		Mode: api.CFModeProxy, NotAfter: h.now.Add(time.Hour), Ref: "REF" + id}
}

type res struct {
	*httptest.ResponseRecorder
	doc map[string]any
}

func (r res) errCode() string { return r.Header().Get(api.CFErrorHeader) }

// call runs one proxied call. uri is below /client/v4 (with query); hdr may carry
// "X-Aqmas-Grant" etc.
func (h *harness) call(method, uri string, body any, hdr map[string]string) res {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(http.MethodGet, "/", rd)
	req.Method = method
	req.RequestURI = PathPrefix + uri
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.p.Serve(rec, req, h.caller)
	out := res{ResponseRecorder: rec}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.doc)
	if strings.Contains(rec.Body.String(), fakeParent) {
		h.t.Errorf("%s %s: parent token in response body", method, uri)
	}
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if strings.Contains(v, fakeParent) {
				h.t.Errorf("parent token in response header %s", k)
			}
		}
	}
	return out
}

func g(ids string) map[string]string { return map[string]string{api.CFGrantHeader: ids} }

func gh(ids string, kv ...string) map[string]string {
	m := g(ids)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func expect(t *testing.T, r res, status int, code string) {
	t.Helper()
	if r.Code != status || r.errCode() != code {
		t.Fatalf("got %d %q (%s), want %d %q", r.Code, r.errCode(), strings.TrimSpace(r.Body.String()), status, code)
	}
}

func (h *harness) pushCount() int {
	h.pmu.Lock()
	defer h.pmu.Unlock()
	return len(h.pushes)
}

const (
	time1h = time.Hour
	time1m = time.Minute
)

// multipartBody builds a Workers upload: a "metadata" JSON part and a script part.
func multipartBody(metadata, script string) (string, string) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	pw, _ := mw.CreateFormField("metadata")
	_, _ = pw.Write([]byte(metadata))
	fw, _ := mw.CreateFormFile("w.js", "w.js")
	_, _ = fw.Write([]byte(script))
	_ = mw.Close()
	return b.String(), mw.FormDataContentType()
}
