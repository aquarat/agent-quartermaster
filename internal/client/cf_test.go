package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/testutil/fakecf"
)

// cfEnv returns an enrolled test env and its fake server.
func cfEnv(t *testing.T) (*fakeServer, *testEnv) {
	t.Helper()
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	e.RetryDelay = time.Millisecond
	reset(e)
	return f, e
}

func reset(e *testEnv) { e.stdout.Reset(); e.stderr.Reset() }

func fakeRequests(f *fakeServer) []fakecf.Request { return f.cf.fake.Requests() }

func lastFake(t *testing.T, f *fakeServer) fakecf.Request {
	t.Helper()
	rs := fakeRequests(f)
	if len(rs) == 0 {
		t.Fatal("no request reached fake Cloudflare")
	}
	return rs[len(rs)-1]
}

func noViolations(t *testing.T, f *fakeServer) {
	t.Helper()
	if v := f.cf.standIn.Violations(); len(v) > 0 {
		t.Errorf("proxy contract violations: %q", v)
	}
}

func TestCFScopes(t *testing.T) {
	f, e := cfEnv(t)
	if err := e.CFScopes(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	out := e.stdout.String()
	for _, want := range []string{"account  " + testAccount, "zones    example.com", "cf.dns.edit", "zone=example.com name?", "proxy,token", "2h0m0s/8h0m0s"} {
		if !strings.Contains(out, want) {
			t.Errorf("scopes output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("escape sequence from the server printed")
	}
	reset(e)
	if err := e.CFScopes(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	var cat api.CFCatalogue
	if err := json.Unmarshal(e.stdout.Bytes(), &cat); err != nil || len(cat.Scopes) != 2 {
		t.Fatalf("json: %v %s", err, e.stdout)
	}
	f.cf.disabled = true
	err := e.CFScopes(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "not enabled") || ExitCode(err) != ExitError {
		t.Fatalf("disabled: %v", err)
	}
}

func TestCFRequestAutoApproved(t *testing.T) {
	f, e := cfEnv(t)
	spec, _ := ParseCFSpec("cf.read", nil)
	if err := e.CFRequestCmd(context.Background(), spec, 0, "look around", false); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	if !strings.Contains(e.stdout.String(), "grant    GREQ0001") || !strings.Contains(e.stderr.String(), "approved at once") {
		t.Errorf("stdout %s stderr %s", e.stdout, e.stderr)
	}
	if strings.Contains(e.stderr.String(), "approve at:") {
		t.Error("approve URL printed for an auto-approved request")
	}
	r := f.requests["REQ0001"].req
	if r.Kind != api.KindCloudflare || r.Cloudflare.Scope != "cf.read" || r.Cloudflare.Params != nil || r.TTLSeconds != 0 ||
		r.Reason != "look around" || r.Requester.Tool != ToolClaudeCode || r.Requester.SessionID != "sess-1" {
		t.Errorf("request %+v", r)
	}
}

func TestCFRequestPendingAndDecisions(t *testing.T) {
	f, e := cfEnv(t)
	f.requestPending = 2
	spec, err := ParseCFSpec("cf.dns.edit", []string{"zone=example.com", "name=*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.CFRequestCmd(context.Background(), spec, 2*time.Hour, "dns for foo", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.stderr.String(), "approve at: https://aqmas.example/#r=REQ0001") ||
		!strings.Contains(e.stderr.String(), "(Ref EQ0001): cloudflare cf.dns.edit name=*.example.com;zone=example.com for 2h0m0s") {
		t.Errorf("stderr: %s", e.stderr)
	}
	var st api.RequestStatus
	if err := json.Unmarshal(e.stdout.Bytes(), &st); err != nil || st.Grant == nil || st.Grant.Cloudflare.ScopeParams != "name=*.example.com;zone=example.com" {
		t.Fatalf("json %v %s", err, e.stdout)
	}
	if f.requests["REQ0001"].req.TTLSeconds != 7200 || f.requests["REQ0001"].req.Cloudflare.Params["zone"] != "example.com" {
		t.Error("ttl/params not sent")
	}
	for _, c := range []struct {
		decision string
		code     int
	}{{api.StatusDenied, ExitDenied}, {api.StatusExpired, ExitExpired}} {
		f.requestDecision = c.decision
		f.decisionNote = "no \x1b[31mway"
		err := e.CFRequestCmd(context.Background(), spec, 0, "x", false)
		if ExitCode(err) != c.code || strings.Contains(err.Error(), "\x1b") {
			t.Errorf("%s: %v code %d", c.decision, err, ExitCode(err))
		}
	}
	// Usage errors: --why without a terminal, bad ttl, unknown scope (server text sanitized).
	if err := e.CFRequestCmd(context.Background(), spec, 0, "", false); ExitCode(err) != ExitUsage {
		t.Errorf("no why: %v", err)
	}
	if err := e.CFRequestCmd(context.Background(), spec, 9*time.Hour, "x", false); ExitCode(err) != ExitUsage {
		t.Errorf("ttl: %v", err)
	}
	bogus, _ := ParseCFSpec("cf.bogus", nil)
	if err := e.CFRequestCmd(context.Background(), bogus, 0, "x", false); ExitCode(err) != ExitError || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("bogus scope: %v", err)
	}
}

func TestCFRequestCancel(t *testing.T) {
	f, e := cfEnv(t)
	f.requestPending = 1 << 30
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	spec, _ := ParseCFSpec("cf.tunnel.config", []string{"tunnel=home"})
	err := e.CFRequestCmd(ctx, spec, 0, "x", false)
	if ExitCode(err) != ExitCancelled {
		t.Fatalf("err %v code %d", err, ExitCode(err))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.requests["REQ0001"].cancelled || !strings.Contains(e.stderr.String(), "cancelled request REQ0001") {
		t.Errorf("not cancelled on the server; stderr %s", e.stderr)
	}
}

func TestCFEnvRequestsAllBeforeWaiting(t *testing.T) {
	f, e := cfEnv(t)
	f.requestPending = 1 << 30
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	a, _ := ParseCFSpec("cf.dns.edit", []string{"zone=example.com"})
	b, _ := ParseCFSpec("cf.pages", []string{"project=site"})
	_, err := e.CFEnv(ctx, CFEnvOptions{Requests: []CFRequestSpec{a, b}, Why: "deploy"}, []string{"true"})
	if ExitCode(err) != ExitCancelled {
		t.Fatalf("err %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || !f.requests["REQ0001"].cancelled || !f.requests["REQ0002"].cancelled {
		t.Errorf("both requests should be created at once and both withdrawn: %d; %s", len(f.requests), e.stderr)
	}
}

func TestCFAPI(t *testing.T) {
	f, e := cfEnv(t)
	ctx := context.Background()

	// GET with no grant: needs --why without a terminal, then requests cf.read automatically.
	err := e.CFAPI(ctx, CFAPIOptions{Method: "get", Path: "/zones"})
	if ExitCode(err) != ExitUsage {
		t.Fatalf("auto cf.read without --why: %v", err)
	}
	reset(e)
	if err := e.CFAPI(ctx, CFAPIOptions{Method: "get", Path: "https://api.cloudflare.com/client/v4/zones?name=example.com", Why: "list zones"}); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	if !strings.Contains(e.stderr.String(), "requesting cf.read") || !strings.Contains(e.stderr.String(), "grant used: GREQ0001") {
		t.Errorf("stderr %s", e.stderr)
	}
	if !strings.Contains(e.stdout.String(), "\n  \"success\": true") || !strings.Contains(e.stdout.String(), `"name": "example.com"`) {
		t.Errorf("not pretty JSON: %s", e.stdout)
	}
	if r := lastFake(t, f); r.Credential != "parent" || r.Path != "/client/v4/zones" || r.Query != "name=example.com" {
		t.Errorf("upstream saw %+v", r)
	}

	// A write with only cf.read: no_grant, the hint as a command, exit 3.
	reset(e)
	body := `{"type":"A","name":"foo","content":"192.0.2.10"}`
	err = e.CFAPI(ctx, CFAPIOptions{Method: "POST", Path: "/zones/" + testZoneID + "/dns_records", Data: body, HasData: true})
	if ExitCode(err) != ExitDenied {
		t.Fatalf("no_grant: %v code %d", err, ExitCode(err))
	}
	if !strings.Contains(e.stderr.String(), `aqmas cf request cf.dns.edit zone=example.com --why "..."`) {
		t.Errorf("hint missing: %s", e.stderr)
	}
	if !strings.Contains(e.stdout.String(), "aqmas no_grant") {
		t.Errorf("refusal body not printed: %s", e.stdout)
	}

	// With a write grant: snapshots and (sanitized) warnings on stderr; --raw prints the body as is.
	gid := f.approveCF("build-box", "cf.dns.edit", map[string]string{"zone": "example.com"})
	reset(e)
	if err := e.CFAPI(ctx, CFAPIOptions{Method: "POST", Path: "/zones/" + testZoneID + "/dns_records", Data: body, HasData: true, Raw: true}); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	se := e.stderr.String()
	if !strings.Contains(se, "grant used: "+gid) || !strings.Contains(se, "snapshot before: SNAPB1  after: SNAPA1") ||
		!strings.Contains(se, "warning: first warning") || !strings.Contains(se, "warning: second ?warning") || strings.Contains(se, "\u202e") {
		t.Errorf("stderr: %q", se)
	}
	if !strings.HasPrefix(e.stdout.String(), `{"success":true`) {
		t.Errorf("raw body: %s", e.stdout)
	}
	if r := lastFake(t, f); r.Method != "POST" || r.Status != 200 || r.BodyBytes != int64(len(body)) {
		t.Errorf("upstream saw %+v", r)
	}

	// Upstream error (Cloudflare 404): body printed, exit 1.
	reset(e)
	err = e.CFAPI(ctx, CFAPIOptions{Method: "GET", Path: "/zones/" + testZoneID + "/dns_records/nope"})
	var se2 *CFStatusError
	if ExitCode(err) != ExitError || !errorsAs(err, &se2) || se2.Status != 404 || !strings.Contains(err.Error(), "Record does not exist") {
		t.Fatalf("upstream 404: %v", err)
	}

	// --data @FILE streams the file; a forbidden -H is a usage error.
	file := filepath.Join(t.TempDir(), "rec.json")
	os.WriteFile(file, []byte(body), 0o600)
	reset(e)
	if err := e.CFAPI(ctx, CFAPIOptions{Method: "POST", Path: "zones/" + testZoneID + "/dns_records", Data: "@" + file, HasData: true,
		Headers: []string{"Content-Type: application/json"}, Grants: []string{gid}}); err != nil {
		t.Fatalf("@file: %v", err)
	}
	if err := e.CFAPI(ctx, CFAPIOptions{Method: "GET", Path: "/zones", Headers: []string{"Authorization: Bearer x"}}); ExitCode(err) != ExitUsage {
		t.Errorf("Authorization header: %v", err)
	}
	if err := e.CFAPI(ctx, CFAPIOptions{Method: "TRACE", Path: "/zones"}); ExitCode(err) != ExitUsage {
		t.Errorf("TRACE: %v", err)
	}
	if err := e.CFAPI(ctx, CFAPIOptions{Method: "GET", Path: "https://evil.example/client/v4/zones"}); ExitCode(err) != ExitUsage {
		t.Errorf("foreign URL: %v", err)
	}

	// The escaped path reaches Cloudflare byte for byte.
	raw := "/accounts/" + testAccount + "/r2/buckets/b/objects/a%2Fb%20c"
	e.CFAPI(ctx, CFAPIOptions{Method: "GET", Path: raw, Grants: []string{"GREQ0001"}})
	if r := lastFake(t, f); r.Path != "/client/v4"+raw {
		t.Errorf("path re-encoded: %q", r.Path)
	}
	calls := f.cf.standIn.Calls()
	if c := calls[len(calls)-1]; c.Path != raw || c.Offered != "GREQ0001" {
		t.Errorf("proxy saw %+v", c)
	}
	noViolations(t, f)

	// Server gone: exit 5.
	f.srv.Close()
	if err := e.CFAPI(ctx, CFAPIOptions{Method: "GET", Path: "/zones", Grants: []string{"GREQ0001"}}); ExitCode(err) != ExitUnreachable {
		t.Errorf("closed server: %v", err)
	}
}

func errorsAs[T any](err error, target *T) bool {
	for err != nil {
		if v, ok := err.(T); ok {
			*target = v
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// shim starts a shim for e against f and returns it with a plain HTTP client.
func startShim(t *testing.T, f *fakeServer, e *testEnv, o ShimOptions) *Shim {
	t.Helper()
	_, c, err := e.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.StartShim(context.Background(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func shimDo(t *testing.T, s *Shim, method, path, bearer string, body io.Reader, mod func(*http.Request)) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.BaseURL()+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if mod != nil {
		mod(req)
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func TestShimAuth(t *testing.T) {
	f, e := cfEnv(t)
	gid := f.approveCF("build-box", "cf.pages", map[string]string{"project": "site"})
	s := startShim(t, f, e, ShimOptions{})
	if g := s.Grants(); len(g) != 1 || g[0] != gid {
		t.Fatalf("grants %v", g)
	}
	n := len(f.cf.standIn.Calls())

	// No bearer, wrong bearer, wrong Host, a browser Origin, a path outside /client/v4.
	for name, c := range map[string]struct {
		bearer string
		mod    func(*http.Request)
		path   string
		status int
	}{
		"no bearer":    {"", nil, "/zones", 401},
		"wrong bearer": {s.Bearer() + "x", nil, "/zones", 401},
		"wrong host":   {s.Bearer(), func(r *http.Request) { r.Host = "evil.example:" + strings.Split(s.hostport, ":")[1] }, "/zones", 421},
		"localhost":    {s.Bearer(), func(r *http.Request) { r.Host = "localhost:" + strings.Split(s.hostport, ":")[1] }, "/zones", 421},
		"origin":       {s.Bearer(), func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, "/zones", 403},
		"method":       {s.Bearer(), func(r *http.Request) { r.Method = "OPTIONS" }, "/zones", 405},
	} {
		resp, body := shimDo(t, s, http.MethodGet, c.path, c.bearer, nil, c.mod)
		if resp.StatusCode != c.status || !strings.Contains(string(body), `"success":false`) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	if got := len(f.cf.standIn.Calls()); got != n {
		t.Errorf("refused calls reached the proxy: %d", got-n)
	}

	// Right bearer: forwarded with the grant, without any Authorization; Cloudflare sees the parent.
	resp, body := shimDo(t, s, http.MethodGet, "/accounts/"+testAccount+"/pages/projects/site/upload-token", s.Bearer(), nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get(api.CFGrantUsedHeader) != gid {
		t.Fatalf("upload-token: %d %s", resp.StatusCode, body)
	}
	calls := f.cf.standIn.Calls()
	if c := calls[len(calls)-1]; c.AuthKind != "none" || c.Offered != gid {
		t.Errorf("proxy saw %+v", c)
	}
	var tok struct{ Result struct{ JWT string } }
	json.Unmarshal(body, &tok)

	// JWT passthrough: the upload JWT (not the shim bearer) is the credential and is forwarded.
	resp, body = shimDo(t, s, http.MethodPost, "/pages/assets/check-missing", tok.Result.JWT, strings.NewReader(`{"hashes":["abc"]}`),
		func(r *http.Request) { r.Header.Set("Content-Type", "application/json") })
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"abc"`) {
		t.Fatalf("check-missing: %d %s", resp.StatusCode, body)
	}
	if r := lastFake(t, f); r.Credential != "upload-jwt" || r.JWTKind != "pages-upload" {
		t.Errorf("upstream credential %+v", r)
	}
	// The shim bearer on a JWT route is not forwarded (and the JWT route then fails upstream).
	resp, _ = shimDo(t, s, http.MethodPost, "/pages/assets/check-missing", s.Bearer(), strings.NewReader(`{"hashes":[]}`), nil)
	if resp.StatusCode != 401 {
		t.Errorf("shim bearer on JWT route: %d", resp.StatusCode)
	}
	// A JWT on a normal route is refused by the shim itself.
	resp, _ = shimDo(t, s, http.MethodGet, "/zones", tok.Result.JWT, nil, nil)
	if resp.StatusCode != 401 {
		t.Errorf("JWT on a normal route: %d", resp.StatusCode)
	}
	noViolations(t, f)
}

func TestIsJWTPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/accounts/abc/workers/assets/upload":         true,
		"/accounts/abc/workers/assets/upload/0123abc": true,
		"/pages/assets/upload":                        true,
		"/pages/assets/check-missing":                 true,
		"/pages/assets/upsert-hashes":                 true,
		"/pages/assets":                               false,
		"/pages/assets/a/b":                           false,
		"/accounts/abc/workers/assets/upload/":        false,
		"/accounts/abc/workers/assets/upload/a/b":     false,
		"/accounts/abc/workers/scripts/x":             false,
		"/accounts//workers/assets/upload":            false,
	} {
		if got := isJWTPath("POST", p); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
	if isJWTPath("GET", "/pages/assets/upload") {
		t.Error("GET is never a JWT route")
	}
}

// slowReader produces n bytes in small chunks.
type slowReader struct{ n, sent int }

func (r *slowReader) Read(p []byte) (int, error) {
	if r.sent >= r.n {
		return 0, io.EOF
	}
	k := min(len(p), 64<<10, r.n-r.sent)
	for i := range p[:k] {
		p[i] = 'a'
	}
	r.sent += k
	return k, nil
}

func TestShimStreamsUploads(t *testing.T) {
	f, e := cfEnv(t)
	f.approveCF("build-box", "cf.workers.deploy", map[string]string{"script": "w"})
	s := startShim(t, f, e, ShimOptions{})
	// An upload session for one 20 MiB asset, uploaded with chunked encoding (unknown length).
	hash := "0123456789abcdef0123456789abcdef"
	resp, body := shimDo(t, s, http.MethodPost, "/accounts/"+testAccount+"/workers/scripts/w/assets-upload-session", s.Bearer(),
		strings.NewReader(`{"manifest":{"/big.bin":{"hash":"`+hash+`","size":20971520}}}`), nil)
	var sess struct{ Result struct{ JWT string } }
	if json.Unmarshal(body, &sess); resp.StatusCode != 200 || sess.Result.JWT == "" {
		t.Fatalf("session: %d %s", resp.StatusCode, body)
	}
	resp, body = shimDo(t, s, http.MethodPost, "/accounts/"+testAccount+"/workers/assets/upload/"+hash, sess.Result.JWT,
		io.MultiReader(&slowReader{n: 20 << 20}), func(r *http.Request) { r.ContentLength = -1 })
	if resp.StatusCode != 201 || !strings.Contains(string(body), `"jwt"`) {
		t.Fatalf("upload: %d %s", resp.StatusCode, body)
	}
	if r := lastFake(t, f); r.BodyBytes != 20<<20 || r.Credential != "upload-jwt" {
		t.Errorf("upstream got %+v", r)
	}
	// Over 100 MiB by Content-Length: refused locally.
	n := len(f.cf.standIn.Calls())
	conn, err := net.Dial("tcp", s.hostport)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /client/v4/accounts/%s/workers/assets/upload HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\nabc",
		testAccount, s.hostport, sess.Result.JWT, MaxUploadBytes+1)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(line, " 413 ") || len(f.cf.standIn.Calls()) != n {
		t.Errorf("oversized: %q", line)
	}
	noViolations(t, f)
}

func TestShimRefreshesAfterNoGrant(t *testing.T) {
	saved := shimRefreshEvery
	shimRefreshEvery = 0
	defer func() { shimRefreshEvery = saved }()
	f, e := cfEnv(t)
	s := startShim(t, f, e, ShimOptions{})
	resp, _ := shimDo(t, s, http.MethodGet, "/zones", s.Bearer(), nil, nil)
	if resp.StatusCode != 403 || resp.Header.Get(api.CFErrorHeader) != "no_grant" {
		t.Fatalf("no grant: %d", resp.StatusCode)
	}
	shimDo(t, s, http.MethodGet, "/zones", s.Bearer(), nil, nil)
	if c := strings.Count(e.stderr.String(), "aqmas cf request cf.dns.edit zone=example.com"); c != 1 {
		t.Errorf("hint printed %d times: %s", c, e.stderr)
	}
	// Approved elsewhere mid-run: the next call refreshes and retries (a small body is replayed).
	gid := f.approveCF("build-box", "cf.dns.edit", map[string]string{"zone": "example.com"})
	resp, body := shimDo(t, s, http.MethodPost, "/zones/"+testZoneID+"/dns_records", s.Bearer(),
		strings.NewReader(`{"type":"A","name":"x","content":"192.0.2.1"}`), func(r *http.Request) { r.Header.Set("Content-Type", "application/json") })
	if resp.StatusCode != 200 || resp.Header.Get(api.CFGrantUsedHeader) != gid {
		t.Fatalf("after approval: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(e.stderr.String(), "snapshot before SNAPB1, after SNAPA1") {
		t.Errorf("write notes: %s", e.stderr)
	}
	// Explicit grants are never refreshed.
	s2 := startShim(t, f, e, ShimOptions{Grants: []string{"GNOPE"}, Explicit: true})
	if resp, _ := shimDo(t, s2, http.MethodGet, "/zones", s2.Bearer(), nil, nil); resp.StatusCode != 403 {
		t.Errorf("explicit: %d", resp.StatusCode)
	}
}

// TestHelperProcess is the command `cf env` / `cf token` run in tests (GO_WANT_HELPER=1).
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER") != "1" {
		return
	}
	defer os.Exit(0)
	switch os.Args[len(os.Args)-1] {
	case "env":
		for _, k := range []string{"CLOUDFLARE_API_BASE_URL", "CF_API_BASE", "CLOUDFLARE_ACCOUNT_ID", "CF_ACCOUNT_ID", "CLOUDFLARE_API_KEY", "CF_API_EMAIL", "NO_PROXY"} {
			fmt.Printf("%s=%s\n", k, os.Getenv(k))
		}
		fmt.Printf("TOKEN_SAME=%v TOKEN_SHIM=%v\n", os.Getenv("CLOUDFLARE_API_TOKEN") == os.Getenv("CF_API_TOKEN"),
			strings.HasPrefix(os.Getenv("CLOUDFLARE_API_TOKEN"), "aqmas-shim-"))
		req, _ := http.NewRequest("GET", os.Getenv("CLOUDFLARE_API_BASE_URL")+"/zones", nil)
		req.Header.Set("Authorization", "Bearer "+os.Getenv("CLOUDFLARE_API_TOKEN"))
		resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
		if err != nil {
			fmt.Println("ERR", err)
			os.Exit(9)
		}
		b, _ := io.ReadAll(resp.Body)
		fmt.Printf("STATUS=%d\n%s\n", resp.StatusCode, b)
		os.Exit(7)
	case "token":
		fmt.Printf("TOKEN_CHILD=%v BASE=%q ACCOUNT=%s\n", strings.HasPrefix(os.Getenv("CLOUDFLARE_API_TOKEN"), "fakecf-child-"),
			os.Getenv("CLOUDFLARE_API_BASE_URL"), os.Getenv("CLOUDFLARE_ACCOUNT_ID"))
		os.Exit(3)
	}
}

func helperCmd(mode string) []string {
	return []string{os.Args[0], "-test.run=^TestHelperProcess$", "--", mode}
}

func helperEnv(e *testEnv) {
	base := append(os.Environ(), "GO_WANT_HELPER=1", "CLOUDFLARE_API_KEY=legacy", "CF_API_EMAIL=me@example.com",
		"CLOUDFLARE_API_BASE_URL=https://elsewhere.example", "NO_PROXY=corp.example")
	e.Environ = func() []string { return base }
}

func TestCFEnvRunsCommand(t *testing.T) {
	f, e := cfEnv(t)
	gid := f.approveCF("build-box", "cf.read", nil)
	helperEnv(e)
	code, err := e.CFEnv(context.Background(), CFEnvOptions{}, helperCmd("env"))
	if err != nil || code != 7 {
		t.Fatalf("code %d err %v\n%s\n%s", code, err, e.stdout, e.stderr)
	}
	out := e.stdout.String()
	for _, want := range []string{"CLOUDFLARE_API_BASE_URL=http://127.0.0.1:", "/client/v4\n", "CLOUDFLARE_ACCOUNT_ID=" + testAccount,
		"CF_ACCOUNT_ID=" + testAccount, "CLOUDFLARE_API_KEY=\n", "CF_API_EMAIL=\n", "NO_PROXY=corp.example,127.0.0.1\n",
		"TOKEN_SAME=true TOKEN_SHIM=true", "STATUS=200", `"name":"example.com"`} {
		if !strings.Contains(out, want) {
			t.Errorf("child output lacks %q:\n%s", want, out)
		}
	}
	calls := f.cf.standIn.Calls()
	if c := calls[len(calls)-1]; c.Offered != gid || c.Path != "/zones" {
		t.Errorf("proxy saw %+v", c)
	}
	// A missing command is a usage error.
	if _, err := e.CFEnv(context.Background(), CFEnvOptions{}, []string{"/nonexistent/cmd"}); ExitCode(err) != ExitUsage {
		t.Errorf("missing command: %v", err)
	}
	noViolations(t, f)
}

func TestCFCurl(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	f, e := cfEnv(t)
	f.approveCF("build-box", "cf.read", nil)
	e.Environ = func() []string { return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()} }
	code, err := e.CFCurl(context.Background(), CFEnvOptions{}, []string{"-sS", "https://api.cloudflare.com/client/v4/zones?name=example.com"})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, e.stderr)
	}
	if !strings.Contains(e.stdout.String(), `"name":"example.com"`) {
		t.Errorf("curl output: %s", e.stdout)
	}
	if ents, _ := filepath.Glob(filepath.Join(e.Paths.CacheDir, ".cf-curl-header-*")); len(ents) != 0 {
		t.Errorf("header file left behind: %v", ents)
	}
	if r := lastFake(t, f); r.Credential != "parent" || r.Query != "name=example.com" {
		t.Errorf("upstream: %+v", r)
	}
	noViolations(t, f)
}

func TestCFToken(t *testing.T) {
	f, e := cfEnv(t)
	f.requestPending = 1
	f.cf.mintFail = 2 // aqmasd answers 502 twice; polling again retries the mint
	spec, _ := ParseCFSpec("cf.dns.edit", []string{"zone=example.com"})
	e.StdoutIsTTY = true
	code, err := e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "terraform"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	if e.stdout.Len() != 0 || !strings.Contains(e.stderr.String(), "not printed to a terminal") {
		t.Errorf("token printed to a terminal? stdout %q stderr %s", e.stdout, e.stderr)
	}
	if f.requests["REQ0001"].req.Cloudflare.Mode != api.CFModeToken {
		t.Error("mode not token")
	}
	path := filepath.Join(e.Paths.CacheDir, cfTokenDirName, "GREQ0001.json")
	if mode(t, path) != 0o600 || mode(t, filepath.Dir(path)) != 0o700 {
		t.Errorf("cache modes %o %o", mode(t, path), mode(t, filepath.Dir(path)))
	}
	var cached cachedCFToken
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cached)
	if !strings.HasPrefix(cached.Token, "fakecf-child-") || cached.AccountID != testAccount || cached.ScopeParams != "zone=example.com" {
		t.Fatalf("cache %+v", cached)
	}
	if strings.Contains(e.stderr.String(), cached.Token) {
		t.Fatal("token on stderr")
	}

	// Reused (no new request); printed when stdout is not a terminal.
	e.StdoutIsTTY = false
	reset(e)
	if _, err := e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "terraform"}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(e.stdout.String()) != cached.Token || f.created != 1 || !strings.Contains(e.stderr.String(), "reusing token grant GREQ0001") {
		t.Errorf("reuse: created %d stdout %q stderr %s", f.created, e.stdout, e.stderr)
	}

	// With a command: the token in the env, the shim's base URL removed, exit status passed on.
	helperEnv(e)
	reset(e)
	code, err = e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "terraform"}, helperCmd("token"))
	if err != nil || code != 3 || !strings.Contains(e.stdout.String(), `TOKEN_CHILD=true BASE="" ACCOUNT=`+testAccount) {
		t.Fatalf("cmd: %d %v %s", code, err, e.stdout)
	}

	// Revoked on the server: dropped and requested again.
	f.mu.Lock()
	f.requests["REQ0001"].revoked = true
	f.mu.Unlock()
	reset(e)
	if _, err := e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "terraform"}, nil); err != nil {
		t.Fatal(err)
	}
	if f.created != 2 || !strings.Contains(e.stderr.String(), "revoked on the server") {
		t.Errorf("revoked: created %d %s", f.created, e.stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("revoked grant's token still cached")
	}

	// Expired: deleted from the cache when seen.
	e.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if toks, _ := e.loadCFTokens(); len(toks) != 0 {
		t.Errorf("expired tokens returned: %d", len(toks))
	}
	if ents, _ := filepath.Glob(filepath.Join(e.Paths.CacheDir, cfTokenDirName, "*.json")); len(ents) != 0 {
		t.Errorf("expired tokens not deleted: %v", ents)
	}
	e.Now = time.Now

	// Less than 2 minutes left: not reused.
	f.cf.ttl = time.Minute
	reset(e)
	e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "x", Fresh: true}, nil)
	before := f.created
	e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "x"}, nil)
	if f.created != before+1 {
		t.Error("token with < 2 min left reused")
	}
}

func TestCFTokenDeliveredElsewhere(t *testing.T) {
	f, e := cfEnv(t)
	spec, _ := ParseCFSpec("cf.dns.edit", []string{"zone=example.com"})
	// Another poll consumed the token first.
	go func() {
		for {
			time.Sleep(5 * time.Millisecond)
			f.mu.Lock()
			if fr := f.requests["REQ0001"]; fr != nil {
				fr.delivered = true
				f.requestPending = 0
				f.mu.Unlock()
				return
			}
			f.mu.Unlock()
		}
	}()
	f.requestPending = 1 << 30
	_, err := e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "already delivered") {
		t.Fatalf("got %v", err)
	}
}

func TestCFListAndStatus(t *testing.T) {
	f, e := cfEnv(t)
	gid := f.approveCF("build-box", "cf.dns.edit", map[string]string{"zone": "example.com", "name": "*.example.com"})
	if err := e.List(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.stdout.String(), gid) || !strings.Contains(e.stdout.String(), "cf.dns.edit name=*.example.com;zone=example.com (proxy)") {
		t.Errorf("list: %s", e.stdout)
	}
	// status ID of a token grant shows the token id, never the value.
	spec, _ := ParseCFSpec("cf.dns.edit", []string{"zone=example.com"})
	e.StdoutIsTTY = true
	if _, err := e.CFToken(context.Background(), CFTokenOptions{Spec: spec, Why: "x"}, nil); err != nil {
		t.Fatal(err)
	}
	reset(e)
	if err := e.Status(context.Background(), "REQ0002"); err != nil {
		t.Fatal(err)
	}
	out := e.stdout.String()
	if !strings.Contains(out, "scope    cf.dns.edit zone=example.com") || !strings.Contains(out, "token id ") || strings.Contains(out, "fakecf-child-") {
		t.Errorf("status: %s", out)
	}
	reset(e)
	if err := e.Status(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.stdout.String(), "CF TOKEN GRANT") || !strings.Contains(e.stdout.String(), "GREQ0002") || strings.Contains(e.stdout.String(), "fakecf-child-") {
		t.Errorf("status: %s", e.stdout)
	}
}

func TestCFSnapshots(t *testing.T) {
	f, e := cfEnv(t)
	now := time.Now()
	f.cf.snapshots = []api.CFSnapshot{
		{ID: "SNAP1", CreatedAt: now, Phase: "before", ObjectType: "tunnel-config", ObjectKey: "tunnel-config:" + testTunnelID + "\x1b[2J", Method: "PUT",
			Path: "/accounts/x/cfd_tunnel/y/configurations", GrantID: "G1", Host: "build-box", Size: 20, Content: json.RawMessage(`{"config":{"ingress":[]}}`)},
		{ID: "SNAP2", CreatedAt: now, Phase: "before", ObjectType: "dns-name", ObjectKey: "dns-name:z:foo", Missing: true, Method: "POST", GrantID: "G2"},
	}
	// Without a Cloudflare grant: 403 from the server, exit 1.
	if err := e.CFSnapshotList(context.Background(), "", "", "", false); ExitCode(err) != ExitError {
		t.Fatalf("no grant: %v", err)
	}
	f.approveCF("build-box", "cf.read", nil)
	if err := e.CFSnapshotList(context.Background(), "", "tunnel-config", "", false); err != nil {
		t.Fatal(err)
	}
	if out := e.stdout.String(); !strings.Contains(out, "SNAP1") || strings.Contains(out, "SNAP2") || strings.Contains(out, "\x1b") {
		t.Errorf("list: %q", out)
	}
	reset(e)
	if err := e.CFSnapshotList(context.Background(), "", "", "G2", false); err != nil || !strings.Contains(e.stdout.String(), "before (missing)") {
		t.Errorf("list by grant: %v %s", err, e.stdout)
	}
	reset(e)
	if err := e.CFSnapshotGet(context.Background(), "SNAP1", ""); err != nil {
		t.Fatal(err)
	}
	if e.stdout.String() != "{\n  \"config\": {\n    \"ingress\": []\n  }\n}\n" {
		t.Errorf("content: %q", e.stdout)
	}
	out := filepath.Join(t.TempDir(), "snap.json")
	if err := e.CFSnapshotGet(context.Background(), "SNAP1", out); err != nil || mode(t, out) != 0o600 {
		t.Errorf("-o: %v", err)
	}
	if err := e.CFSnapshotGet(context.Background(), "../x", ""); ExitCode(err) != ExitUsage {
		t.Errorf("bad id: %v", err)
	}
}

func TestParseCFSpecAndHints(t *testing.T) {
	s, err := ParseCFSpec("cf.dns.edit", []string{"zone=example.com", "name=*.example.com"})
	if err != nil || canonicalScopeParams(s.Params) != "name=*.example.com;zone=example.com" {
		t.Fatalf("%v %v", s, err)
	}
	for _, bad := range [][]string{{"zone"}, {"zone=a;b"}, {"zone=a=b"}, {"Zone=a"}, {"zone=a", "zone=b"}, {"zone=\x1b"}, {"zone="}} {
		if _, err := ParseCFSpec("cf.dns.edit", bad); ExitCode(err) != ExitUsage {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, bad := range []string{"dns.edit", "cf.", "cf.DNS", "cf.a;b"} {
		if _, err := ParseCFSpec(bad, nil); err == nil {
			t.Errorf("scope %q accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"cf.dns.edit name=*.example.com;zone=example.com": `aqmas cf request cf.dns.edit 'name=*.example.com' zone=example.com --why "..."`,
		"cf.read":                    `aqmas cf request cf.read --why "..."`,
		"cf.admin":                   `aqmas cf request cf.admin --why "..."`,
		"cf.x name=$(rm -rf /)":      `aqmas cf request cf.x 'name=$(rm -rf /)' --why "..."`,
		"rm -rf":                     "",
		"cf.d1 access=read;db=times": `aqmas cf request cf.d1 access=read db=times --why "..."`,
	} {
		if got := NeedsScopeCommand(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}

func TestSplitCFPathAndChildEnv(t *testing.T) {
	for in, want := range map[string]string{
		"/zones":                     "/zones|",
		"zones?name=a":               "/zones|name=a",
		"/client/v4/zones":           "/zones|",
		CloudflareAPIBase + "/zones": "/zones|",
		CloudflareAPIBase + "/a?b=c": "/a|b=c",
	} {
		p, q, err := splitCFPath(in)
		if err != nil || p+"|"+q != want {
			t.Errorf("%q: %q %q %v", in, p, q, err)
		}
	}
	env := childEnv([]string{"A=1", "CLOUDFLARE_API_KEY=k", "CF_API_TOKEN=old", "X=2"}, map[string]string{"CF_API_TOKEN": "new"}, []string{"X"})
	if strings.Join(env, " ") != "A=1 CF_API_TOKEN=new" {
		t.Errorf("env %q", env)
	}
	if withNoProxy("") != "127.0.0.1" || withNoProxy("a, 127.0.0.1") != "a, 127.0.0.1" {
		t.Error("withNoProxy")
	}
}

func TestShimRandomBearer(t *testing.T) {
	f, e := cfEnv(t)
	a := startShim(t, f, e, ShimOptions{Explicit: true})
	b := startShim(t, f, e, ShimOptions{Explicit: true})
	if a.Bearer() == b.Bearer() || len(a.Bearer()) < 40 {
		t.Error("bearer not random per run")
	}
	if h, _, _ := net.SplitHostPort(a.hostport); h != "127.0.0.1" {
		t.Errorf("listens on %s", a.hostport)
	}
	_ = rand.Reader
	_ = bytes.MinRead
}

func TestCtrlFilter(t *testing.T) {
	var b bytes.Buffer
	n, err := ctrlFilter{&b}.Write([]byte("a\x1b[2Jb\tc\nd\x7f"))
	if err != nil || n != 11 || b.String() != "a?[2Jb\tc\nd?" {
		t.Errorf("%d %v %q", n, err, b.String())
	}
}
