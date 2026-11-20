package cfproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

func TestReadForwardingAndHeaders(t *testing.T) {
	h := newHarness(t)
	h.grant("G1", api.CFScopeRead, nil)
	h.cf.result("GET /zones/"+zoneA+"/dns_records", []any{map[string]any{"id": "r1", "name": "a.example.com"}})
	r := h.call("GET", "/zones/"+zoneA+"/dns_records?name=a.example.com&per_page=50", nil, gh("G1",
		"Authorization", "Bearer shim-secret", "Cookie", "x=1", "X-Auth-Key", "k", "Cf-Connecting-Ip", "1.2.3.4", "Accept", "application/json"))
	expect(t, r, 200, "")
	if r.Header().Get(api.CFGrantUsedHeader) != "G1" || r.Header().Get("Cf-Ray") == "" || r.Header().Get("Set-Cookie") != "" {
		t.Fatalf("headers %v", r.Header())
	}
	reqs := h.cf.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d upstream calls", len(reqs))
	}
	u := reqs[0]
	if u.Auth != "Bearer "+fakeParent || u.Cookie != "" || u.XAuth != "" || u.UA != userAgent {
		t.Fatalf("upstream got %+v", u)
	}
	if u.URI != "/client/v4/zones/"+zoneA+"/dns_records?name=a.example.com&per_page=50" {
		t.Fatalf("uri %s", u.URI)
	}
	if !strings.Contains(h.logs.String(), "duration_ms") {
		t.Fatal("no read log line")
	}
	if len(h.grants.audits) != 0 {
		t.Fatal("reads are not audited")
	}
}

func TestPathTricks(t *testing.T) {
	h := newHarness(t)
	h.grant("R", api.CFScopeRead, nil)
	h.grant("O", api.CFScopeR2Objects, map[string]string{"bucket": "photos", "access": "write"})
	z := "/zones/" + zoneA
	obj := "/accounts/" + acct + "/r2/buckets/photos/objects/"
	cases := []struct {
		uri    string
		status int
		code   string
	}{
		{z + "/dns_records%2Fexport", 400, api.CFErrBadPath},
		{z + "/dns_records%2fexport", 400, api.CFErrBadPath},
		{z + "/%2e%2e/" + zoneB, 400, api.CFErrBadPath},
		{z + "/%2E", 400, api.CFErrBadPath},
		{z + "/../" + zoneB, 400, api.CFErrBadPath},
		{z + "/./dns_records", 400, api.CFErrBadPath},
		{z + "//dns_records", 400, api.CFErrBadPath},
		{z + "/dns_records/", 400, api.CFErrBadPath},
		{z + "/dns_records;x=1", 400, api.CFErrBadPath},
		{z + "/dns_records\\export", 400, api.CFErrBadPath},
		{z + "/dns_récords", 400, api.CFErrBadPath},
		{z + "/dns_records%00", 400, api.CFErrBadPath},
		{z + "/dns_records%5Cx", 400, api.CFErrBadPath},
		{z + "/dns_records%", 400, api.CFErrBadPath},
		{z + "/dns_records%zz", 400, api.CFErrBadPath},
		{z + "/dns_records#frag", 400, api.CFErrBadPath},
		{z + "/dns_records?name=a/b", 400, api.CFErrBadPath},
		{z + "/dns_records?name='x'", 400, api.CFErrBadPath},
		{z + "/dns_records?q=" + strings.Repeat("a", 2100), 400, api.CFErrBadPath},
		{z + "/dns_records?q=%G1", 400, api.CFErrBadPath},
		{"", 400, api.CFErrBadPath},
		{"/", 400, api.CFErrBadPath},
		// Encoded segments only match {key...}.
		{z + "/dns%5Frecords", 403, api.CFErrNoGrant},
		{z + "/dns_records%252Fexport", 403, api.CFErrNoGrant},
		{z + "/dns_records%3Fx", 403, api.CFErrNoGrant},
		// R2 keys may be encoded (and pass byte for byte).
		{obj + "a%252Fb", 200, ""},
		{obj + "dir/caf%C3%A9%20x.jpg", 200, ""},
		{obj + "what%3Fx", 200, ""},
		{obj + "a%2Fb", 400, api.CFErrBadPath},
	}
	for _, c := range cases {
		r := h.call("GET", c.uri, nil, g("R,O"))
		if r.Code != c.status || r.errCode() != c.code {
			t.Errorf("%s: got %d %q", c.uri, r.Code, r.errCode())
		}
	}
	var got []string
	for _, u := range h.cf.requests() {
		got = append(got, u.URI)
	}
	want := []string{"/client/v4" + obj + "a%252Fb", "/client/v4" + obj + "dir/caf%C3%A9%20x.jpg", "/client/v4" + obj + "what%3Fx"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("upstream saw %v", got)
	}
	// The absolute-form request target is refused.
	req := httptest.NewRequest("GET", "/", nil)
	req.RequestURI = "http://api.cloudflare.com/client/v4/zones"
	rec := httptest.NewRecorder()
	h.p.Serve(rec, req, h.caller)
	if rec.Code != 400 {
		t.Fatalf("absolute form %d", rec.Code)
	}
}

func TestMethodsAndOverrides(t *testing.T) {
	h := newHarness(t)
	h.grant("R", api.CFScopeRead, nil)
	for _, m := range []string{"HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND"} {
		r := h.call(m, "/zones", nil, g("R"))
		if r.Code != 405 || r.Header().Get("Allow") == "" {
			t.Errorf("%s: %d", m, r.Code)
		}
	}
	for _, hd := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		expect(t, h.call("GET", "/zones", nil, gh("R", hd, "DELETE")), 400, api.CFErrBadRequest)
	}
	if n := len(h.cf.requests()); n != 0 {
		t.Fatalf("%d upstream calls", n)
	}
}

func TestGrantSelection(t *testing.T) {
	h := newHarness(t)
	h.grant("DNSA", api.CFScopeDNSEdit, map[string]string{"zone": "example.com"})
	h.grant("DNSB", api.CFScopeDNSEdit, map[string]string{"zone": "example.org"})
	h.grant("R", api.CFScopeRead, nil)
	recB := "/zones/" + zoneB + "/dns_records/rec1"
	h.cf.result("GET "+recB, map[string]any{"id": "rec1", "name": "www.example.org", "type": "A", "content": "203.0.113.9"})

	// Zone A grant on zone B: no_grant with the hint.
	r := h.call("PUT", recB, map[string]any{"name": "www.example.org", "type": "A", "content": "203.0.113.10"}, g("DNSA"))
	expect(t, r, 403, api.CFErrNoGrant)
	if r.Header().Get(api.CFNeedsScopeHeader) != "cf.dns.edit zone=example.org" {
		t.Fatalf("hint %q", r.Header().Get(api.CFNeedsScopeHeader))
	}
	if a := h.grants.last("cf_refused"); a == nil || !strings.Contains(a.Detail, "no_grant") {
		t.Fatal("write no_grant not audited")
	}
	// Order: first offered grant that allows.
	r = h.call("GET", recB, nil, g("DNSA,DNSB,R"))
	if r.Header().Get(api.CFGrantUsedHeader) != "DNSB" {
		t.Fatalf("used %q", r.Header().Get(api.CFGrantUsedHeader))
	}
	r = h.call("GET", recB, nil, g("R,DNSB"))
	if r.Header().Get(api.CFGrantUsedHeader) != "R" {
		t.Fatalf("used %q", r.Header().Get(api.CFGrantUsedHeader))
	}
	// Peer address binding.
	h.caller.PeerAddress = "192.0.2.71"
	expect(t, h.call("GET", recB, nil, g("R")), 403, api.CFErrNoGrant)
	h.caller.PeerAddress = peer
	// Another host's grant id.
	h.caller.HostID = 2
	expect(t, h.call("GET", recB, nil, g("R")), 403, api.CFErrNoGrant)
	h.caller.HostID = 1
	// Unknown, none, too many, malformed.
	expect(t, h.call("GET", recB, nil, g("NOPE")), 403, api.CFErrNoGrant)
	r = h.call("GET", recB, nil, nil)
	expect(t, r, 403, api.CFErrNoGrant)
	if r.Header().Get(api.CFNeedsScopeHeader) != "cf.read" {
		t.Fatalf("hint %q", r.Header().Get(api.CFNeedsScopeHeader))
	}
	expect(t, h.call("GET", recB, nil, g("a,b,c,d,e,f,g,h,i")), 400, api.CFErrBadRequest)
	expect(t, h.call("GET", recB, nil, g("a b")), 400, api.CFErrBadRequest)
	// Unconfigured zone: only cf.admin.
	r = h.call("GET", "/zones/"+zoneX+"/dns_records", nil, g("R"))
	if r.Header().Get(api.CFNeedsScopeHeader) != "cf.admin" {
		t.Fatalf("hint %q", r.Header().Get(api.CFNeedsScopeHeader))
	}
	// Cloudflare-shaped error body.
	errs, _ := r.doc["errors"].([]any)
	if r.doc["success"] != false || len(errs) != 1 || !strings.HasPrefix(errs[0].(map[string]any)["message"].(string), "aqmas no_grant: ") {
		t.Fatalf("body %s", r.Body)
	}
}

func TestDenyListThroughProxy(t *testing.T) {
	h := newHarness(t)
	h.grant("A", api.CFScopeAdmin, nil)
	for _, c := range []struct {
		m, p string
		push bool
	}{
		{"POST", "/user/tokens", true},
		{"GET", "/accounts/" + acct + "/cfd_tunnel/" + tunHome + "/token", true},
		{"DELETE", "/accounts/" + acct + "/cfd_tunnel/" + tunHome, true},
		{"GET", "/accounts/ffffffffffffffffffffffffffffffff/cfd_tunnel", false},
		{"GET", "/accounts/" + acct + "/workers/scripts/hello", false},
		{"POST", "/graphql", false},
	} {
		before := h.pushCount()
		r := h.call(c.m, c.p, nil, g("A"))
		expect(t, r, 403, api.CFErrDenied)
		if a := h.grants.last("cf_refused"); a == nil || !strings.Contains(a.Detail, c.p) {
			t.Errorf("%s not audited", c.p)
		}
		if pushed := h.pushCount() > before; pushed != c.push {
			t.Errorf("%s push=%v", c.p, pushed)
		}
	}
	if n := len(h.cf.requests()); n != 0 {
		t.Fatalf("%d upstream calls", n)
	}
	// extra_deny for the grant's scope.
	h2 := newHarness(t, func(c *config.Cloudflare) {
		c.Scopes["cf.read"] = config.CFScopeOverride{ExtraDeny: []string{"GET /zones/*/dns_records/export"}}
	})
	h2.grant("R", api.CFScopeRead, nil)
	expect(t, h2.call("GET", "/zones/"+zoneA+"/dns_records/export", nil, g("R")), 403, api.CFErrDenied)
	expect(t, h2.call("GET", "/zones/"+zoneA+"/dns_records", nil, g("R")), 200, "")
}

func TestSynthetic(t *testing.T) {
	h := newHarness(t)
	expect(t, h.call("GET", "/user/tokens/verify", nil, nil), 403, api.CFErrNoGrant)
	h.grant("R", api.CFScopeRead, nil)
	r := h.call("GET", "/user/tokens/verify", nil, g("R"))
	expect(t, r, 200, "")
	res := r.doc["result"].(map[string]any)
	if res["id"] != "aqmas:R" || res["status"] != "active" || res["expires_on"] != "2026-11-20T13:00:00Z" {
		t.Fatalf("verify %v", res)
	}
	r = h.call("GET", "/user", nil, g("R"))
	if r.doc["result"].(map[string]any)["email"] != "aqmas-proxy@hosta.invalid" {
		t.Fatalf("user %s", r.Body)
	}
	r = h.call("GET", "/memberships?page=1&per_page=50", nil, g("R"))
	ms := r.doc["result"].([]any)
	if len(ms) != 1 || ms[0].(map[string]any)["account"].(map[string]any)["id"] != acct {
		t.Fatalf("memberships %s", r.Body)
	}
	if r = h.call("GET", "/memberships?page=2", nil, g("R")); len(r.doc["result"].([]any)) != 0 {
		t.Fatal("page 2 not empty")
	}
	r = h.call("GET", "/accounts", nil, g("R"))
	if r.doc["result"].([]any)[0].(map[string]any)["id"] != acct {
		t.Fatalf("accounts %s", r.Body)
	}
	if n := len(h.cf.requests()); n != 0 {
		t.Fatalf("synthetic went upstream %d times", n)
	}
	// Other methods on those paths are denied.
	expect(t, h.call("POST", "/user/tokens/verify", nil, g("R")), 403, api.CFErrDenied)
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t, func(c *config.Cloudflare) { c.RatePerMinute = 3; c.WriteRatePerMinute = 1 })
	h.grant("P", api.CFScopeCachePurge, map[string]string{"zone": "example.com"})
	h.grant("R", api.CFScopeRead, nil)
	purge := map[string]any{"files": []any{"https://example.com/a.css"}}
	expect(t, h.call("POST", "/zones/"+zoneA+"/purge_cache", purge, g("P")), 200, "")
	r := h.call("POST", "/zones/"+zoneA+"/purge_cache", purge, g("P"))
	expect(t, r, 429, api.CFErrRateLimited)
	if r.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	expect(t, h.call("GET", "/zones", nil, g("R")), 200, "")
	expect(t, h.call("GET", "/zones", nil, g("R")), 429, api.CFErrRateLimited)
	// Another host has its own buckets; time refills.
	h.caller.HostID = 2
	h.grants.grants["R2"] = Grant{ID: "R2", HostID: 2, PeerAddress: peer, Scope: api.CFScopeRead, Mode: api.CFModeProxy, NotAfter: h.now.Add(time1h)}
	expect(t, h.call("GET", "/zones", nil, g("R2")), 200, "")
	h.caller.HostID = 1
	h.now = h.now.Add(time1m)
	expect(t, h.call("GET", "/zones", nil, g("R")), 200, "")
}

func TestNoRedirects(t *testing.T) {
	h := newHarness(t)
	h.grant("R", api.CFScopeRead, nil)
	h.cf.on("GET /zones", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/client/v4/zones/"+zoneA, http.StatusFound)
	})
	expect(t, h.call("GET", "/zones", nil, g("R")), 502, api.CFErrUpstream)
	if n := len(h.cf.requests()); n != 1 {
		t.Fatalf("redirect followed: %d calls", n)
	}
	// Unreachable upstream: 502, and the transport error (which names the URL) is logged
	// without the token (checkNoLeak).
	h.cf.srv.Close()
	expect(t, h.call("GET", "/zones", nil, g("R")), 502, api.CFErrUpstream)
	if !strings.Contains(h.logs.String(), "upstream") {
		t.Fatal("no upstream error logged")
	}
}

func TestRedaction(t *testing.T) {
	h := newHarness(t)
	h.grant("A", api.CFScopeAdmin, nil)
	h.grant("P", api.CFScopePages, map[string]string{"project": "blog"})
	h.cf.result("GET /accounts/"+acct+"/access/identity_providers/idp1", map[string]any{
		"id": "idp1", "config": map[string]any{"client_id": "cid", "Client_Secret": "s3cret", "nested": []any{map[string]any{"password": "pw", "token": ""}}},
	})
	r := h.call("GET", "/accounts/"+acct+"/access/identity_providers/idp1", nil, g("A"))
	expect(t, r, 200, "")
	body := r.Body.String()
	if strings.Contains(body, "s3cret") || strings.Contains(body, `"pw"`) || !strings.Contains(body, "cid") || !strings.Contains(body, RedactedMarker) {
		t.Fatalf("redaction %s", body)
	}
	if w := r.Header().Values(api.CFWarningHeader); len(w) != 1 || w[0] != "redacted 2 fields" {
		t.Fatalf("warning %v", w)
	}
	proj := "/accounts/" + acct + "/pages/projects/blog"
	h.cf.result("GET "+proj, map[string]any{"name": "blog", "deployment_configs": map[string]any{"production": map[string]any{"env_vars": map[string]any{
		"PLAIN": map[string]any{"type": "plain_text", "value": "visible"},
		"KEY":   map[string]any{"type": "secret_text", "value": "hidden-value"},
	}}}})
	r = h.call("GET", proj, nil, g("P"))
	if b := r.Body.String(); strings.Contains(b, "hidden-value") || !strings.Contains(b, "visible") {
		t.Fatalf("env_vars %s", b)
	}
	// Writing the redacted object back is refused, also when escaped, never overridable.
	for _, body := range []string{
		`{"deployment_configs":{"production":{"env_vars":{"KEY":{"type":"secret_text","value":"[redacted by aqmas]"}}}}}`,
		`{"x":"[redacted by aqmas]"}`,
	} {
		r = h.call("PATCH", proj, body, g("P"))
		expect(t, r, 403, api.CFErrGuardRail)
		if !strings.Contains(r.Body.String(), GRedactedWrite) {
			t.Fatalf("body %s", r.Body)
		}
	}
	expect(t, h.call("PATCH", proj, `{"x":"[redacted by aqmas]"}`, gh("A", api.CFOverrideHeader, GRedactedWrite)), 400, api.CFErrBadRequest)
	if h.cf.count("PATCH", "/") != 0 {
		t.Fatal("redacted write forwarded")
	}
	// Non-JSON passes through unchanged.
	h.cf.on("GET /accounts/"+acct+"/pages/projects/blog/deployments/d1/history/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`password: "plain"`))
	})
	r = h.call("GET", proj+"/deployments/d1/history/logs", nil, g("P"))
	if r.Body.String() != `password: "plain"` {
		t.Fatalf("non-JSON %q", r.Body)
	}
	// R2 object bodies are the caller's data: never rewritten.
	h.grant("O", api.CFScopeR2Objects, map[string]string{"bucket": "photos", "access": "read"})
	h.cf.on("GET /accounts/"+acct+"/r2/buckets/photos/objects/conf.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"password":"mine"`))
	})
	if r = h.call("GET", "/accounts/"+acct+"/r2/buckets/photos/objects/conf.json", nil, g("O")); r.Body.String() != `{"password":"mine"` {
		t.Fatalf("object %q", r.Body)
	}
	// JSON that does not parse is not passed on unchecked.
	h.cf.on("GET /zones", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret": "x"`))
	})
	expect(t, h.call("GET", "/zones", nil, g("A")), 502, api.CFErrUpstream)
}

func TestBodiesAndUploads(t *testing.T) {
	h := newHarness(t, func(c *config.Cloudflare) { c.MaxBodyBytes = 64; c.UploadMaxBodyBytes = 1024 })
	h.grant("W", api.CFScopeWorkersDeploy, map[string]string{"script": "hello"})
	h.grant("O", api.CFScopeR2Objects, map[string]string{"bucket": "photos", "access": "write"})
	s := "/accounts/" + acct + "/workers/scripts/hello"
	expect(t, h.call("PUT", s+"/secrets", strings.Repeat("x", 100), g("W")), 413, api.CFErrBadRequest)
	// Uploads stream up to the upload limit.
	mp, ct := multipartBody(`{"main_module":"w.js","bindings":[]}`, strings.Repeat("y", 400))
	r := h.call("PUT", s+"?excludeScript=true&bindings_inherit=strict", mp, gh("W", "Content-Type", ct))
	expect(t, r, 200, "")
	if u := h.cf.requests(); len(u) != 1 || len(u[0].Body) != len(mp) || u[0].Auth != "Bearer "+fakeParent || u[0].CT != ct {
		t.Fatalf("upload %+v", len(u))
	}
	expect(t, h.call("PUT", s, strings.Repeat("y", 2000), g("W")), 413, api.CFErrBadRequest)
	expect(t, h.call("PUT", "/accounts/"+acct+"/r2/buckets/photos/objects/k", "abc"+RedactedMarker+"def", g("O")), 403, api.CFErrGuardRail)
	if a := h.grants.last("cf_write"); a == nil {
		t.Fatal("upload not audited")
	}
}

func TestJWTPassthrough(t *testing.T) {
	h := newHarness(t)
	h.grant("W", api.CFScopeWorkersDeploy, map[string]string{"script": "hello"})
	h.grant("P", api.CFScopePages, map[string]string{"project": "blog"})
	r := h.call("POST", "/accounts/"+acct+"/workers/assets/upload?base64=true", "--multipart--", gh("W", "Authorization", "Bearer upload.jwt.value"))
	expect(t, r, 200, "")
	u := h.cf.requests()[0]
	if u.Auth != "Bearer upload.jwt.value" {
		t.Fatalf("auth %q", u.Auth)
	}
	expect(t, h.call("POST", "/pages/assets/upsert-hashes", `{"hashes":[]}`, g("P")), 400, api.CFErrBadRequest)
	expect(t, h.call("POST", "/pages/assets/check-missing", `{"hashes":[]}`, gh("P", "Authorization", "Bearer pages.jwt")), 200, "")
	if h.cf.requests()[1].Auth != "Bearer pages.jwt" {
		t.Fatal("pages jwt")
	}
	// Non-J routes never forward the client's Authorization.
	h.call("POST", "/accounts/"+acct+"/workers/scripts/hello/assets-upload-session", `{"manifest":{}}`, gh("W", "Authorization", "Bearer upload.jwt.value"))
	if a := h.cf.requests()[2].Auth; a != "Bearer "+fakeParent {
		t.Fatalf("session auth %q", a)
	}
	if h.pushCount() != 1 { // only the session call pushes; JWT uploads are quiet
		t.Fatalf("pushes %d", h.pushCount())
	}
}
