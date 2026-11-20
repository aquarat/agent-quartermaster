package fakecf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	acct   = "0123456789abcdef0123456789abcdef"
	zoneID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tunID  = "11111111-2222-4333-8444-555555555555"
	dbID   = "99999999-2222-4333-8444-555555555555"
	parent = "parent-token-abcdefgh"
)

type tc struct {
	t   *testing.T
	srv *httptest.Server
	f   *Fake
	now time.Time
}

func newTC(t *testing.T) *tc {
	c := &tc{t: t, now: time.Now()}
	f, err := New(Options{Tokens: []string{parent, "second-parent-123"}, AccountID: acct, Zones: []Named{{Name: "example.com", ID: zoneID}},
		Tunnels: []Named{{Name: "home", ID: tunID}}, D1: []Named{{Name: "times", ID: dbID}}, PagesProjects: []string{"site"},
		Now: func() time.Time { return c.now }})
	if err != nil {
		t.Fatal(err)
	}
	c.f = f
	c.srv = httptest.NewServer(f)
	t.Cleanup(func() { c.srv.Close(); f.Close() })
	return c
}

type result struct {
	Success    bool              `json:"success"`
	Errors     []cfErr           `json:"errors"`
	Result     json.RawMessage   `json:"result"`
	ResultInfo map[string]any    `json:"result_info"`
	raw        []byte            `json:"-"`
	status     int               `json:"-"`
	hdr        http.Header       `json:"-"`
	m          map[string]any    `json:"-"`
	list       []json.RawMessage `json:"-"`
}

func (c *tc) do(method, path, token string, body any, ct string) *result {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		data, _ := json.Marshal(b)
		rd = bytes.NewReader(data)
		ct = "application/json"
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	r := &result{status: resp.StatusCode, hdr: resp.Header}
	r.raw, _ = io.ReadAll(resp.Body)
	json.Unmarshal(r.raw, r)
	json.Unmarshal(r.Result, &r.m)
	json.Unmarshal(r.Result, &r.list)
	return r
}

func (c *tc) ok(method, path string, body any) *result {
	c.t.Helper()
	r := c.do(method, path, parent, body, "")
	if r.status/100 != 2 || !r.Success {
		c.t.Fatalf("%s %s: %d %s", method, path, r.status, r.raw)
	}
	return r
}

const v4 = "/client/v4"

func TestAuthAndRecording(t *testing.T) {
	c := newTC(t)
	r := c.do("GET", v4+"/zones", "wrong-token", nil, "")
	if r.status != 401 || r.Success || len(r.Errors) != 1 || r.Errors[0].Code != 1000 || string(r.Result) != "null" {
		t.Fatalf("unknown bearer: %d %s", r.status, r.raw)
	}
	if r := c.do("GET", v4+"/zones", "", nil, ""); r.status != 401 {
		t.Errorf("no bearer: %d", r.status)
	}
	c.ok("GET", v4+"/zones?name=example.com", nil)
	c.do("GET", v4+"/accounts/"+acct+"/r2/buckets/b/objects/a%2Fb", "second-parent-123", nil, "")
	if r := c.do("GET", v4+"/nope/route", parent, nil, ""); r.status != 404 || r.Errors[0].Code != 7003 {
		t.Errorf("unrouted: %d %s", r.status, r.raw)
	}
	if r := c.do("GET", v4+"/accounts/ffffffffffffffffffffffffffffffff/cfd_tunnel", parent, nil, ""); r.status != 403 {
		t.Errorf("other account: %d", r.status)
	}
	resp, _ := http.Get(c.srv.URL + "/__fake/requests")
	var recs []Request
	json.NewDecoder(resp.Body).Decode(&recs)
	resp.Body.Close()
	if len(recs) != 6 || recs[0].Credential != "invalid" || recs[1].Credential != "none" || recs[2].Credential != "parent" ||
		recs[2].Query != "name=example.com" || recs[3].Path != v4+"/accounts/"+acct+"/r2/buckets/b/objects/a%2Fb" || recs[4].Route != "" {
		t.Fatalf("records %+v", recs)
	}
	for _, rec := range recs {
		if strings.Contains(fmt.Sprint(rec), parent) {
			t.Fatal("parent token recorded")
		}
	}
	req, _ := http.NewRequest("DELETE", c.srv.URL+"/__fake/requests", nil)
	http.DefaultClient.Do(req)
	if len(c.f.Requests()) != 0 {
		t.Error("not cleared")
	}
}

func TestTokens(t *testing.T) {
	c := newTC(t)
	pg := c.ok("GET", v4+"/user/tokens/permission_groups", nil)
	if !strings.Contains(string(pg.raw), `"DNS Write"`) {
		t.Fatal("permission groups")
	}
	var ids []string
	for i := 0; i < 3; i++ {
		r := c.ok("POST", v4+"/user/tokens", map[string]any{"name": fmt.Sprintf("aqmas:G%d:host", i),
			"expires_on": c.now.Add(time.Hour).UTC().Format(time.RFC3339),
			"condition":  map[string]any{"request_ip": map[string]any{"in": []string{"192.0.2.1/32"}}},
			"policies": []any{map[string]any{"effect": "allow", "resources": map[string]string{"com.cloudflare.api.account.zone." + zoneID: "*"},
				"permission_groups": []any{map[string]string{"id": "4755a26eedb94da69e1066d98aa820be"}}}}})
		ids = append(ids, r.m["id"].(string))
		if i == 0 {
			v := r.m["value"].(string)
			if r := c.do("GET", v4+"/zones", v, nil, ""); r.status != 200 {
				t.Fatalf("child token refused: %d", r.status)
			}
			if r := c.do("GET", v4+"/user/tokens", v, nil, ""); r.status != 403 {
				t.Errorf("child may list tokens: %d", r.status)
			}
			if r := c.do("GET", v4+"/user/tokens/verify", v, nil, ""); r.m["id"] != ids[0] {
				t.Errorf("verify %s", r.raw)
			}
			recs := c.f.Requests()
			if last := recs[len(recs)-1]; last.Credential != "child" || last.TokenID != ids[0] {
				t.Errorf("record %+v", last)
			}
			// Deleted: no longer valid.
			c.ok("DELETE", v4+"/user/tokens/"+ids[0], nil)
			if r := c.do("GET", v4+"/zones", v, nil, ""); r.status != 401 {
				t.Errorf("deleted token works: %d", r.status)
			}
			if r := c.do("DELETE", v4+"/user/tokens/"+ids[0], parent, nil, ""); r.status != 404 {
				t.Errorf("double delete: %d", r.status)
			}
		}
	}
	if r := c.do("POST", v4+"/user/tokens", parent, map[string]any{"name": "x", "policies": []any{map[string]any{"effect": "allow",
		"resources": map[string]string{"a": "*"}, "permission_groups": []any{map[string]string{"id": "nope"}}}}}, ""); r.status != 400 {
		t.Errorf("unknown permission group: %d", r.status)
	}
	p1 := c.ok("GET", v4+"/user/tokens?per_page=2&page=1", nil)
	p2 := c.ok("GET", v4+"/user/tokens?per_page=2&page=2", nil)
	if len(p1.list) != 2 || len(p2.list) != 1 || p1.ResultInfo["total_pages"].(float64) != 2 || strings.Contains(string(p1.raw), "fakecf-child-") {
		t.Errorf("pagination: %s %s", p1.raw, p2.raw)
	}
	// Expiry: tokens stop working at expires_on.
	r := c.ok("POST", v4+"/user/tokens", map[string]any{"name": "short", "expires_on": c.now.Add(time.Minute).UTC().Format(time.RFC3339),
		"policies": []any{map[string]any{"effect": "allow", "resources": map[string]string{"a": "*"}, "permission_groups": []any{map[string]string{"id": "4755a26eedb94da69e1066d98aa820be"}}}}})
	c.now = c.now.Add(2 * time.Minute)
	if r := c.do("GET", v4+"/zones", r.m["value"].(string), nil, ""); r.status != 401 {
		t.Errorf("expired token works: %d", r.status)
	}
	resp, _ := http.Get(c.srv.URL + "/__fake/tokens")
	body, _ := io.ReadAll(resp.Body)
	var st []TokenState
	json.Unmarshal(body, &st)
	if len(st) != 4 || st[0].Status != "deleted" || st[3].Status != "expired" || strings.Contains(string(body), "fakecf-child-") {
		t.Errorf("token state %s", body)
	}
}

func TestTunnelAccessDNS(t *testing.T) {
	c := newTC(t)
	base := v4 + "/accounts/" + acct + "/cfd_tunnel/" + tunID + "/configurations"
	g := c.ok("GET", base, nil)
	if g.m["version"].(float64) != 1 {
		t.Fatal(string(g.raw))
	}
	cfg := map[string]any{"config": map[string]any{"ingress": []any{map[string]any{"hostname": "a.example.com", "service": "http://x"}, map[string]any{"service": "http_status:404"}}}}
	p := c.ok("PUT", base, cfg)
	if p.m["version"].(float64) != 2 || !strings.Contains(string(c.ok("GET", base, nil).raw), "a.example.com") {
		t.Errorf("put: %s", p.raw)
	}

	apps := v4 + "/accounts/" + acct + "/access/apps"
	a := c.ok("POST", apps, map[string]any{"name": "x", "domain": "x.example.com", "type": "self_hosted"})
	id := a.m["id"].(string)
	if r := c.do("PATCH", apps+"/"+id, parent, map[string]any{"name": "y"}, ""); r.status != 405 || r.Errors[0].Code != 10405 {
		t.Errorf("patch: %d %s", r.status, r.raw)
	}
	u := c.ok("PUT", apps+"/"+id, map[string]any{"name": "y", "domain": "x.example.com"})
	if u.m["aud"] != a.m["aud"] || u.m["name"] != "y" {
		t.Errorf("put keeps aud: %s", u.raw)
	}
	c.ok("POST", apps+"/"+id+"/policies", map[string]any{"name": "p", "decision": "allow"})
	pol := c.ok("POST", v4+"/accounts/"+acct+"/access/policies", map[string]any{"name": "p", "decision": "allow"})
	if pol.m["reusable"] != true {
		t.Error("reusable")
	}
	c.ok("POST", v4+"/accounts/"+acct+"/access/groups", map[string]any{"name": "g"})
	c.ok("DELETE", apps+"/"+id, nil)
	if r := c.do("GET", apps+"/"+id, parent, nil, ""); r.status != 404 {
		t.Error("deleted app still there")
	}

	dns := v4 + "/zones/" + zoneID + "/dns_records"
	rec := c.ok("POST", dns, map[string]any{"type": "A", "name": "foo", "content": "192.0.2.1", "proxied": true})
	c.ok("POST", dns, map[string]any{"type": "CNAME", "name": "bar.example.com", "content": "x.cfargotunnel.com"})
	if rec.m["name"] != "foo.example.com" {
		t.Errorf("name: %s", rec.raw)
	}
	l := c.ok("GET", dns+"?name=foo.example.com", nil)
	if len(l.list) != 1 {
		t.Errorf("filter: %s", l.raw)
	}
	rid := rec.m["id"].(string)
	c.ok("PATCH", dns+"/"+rid, map[string]any{"content": "192.0.2.2"})
	if g := c.ok("GET", dns+"/"+rid, nil); g.m["content"] != "192.0.2.2" || g.m["type"] != "A" {
		t.Errorf("patch: %s", g.raw)
	}
	c.ok("PUT", dns+"/"+rid, map[string]any{"type": "A", "name": "foo.example.com", "content": "192.0.2.3"})
	c.ok("DELETE", dns+"/"+rid, nil)
	if l := c.ok("GET", dns, nil); len(l.list) != 1 {
		t.Errorf("after delete: %s", l.raw)
	}
	if r := c.do("GET", v4+"/zones/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/dns_records", parent, nil, ""); r.status != 404 {
		t.Errorf("unknown zone: %d", r.status)
	}
}

func TestRulesetsSettingsPurge(t *testing.T) {
	c := newTC(t)
	ep := v4 + "/zones/" + zoneID + "/rulesets/phases/http_request_dynamic_redirect/entrypoint"
	if r := c.do("GET", ep, parent, nil, ""); r.status != 404 {
		t.Fatalf("no entrypoint yet: %d", r.status)
	}
	p := c.ok("PUT", ep, map[string]any{"rules": []any{map[string]any{"expression": "true", "action": "redirect"}}})
	rsID := p.m["id"].(string)
	add := c.ok("POST", v4+"/zones/"+zoneID+"/rulesets/"+rsID+"/rules", map[string]any{"expression": "false", "action": "redirect"})
	rules := add.m["rules"].([]any)
	if len(rules) != 2 || add.m["version"] != "2" {
		t.Fatalf("add: %s", add.raw)
	}
	rid := rules[0].(map[string]any)["id"].(string)
	c.ok("PATCH", v4+"/zones/"+zoneID+"/rulesets/"+rsID+"/rules/"+rid, map[string]any{"enabled": false})
	d := c.ok("DELETE", v4+"/zones/"+zoneID+"/rulesets/"+rsID+"/rules/"+rid, nil)
	if len(d.m["rules"].([]any)) != 1 {
		t.Errorf("delete rule: %s", d.raw)
	}
	if l := c.ok("GET", v4+"/zones/"+zoneID+"/rulesets", nil); len(l.list) != 1 || strings.Contains(string(l.raw), "expression") {
		t.Errorf("list: %s", l.raw)
	}

	s := v4 + "/zones/" + zoneID + "/settings"
	if g := c.ok("GET", s+"/min_tls_version", nil); g.m["value"] != "1.2" {
		t.Errorf("setting: %s", g.raw)
	}
	c.ok("PATCH", s+"/min_tls_version", map[string]any{"value": "1.3"})
	c.ok("PATCH", s, map[string]any{"items": []any{map[string]any{"id": "ssl", "value": "full"}}})
	if g := c.ok("GET", s, nil); !strings.Contains(string(g.raw), `"1.3"`) || !strings.Contains(string(g.raw), `"full"`) {
		t.Errorf("settings: %s", g.raw)
	}
	c.ok("POST", v4+"/zones/"+zoneID+"/purge_cache", map[string]any{"files": []string{"https://example.com/a"}})
}

func TestD1(t *testing.T) {
	c := newTC(t)
	q := v4 + "/accounts/" + acct + "/d1/database/" + dbID + "/query"
	r := c.ok("POST", q, map[string]any{"sql": "CREATE TABLE t(a INTEGER, b TEXT); INSERT INTO t VALUES (1, 'x;y'); -- c;\nSELECT a, b FROM t"})
	if len(r.list) != 3 || !strings.Contains(string(r.list[2]), `"b":"x;y"`) {
		t.Fatalf("query: %s", r.raw)
	}
	raw := c.ok("POST", v4+"/accounts/"+acct+"/d1/database/"+dbID+"/raw", map[string]any{"sql": "SELECT ?1 AS v", "params": []any{5}})
	if !strings.Contains(string(raw.raw), `"rows":[[5]]`) {
		t.Errorf("raw: %s", raw.raw)
	}
	if r := c.do("POST", q, parent, map[string]any{"sql": "SELEC nonsense"}, ""); r.status != 400 {
		t.Errorf("bad sql: %d", r.status)
	}
	if g := c.ok("GET", v4+"/accounts/"+acct+"/d1/database/times", nil); g.m["uuid"] != dbID {
		t.Errorf("lookup by name: %s", g.raw)
	}
}

func multipartBody(fields map[string]string) (*bytes.Buffer, string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		fw, _ := w.CreateFormFile(k, k)
		fw.Write([]byte(v))
	}
	w.Close()
	return &b, w.FormDataContentType()
}

func TestWorkersAssetsAndPages(t *testing.T) {
	c := newTC(t)
	a := v4 + "/accounts/" + acct
	s := c.ok("POST", a+"/workers/scripts/w/assets-upload-session", map[string]any{"manifest": map[string]any{
		"/index.html": map[string]any{"hash": "h1", "size": 3}, "/a.css": map[string]any{"hash": "h2", "size": 3}, "/b.js": map[string]any{"hash": "h3", "size": 3}}})
	jwt := s.m["jwt"].(string)
	if len(s.m["buckets"].([]any)) != 2 || strings.Count(jwt, ".") != 2 {
		t.Fatalf("session: %s", s.raw)
	}
	// The upload route takes only the JWT.
	body, ct := multipartBody(map[string]string{"h1": "YWJj", "h2": "YWJj"})
	if r := c.do("POST", a+"/workers/assets/upload?base64=true", parent, body.Bytes(), ct); r.status != 401 {
		t.Errorf("parent token on the upload route: %d", r.status)
	}
	if r := c.do("POST", a+"/workers/assets/upload?base64=true", jwt, body.Bytes(), ct); r.status != 202 {
		t.Fatalf("bucket 1: %d %s", r.status, r.raw)
	}
	if r := c.do("GET", v4+"/zones", jwt, nil, ""); r.status != 401 {
		t.Errorf("upload JWT on an API route: %d", r.status)
	}
	body, ct = multipartBody(map[string]string{"h3": "YWJj"})
	done := c.do("POST", a+"/workers/assets/upload?base64=true", jwt, body.Bytes(), ct)
	completion, _ := done.m["jwt"].(string)
	if done.status != 201 || completion == "" {
		t.Fatalf("bucket 2: %d %s", done.status, done.raw)
	}
	meta := `{"main_module":"index.js","compatibility_date":"2025-01-01","assets":{"jwt":"` + completion + `"},"bindings":[{"type":"secret_text","name":"S","text":"x"}]}`
	body, ct = multipartBody(map[string]string{"metadata": meta, "index.js": "export default {}"})
	if r := c.do("PUT", a+"/workers/scripts/w", parent, body.Bytes(), ct); r.status != 200 || r.m["has_assets"] != true {
		t.Fatalf("script put: %d %s", r.status, r.raw)
	}
	c.ok("PUT", a+"/workers/scripts/w/schedules", []any{map[string]any{"cron": "*/5 * * * *"}})
	c.ok("PUT", a+"/workers/scripts/w/secrets", map[string]any{"name": "T", "text": "v", "type": "secret_text"})
	if l := c.ok("GET", a+"/workers/scripts/w/secrets", nil); len(l.list) != 2 {
		t.Errorf("secrets: %s", l.raw)
	}
	// Assets already uploaded: the session answers with a completion token at once.
	if s2 := c.ok("POST", a+"/workers/scripts/w/assets-upload-session", map[string]any{"manifest": map[string]any{"/index.html": map[string]any{"hash": "h1", "size": 3}}}); len(s2.m["buckets"].([]any)) != 0 {
		t.Errorf("no buckets expected: %s", s2.raw)
	}

	// Pages: upload-token JWT, check-missing, upload, deploy.
	p := c.ok("GET", a+"/pages/projects/site/upload-token", nil)
	pj := p.m["jwt"].(string)
	m := c.do("POST", v4+"/pages/assets/check-missing", pj, map[string]any{"hashes": []string{"p1"}}, "")
	if m.status != 200 || len(m.list) != 1 {
		t.Fatalf("check-missing: %s", m.raw)
	}
	if r := c.do("POST", v4+"/pages/assets/upload", parent, []any{}, ""); r.status != 401 {
		t.Errorf("parent token on pages upload: %d", r.status)
	}
	c.do("POST", v4+"/pages/assets/upload", pj, []any{map[string]any{"key": "p1", "value": "YWJj", "base64": true}}, "")
	body, ct = multipartBody(map[string]string{"manifest": `{"/index.html":"p1"}`, "branch": "main"})
	d := c.do("POST", a+"/pages/projects/site/deployments", parent, body.Bytes(), ct)
	if d.status != 200 || d.m["environment"] != "production" {
		t.Fatalf("deploy: %s", d.raw)
	}
	body, ct = multipartBody(map[string]string{"manifest": `{"/x.html":"never-uploaded"}`})
	if r := c.do("POST", a+"/pages/projects/site/deployments", parent, body.Bytes(), ct); r.status != 400 {
		t.Errorf("deploy with a missing asset: %d", r.status)
	}
}

func TestSplitSQL(t *testing.T) {
	got := splitSQL("a; 'b;c' ; -- d;e\n f /* g; */ ;; \"h;\"")
	if strings.Join(got, "|") != "a|'b;c'|f|\"h;\"" {
		t.Errorf("%q", got)
	}
}
