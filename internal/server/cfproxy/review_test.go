package cfproxy

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Regression tests for the M2 review findings (protected hostnames everywhere, data bindings,
// case-folded JSON keys, unannotated admin paths, D1 body shapes, snapshot access, email
// forwarding, Workers route ownership and service URL normalisation).

func expectGuard(t *testing.T, r res, guard string) {
	t.Helper()
	expect(t, r, 403, api.CFErrGuardRail)
	if !strings.Contains(r.Body.String(), guard) {
		t.Fatalf("want guard %s: %s", guard, r.Body)
	}
}

func TestProtectedWorkersAndPages(t *testing.T) {
	h := newHarness(t)
	h.grant("WZ", api.CFScopeWorkersDeploy, map[string]string{"script": "hello", "zone": "example.com"})
	h.grant("PG", api.CFScopePages, map[string]string{"project": "blog"})
	h.grant("A", api.CFScopeAdmin, nil)
	w := "/accounts/" + acct + "/workers"
	dom := `{"hostname":"id.example.com","service":"hello","zone_id":"` + zoneA + `","environment":"production","override_existing_dns_record":true}`
	expectGuard(t, h.call("PUT", w+"/domains", dom, g("WZ")), GProtectedHost)
	expectGuard(t, h.call("PUT", w+"/domains", dom, g("A")), GProtectedHost)
	expect(t, h.call("PUT", w+"/domains", dom, gh("A", api.CFOverrideHeader, GProtectedHost)), 400, api.CFErrBadRequest)
	expectGuard(t, h.call("PUT", w+"/scripts/hello/domains/records", `{"origins":[{"hostname":"ID.Example.com."}]}`, g("WZ")), GProtectedHost)
	expectGuard(t, h.call("POST", w+"/scripts/hello/domains/changeset?replace_state=true", `[{"hostname":"id.example.com"}]`, g("WZ")), GProtectedHost)
	zr := "/zones/" + zoneA + "/workers/routes"
	for _, p := range []string{"id.example.com/*", "*example.com/*", "*.example.com/*", "https://id.example.com:443/x*", "ID.EXAMPLE.COM/*"} {
		expectGuard(t, h.call("POST", zr, map[string]any{"pattern": p, "script": "hello"}, g("WZ")), GProtectedHost)
	}
	expect(t, h.call("POST", zr, map[string]any{"pattern": "app.example.com/*", "script": "hello"}, g("WZ")), 200, "")
	// Removing the custom domain of a protected hostname: never, not even with the
	// workers-domain-remove override.
	h.cf.result("GET "+w+"/domains", []any{map[string]any{"id": "d1", "hostname": "id.example.com"}, map[string]any{"id": "d2", "hostname": "app.example.com"}})
	expectGuard(t, h.call("DELETE", w+"/domains/d1", nil, gh("A", api.CFOverrideHeader, GWorkersDomainRm)), GProtectedHost)
	expect(t, h.call("DELETE", w+"/domains/d2", nil, gh("A", api.CFOverrideHeader, GWorkersDomainRm)), 200, "")
	// Pages custom domains.
	pd := "/accounts/" + acct + "/pages/projects/blog/domains"
	expectGuard(t, h.call("POST", pd, `{"name":"id.example.com"}`, g("PG")), GProtectedHost)
	expectGuard(t, h.call("DELETE", pd+"/id.example.com", nil, g("PG")), GProtectedHost)
	expect(t, h.call("POST", pd, `{"name":"blog.example.com"}`, g("PG")), 200, "")
}

func TestProtectedR2Domains(t *testing.T) {
	h := newHarness(t)
	h.grant("R2", api.CFScopeR2Admin, nil)
	cd := "/accounts/" + acct + "/r2/buckets/photos/domains/custom"
	expectGuard(t, h.call("POST", cd, `{"domain":"id.example.com","zoneId":"`+zoneA+`","enabled":true}`, g("R2")), GProtectedHost)
	expect(t, h.call("POST", cd, `{"domain":"files.example.com","zoneId":"`+zoneA+`","enabled":true}`, g("R2")), 200, "")
	expect(t, h.call("POST", cd, `{"domain":"files.example.net","enabled":true}`, g("R2")), 403, api.CFErrNoGrant)
	expect(t, h.call("POST", cd, `{"domain":"files.example.com","zoneId":"`+zoneB+`","enabled":true}`, g("R2")), 403, api.CFErrNoGrant)
	expectGuard(t, h.call("DELETE", cd+"/id.example.com", nil, g("R2")), GProtectedHost)
	expect(t, h.call("PUT", cd+"/files.example.com", `{"enabled":false}`, g("R2")), 200, "")
}

func TestProtectedTunnelRules(t *testing.T) {
	h := newHarness(t)
	h.grant("T", api.CFScopeTunnelConfig, map[string]string{"tunnel": "home"})
	h.grant("A", api.CFScopeAdmin, nil)
	idRule := map[string]any{"hostname": "id.example.com", "service": "https://192.0.2.10:8443",
		"originRequest": map[string]any{"originServerName": "id.example.com", "matchSNItoHost": true, "http2Origin": true}}
	live := map[string]any{"version": 4, "config": map[string]any{"ingress": []any{idRule, map[string]any{"service": "http_status:404"}}}}
	h.cf.result("GET "+tunPath, live)
	expect(t, h.call("GET", tunPath, nil, g("T")), 200, "")
	body := func(rules ...any) map[string]any {
		return map[string]any{"config": map[string]any{"ingress": append(rules, map[string]any{"service": "http_status:404"})}}
	}
	other := map[string]any{"hostname": "app.example.com", "service": "http://198.51.100.7:8080"}
	expect(t, h.call("PUT", tunPath, body(idRule, other), g("T")), 200, "")
	changed := map[string]any{"hostname": "id.example.com", "service": "http://198.51.100.7:8080"}
	expectGuard(t, h.call("PUT", tunPath, body(changed), g("T")), GProtectedHost)
	expectGuard(t, h.call("PUT", tunPath, body(other), g("T")), GProtectedHost)                                                                                 // removed
	expectGuard(t, h.call("PUT", tunPath, body(map[string]any{"hostname": "*.example.com", "service": "http://198.51.100.7"}, idRule), g("T")), GProtectedHost) // wildcard added in front
	expectGuard(t, h.call("PUT", tunPath, body(idRule, map[string]any{"hostname": "ID.example.com", "service": "http://198.51.100.7"}), g("T")), GProtectedHost)
	gb := body(idRule)
	gb["config"].(map[string]any)["originRequest"] = map[string]any{"connectTimeout": "5s"}
	expectGuard(t, h.call("PUT", tunPath, gb, g("T")), GProtectedHost)
	expect(t, h.call("GET", tunPath, nil, g("A")), 200, "")
	expect(t, h.call("PUT", tunPath, body(changed), gh("A", api.CFOverrideHeader, GProtectedHost)), 400, api.CFErrBadRequest)
	expectGuard(t, h.call("PUT", tunPath, body(changed), g("A")), GProtectedHost)
}

func TestProtectedDNSNeverOverridable(t *testing.T) {
	h := newHarness(t)
	h.grant("A", api.CFScopeAdmin, nil)
	recs := "/zones/" + zoneA + "/dns_records"
	h.cf.result("GET "+recs+"/r1", map[string]any{"id": "r1", "name": "id.example.com", "type": "CNAME", "content": "x.cfargotunnel.com"})
	expectGuard(t, h.call("PUT", recs+"/r1", map[string]any{"name": "id", "type": "CNAME", "content": "evil.example.net"}, gh("A", api.CFOverrideHeader, GDNSProtected)), GProtectedHost)
	expectGuard(t, h.call("DELETE", recs+"/r1", nil, gh("A", api.CFOverrideHeader, GDNSProtected)), GProtectedHost)
	expectGuard(t, h.call("POST", recs, map[string]any{"name": "*.example.com", "type": "A", "content": "203.0.113.9"}, gh("A", api.CFOverrideHeader, GDNSProtected)), GProtectedHost)
}

// ---- data bindings ----

func mpParts(parts ...[3]string) (string, string) { // name, header extra ("qp"), body
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for _, p := range parts {
		hdr := textproto.MIMEHeader{"Content-Disposition": {`form-data; name="` + p[0] + `"`}, "Content-Type": {"application/json"}}
		if p[1] == "qp" {
			hdr.Set("Content-Transfer-Encoding", "quoted-printable")
		}
		pw, _ := mw.CreatePart(hdr)
		_, _ = pw.Write([]byte(p[2]))
	}
	_ = mw.Close()
	return b.String(), mw.FormDataContentType()
}

func TestWorkerBindings(t *testing.T) {
	h := newHarness(t, func(c *config.Cloudflare) {
		c.WorkerBindings = []config.CFBindings{{Script: "allowed", Allow: []string{"d1:app-db", "r2:assets", "service:auth"}},
			{PagesProject: "site", Allow: []string{"d1:app-db"}}}
	})
	h.grant("W", api.CFScopeWorkersDeploy, map[string]string{"script": "hello"})
	h.grant("WA", api.CFScopeWorkersDeploy, map[string]string{"script": "allowed"})
	h.grant("A", api.CFScopeAdmin, nil)
	d1 := `{"type":"d1","name":"DB","id":"` + dbTT + `"}`
	put := func(script, grant, meta string) res {
		b, ct := mpParts([3]string{"metadata", "", meta}, [3]string{"w.js", "", "export default {}"})
		return h.call("PUT", "/accounts/"+acct+"/workers/scripts/"+script, b, gh(grant, "Content-Type", ct))
	}
	free := `{"main_module":"w.js","bindings":[{"type":"plain_text","name":"X","text":"y"},{"type":"secret_text","name":"S","text":"z"},{"type":"durable_object_namespace","name":"D","class_name":"C"},{"type":"assets","name":"ASSETS"},{"type":"ai","name":"AI"}]}`
	expect(t, put("hello", "W", free), 200, "")
	for _, m := range []string{
		`{"bindings":[` + d1 + `]}`,
		`{"bindings":[{"type":"r2_bucket","name":"B","bucket_name":"assets"}]}`,
		`{"bindings":[{"type":"kv_namespace","name":"K","namespace_id":"abc"}]}`,
		`{"bindings":[{"type":"service","name":"S","service":"auth"}]}`,
		`{"bindings":[{"type":"durable_object_namespace","name":"D","class_name":"C","script_name":"other"}]}`,
		`{"bindings":[{"type":"queue","name":"Q","queue_name":"q"}]}`,
		`{"bindings":[{"type":"unsafe_whatever","name":"U"}]}`,
		`{"bindings":[],"tail_consumers":[{"service":"spy"}]}`,
	} {
		r := put("hello", "W", m)
		expect(t, r, 403, api.CFErrNoGrant)
	}
	expect(t, put("allowed", "WA", `{"bindings":[`+d1+`,{"type":"r2_bucket","name":"B","bucket_name":"assets"},{"type":"service","name":"S","service":"auth"}]}`), 200, "")
	expect(t, put("allowed", "WA", `{"bindings":[{"type":"r2_bucket","name":"B","bucket_name":"secrets"}]}`), 403, api.CFErrNoGrant)
	expect(t, put("hello", "A", `{"bindings":[`+d1+`]}`), 200, "") // cf.admin is not limited
	// Malformed uploads.
	for _, parts := range [][][3]string{
		{{"metadata", "", free}, {"metadata", "", `{"bindings":[` + d1 + `]}`}},
		{{"Metadata", "", `{"bindings":[` + d1 + `]}`}},
		{{"metadata", "qp", free}},
		{{"w.js", "", "x"}},
		{{"metadata", "", `{"Bindings":[` + d1 + `],"bindings":[]}`}},
	} {
		b, ct := mpParts(parts...)
		expect(t, h.call("PUT", "/accounts/"+acct+"/workers/scripts/hello", b, gh("W", "Content-Type", ct)), 400, api.CFErrBadRequest)
	}
	expect(t, h.call("PUT", "/accounts/"+acct+"/workers/scripts/hello", "export default {}", gh("W", "Content-Type", "application/javascript")), 400, api.CFErrBadRequest)
	// versions upload and settings (JSON and multipart).
	b, ct := mpParts([3]string{"metadata", "", `{"bindings":[` + d1 + `]}`})
	expect(t, h.call("POST", "/accounts/"+acct+"/workers/scripts/hello/versions?bindings_inherit=strict", b, gh("W", "Content-Type", ct)), 403, api.CFErrNoGrant)
	h.cf.result("GET /accounts/"+acct+"/workers/scripts/hello/settings", map[string]any{"bindings": []any{}})
	h.cf.result("GET /accounts/"+acct+"/workers/scripts/hello/script-settings", map[string]any{})
	expect(t, h.call("PATCH", "/accounts/"+acct+"/workers/scripts/hello/settings", `{"bindings":[`+d1+`]}`, g("W")), 403, api.CFErrNoGrant)
	b, ct = mpParts([3]string{"settings", "", `{"bindings":[` + d1 + `]}`})
	expect(t, h.call("PATCH", "/accounts/"+acct+"/workers/scripts/hello/settings", b, gh("W", "Content-Type", ct)), 403, api.CFErrNoGrant)
	expect(t, h.call("PATCH", "/accounts/"+acct+"/workers/scripts/hello/script-settings", `{"logpush":false,"tail_consumers":[{"service":"spy"}]}`, g("W")), 403, api.CFErrNoGrant)
	expect(t, h.call("PATCH", "/accounts/"+acct+"/workers/scripts/hello/script-settings", `{"logpush":false,"observability":{"enabled":true}}`, g("W")), 200, "")

	// Pages project bindings.
	h.grant("PB", api.CFScopePages, map[string]string{"project": "blog"})
	h.grant("PS", api.CFScopePages, map[string]string{"project": "site"})
	pd1 := `{"deployment_configs":{"production":{"d1_databases":{"DB":{"id":"` + dbTT + `"}}}}}`
	expect(t, h.call("PATCH", "/accounts/"+acct+"/pages/projects/blog", pd1, g("PB")), 403, api.CFErrNoGrant)
	expect(t, h.call("PATCH", "/accounts/"+acct+"/pages/projects/site", pd1, g("PS")), 200, "")
	expect(t, h.call("PATCH", "/accounts/"+acct+"/pages/projects/blog", `{"deployment_configs":{"production":{"env_vars":{"A":{"type":"plain_text","value":"b"}},"d1_databases":{"OLD":null}}}}`, g("PB")), 200, "")
	expect(t, h.call("PATCH", "/accounts/"+acct+"/pages/projects/blog", `{"deployment_configs":{"production":{"new_binding_kind":{"X":{"id":"y"}}}}}`, g("PB")), 403, api.CFErrNoGrant)
	expect(t, h.call("PATCH", "/accounts/"+acct+"/pages/projects/blog", `{"deployment_configs":{"production":{"kv_namespaces":{"K":{"namespace_id":"n"}}}}}`, g("PB")), 403, api.CFErrNoGrant)
}

// ---- case-folded and duplicate JSON keys ----

func TestCaseFoldedKeys(t *testing.T) {
	h := newHarness(t)
	h.grant("AP", api.CFScopeAccessApps, nil)
	h.grant("T", api.CFScopeTunnelConfig, map[string]string{"tunnel": "home"})
	h.grant("D1", api.CFScopeD1, map[string]string{"db": "app-db", "access": "read"})
	apps := "/accounts/" + acct + "/access/apps"
	for _, b := range []string{
		`{"type":"self_hosted","Domain":"id.example.com"}`,
		`{"type":"self_hosted","domain":"ok.example.com","DOMAIN":"id.example.com"}`,
		`{"type":"self_hosted","domain":"ok.example.com","domain":"id.example.com"}`,
		`{"type":"self_hosted","domain":"ok.example.com","domain":"id.example.com"}`,
		`{"type":"self_hosted","domain":"ok.example.com","self_hosted_domains":["ok.example.com"],"Self_Hosted_Domains":["id.example.com"]}`,
		"{\"type\":\"self_hosted\",\"domain\":\"ok.example.com\",\"x\":\"\xff\"}",
	} {
		expect(t, h.call("POST", apps, b, g("AP")), 400, api.CFErrBadRequest)
	}
	// Unicode folding: the long s folds to "s".
	expect(t, h.call("POST", "/accounts/"+acct+"/d1/database/"+dbTT+"/query", "{\"ſql\":\"DROP TABLE t\",\"sql\":\"SELECT 1\"}", g("D1")), 400, api.CFErrBadRequest)
	// Non-JSON content types are refused; the forwarded type is application/json.
	expect(t, h.call("POST", apps, `{"domain":"ok.example.com"}`, gh("AP", "Content-Type", "text/plain")), 400, api.CFErrBadRequest)
	expect(t, h.call("POST", apps, `{"domain":"ok.example.com"}`, gh("AP", "Content-Type", "application/vnd.api+json")), 200, "")
	if u := h.cf.requests(); u[len(u)-1].CT != "application/json" {
		t.Fatalf("forwarded content type %q", u[len(u)-1].CT)
	}
	// The reviewer's tunnel body: an "OriginRequest" next to "originRequest", "Hostname".
	h.cf.result("GET "+tunPath, liveTunnel(3))
	expect(t, h.call("GET", tunPath, nil, g("T")), 200, "")
	body := `{"config":{"ingress":[{"hostname":"a.example.com","service":"https://192.0.2.10:8443","originRequest":{"originServerName":"a.example.com"},"OriginRequest":{"noTLSVerify":true}},{"Hostname":"b.example.com","Service":"https://192.0.2.10:8443"},{"service":"http_status:404"}]}}`
	expect(t, h.call("PUT", tunPath, body, g("T")), 400, api.CFErrBadRequest)
	if h.cf.count("PUT", "/") != 0 || h.cf.count("POST", "/") != 1 {
		t.Fatal("refused bodies forwarded")
	}
}

// ---- cf.admin on unannotated paths ----

func TestAdminUnannotatedDenied(t *testing.T) {
	h := newHarness(t)
	h.grant("A", api.CFScopeAdmin, nil)
	z := "/zones/" + zoneA
	for _, c := range [][2]string{
		{"POST", z + "/access/apps"},
		{"PUT", z + "/access/apps/x"},
		{"POST", z + "/dns_records/batch"},
		{"POST", z + "/dns_records/import"},
		{"PUT", z + "/dns_records"},
		{"PUT", "/accounts/" + acct + "/access/apps/x/settings"},
		{"PATCH", z},
		{"POST", z + "/pagerules"},
		{"PUT", z + "/snippets/s1"},
		{"POST", z + "/load_balancers"},
		{"POST", z + "/custom_hostnames"},
		{"POST", z + "/rulesets"},
		{"DELETE", z + "/rulesets/rs1"},
		{"PATCH", z + "/hostnames/settings/min_tls_version/id.example.com"},
		{"PUT", "/accounts/" + acct + "/workers/services/hello/environments/production"},
		{"POST", "/accounts/" + acct + "/workers/workers"},
		{"PUT", "/accounts/" + acct + "/workers/domains/records/d1"},
		{"POST", "/accounts/" + acct + "/tunnels"},
	} {
		expect(t, h.call(c[0], c[1], `{}`, g("A")), 403, api.CFErrDenied)
	}
	if n := len(h.cf.requests()); n != 0 {
		t.Fatalf("%d upstream calls", n)
	}
	// Replacing a ruleset by id is guarded like the entrypoint.
	h.grant("RS", api.CFScopeRulesets, map[string]string{"zone": "example.com"})
	h.cf.result("GET "+z+"/rulesets/rs1", map[string]any{"id": "rs1", "phase": "http_request_dynamic_redirect", "rules": []any{map[string]any{"id": "r1"}}})
	expectGuard(t, h.call("PUT", z+"/rulesets/rs1", map[string]any{"rules": []any{}}, g("RS")), GRulesetKeepRules)
	expect(t, h.call("PUT", z+"/rulesets/rs1", map[string]any{"rules": []any{map[string]any{"id": "r1"}, map[string]any{"expression": `http.host eq "app.example.com"`}}}, g("RS")), 200, "")
}

// ---- D1 body shapes ----

func TestD1BodyShapes(t *testing.T) {
	h := newHarness(t)
	h.grant("RO", api.CFScopeD1, map[string]string{"db": "app-db", "access": "read"})
	h.grant("MG", api.CFScopeD1, map[string]string{"db": "app-db", "access": "migrate"})
	q := "/accounts/" + acct + "/d1/database/" + dbTT + "/query"
	for _, b := range []string{
		`{"batch":[{"sql":"SELECT 1"}],"sql":"DROP TABLE users"}`,
		`{"sql":"SELECT 1","query":"DROP TABLE users"}`,
		`{"batch":[{"sql":"SELECT 1"},{"sql":"DROP TABLE users"}]}`,
		`{"batch":[{"sql":"SELECT 1","statement":"DROP TABLE users"}]}`,
		`[{"sql":"SELECT 1"},{"sql":"DELETE FROM users"}]`,
		`{"sql":"SELECT 1","params":"x"}`,
		`{"batch":[]}`,
	} {
		expect(t, h.call("POST", q, b, g("RO")), 403, api.CFErrNoGrant)
	}
	expect(t, h.call("POST", q, `{"batch":[{"sql":"SELECT 1","params":[]},{"sql":"SELECT 2"}]}`, g("RO")), 200, "")
	expect(t, h.call("POST", q, `{"sql":"DROP TABLE x","extra":1}`, g("MG")), 403, api.CFErrNoGrant)
	expect(t, h.call("POST", q, `{"sql":"DROP TABLE x","params":[]}`, g("MG")), 200, "")
}

// ---- snapshot access ----

func TestSnapshotAccess(t *testing.T) {
	h := newHarness(t)
	h.grant("W", api.CFScopeWorkersDeploy, map[string]string{"script": "hello"})
	h.grant("D", api.CFScopeDNSEdit, map[string]string{"zone": "example.com"})
	h.cf.result("GET /accounts/"+acct+"/workers/scripts/hello/script-settings", map[string]any{"logpush": true})
	h.cf.result("GET /zones/"+zoneA+"/dns_records/a1", map[string]any{"id": "a1", "name": "www.example.com", "type": "A", "content": "203.0.113.1"})
	rs := h.call("PATCH", "/accounts/"+acct+"/workers/scripts/hello/script-settings", `{"logpush":false}`, g("W"))
	rd := h.call("PUT", "/zones/"+zoneA+"/dns_records/a1", map[string]any{"name": "www", "type": "A", "content": "203.0.113.2"}, g("D"))
	settingsID, dnsID := rs.Header().Get(api.CFSnapshotBeforeHeader), rd.Header().Get(api.CFSnapshotBeforeHeader)
	// No cf.read.private / cf.workers.deploy / cf.admin among the active scopes: settings hidden.
	h.grants.scopes = []string{api.CFScopeRead}
	if _, l := h.snapList(""); len(l.Snapshots) != 2 {
		t.Fatalf("visible %d", len(l.Snapshots))
	}
	if c, _ := h.snapGet(settingsID); c != 403 {
		t.Fatalf("sensitive get %d", c)
	}
	h.grants.scopes = []string{api.CFScopeWorkersDeploy}
	if _, l := h.snapList(""); len(l.Snapshots) != 4 {
		t.Fatalf("visible %d", len(l.Snapshots))
	}
	if c, _ := h.snapGet(settingsID); c != 200 {
		t.Fatalf("sensitive get with scope %d", c)
	}
	// Another host sees none of them.
	h.caller = Caller{HostID: 2, HostName: "hostb", PeerAddress: peer}
	if _, l := h.snapList(""); len(l.Snapshots) != 0 {
		t.Fatalf("other host sees %d", len(l.Snapshots))
	}
	if c, _ := h.snapGet(dnsID); c != 404 {
		t.Fatalf("other host get %d", c)
	}
}

// ---- email routing ----

func TestEmailForwarding(t *testing.T) {
	h := newHarness(t, func(c *config.Cloudflare) { c.EmailForwardAllow = []string{"Owner@example.net"} })
	h.grant("E", api.CFScopeEmail, map[string]string{"zone": "example.com"})
	h.grant("A", api.CFScopeAdmin, nil)
	rules := "/zones/" + zoneA + "/email/routing/rules"
	rule := func(action string) string {
		return `{"matchers":[{"type":"literal","field":"to","value":"a@example.com"}],"actions":[` + action + `],"enabled":true}`
	}
	expect(t, h.call("POST", rules, rule(`{"type":"forward","value":["owner@example.net"]}`), g("E")), 200, "")
	expect(t, h.call("POST", rules, rule(`{"type":"drop"}`), g("E")), 200, "")
	expectGuard(t, h.call("POST", rules, rule(`{"type":"forward","value":["owner@example.net","spy@example.org"]}`), g("E")), GEmailForward)
	expectGuard(t, h.call("POST", rules, rule(`{"type":"worker","value":["mailer"]}`), g("E")), GEmailForward)
	expectGuard(t, h.call("PUT", rules+"/catch_all", rule(`{"type":"forward","value":["spy@example.org"]}`), g("E")), GEmailForward)
	expect(t, h.call("PUT", rules+"/catch_all", rule(`{"type":"forward","value":["spy@example.org"]}`), gh("A", api.CFOverrideHeader, GEmailForward)), 200, "")
	addrs := "/accounts/" + acct + "/email/routing/addresses"
	expectGuard(t, h.call("POST", addrs, `{"email":"spy@example.org"}`, g("E")), GEmailForward)
	expect(t, h.call("POST", addrs, `{"email":"owner@example.net"}`, g("E")), 200, "")
}

// ---- Workers route ownership, service URL forms ----

func TestWorkersRouteOwnership(t *testing.T) {
	h := newHarness(t)
	h.grant("WZ", api.CFScopeWorkersDeploy, map[string]string{"script": "hello", "zone": "example.com"})
	zr := "/zones/" + zoneA + "/workers/routes"
	h.cf.result("GET "+zr, []any{map[string]any{"id": "mine", "pattern": "app.example.com/*", "script": "hello"}, map[string]any{"id": "theirs", "pattern": "other.example.com/*", "script": "other"}})
	expect(t, h.call("DELETE", zr+"/theirs", nil, g("WZ")), 403, api.CFErrNoGrant)
	expect(t, h.call("PUT", zr+"/theirs", map[string]any{"pattern": "other.example.com/*", "script": "hello"}, g("WZ")), 403, api.CFErrNoGrant)
	expect(t, h.call("DELETE", zr+"/missing", nil, g("WZ")), 403, api.CFErrNoGrant)
	expect(t, h.call("DELETE", zr+"/mine", nil, g("WZ")), 200, "")
}

func TestServiceURLForms(t *testing.T) {
	traefik := "https://192.0.2.10:8443"
	for _, s := range []string{"https://192.000.002.010:8443", "https://[::ffff:192.0.2.10]:8443", "HTTPS://192.0.2.10:8443/", "https://192.0.2.012:8443"} {
		if !sameService(s, traefik) {
			t.Errorf("%s should match", s)
		}
		rules := []ingressRule{{hostname: "n.example.com", service: s}}
		if f, _ := guardTunnelTraefikSNI(rules, traefik); f == nil {
			t.Errorf("%s: SNI guard did not apply", s)
		}
	}
	for _, s := range []string{"https://192.0.2.11:8443", "http://192.0.2.10:8443", "https://192.0.2.10:443"} {
		if sameService(s, traefik) {
			t.Errorf("%s should not match", s)
		}
	}
	plain := []string{"http://192.0.2.10"}
	for _, s := range []string{"http://192.0.2.10:80", "http://192.0.2.10:0080", "http://[::ffff:c000:20a]"} {
		if guardTunnelPlainOrigin([]ingressRule{{hostname: "n.example.com", service: s}}, plain) == nil {
			t.Errorf("%s: plain origin not caught", s)
		}
	}
}

func TestProtectedHitHelpers(t *testing.T) {
	prot := []string{"id.example.com"}
	for _, c := range []string{"id.example.com", "ID.EXAMPLE.COM.", "*.example.com", "*example.com", "*", "https://id.example.com:8443/x", "id.example.com@evil", "іd.example.com"} {
		if _, hit := protectedHit(c, prot); !hit {
			t.Errorf("%q should hit", c)
		}
	}
	for _, c := range []string{"app.example.com", "example.com", "id.example.com.evil.net", "*.app.example.com"} {
		if _, hit := protectedHit(c, prot); hit {
			t.Errorf("%q should not hit", c)
		}
	}
	if _, hit := protectedHit("a.id.example.com", []string{"*.id.example.com"}); !hit {
		t.Error("protected wildcard")
	}
	_ = http.MethodGet
}
