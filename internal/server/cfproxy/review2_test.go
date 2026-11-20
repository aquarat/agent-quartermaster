package cfproxy

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Regression tests for the second review (guard-code findings).

func TestTunnelHostlessRuleBeforeProtected(t *testing.T) {
	h := newHarness(t)
	h.grant("T1", api.CFScopeTunnelConfig, map[string]string{"tunnel": "home"})
	idRule := map[string]any{"hostname": "id.example.com", "service": "http://192.0.2.20:1411"}
	h.cf.result("GET "+tunPath, map[string]any{"version": 3, "config": map[string]any{"ingress": []any{idRule, map[string]any{"service": "http_status:404"}}}})
	expect(t, h.call("GET", tunPath, nil, g("T1")), 200, "")
	body := func(rules ...any) map[string]any {
		return map[string]any{"config": map[string]any{"ingress": append(rules, map[string]any{"service": "http_status:404"})}}
	}
	pathRule := map[string]any{"path": "^/", "service": "http://203.0.113.66:80"}
	expectGuard(t, h.call("PUT", tunPath, body(pathRule, idRule), g("T1")), GProtectedHost)
	expectGuard(t, h.call("PUT", tunPath, body(map[string]any{"hostname": "*", "service": "http://203.0.113.66"}, idRule), g("T1")), GProtectedHost)
	// After the protected rule a hostless rule changes nothing for it.
	expect(t, h.call("PUT", tunPath, body(idRule, pathRule), g("T1")), 200, "")
}

func workerPut(h *harness, grant, script, meta string) res {
	b, ct := mpParts([3]string{"metadata", "", meta}, [3]string{"w.js", "", "export default {}"})
	return h.call("PUT", "/accounts/"+acct+"/workers/scripts/"+script, b, gh(grant, "Content-Type", ct))
}

func TestWorkersMigrationsAndAliases(t *testing.T) {
	h := newHarness(t, func(c *config.Cloudflare) {
		c.WorkerBindings = []config.CFBindings{{Script: "evil", Allow: []string{"d1:app-db"}}, {Script: "heir", Allow: []string{"durable_object:victim"}}}
	})
	h.grant("W", api.CFScopeWorkersDeploy, map[string]string{"script": "evil"})
	h.grant("H", api.CFScopeWorkersDeploy, map[string]string{"script": "heir"})
	transfer := `{"main_module":"w.js","bindings":[{"type":"durable_object_namespace","name":"D","class_name":"Vault"}],"migrations":{"new_tag":"v2","transferred_classes":[{"from":"Vault","from_script":"victim","to":"Vault"}]}}`
	expect(t, workerPut(h, "W", "evil", transfer), 403, api.CFErrNoGrant)
	expect(t, workerPut(h, "W", "evil", `{"migrations":{"steps":[{"renamed_classes":[{"from":"A","to":"B"}]},{"transferred_classes":[{"from":"X","from_script":"victim","to":"X"}]}]}}`), 403, api.CFErrNoGrant)
	expect(t, workerPut(h, "W", "evil", `{"migrations":{"new_tag":"v3","renamed_classes":[{"from":"A","to":"B"}],"deleted_classes":["C"]}}`), 200, "")
	expect(t, workerPut(h, "H", "heir", transfer), 200, "")
	// D1 with two different ids, alias fields.
	expect(t, workerPut(h, "W", "evil", `{"bindings":[{"type":"d1","name":"DB","id":"`+dbTT+`","database_id":"99999999-2222-4333-8444-555555555555"}]}`), 403, api.CFErrNoGrant)
	expect(t, workerPut(h, "W", "evil", `{"bindings":[{"type":"d1","name":"DB","id":"`+dbTT+`","database_id":"`+dbTT+`"}]}`), 200, "")
	expect(t, workerPut(h, "W", "evil", `{"bindings":[{"type":"d1","name":"DB","id":"`+dbTT+`","database_name":"other"}]}`), 403, api.CFErrNoGrant)
	expect(t, workerPut(h, "W", "evil", `{"bindings":[{"type":"kv_namespace","name":"K","namespace_id":"ok","id":"victimkv"}]}`), 403, api.CFErrNoGrant)
}

func TestMultipartDifferential(t *testing.T) {
	h := newHarness(t)
	h.grant("W", api.CFScopeWorkersDeploy, map[string]string{"script": "evil"})
	u := "/accounts/" + acct + "/workers/scripts/evil"
	const bd = "BOUND"
	mp := func(parts ...string) string {
		return "--" + bd + "\r\n" + strings.Join(parts, "\r\n--"+bd+"\r\n") + "\r\n--" + bd + "--\r\n"
	}
	kv := `{"bindings":[{"type":"kv_namespace","name":"K","namespace_id":"victimkv"}]}`
	for _, body := range []string{
		mp("Content-Disposition: form-data; name=\"metadata\"\r\nContent-Disposition: form-data; name=\"decoy\"\r\nContent-Type: application/json\r\n\r\n{\"bindings\":[]}",
			"Content-Disposition: form-data; name=\"decoy\"\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n"+kv),
		mp("Content-Disposition: form-data; name=\"x\"; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n"+kv,
			"Content-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"bindings\":[]}"),
		mp("Content-Disposition: form-data; name=\"metadata\"\r\n\r\n{\"bindings\":[]}", "Content-Disposition: form-data; name=\"metadata\"\r\n\r\n"+kv),
		mp("Content-Disposition: form-data; name=\"metadata\"\r\nX-Extra: 1\r\n\r\n{\"bindings\":[]}"),
		mp("Content-Disposition: form-data; name*=utf-8''metadata\r\n\r\n" + kv),
		mp("Content-Disposition: attachment; name=\"metadata\"\r\n\r\n{\"bindings\":[]}"),
		mp("Content-Disposition: form-data; name=\"metadata\r\n\r\n{\"bindings\":[]}"),
	} {
		expect(t, h.call("PUT", u, body, gh("W", "Content-Type", "multipart/form-data; boundary="+bd)), 400, api.CFErrBadRequest)
	}
	// A clean upload is re-encoded: preamble/epilogue junk does not reach Cloudflare.
	body := "junk before\r\n" + mp("Content-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"main_module\":\"w.js\"}",
		"Content-Disposition: form-data; name=\"w.js\"; filename=\"w.js\"\r\nContent-Type: application/javascript+module\r\n\r\nexport default {}") + "trailing junk"
	expect(t, h.call("PUT", u, body, gh("W", "Content-Type", "multipart/form-data; boundary="+bd)), 200, "")
	up := h.cf.requests()
	got := string(up[len(up)-1].Body)
	if strings.Contains(got, "junk") || strings.Contains(got, "--BOUND") || !strings.Contains(got, "export default {}") || !strings.Contains(got, `filename="w.js"`) {
		t.Fatalf("forwarded %q", got)
	}
}

func TestRulesetEscapesAndDisable(t *testing.T) {
	h := newHarness(t)
	h.grant("R", api.CFScopeRulesets, map[string]string{"zone": "example.com"})
	h.grant("A", api.CFScopeAdmin, nil)
	z := "/zones/" + zoneA + "/rulesets"
	h.cf.result("GET "+z+"/rs1", map[string]any{"id": "rs1", "phase": "http_request_late_transform", "rules": []any{
		map[string]any{"id": "r1", "expression": `http.host eq "id.example.com"`, "action": "rewrite", "action_parameters": map[string]any{"headers": map[string]any{"Remote-User": map[string]any{"operation": "remove"}}}, "enabled": true}}})
	expectGuard(t, h.call("POST", z+"/rs1/rules", `{"expression":"http.host eq \"\\x69d.example.com\"","action":"rewrite","action_parameters":{"headers":{"Remote-User":{"operation":"set","value":"admin"}}}}`, g("R")), GRulesetProtected)
	expectGuard(t, h.call("POST", z+"/rs1/rules", `{"expression":"http.host eq r#\"app.example.com\"#","action":"rewrite"}`, g("R")), GRulesetProtected)
	expectGuard(t, h.call("PATCH", z+"/rs1/rules/r1", `{"enabled":false}`, g("R")), GRulesetProtectedRemoval)
	expect(t, h.call("PATCH", z+"/rs1/rules/r1", `{"enabled":false}`, gh("A", api.CFOverrideHeader, GRulesetProtectedRemoval)), 200, "")
	expectGuard(t, h.call("POST", z+"/rs1/rules", `{"expression":"http.host eq \"id.example.com\"","action":"rewrite"}`, g("R")), GRulesetProtected)
	expect(t, h.call("POST", z+"/rs1/rules", `{"expression":"http.host eq \"app.example.com\"","action":"rewrite"}`, g("R")), 200, "")
}

// pagesDeployBody: an outer Pages deployment upload whose _worker.bundle carries meta.
func pagesDeployBody(meta string, extra ...string) (string, string) {
	var inner bytes.Buffer
	iw := multipart.NewWriter(&inner)
	pw, _ := iw.CreateFormField("metadata")
	_, _ = pw.Write([]byte(meta))
	fw, _ := iw.CreateFormFile("index.js", "index.js")
	_, _ = fw.Write([]byte("export default {}"))
	_ = iw.Close()
	var outer bytes.Buffer
	ow := multipart.NewWriter(&outer)
	mf, _ := ow.CreateFormField("manifest")
	_, _ = mf.Write([]byte(`{}`))
	bf, _ := ow.CreateFormFile("_worker.bundle", "_worker.bundle")
	_, _ = bf.Write(inner.Bytes())
	for _, e := range extra {
		x, _ := ow.CreateFormFile(e, e)
		_, _ = x.Write([]byte("[[d1_databases]]"))
	}
	_ = ow.Close()
	return outer.String(), ow.FormDataContentType()
}

func TestPagesDeploymentBindings(t *testing.T) {
	h := newHarness(t, func(c *config.Cloudflare) {
		c.WorkerBindings = []config.CFBindings{{PagesProject: "site", Allow: []string{"d1:app-db"}}}
	})
	h.grant("PB", api.CFScopePages, map[string]string{"project": "blog"})
	h.grant("PS", api.CFScopePages, map[string]string{"project": "site"})
	h.grant("A", api.CFScopeAdmin, nil)
	dep := func(p string) string { return "/accounts/" + acct + "/pages/projects/" + p + "/deployments" }
	d1 := `{"main_module":"index.js","bindings":[{"type":"d1","name":"DB","id":"` + dbTT + `"}]}`
	b, ct := pagesDeployBody(d1)
	expect(t, h.call("POST", dep("blog"), b, gh("PB", "Content-Type", ct)), 403, api.CFErrNoGrant)
	expect(t, h.call("POST", dep("site"), b, gh("PS", "Content-Type", ct)), 200, "")
	expect(t, h.call("POST", dep("blog"), b, gh("A", "Content-Type", ct)), 200, "") // cf.admin is not limited
	b, ct = pagesDeployBody(`{"main_module":"index.js"}`)
	expect(t, h.call("POST", dep("blog"), b, gh("PB", "Content-Type", ct)), 200, "")
	b, ct = pagesDeployBody(`{"main_module":"index.js"}`, "wrangler.toml")
	expect(t, h.call("POST", dep("blog"), b, gh("PB", "Content-Type", ct)), 403, api.CFErrNoGrant)
	expect(t, h.call("POST", dep("blog"), "not multipart", gh("PB", "Content-Type", "application/octet-stream")), 400, api.CFErrBadRequest)
}
