package cfproxy

import (
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func TestExprCovers(t *testing.T) {
	prot := []string{"id.example.com"}
	covers := []string{
		`true`,
		`(http.request.uri.path eq "/")`,
		`http.host eq "id.example.com"`,
		`http.host == r"ID.example.com"`,
		`http.host in {"app.example.com" "id.example.com"}`,
		`ends_with(http.host, ".example.com")`,
		`http.host contains "example"`,
		`http.host eq "app.example.com" or http.request.uri.path eq "/x"`,
		`not http.host eq "app.example.com"`,
		`http.host ne "app.example.com"`,
		`http.request.full_uri wildcard "https://*.example.com/*"`,
		`lower(http.host) eq "app.example.com"`,
		`http.host eq "app.example.com`, // unterminated
		`http.host in {"app.example.com" "*.example.com"}`,
		`http.host eq r#"app.example.com"#`,
		`http.host eq r"app.example.com"`,
		`http.host eq "\x69d.example.com"`,
		`http.host eq "app.example.com" and http.request.uri.path eq "\u{2f}"`,
	}
	for _, e := range covers {
		if c := exprCovers(e, prot); !c["id.example.com"] {
			t.Errorf("%s: should cover", e)
		}
	}
	safe := []string{
		`http.host eq "app.example.com"`,
		`http.host in {"a.example.com" "b.example.com"} and http.request.uri.path eq "/"`,
		`(http.host eq "app.example.com" and ssl) and http.request.method eq "POST"`,
		`http.request.uri.path eq "/" && http.host in {"a.example.com", "b.example.com"}`,
		`http.host in {"app.example.com" "id.example.com"} and http.host eq "app.example.com"`,
	}
	for _, e := range safe {
		if c := exprCovers(e, prot); len(c) != 0 {
			t.Errorf("%s: should not cover (%v)", e, c)
		}
	}
}

func TestRulesetProtectedHostname(t *testing.T) {
	h := newHarness(t)
	h.grant("RT", api.CFScopeRulesets, map[string]string{"zone": "example.com", "phase": "http_request_late_transform"})
	h.grant("RR", api.CFScopeRulesets, map[string]string{"zone": "example.com", "phase": "http_request_dynamic_redirect"})
	h.grant("A", api.CFScopeAdmin, nil)
	z := "/zones/" + zoneA + "/rulesets"
	xff := map[string]any{"id": "xff", "expression": `http.host in {"app.example.com" "id.example.com"}`, "action": "rewrite",
		"action_parameters": map[string]any{"headers": map[string]any{"X-Forwarded-For": map[string]any{"operation": "remove"}}}}
	lt := z + "/phases/http_request_late_transform/entrypoint"
	h.cf.result("GET "+lt, map[string]any{"id": "rsl", "phase": "http_request_late_transform", "rules": []any{xff}})
	with := func(r map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range r {
			out[k] = v
		}
		return out
	}
	put := func(grant string, rules ...any) res {
		return h.call("PUT", lt, map[string]any{"rules": rules}, g(grant))
	}
	// Unchanged rule plus a new restricted rule: fine.
	expect(t, put("RT", xff, map[string]any{"expression": `http.host eq "b.example.com"`, "action": "rewrite"}), 200, "")
	// Adding unprotected hosts to the covering rule's set: fine.
	more := with(xff)
	more["expression"] = `http.host in {"app.example.com" "id.example.com" "new.example.com"}`
	expect(t, put("RT", more), 200, "")
	// A new rule that could match the protected host: never.
	expectGuard(t, put("RT", xff, map[string]any{"expression": `true`, "action": "rewrite"}), GRulesetProtected)
	expectGuard(t, put("A", xff, map[string]any{"expression": `http.host eq "id.example.com"`, "action": "rewrite"}), GRulesetProtected)
	expect(t, h.call("PUT", lt, map[string]any{"rules": []any{xff, map[string]any{"expression": `true`}}}, gh("A", api.CFOverrideHeader, GRulesetProtected)), 400, api.CFErrBadRequest)
	// The covering rule changing its action parameters: never.
	act := with(xff)
	act["action_parameters"] = map[string]any{"headers": map[string]any{"X-Evil": map[string]any{"operation": "set", "value": "1"}}}
	expectGuard(t, put("RT", act), GRulesetProtected)
	// A rule newly covering it.
	h.cf.result("GET "+z+"/rsr", map[string]any{"id": "rsr", "phase": "http_request_dynamic_redirect", "rules": []any{
		map[string]any{"id": "r1", "expression": `http.host eq "old.example.com"`, "action": "redirect"}}})
	expectGuard(t, h.call("PATCH", z+"/rsr/rules/r1", map[string]any{"expression": `http.host in {"old.example.com" "id.example.com"}`}, g("RR")), GRulesetProtected)
	expectGuard(t, h.call("POST", z+"/rsr/rules", map[string]any{"expression": `http.request.uri.path eq "/login"`, "action": "redirect"}, g("RR")), GRulesetProtected)
	expect(t, h.call("PATCH", z+"/rsr/rules/r1", map[string]any{"expression": `http.host eq "new.example.com"`}, g("RR")), 200, "")
	// Dropping the protected host from the protective late_transform rule: refused,
	// overridable by cf.admin only.
	less := with(xff)
	less["expression"] = `http.host in {"app.example.com"}`
	expectGuard(t, put("RT", less), GRulesetProtectedRemoval)
	expect(t, h.call("GET", lt, nil, g("A")), 200, "")
	expect(t, h.call("PUT", lt, map[string]any{"rules": []any{less}}, gh("A", api.CFOverrideHeader, GRulesetProtectedRemoval)), 200, "")
	// Deleting it (rule DELETE, or a PUT without it under the keep-rules override).
	h.cf.result("GET "+z+"/rsl", map[string]any{"id": "rsl", "phase": "http_request_late_transform", "rules": []any{xff}})
	expectGuard(t, h.call("DELETE", z+"/rsl/rules/xff", nil, g("RT")), GRulesetProtectedRemoval)
	expectGuard(t, h.call("PUT", lt, map[string]any{"rules": []any{}}, gh("A", api.CFOverrideHeader, GRulesetKeepRules)), GRulesetProtectedRemoval)
	expect(t, h.call("PUT", lt, map[string]any{"rules": []any{}}, gh("A", api.CFOverrideHeader, GRulesetKeepRules+","+GRulesetProtectedRemoval)), 200, "")
}
