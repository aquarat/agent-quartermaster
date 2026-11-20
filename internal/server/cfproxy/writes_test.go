package cfproxy

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

var tunPath = "/accounts/" + acct + "/cfd_tunnel/" + tunHome + "/configurations"

func liveTunnel(version int) map[string]any {
	return map[string]any{"tunnel_id": tunHome, "version": version, "config": map[string]any{"ingress": []any{
		map[string]any{"hostname": "git.example.com", "service": "https://192.0.2.10:8443",
			"originRequest": map[string]any{"originServerName": "git.example.com", "matchSNItoHost": true, "http2Origin": true, "access": map[string]any{"required": true, "audTag": []any{"aud1"}}}},
		map[string]any{"hostname": "old.example.com", "service": "http://localhost:8080"},
		map[string]any{"service": "http_status:404"},
	}}}
}

// tunnelBody: the live config with one rule changed/added.
func tunnelBody(extra ...map[string]any) map[string]any {
	ing := []any{
		map[string]any{"hostname": "git.example.com", "service": "https://192.0.2.10:8443",
			"originRequest": map[string]any{"originServerName": "git.example.com", "matchSNItoHost": true, "http2Origin": true, "access": map[string]any{"required": true, "audTag": []any{"aud1"}}}},
	}
	for _, e := range extra {
		ing = append(ing, e)
	}
	ing = append(ing, map[string]any{"service": "http_status:404"})
	return map[string]any{"config": map[string]any{"ingress": ing}}
}

func TestTunnelWriteFlow(t *testing.T) {
	h := newHarness(t)
	h.grant("T", api.CFScopeTunnelConfig, map[string]string{"tunnel": "home"})
	version := 7
	var putBody []byte
	h.cf.on("GET "+tunPath, func(w http.ResponseWriter, r *http.Request) { cfJSON(w, 200, liveTunnel(version)) })
	h.cf.on("PUT "+tunPath, func(w http.ResponseWriter, r *http.Request) {
		putBody = h.cf.requests()[len(h.cf.requests())-1].Body
		version++
		cfJSON(w, 200, map[string]any{"version": version})
	})
	h.cf.result("GET /zones/"+zoneA+"/dns_records", []any{map[string]any{"name": "new.example.com", "proxied": true}})
	h.cf.result("GET /accounts/"+acct+"/access/apps", []any{map[string]any{"domain": "git.example.com"}})
	good := tunnelBody(map[string]any{"hostname": "new.example.com", "service": "https://192.0.2.10:8443",
		"originRequest": map[string]any{"originServerName": "new.example.com", "matchSNItoHost": true, "http2Origin": true}})

	// Never read through the proxy: 409.
	r := h.call("PUT", tunPath, good, g("T"))
	expect(t, r, 409, api.CFErrGuardRail)
	if !strings.Contains(r.Body.String(), GTunnelVersion) || h.cf.count("PUT", "/") != 0 {
		t.Fatalf("version guard %s", r.Body)
	}
	if a := h.grants.last("cf_refused"); a == nil || !strings.Contains(a.Detail, "guard="+GTunnelVersion) {
		t.Fatal("refusal not audited")
	}
	// Read it (cf.read also counts), then PUT.
	h.grant("R", api.CFScopeRead, nil)
	expect(t, h.call("GET", tunPath, nil, g("R")), 200, "")
	r = h.call("PUT", tunPath, good, g("T"))
	expect(t, r, 200, "")
	if !strings.Contains(string(putBody), "new.example.com") {
		t.Fatalf("forwarded %s", putBody)
	}
	bid, aid := r.Header().Get(api.CFSnapshotBeforeHeader), r.Header().Get(api.CFSnapshotAfterHeader)
	if bid == "" || aid == "" {
		t.Fatalf("snapshot headers %v", r.Header())
	}
	b, err := h.p.snaps.get(bid)
	if err != nil || b.Phase != "before" || b.ObjectKey != "tunnel-config:"+tunHome || b.PairID != aid || b.GrantID != "T" || b.Host != "hosta" || !strings.Contains(string(b.Content), "old.example.com") {
		t.Fatalf("before %+v %v", b, err)
	}
	a, err := h.p.snaps.get(aid)
	if err != nil || a.Phase != "after" || a.PairID != bid || a.Method != "PUT" || a.Path != tunPath {
		t.Fatalf("after %+v", a)
	}
	fi, _ := os.Stat(filepath.Join(h.p.snaps.dir, "2026-11-20", bid+".json"))
	di, _ := os.Stat(filepath.Join(h.p.snaps.dir, "2026-11-20"))
	if fi == nil || fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatal("snapshot modes")
	}
	au := h.grants.last("cf_write")
	if au == nil || au.Object != "grant:T" || au.Actor != "host:hosta" || !strings.Contains(au.Detail, "hosts=+new.example.com -old.example.com") || !strings.Contains(au.Detail, "before="+bid) {
		t.Fatalf("audit %+v", au)
	}
	if h.pushes[len(h.pushes)-1] != "aqmas: hosta PUT tunnel-config:"+tunHome+" (+new.example.com -old.example.com) [ref REFT]" {
		t.Fatalf("push %q", h.pushes[len(h.pushes)-1])
	}
	// The after-snapshot's version counts as read: a second PUT works without a GET...
	expect(t, h.call("PUT", tunPath, good, g("T")), 200, "")
	// ...but not after someone else changed it.
	version += 3
	expect(t, h.call("PUT", tunPath, good, g("T")), 409, api.CFErrGuardRail)
}

func TestTunnelGuards(t *testing.T) {
	h := newHarness(t)
	h.grant("T", api.CFScopeTunnelConfig, map[string]string{"tunnel": "home"})
	h.grant("A", api.CFScopeAdmin, nil)
	h.cf.result("GET "+tunPath, liveTunnel(3))
	expect(t, h.call("GET", tunPath, nil, g("T")), 200, "")
	traefik := "https://192.0.2.10:8443"
	cases := map[string]any{
		GTunnelWholeConfig: map[string]any{"config": map[string]any{"ingress": []any{}}, "extra": 1},
		GTunnelCatchAll:    map[string]any{"config": map[string]any{"ingress": []any{map[string]any{"hostname": "x.example.com", "service": "http_status:404"}}}},
		GTunnelTraefikSNI:  tunnelBody(map[string]any{"hostname": "n.example.com", "service": traefik}),
		GTunnelPlainOrigin: tunnelBody(map[string]any{"hostname": "n.example.com", "service": "http://192.0.2.10:80/"}),
		GTunnelNoTLSVerify: tunnelBody(map[string]any{"hostname": "n.example.com", "service": "https://10.0.0.1", "originRequest": map[string]any{"noTLSVerify": true}}),
		GTunnelAccessAud: map[string]any{"config": map[string]any{"ingress": []any{
			map[string]any{"hostname": "git.example.com", "service": traefik, "originRequest": map[string]any{"originServerName": "git.example.com"}},
			map[string]any{"service": "http_status:404"}}}},
	}
	for guard, body := range cases {
		r := h.call("PUT", tunPath, body, g("T"))
		expect(t, r, 403, api.CFErrGuardRail)
		if !strings.Contains(r.Body.String(), guard) {
			t.Errorf("%s: %s", guard, r.Body)
		}
		// Overridable with cf.admin only, never with another scope.
		expect(t, h.call("PUT", tunPath, body, gh("T", api.CFOverrideHeader, guard)), 400, api.CFErrBadRequest)
	}
	if h.cf.count("PUT", "/") != 0 {
		t.Fatal("refused tunnel write forwarded")
	}
	// Global noTLSVerify switched on.
	gb := tunnelBody()
	gb["config"].(map[string]any)["originRequest"] = map[string]any{"noTLSVerify": true}
	expect(t, h.call("PUT", tunPath, gb, g("T")), 403, api.CFErrGuardRail)
	// Traefik rule without matchSNItoHost: allowed with a warning.
	r := h.call("PUT", tunPath, tunnelBody(map[string]any{"hostname": "n.example.com", "service": traefik, "originRequest": map[string]any{"originServerName": "n.example.com"}}), g("T"))
	expect(t, r, 200, "")
	if !strings.Contains(strings.Join(r.Header().Values(api.CFWarningHeader), "|"), "matchSNItoHost") {
		t.Fatalf("warnings %v", r.Header().Values(api.CFWarningHeader))
	}
	// cf.admin override (the admin must also have read the config).
	expect(t, h.call("GET", tunPath, nil, g("A")), 200, "")
	r = h.call("PUT", tunPath, cases[GTunnelPlainOrigin], gh("A", api.CFOverrideHeader, GTunnelPlainOrigin))
	expect(t, r, 200, "")
	if !strings.Contains(h.grants.last("cf_write").Detail, "overrides="+GTunnelPlainOrigin) || !strings.Contains(h.pushes[len(h.pushes)-1], "OVERRIDE") {
		t.Fatal("override not audited/pushed")
	}
	// An override for a different guard does not help.
	expect(t, h.call("PUT", tunPath, cases[GTunnelPlainOrigin], gh("A", api.CFOverrideHeader, GTunnelCatchAll)), 403, api.CFErrGuardRail)
	expect(t, h.call("PUT", tunPath, cases[GTunnelPlainOrigin], gh("A", api.CFOverrideHeader, "bogus")), 400, api.CFErrBadRequest)
}

func TestTunnelBeforeSnapshotFailure(t *testing.T) {
	h := newHarness(t)
	h.grant("T", api.CFScopeTunnelConfig, map[string]string{"tunnel": "home"})
	h.cf.on("GET "+tunPath, func(w http.ResponseWriter, r *http.Request) { cfJSON(w, 500, nil) })
	expect(t, h.call("PUT", tunPath, tunnelBody(), g("T")), 502, api.CFErrUpstream)
	if h.cf.count("PUT", "/") != 0 {
		t.Fatal("written without a before-snapshot")
	}
}

func TestAccessApps(t *testing.T) {
	h := newHarness(t)
	h.grant("AP", api.CFScopeAccessApps, nil)
	h.grant("A", api.CFScopeAdmin, nil)
	apps := "/accounts/" + acct + "/access/apps"
	bad := []map[string]any{
		{"domain": "id.example.com"},
		{"domain": "ID.Example.COM."},
		{"domain": "id.example.com/admin"},
		{"domain": "id.example.com:443/x"},
		{"domain": "https://id.example.com"},
		{"domain": "*.example.com"},
		{"domain": "*.com"},
		{"domain": "i*.example.com"},
		{"domain": "*"},
		{"domain": "ok.example.com", "self_hosted_domains": []any{"ok.example.com", "id.example.com"}},
		{"domain": "ok.example.com", "destinations": []any{map[string]any{"type": "public", "uri": "id.example.com/path"}}},
		{"domain": "id.example%2ecom"},
	}
	for _, b := range bad {
		r := h.call("POST", apps, b, g("AP"))
		expect(t, r, 403, api.CFErrGuardRail)
		if !strings.Contains(r.Body.String(), GAccessProtected) {
			t.Errorf("%v: %s", b, r.Body)
		}
		// Never overridable: the header itself is refused.
		expect(t, h.call("POST", apps, b, gh("A", api.CFOverrideHeader, GAccessProtected)), 400, api.CFErrBadRequest)
		expect(t, h.call("POST", apps, b, g("A")), 403, api.CFErrGuardRail)
	}
	// A legitimate create: before = missing, after from result.id.
	h.cf.result("POST "+apps, map[string]any{"id": "app9", "domain": "ok.example.com"})
	h.cf.result("GET "+apps+"/app9", map[string]any{"id": "app9", "domain": "ok.example.com"})
	r := h.call("POST", apps, map[string]any{"domain": "ok.example.com", "session_duration": "8760h"}, g("AP"))
	expect(t, r, 200, "")
	if !strings.Contains(strings.Join(r.Header().Values(api.CFWarningHeader), "|"), "730h") {
		t.Fatal("session warning")
	}
	b, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotBeforeHeader))
	a, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotAfterHeader))
	if b == nil || !b.Missing || b.ObjectKey != "access-app:app9" || a == nil || a.ObjectKey != "access-app:app9" || !strings.Contains(string(a.Content), "app9") {
		t.Fatalf("create snapshots %+v %+v", b, a)
	}
	// PATCH: always refused, never overridable.
	expect(t, h.call("PATCH", apps+"/app9", map[string]any{"name": "x"}, g("AP")), 403, api.CFErrGuardRail)
	expect(t, h.call("PATCH", apps+"/app9", map[string]any{"name": "x"}, g("A")), 403, api.CFErrGuardRail)
	// DELETE of an app whose hostname a tunnel routes: warning.
	h.cf.result("GET "+tunPath, liveTunnel(1))
	deleted := false
	h.cf.on("GET "+apps+"/appfj", func(w http.ResponseWriter, r *http.Request) {
		if deleted {
			cfJSON(w, 404, nil)
			return
		}
		cfJSON(w, 200, map[string]any{"id": "appfj", "domain": "git.example.com"})
	})
	h.cf.on("DELETE "+apps+"/appfj", func(w http.ResponseWriter, r *http.Request) {
		deleted = true
		cfJSON(w, 200, map[string]any{"id": "appfj"})
	})
	r = h.call("DELETE", apps+"/appfj", nil, g("AP"))
	expect(t, r, 200, "")
	if !strings.Contains(strings.Join(r.Header().Values(api.CFWarningHeader), "|"), "tunnel home still routes") {
		t.Fatalf("warnings %v", r.Header().Values(api.CFWarningHeader))
	}
	if a, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotAfterHeader)); a == nil || !a.Missing {
		t.Fatal("after of a delete should be missing")
	}
}

func TestAccessPolicyShared(t *testing.T) {
	h := newHarness(t)
	h.grant("PO", api.CFScopeAccessPolicies, nil)
	h.grant("A", api.CFScopeAdmin, nil)
	base := "/accounts/" + acct + "/access"
	h.cf.result("GET "+base+"/policies/p1", map[string]any{"id": "p1", "reusable": true})
	h.cf.result("GET "+base+"/policies/p2", map[string]any{"id": "p2", "reusable": true})
	h.cf.result("GET "+base+"/groups/g1", map[string]any{"id": "g1"})
	h.cf.on("GET "+base+"/apps", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		var res []any
		if page == "1" {
			res = []any{
				map[string]any{"id": "a1", "policies": []any{map[string]any{"id": "p1"}, map[string]any{"id": "p2"}}},
				map[string]any{"id": "a2", "policies": []any{map[string]any{"id": "p9", "include": []any{map[string]any{"group": map[string]any{"id": "g1"}}}}}},
			}
		} else {
			res = []any{map[string]any{"id": "a3", "policies": []any{map[string]any{"id": "p1", "include": []any{map[string]any{"group": map[string]any{"id": "g1"}}}}}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": res, "result_info": map[string]any{"page": page, "total_pages": 2}})
	})
	expect(t, h.call("PUT", base+"/policies/p1", map[string]any{"decision": "allow"}, g("PO")), 403, api.CFErrGuardRail)
	expect(t, h.call("DELETE", base+"/groups/g1", nil, g("PO")), 403, api.CFErrGuardRail)
	r := h.call("PUT", base+"/policies/p2", map[string]any{"decision": "bypass", "include": []any{map[string]any{"everyone": map[string]any{}}}}, g("PO"))
	expect(t, r, 200, "")
	if w := r.Header().Values(api.CFWarningHeader); len(w) != 2 {
		t.Fatalf("warnings %v", w)
	}
	expect(t, h.call("PUT", base+"/policies/p1", map[string]any{"decision": "allow"}, gh("A", api.CFOverrideHeader, GAccessPolicyShared)), 200, "")
}

func TestIdPAndOrg(t *testing.T) {
	h := newHarness(t)
	h.grant("I", api.CFScopeAccessIdPOrg, nil)
	h.grant("A", api.CFScopeAdmin, nil)
	idp := "/accounts/" + acct + "/access/identity_providers/idp1"
	h.cf.result("GET "+idp, map[string]any{"id": "idp1", "config": map[string]any{"client_secret": "zzz"}})
	expect(t, h.call("DELETE", idp, nil, g("I")), 403, api.CFErrGuardRail)
	r := h.call("DELETE", idp, nil, gh("A", api.CFOverrideHeader, GIdPDelete))
	expect(t, r, 200, "")
	b, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotBeforeHeader))
	if b == nil || strings.Contains(string(b.Content), "zzz") || !strings.Contains(string(b.Content), RedactedMarker) {
		t.Fatalf("snapshot not redacted: %+v", b)
	}
	expect(t, h.call("PUT", "/accounts/"+acct+"/access/organizations", map[string]any{"name": "x"}, g("I")), 200, "")
}

func TestDNS(t *testing.T) {
	h := newHarness(t)
	h.grant("D", api.CFScopeDNSEdit, map[string]string{"zone": "example.com"})
	h.grant("DG", api.CFScopeDNSEdit, map[string]string{"zone": "example.com", "name": "*.dev.example.com"})
	h.grant("A", api.CFScopeAdmin, nil)
	recs := "/zones/" + zoneA + "/dns_records"
	h.cf.result("GET "+recs+"/mx1", map[string]any{"id": "mx1", "name": "example.com", "type": "MX", "content": "mx.example"})
	h.cf.result("GET "+recs+"/a1", map[string]any{"id": "a1", "name": "www.example.com", "type": "A", "content": "203.0.113.1"})
	h.cf.result("GET "+recs+"/d1", map[string]any{"id": "d1", "name": "x.dev.example.com", "type": "A", "content": "203.0.113.1"})
	h.cf.result("POST "+recs, map[string]any{"id": "new1"})
	h.cf.result("GET "+recs+"/new1", map[string]any{"id": "new1", "name": "app.dev.example.com"})
	refused := []map[string]any{
		{"name": "@", "type": "A", "content": "1.2.3.4"},
		{"name": "example.com", "type": "CNAME", "content": "x"},
		{"name": "mail.example.com", "type": "MX", "content": "x"},
		{"name": "sub", "type": "NS", "content": "ns1"},
		{"name": "x.example.com", "type": "CAA", "content": "x"},
		{"name": "_dmarc", "type": "TXT", "content": "v=DMARC1"},
		{"name": "s1._domainkey.example.com", "type": "TXT", "content": "k=rsa"},
		{"name": "mail.example.com", "type": "TXT", "content": "\"v=spf1 -all\""},
		{"name": "_acme-challenge.www", "type": "TXT", "content": "x"},
		{"name": "ID.example.com", "type": "A", "content": "1.2.3.4"},
	}
	for _, b := range refused {
		r := h.call("POST", recs, b, g("D"))
		expect(t, r, 403, api.CFErrGuardRail)
		if !strings.Contains(r.Body.String(), GDNSProtected) {
			t.Errorf("%v: %s", b, r.Body)
		}
	}
	// The before-snapshot protects too (PATCH/DELETE of the apex MX).
	expect(t, h.call("PATCH", recs+"/mx1", map[string]any{"content": "evil"}, g("D")), 403, api.CFErrGuardRail)
	expect(t, h.call("DELETE", recs+"/mx1", nil, g("D")), 403, api.CFErrGuardRail)
	// PATCH merges over before: changing a record's type to MX.
	expect(t, h.call("PATCH", recs+"/a1", map[string]any{"type": "MX"}, g("D")), 403, api.CFErrGuardRail)
	// Override with cf.admin.
	expect(t, h.call("DELETE", recs+"/mx1", nil, gh("A", api.CFOverrideHeader, GDNSProtected)), 200, "")
	// Warnings.
	r := h.call("POST", recs, map[string]any{"name": "t", "type": "CNAME", "content": "abc.cfargotunnel.com", "proxied": false}, g("D"))
	expect(t, r, 200, "")
	if len(r.Header().Values(api.CFWarningHeader)) != 1 {
		t.Fatalf("warnings %v", r.Header().Values(api.CFWarningHeader))
	}
	r = h.call("PUT", recs+"/a1", map[string]any{"name": "www", "type": "A", "content": "10.0.0.5"}, g("D"))
	if !strings.Contains(strings.Join(r.Header().Values(api.CFWarningHeader), "|"), "private") {
		t.Fatal("RFC 1918 warning")
	}
	// dns-name snapshot for POST.
	h.cf.result("GET "+recs, []any{})
	r = h.call("POST", recs, map[string]any{"name": "app.dev", "type": "A", "content": "203.0.113.5"}, g("DG"))
	expect(t, r, 200, "")
	b, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotBeforeHeader))
	if b == nil || b.ObjectKey != "dns-name:"+zoneA+":app.dev.example.com" || b.ObjectType != "dns-name" {
		t.Fatalf("dns-name %+v", b)
	}
	var sawQuery bool
	for _, u := range h.cf.requests() {
		if u.URI == "/client/v4"+recs+"?name=app.dev.example.com" {
			sawQuery = true
		}
	}
	if !sawQuery {
		t.Fatal("dns-name before GET")
	}
	// Name glob: outside, the base itself, an existing record outside.
	for _, b := range []map[string]any{
		{"name": "www", "type": "A", "content": "203.0.113.5"},
		{"name": "dev", "type": "A", "content": "203.0.113.5"},
	} {
		r := h.call("POST", recs, b, g("DG"))
		expect(t, r, 403, api.CFErrNoGrant)
		if r.Header().Get(api.CFNeedsScopeHeader) != "cf.dns.edit zone=example.com" {
			t.Fatalf("hint %q", r.Header().Get(api.CFNeedsScopeHeader))
		}
	}
	expect(t, h.call("PUT", recs+"/a1", map[string]any{"name": "x.dev", "type": "A", "content": "203.0.113.5"}, g("DG")), 403, api.CFErrNoGrant)
	expect(t, h.call("DELETE", recs+"/a1", nil, g("DG")), 403, api.CFErrNoGrant)
	expect(t, h.call("PATCH", recs+"/d1", map[string]any{"content": "203.0.113.6"}, g("DG")), 200, "")
	expect(t, h.call("PATCH", recs+"/d1", map[string]any{"name": "www"}, g("DG")), 403, api.CFErrNoGrant)
	// Body must be JSON on guarded routes.
	expect(t, h.call("POST", recs, "name=x", g("D")), 400, api.CFErrBadRequest)
}

func TestRulesets(t *testing.T) {
	h := newHarness(t)
	h.grant("RS", api.CFScopeRulesets, map[string]string{"zone": "example.com", "phase": "http_request_dynamic_redirect"})
	h.grant("A", api.CFScopeAdmin, nil)
	ep := "/zones/" + zoneA + "/rulesets/phases/http_request_dynamic_redirect/entrypoint"
	h.cf.result("GET "+ep, map[string]any{"id": "rs1", "phase": "http_request_dynamic_redirect", "rules": []any{map[string]any{"id": "r1"}, map[string]any{"id": "r2"}}})
	expect(t, h.call("PUT", ep, map[string]any{"rules": []any{map[string]any{"id": "r1"}}}, g("RS")), 403, api.CFErrGuardRail)
	expect(t, h.call("PUT", ep, map[string]any{"rules": []any{map[string]any{"id": "r1"}, map[string]any{"id": "r2"}, map[string]any{"expression": "true"}}}, g("RS")), 200, "")
	expect(t, h.call("PUT", ep, map[string]any{"rules": []any{}}, gh("A", api.CFOverrideHeader, GRulesetKeepRules)), 200, "")
	// No entrypoint yet: 404 before = missing.
	ep2 := "/zones/" + zoneA + "/rulesets/phases/http_request_dynamic_redirect/entrypoint"
	h.cf.on("GET "+ep2, func(w http.ResponseWriter, r *http.Request) { cfJSON(w, 404, nil) })
	r := h.call("PUT", ep2, map[string]any{"rules": []any{map[string]any{"expression": "true"}}}, g("RS"))
	expect(t, r, 200, "")
	if b, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotBeforeHeader)); b == nil || !b.Missing {
		t.Fatal("missing entrypoint snapshot")
	}
	// Rule writes: the phase comes from the before-snapshot.
	h.cf.result("GET /zones/"+zoneA+"/rulesets/rsw", map[string]any{"id": "rsw", "phase": "http_request_firewall_managed"})
	h.cf.result("GET /zones/"+zoneA+"/rulesets/rsr", map[string]any{"id": "rsr", "phase": "http_request_dynamic_redirect"})
	expect(t, h.call("POST", "/zones/"+zoneA+"/rulesets/rsw/rules", map[string]any{"expression": "true"}, g("RS")), 403, api.CFErrNoGrant)
	expect(t, h.call("POST", "/zones/"+zoneA+"/rulesets/rsr/rules", map[string]any{"expression": "true"}, g("RS")), 200, "")
	r = h.call("DELETE", "/zones/"+zoneA+"/rulesets/rsr/rules/x1", nil, g("RS"))
	expect(t, r, 200, "")
	if len(r.Header().Values(api.CFWarningHeader)) == 0 {
		t.Fatal("rule delete warning")
	}
	// cf.admin is not limited by the phase.
	expect(t, h.call("POST", "/zones/"+zoneA+"/rulesets/rsw/rules", map[string]any{"expression": "true"}, g("A")), 200, "")
}

func TestZoneSettings(t *testing.T) {
	h := newHarness(t)
	h.grant("Z", api.CFScopeZoneSettings, map[string]string{"zone": "example.com"})
	s := "/zones/" + zoneA + "/settings"
	for name, v := range map[string]any{
		"ssl": "flexible", "min_tls_version": "1.0", "always_use_https": "off",
		"security_header": map[string]any{"strict_transport_security": map[string]any{"enabled": true, "preload": true}},
	} {
		r := h.call("PATCH", s+"/"+name, map[string]any{"value": v}, g("Z"))
		expect(t, r, 403, api.CFErrGuardRail)
		if !strings.Contains(r.Body.String(), GZoneSettingsPolicy) {
			t.Errorf("%s: %s", name, r.Body)
		}
	}
	expect(t, h.call("PATCH", s, map[string]any{"items": []any{map[string]any{"id": "brotli", "value": "on"}, map[string]any{"id": "ssl", "value": "full"}}}, g("Z")), 403, api.CFErrGuardRail)
	r := h.call("PATCH", s, map[string]any{"items": []any{map[string]any{"id": "brotli", "value": "on"}, map[string]any{"id": "min_tls_version", "value": "1.3"}}}, g("Z"))
	expect(t, r, 200, "")
	if b, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotBeforeHeader)); b == nil || b.ObjectKey != "zone-setting:"+zoneA+":all" {
		t.Fatalf("snapshot %+v", b)
	}
	r = h.call("PATCH", s+"/ssl", map[string]any{"value": "strict"}, g("Z"))
	if b, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotBeforeHeader)); b == nil || b.ObjectKey != "zone-setting:"+zoneA+":ssl" {
		t.Fatalf("snapshot %+v", b)
	}
}

func TestPurge(t *testing.T) {
	h := newHarness(t)
	h.grant("P", api.CFScopeCachePurge, map[string]string{"zone": "example.com"})
	h.grant("A", api.CFScopeAdmin, nil)
	p := "/zones/" + zoneA + "/purge_cache"
	expect(t, h.call("POST", p, map[string]any{"files": []any{"https://example.com/a.css", map[string]any{"url": "http://www.example.com/b"}}}, g("P")), 200, "")
	r := h.call("POST", p, map[string]any{"purge_everything": true}, g("P"))
	expect(t, r, 403, api.CFErrNoGrant)
	if r.Header().Get(api.CFNeedsScopeHeader) != "cf.admin" {
		t.Fatal("purge hint")
	}
	many := []any{}
	for i := 0; i < 31; i++ {
		many = append(many, "https://example.com/x")
	}
	for _, b := range []any{
		map[string]any{"files": []any{"https://example.org/a"}},
		map[string]any{"files": []any{"https://evilexample.com/a"}},
		map[string]any{"files": []any{"ftp://example.com/a"}},
		map[string]any{"files": []any{"https://u:p@example.com/a"}},
		map[string]any{"files": []any{}},
		map[string]any{"files": many},
		map[string]any{"files": []any{"https://example.com/a"}, "tags": []any{"x"}},
	} {
		expect(t, h.call("POST", p, b, g("P")), 403, api.CFErrNoGrant)
	}
	expect(t, h.call("POST", p, map[string]any{"purge_everything": true}, g("A")), 200, "")
}

func TestD1(t *testing.T) {
	h := newHarness(t)
	h.grant("RO", api.CFScopeD1, map[string]string{"db": "app-db", "access": "read"})
	h.grant("MG", api.CFScopeD1, map[string]string{"db": "app-db", "access": "migrate"})
	q := "/accounts/" + acct + "/d1/database/" + dbTT + "/query"
	ok := []string{
		"SELECT * FROM t",
		"select replace(name, 'a', 'b') from t; EXPLAIN QUERY PLAN SELECT 1",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"PRAGMA table_info(t)", "PRAGMA main.table_list", "SELECT 'DELETE FROM t' -- DROP TABLE t\n",
		"SELECT \"update\" FROM t /* insert */",
	}
	for _, s := range ok {
		expect(t, h.call("POST", q, map[string]any{"sql": s}, g("RO")), 200, "")
	}
	bad := []string{
		"DELETE FROM t", "SELECT 1; DROP TABLE t", "WITH x AS (SELECT 1) DELETE FROM t", "PRAGMA journal_mode=WAL",
		"PRAGMA writable_schema", "INSERT INTO t VALUES (1)", "REPLACE INTO t VALUES (1)", "SELECT 'unterminated",
		"ATTACH DATABASE 'x' AS y", "", "CREATE TABLE x (a)",
	}
	for _, s := range bad {
		r := h.call("POST", q, map[string]any{"sql": s}, g("RO"))
		expect(t, r, 403, api.CFErrNoGrant)
		if r.Header().Get(api.CFNeedsScopeHeader) != "cf.d1 access=migrate;db=app-db" {
			t.Fatalf("hint %q", r.Header().Get(api.CFNeedsScopeHeader))
		}
	}
	expect(t, h.call("POST", q, []any{map[string]any{"sql": "SELECT 1"}, map[string]any{"sql": "DELETE FROM t"}}, g("RO")), 403, api.CFErrNoGrant)
	pushes := h.pushCount()
	expect(t, h.call("POST", q, map[string]any{"sql": "DELETE FROM t"}, g("MG")), 200, "")
	if h.pushCount() != pushes+1 {
		t.Fatal("migrate write not pushed")
	}
	if pushes != 0 {
		t.Fatalf("read-only queries pushed %d", pushes)
	}
	expect(t, h.call("POST", "/accounts/"+acct+"/d1/database/"+dbTT+"/export", map[string]any{}, g("MG")), 403, api.CFErrDenied)
}

func TestWorkersScopeChecks(t *testing.T) {
	h := newHarness(t)
	h.grant("W", api.CFScopeWorkersDeploy, map[string]string{"script": "hello"})
	h.grant("WZ", api.CFScopeWorkersDeploy, map[string]string{"script": "hello", "zone": "example.com"})
	h.grant("A", api.CFScopeAdmin, nil)
	a := "/accounts/" + acct + "/workers"
	dom := map[string]any{"hostname": "hello.example.com", "service": "hello", "zone_id": zoneA, "environment": "production"}
	expect(t, h.call("PUT", a+"/domains", dom, g("W")), 403, api.CFErrNoGrant) // no zone param
	expect(t, h.call("PUT", a+"/domains", dom, g("WZ")), 200, "")
	expect(t, h.call("PUT", a+"/domains", map[string]any{"hostname": "hello.example.org", "service": "hello"}, g("WZ")), 403, api.CFErrNoGrant)
	expect(t, h.call("PUT", a+"/domains", map[string]any{"hostname": "x.example.com", "service": "other"}, g("WZ")), 403, api.CFErrNoGrant)
	expect(t, h.call("PUT", a+"/domains", map[string]any{"hostname": "x.example.com", "service": "hello", "zone_id": zoneB}, g("WZ")), 403, api.CFErrNoGrant)
	recs := a + "/scripts/hello/domains/records"
	expect(t, h.call("PUT", recs, map[string]any{"origins": []any{map[string]any{"hostname": "p.example.com"}}, "override_scope": true}, g("WZ")), 200, "")
	expect(t, h.call("POST", a+"/scripts/hello/domains/changeset?replace_state=true", []any{map[string]any{"hostname": "p.example.org"}}, g("WZ")), 403, api.CFErrNoGrant)
	// Custom domain removal: guard rail.
	expect(t, h.call("DELETE", a+"/domains/dom1", nil, g("WZ")), 403, api.CFErrGuardRail)
	expect(t, h.call("DELETE", a+"/domains/dom1", nil, gh("A", api.CFOverrideHeader, GWorkersDomainRm)), 200, "")
	// Routes.
	zr := "/zones/" + zoneA + "/workers/routes"
	expect(t, h.call("POST", zr, map[string]any{"pattern": "example.com/p/*", "script": "hello"}, g("WZ")), 200, "")
	expect(t, h.call("POST", zr, map[string]any{"pattern": "example.com/p/*", "script": "other"}, g("WZ")), 403, api.CFErrNoGrant)
	sr := a + "/scripts/hello/routes"
	expect(t, h.call("PUT", sr, []any{map[string]any{"pattern": "app.example.com/api/*", "zone_name": "example.com"}}, g("WZ")), 200, "")
	expect(t, h.call("PUT", sr, []any{map[string]any{"pattern": "*.example.com/api/*", "zone_name": "example.com"}}, g("WZ")), 403, api.CFErrGuardRail)
	expect(t, h.call("PUT", sr, []any{map[string]any{"pattern": "example.org/*"}}, g("WZ")), 403, api.CFErrNoGrant)
	expect(t, h.call("PUT", sr, []any{map[string]any{"pattern": "example.com/*"}}, g("W")), 403, api.CFErrNoGrant)
	// Script binding: another script is not this grant's.
	r := h.call("PUT", a+"/scripts/other", "x", g("W,WZ"))
	expect(t, r, 403, api.CFErrNoGrant)
	if r.Header().Get(api.CFNeedsScopeHeader) != "cf.workers.deploy script=other" {
		t.Fatalf("hint %q", r.Header().Get(api.CFNeedsScopeHeader))
	}
	// Secrets and settings.
	expect(t, h.call("PUT", a+"/scripts/hello/secrets", map[string]any{"name": "K", "text": "v", "type": "secret_text"}, g("W")), 200, "")
	expect(t, h.call("DELETE", a+"/scripts/hello/secrets/K?url_encoded=true", nil, g("W")), 200, "")
	r = h.call("PATCH", a+"/scripts/hello/script-settings", map[string]any{"logpush": false}, g("W"))
	expect(t, r, 200, "")
	if b, _ := h.p.snaps.get(r.Header().Get(api.CFSnapshotBeforeHeader)); b == nil || b.ObjectKey != "workers-script-settings:hello" {
		t.Fatalf("settings snapshot %+v", b)
	}
}
