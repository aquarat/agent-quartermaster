package cfscope

import (
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

const (
	tAcct   = "0123456789abcdef0123456789abcdef"
	tZone   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tZoneB  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tUnconf = "cccccccccccccccccccccccccccccccc"
	tTunnel = "0b1c2d3e-0000-4000-8000-000000000000"
	tOffice = "0f0f0f0f-0000-4000-8000-000000000000"
	tDB     = "11111111-2222-4333-8444-555555555555"
)

func matchCfg() *config.Cloudflare {
	c := testCfg()
	c.Zones = append(c.Zones, config.CFObject{Name: "example.org", ID: tZoneB})
	return c
}

func call(method, path string) Call {
	return Call{Method: method, Path: path, Segments: SplitPath(path)}
}

func mustCat(t *testing.T, cfg *config.Cloudflare) *Catalogue {
	t.Helper()
	c, err := NewCatalogue(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func grant(t *testing.T, c *Catalogue, scope string, params map[string]string) *Resolved {
	t.Helper()
	r, err := c.Resolve(api.CloudflareRequest{Scope: scope, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMatchBinding(t *testing.T) {
	c := mustCat(t, matchCfg())
	dns := grant(t, c, api.CFScopeDNSEdit, map[string]string{"zone": "example.com"})
	m, ok := c.Match(dns, call("PUT", "/zones/"+tZone+"/dns_records/abc123"))
	if !ok || m.Snapshot != SnapDNSRecord || m.Guard != GuardDNS || m.Vars["zone"] != tZone || m.Vars["id"] != "abc123" || !m.Write {
		t.Fatalf("got %+v %v", m, ok)
	}
	// Zone B with a zone A grant: no match, and the hint names zone B.
	cb := call("PUT", "/zones/"+tZoneB+"/dns_records/abc123")
	if _, ok := c.Match(dns, cb); ok {
		t.Fatal("zone A grant used on zone B")
	}
	if h := c.NeedsScope(cb); h != "cf.dns.edit zone=example.org" {
		t.Fatalf("hint %q", h)
	}
	// Unconfigured zone: only cf.admin.
	if h := c.NeedsScope(call("PUT", "/zones/"+tUnconf+"/dns_records/abc")); h != "cf.admin" {
		t.Fatalf("unconfigured hint %q", h)
	}
	// cf.read reads any configured zone, never an unconfigured one.
	rd := grant(t, c, api.CFScopeRead, nil)
	if _, ok := c.Match(rd, call("GET", "/zones/"+tZoneB+"/dns_records")); !ok {
		t.Fatal("cf.read zone B")
	}
	if _, ok := c.Match(rd, call("GET", "/zones/"+tUnconf+"/dns_records")); ok {
		t.Fatal("cf.read unconfigured zone")
	}
	if _, ok := c.Match(rd, call("POST", "/zones/"+tZone+"/dns_records")); ok {
		t.Fatal("cf.read write")
	}
	// Tunnel binding; a second tunnel is unconfigured.
	tun := grant(t, c, api.CFScopeTunnelConfig, map[string]string{"tunnel": "home"})
	if m, ok := c.Match(tun, call("PUT", "/accounts/"+tAcct+"/cfd_tunnel/"+tTunnel+"/configurations")); !ok || m.Snapshot != SnapTunnelConfig {
		t.Fatal("tunnel put")
	}
	if _, ok := c.Match(tun, call("PUT", "/accounts/"+tAcct+"/cfd_tunnel/"+tOffice+"/configurations")); ok {
		t.Fatal("office tunnel")
	}
	// Foreign account.
	if _, ok := c.Match(rd, call("GET", "/accounts/ffffffffffffffffffffffffffffffff/cfd_tunnel")); ok {
		t.Fatal("foreign account")
	}
	// Script binding.
	wk := grant(t, c, api.CFScopeWorkersDeploy, map[string]string{"script": "hello"})
	if m, ok := c.Match(wk, call("PUT", "/accounts/"+tAcct+"/workers/scripts/hello")); !ok || !m.Upload {
		t.Fatal("script put")
	}
	if _, ok := c.Match(wk, call("PUT", "/accounts/"+tAcct+"/workers/scripts/other")); ok {
		t.Fatal("other script")
	}
	// Optional zone absent: no zone routes.
	rc := call("POST", "/zones/"+tZone+"/workers/routes")
	if _, ok := c.Match(wk, rc); ok {
		t.Fatal("route without zone param")
	}
	if h := c.NeedsScopeFor(rc, []*Resolved{wk}); h != "cf.workers.deploy script=hello;zone=example.com" {
		t.Fatalf("held hint %q", h)
	}
	if h := c.NeedsScope(rc); h != "cf.admin" {
		t.Fatalf("hint without held %q", h)
	}
	// Alternation and the JWT route.
	if m, ok := c.Match(wk, call("PATCH", "/accounts/"+tAcct+"/workers/scripts/hello/script-settings")); !ok || m.Snapshot != SnapWorkersScriptSettings {
		t.Fatal("script-settings")
	}
	if m, ok := c.Match(wk, call("POST", "/accounts/"+tAcct+"/workers/assets/upload")); !ok || !m.JWTPassthrough {
		t.Fatal("assets upload")
	}
}

func TestMatchRestAndWhen(t *testing.T) {
	c := mustCat(t, matchCfg())
	ro := grant(t, c, api.CFScopeR2Objects, map[string]string{"bucket": "photos", "access": "read"})
	rw := grant(t, c, api.CFScopeR2Objects, map[string]string{"bucket": "photos", "access": "write"})
	key := "/accounts/" + tAcct + "/r2/buckets/photos/objects/a/b%2Fc%20d.jpg"
	if m, ok := c.Match(ro, call("GET", key)); !ok || m.Vars["key"] != "a/b%2Fc%20d.jpg" {
		t.Fatalf("get key %+v", m)
	}
	if _, ok := c.Match(ro, call("PUT", key)); ok {
		t.Fatal("read grant wrote")
	}
	if m, ok := c.Match(rw, call("PUT", key)); !ok || !m.Upload {
		t.Fatal("write grant")
	}
	if h := c.NeedsScope(call("PUT", key)); h != "cf.r2.objects access=write;bucket=photos" {
		t.Fatalf("hint %q", h)
	}
	if _, ok := c.Match(ro, call("GET", "/accounts/"+tAcct+"/r2/buckets/photos/objects")); !ok {
		t.Fatal("list")
	}
	// Percent-encoding outside {key...} never matches.
	rd := grant(t, c, api.CFScopeRead, nil)
	if _, ok := c.Match(rd, call("GET", "/zones/"+tZone+"/dns%5Frecords")); ok {
		t.Fatal("encoded literal matched")
	}
	// Phase binding.
	rs := grant(t, c, api.CFScopeRulesets, map[string]string{"zone": "example.com", "phase": "http_request_dynamic_redirect"})
	if _, ok := c.Match(rs, call("PUT", "/zones/"+tZone+"/rulesets/phases/http_request_dynamic_redirect/entrypoint")); !ok {
		t.Fatal("phase")
	}
	if _, ok := c.Match(rs, call("PUT", "/zones/"+tZone+"/rulesets/phases/http_request_firewall_custom/entrypoint")); ok {
		t.Fatal("other phase")
	}
	rsAny := grant(t, c, api.CFScopeRulesets, map[string]string{"zone": "example.com"})
	if _, ok := c.Match(rsAny, call("PUT", "/zones/"+tZone+"/rulesets/phases/http_request_firewall_managed/entrypoint")); ok {
		t.Fatal("disallowed phase")
	}
	if m, ok := c.Match(rsAny, call("DELETE", "/zones/"+tZone+"/rulesets/abc/rules/def")); !ok || m.Vars["id"] != "abc" || m.Vars["id2"] != "def" {
		t.Fatalf("rule delete %+v", m)
	}
}

func TestDenyList(t *testing.T) {
	c := mustCat(t, matchCfg())
	admin := grant(t, c, api.CFScopeAdmin, nil)
	a := "/accounts/" + tAcct
	denied := []struct {
		m, p string
		push bool
	}{
		{"GET", "/user/tokens", true},
		{"POST", "/user/tokens", true},
		{"GET", "/user/tokens/permission_groups", true},
		{"POST", "/user/tokens/verify", true},
		{"GET", "/User/Tokens", true},
		{"GET", "/user/%74okens", true},
		{"POST", a + "/tokens", true},
		{"GET", a + "/tokens/x/value", true},
		{"POST", "/memberships", true},
		{"GET", "/memberships/abc", true},
		{"GET", a + "/members", true},
		{"PATCH", "/user", true},
		{"GET", "/user/billing/profile", true},
		{"GET", "/user/organizations", true},
		{"GET", a + "/cfd_tunnel/" + tTunnel + "/token", true},
		{"GET", a + "/cfd_tunnel/" + tTunnel + "/management", true},
		{"POST", a + "/cfd_tunnel/" + tTunnel + "/management/x", true},
		{"GET", a + "/warp_connector/abc/token", true},
		{"GET", a + "/tunnels/abc/token", true},
		{"POST", a + "/cfd_tunnel", true},
		{"PUT", a + "/cfd_tunnel/" + tTunnel, true},
		{"PATCH", a + "/cfd_tunnel/" + tTunnel, true},
		{"DELETE", a + "/cfd_tunnel/" + tTunnel, true},
		{"DELETE", a + "/cfd_tunnel/" + tTunnel + "/connections", true},
		{"POST", a + "/access/service_tokens", false},
		{"POST", a + "/access/service_tokens/abc/rotate", false},
		{"POST", a + "/access/service_tokens/abc/refresh", false},
		{"GET", a + "/challenges/widgets/abc", false},
		{"POST", a + "/challenges/widgets/abc/rotate_secret", false},
		{"GET", a + "/workers/scripts/hello/tails", false},
		{"POST", a + "/workers/scripts/hello/tails/abc", false},
		{"GET", a + "/workers/scripts/hello", false},
		{"GET", a + "/workers/scripts/hello/content", false},
		{"GET", a + "/workers/scripts/hello/content/v2", false},
		{"GET", a + "/workers/services/hello/environments/production/content", false},
		{"POST", a + "/r2/temp-access-credentials", false},
		{"POST", a + "/d1/database/" + tDB + "/export", false},
		{"GET", a + "/logpush/jobs", false},
		{"POST", "/zones/" + tZone + "/logpush/jobs", false},
		{"GET", "/certificates", false},
		{"GET", "/zones/" + tZone + "/origin_tls_client_auth", false},
		{"POST", "/zones/" + tZone + "/custom_certificates", false},
		{"POST", "/zones/" + tZone + "/ssl/certificate_packs/order", false},
		{"POST", a + "/secrets_store/stores", false},
		{"PUT", a + "/hyperdrive/configs/x", false},
		{"POST", a + "/teamnet/routes", false},
		{"PATCH", a + "/devices/policy", false},
		{"PUT", a + "/gateway/rules/x", false},
		{"GET", a + "/registrar/domains", false},
		{"GET", a + "/subscriptions", false},
		{"GET", "/zones/" + tZone + "/subscription", false},
		{"POST", "/zones", false},
		{"DELETE", "/zones/" + tZone, false},
		{"POST", "/graphql", false},
		{"GET", "/accounts/ffffffffffffffffffffffffffffffff", false},
		{"GET", "/accounts/" + strings.ToUpper(tAcct) + "/cfd_tunnel", false},
	}
	for _, d := range denied {
		cl := call(d.m, d.p)
		dv := c.CheckDeny(cl)
		if !dv.Denied || dv.Push != d.push {
			t.Errorf("%s %s: %+v", d.m, d.p, dv)
		}
		if _, ok := c.Match(admin, cl); ok {
			t.Errorf("admin passed %s %s", d.m, d.p)
		}
		if h := c.NeedsScope(cl); h != "" {
			t.Errorf("hint for denied %s %s: %q", d.m, d.p, h)
		}
	}
	allowed := []struct{ m, p string }{
		{"GET", "/user/tokens/verify"}, {"GET", "/user"}, {"GET", "/memberships"}, {"GET", "/accounts"},
		{"GET", a + "/challenges/widgets"},
		{"GET", "/zones/" + tZone + "/ssl/certificate_packs"},
		{"GET", a + "/gateway/rules"},
		{"GET", a + "/cfd_tunnel/" + tTunnel + "/connections"},
		{"PUT", a + "/cfd_tunnel/" + tTunnel + "/configurations"},
	}
	for _, d := range allowed {
		if dv := c.CheckDeny(call(d.m, d.p)); dv.Denied {
			t.Errorf("%s %s denied: %s", d.m, d.p, dv.Reason)
		}
	}
}

func TestAdminAnnotations(t *testing.T) {
	cfg := matchCfg()
	cfg.Scopes["cf.admin"] = config.CFScopeOverride{ExtraDeny: []string{"DELETE /zones/{zone}/dns_records"}}
	cfg.Scopes["cf.dns.edit"] = config.CFScopeOverride{ExtraDeny: []string{"* /zones/*/dns_records/export"}}
	c := mustCat(t, cfg)
	admin := grant(t, c, api.CFScopeAdmin, nil)
	// Unconfigured zone, upper-case id: still the DNS guard and snapshot.
	m, ok := c.Match(admin, call("PUT", "/zones/"+strings.ToUpper(tUnconf)+"/dns_records/x1"))
	if !ok || m.Scope != api.CFScopeAdmin || m.Guard != GuardDNS || m.Snapshot != SnapDNSRecord || m.Vars["zone"] != tUnconf {
		t.Fatalf("admin dns %+v", m)
	}
	m, ok = c.Match(admin, call("PUT", "/accounts/"+tAcct+"/cfd_tunnel/"+tOffice+"/configurations"))
	if !ok || m.Guard != GuardTunnel {
		t.Fatalf("admin tunnel %+v", m)
	}
	if m, ok := c.Match(admin, call("PATCH", "/Accounts/"+tAcct+"/Access/Apps/abc")); !ok || m.Guard != GuardAccessPatch {
		t.Fatalf("case trick %+v", m)
	}
	if m, ok := c.Match(admin, call("POST", "/zones/"+tZone+"/something/new")); !ok || m.Guard != "" {
		t.Fatalf("admin free path %+v", m)
	}
	if _, ok := c.Match(admin, call("POST", "/zones/"+tZone+"/x%2Fy")); ok {
		t.Fatal("admin encoded segment")
	}
	// extra_deny for the admin scope only.
	if _, ok := c.Match(admin, call("DELETE", "/zones/"+tZone+"/dns_records/x1")); ok {
		t.Fatal("extra_deny ignored")
	}
	if !c.ExtraDenied("cf.admin", call("DELETE", "/zones/"+tZone+"/dns_records/x1")) {
		t.Fatal("ExtraDenied")
	}
	dns := grant(t, c, api.CFScopeDNSEdit, map[string]string{"zone": "example.com"})
	if _, ok := c.Match(dns, call("DELETE", "/zones/"+tZone+"/dns_records/x1")); !ok {
		t.Fatal("extra_deny leaked to another scope")
	}
	rd := grant(t, c, api.CFScopeRead, nil)
	if _, ok := c.Match(rd, call("GET", "/zones/"+tZone+"/dns_records/export")); !ok {
		t.Fatal("cf.read export")
	}
	cfg.Scopes["cf.read"] = config.CFScopeOverride{ExtraDeny: []string{"/no-method"}}
	if _, err := NewCatalogue(cfg); err == nil {
		t.Fatal("bad extra_deny accepted")
	}
}

func TestNeedsScopeNarrowest(t *testing.T) {
	c := mustCat(t, matchCfg())
	cases := map[string]string{
		"GET /zones/" + tZone + "/dns_records":                                  "cf.read",
		"POST /zones/" + tZone + "/dns_records":                                 "cf.dns.edit zone=example.com",
		"POST /zones/" + tZone + "/purge_cache":                                 "cf.cache.purge zone=example.com",
		"PUT /accounts/" + tAcct + "/cfd_tunnel/" + tTunnel + "/configurations": "cf.tunnel.config tunnel=home",
		"POST /accounts/" + tAcct + "/d1/database/" + tDB + "/query":            "cf.d1 access=read;db=app-db",
		"PUT /accounts/" + tAcct + "/workers/scripts/hello":                     "cf.workers.deploy script=hello",
		"GET /accounts/" + tAcct + "/workers/scripts/hello/settings":            "cf.workers.deploy script=hello",
		"GET /accounts/" + tAcct + "/access/logs/access_requests":               "cf.read.private",
		"PATCH /zones/" + tZone + "/settings/ssl":                               "cf.zone-settings zone=example.com",
		"POST /accounts/" + tAcct + "/pages/projects/blog/deployments":          "cf.pages project=blog",
		"PUT /zones/" + tZone + "/rulesets/phases/http_ratelimit/entrypoint":    "cf.rulesets phase=http_ratelimit;zone=example.com",
		"PUT /zones/" + tZone + "/rulesets/phases/http_request_sbfm/entrypoint": "cf.admin",
		"PUT /accounts/" + tAcct + "/access/organizations":                      "cf.access.idp-org",
		"DELETE /zones/" + tZone + "/email/routing/rules/abc":                   "cf.email zone=example.com",
		"POST /accounts/" + tAcct + "/workers/scripts/hello/tails":              "",
	}
	for k, want := range cases {
		m, p, _ := strings.Cut(k, " ")
		if got := c.NeedsScope(call(m, p)); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
}

// Every template parses and only uses known placeholders (parseTemplate panics otherwise),
// and every snapshot/guard name is one cfproxy knows.
func TestRouteTables(t *testing.T) {
	snaps := map[string]bool{"": true}
	for _, s := range []string{SnapTunnelConfig, SnapAccessApp, SnapAccessPolicy, SnapAccessGroup, SnapAccessIdP, SnapAccessOrg, SnapDNSRecord, SnapDNSName, SnapRulesetEntrypoint, SnapRuleset, SnapZoneSetting, SnapEmailRules, SnapPagesProject, SnapWorkersScriptSettings, SnapWorkersRoutes, SnapWorkersDomains, SnapWorkersScriptRoutes} {
		snaps[s] = true
	}
	for _, b := range builtins {
		if b.scope.Name == api.CFScopeAdmin {
			continue
		}
		rs, ok := scopeRoutes[b.scope.Name]
		if !ok || len(rs) == 0 {
			t.Errorf("scope %s has no routes", b.scope.Name)
		}
		for _, r := range rs {
			if !snaps[r.snapshot] {
				t.Errorf("%s: unknown snapshot %q", r.tmpl, r.snapshot)
			}
			for _, m := range r.methods {
				switch m {
				case "GET", "POST", "PUT", "PATCH", "DELETE":
				default:
					t.Errorf("%s: method %q", r.tmpl, m)
				}
			}
		}
	}
}

func TestD1Routes(t *testing.T) {
	c := mustCat(t, matchCfg())
	ro := grant(t, c, api.CFScopeD1, map[string]string{"db": "app-db", "access": "read"})
	mg := grant(t, c, api.CFScopeD1, map[string]string{"db": "app-db", "access": "migrate"})
	if m, ok := c.Match(ro, call("GET", "/accounts/"+tAcct+"/d1/database/app-db")); !ok || m.Vars["dbname"] != tDB {
		t.Fatalf("lookup by name %+v", m)
	}
	if _, ok := c.Match(ro, call("GET", "/accounts/"+tAcct+"/d1/database/other-db")); ok {
		t.Fatal("other db by name")
	}
	imp := call("POST", "/accounts/"+tAcct+"/d1/database/"+tDB+"/import")
	if _, ok := c.Match(ro, imp); ok {
		t.Fatal("read grant import")
	}
	if _, ok := c.Match(mg, imp); !ok {
		t.Fatal("migrate import")
	}
	if h := c.NeedsScope(call("GET", "/accounts/"+tAcct+"/d1/database/app-db")); h != "cf.d1 access=read;db=app-db" {
		t.Fatalf("hint %q", h)
	}
}
