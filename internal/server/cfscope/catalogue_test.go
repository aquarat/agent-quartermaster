package cfscope

import (
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

func testCfg() *config.Cloudflare {
	return &config.Cloudflare{
		Enabled: true, AccountID: "0123456789abcdef0123456789abcdef",
		Zones:            []config.CFObject{{Name: "example.com", ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		Tunnels:          []config.CFObject{{Name: "home", ID: "aa11bb22-0000-4000-8000-000000000000"}},
		D1Databases:      []config.CFObject{{Name: "app-db", ID: "11111111-2222-4333-8444-555555555555"}},
		TokenIPCondition: []string{"203.0.113.7/32"},
		Scopes:           map[string]config.CFScopeOverride{},
	}
}

func TestResolve(t *testing.T) {
	c, err := NewCatalogue(testCfg())
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Resolve(api.CloudflareRequest{Scope: api.CFScopeDNSEdit, Params: map[string]string{"zone": "example.com", "name": "*.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.ScopeParams != "name=*.example.com;zone=example.com" || r.IDs["zone"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || r.Mode != api.CFModeProxy {
		t.Fatalf("got %+v", r)
	}
	if _, err := c.Reparse(api.CFScopeDNSEdit, r.ScopeParams, r.Mode); err != nil {
		t.Fatal(err)
	}
	bad := []api.CloudflareRequest{
		{Scope: "cf.nope"},
		{Scope: api.CFScopeDNSEdit},
		{Scope: api.CFScopeDNSEdit, Params: map[string]string{"zone": "other.com"}},
		{Scope: api.CFScopeDNSEdit, Params: map[string]string{"zone": "example.com", "name": "x.other.com"}},
		{Scope: api.CFScopeDNSEdit, Params: map[string]string{"zone": "example.com", "name": "a;b=c"}},
		{Scope: api.CFScopeRead, Params: map[string]string{"zone": "example.com"}},
		{Scope: api.CFScopeRead, Mode: api.CFModeToken},
		{Scope: api.CFScopeAdmin, Mode: api.CFModeToken},
		{Scope: api.CFScopeTunnelConfig, Params: map[string]string{"tunnel": "office"}},
		{Scope: api.CFScopeWorkersDeploy, Params: map[string]string{"script": "../x"}},
	}
	for _, b := range bad {
		if _, err := c.Resolve(b); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
	tr, err := c.Resolve(api.CloudflareRequest{Scope: api.CFScopeWorkersDeploy, Mode: api.CFModeToken, Params: map[string]string{"script": "my-worker", "zone": "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Permissions) != 4 || !strings.Contains(strings.Join(tr.Notes, " "), "ANY Worker") {
		t.Fatalf("token resolve: %+v", tr)
	}
}

func TestOverrides(t *testing.T) {
	cfg := testCfg()
	cfg.Scopes["cf.admin"] = config.CFScopeOverride{MaxTTLSeconds: 7200}
	if _, err := NewCatalogue(cfg); err == nil {
		t.Fatal("admin ttl widened")
	}
	cfg.Scopes = map[string]config.CFScopeOverride{"cf.bogus": {}}
	if _, err := NewCatalogue(cfg); err == nil {
		t.Fatal("unknown scope accepted")
	}
	cfg.Scopes = map[string]config.CFScopeOverride{"cf.read": {NoAutoApprove: true}, "cf.email": {Disabled: true}}
	c, err := NewCatalogue(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := c.Lookup("cf.read"); s.AutoApprove {
		t.Fatal("auto not turned off")
	}
	if _, ok := c.Lookup("cf.email"); ok {
		t.Fatal("disabled scope offered")
	}
	if a, _ := c.Lookup("cf.admin"); a.AutoApprove || a.StandingAllowed || a.MaxTTL != 3600 {
		t.Fatalf("admin %+v", a)
	}
	if len(c.API().Scopes) != len(builtins)-1 {
		t.Fatal("catalogue size")
	}
}
