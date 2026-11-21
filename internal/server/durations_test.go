package server

import (
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
	"testing"
)

func TestRelaxationIsScopeSpecificAndNeverWidensConfiguredCaps(t *testing.T) {
	cfg := config.Defaults()
	cfg.Cloudflare.Scopes = map[string]config.CFScopeOverride{api.CFScopeDNSEdit: {MaxTTLSeconds: 600}, api.CFScopeReadPrivate: {MaxTTLSeconds: 1800}}
	cat, err := cfscope.NewCatalogue(&cfg.Cloudflare)
	if err != nil {
		t.Fatal(err)
	}
	s := Server{cfg: cfg}
	s.cf.cat = cat
	b := organisations.Resource{Class: api.ClassOwner, Kind: "cloudflare-proxy", PolicyRevision: 2}
	for _, tc := range []struct {
		scope   string
		relax   bool
		max     int
		forever bool
	}{{api.CFScopeRead, false, 28800, false}, {api.CFScopeRead, true, maxFinite, true}, {api.CFScopeAdmin, true, 3600, false}, {api.CFScopeReadPrivate, true, 1800, false}, {api.CFScopeDNSEdit, true, 600, false}} {
		l, err := s.resourceLimits(b, api.CatalogueRule{Scope: tc.scope, Relax: tc.relax}, initialPolicy)
		if err != nil || l.Hard != tc.max || l.Forever != tc.forever {
			t.Errorf("%s relaxed=%t: hard=%d indefinite=%t err=%v", tc.scope, tc.relax, l.Hard, l.Forever, err)
		}
		if _, err := l.requestTTL(0, 60, true); (err == nil) != tc.forever {
			t.Errorf("indefinite request gate %s: %v", tc.scope, err)
		}
	}
	cfg.Targets = []config.Target{{Name: "db", MaxTTLSeconds: 7200}}
	b.Kind, b.SetSlug = "ssh-ca", "db"
	p := initialPolicy
	p.Soft = 600
	p.Default = 120
	l, err := s.resourceLimits(b, api.CatalogueRule{}, p)
	if err != nil || l.Hard != 600 || l.Forever {
		t.Fatalf("SSH ceiling: %+v %v", l, err)
	}
}
