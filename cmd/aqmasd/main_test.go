package main

import (
	"os"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// The shipped example config parses, and its commented [cloudflare] block is valid once
// uncommented and filled with (fake) ids.
func TestExampleConfigCloudflare(t *testing.T) {
	b, err := os.ReadFile("../../deploy/bastion/config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(b)
	if err != nil {
		t.Fatalf("example config as shipped: %v", err)
	}
	if cfg.Cloudflare.Enabled {
		t.Fatal("cloudflare enabled in the example as shipped")
	}
	var out []string
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		if l == "# [cloudflare]" {
			in = true
		}
		if in && !strings.HasPrefix(l, "#") {
			in = false
		}
		if in {
			l = strings.TrimPrefix(strings.TrimPrefix(l, "#"), " ")
		}
		out = append(out, l)
	}
	text := strings.NewReplacer(
		"<32 lowercase hex>", "0123456789abcdef0123456789abcdef",
		"<32 hex zone id>", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"<tunnel uuid>", "aa11bb22-0000-4000-8000-000000000000",
		"<database uuid>", "11111111-2222-4333-8444-555555555555",
		"<static home IPv4>", "203.0.113.7",
	).Replace(strings.Join(out, "\n"))
	cfg, err = config.Parse([]byte(text))
	if err != nil {
		t.Fatalf("uncommented [cloudflare] example: %v", err)
	}
	cf := cfg.Cloudflare
	if !cf.Enabled || cf.ProxyTokenCredential != "cf-proxy-token" || cf.MinterTokenCredential != "cf-minter-token" || len(cf.Zones) != 1 {
		t.Fatalf("parsed %+v", cf)
	}
	if _, err := cfscope.NewCatalogue(&cf); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile("../../deploy/bastion/aqmasd.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LoadCredential=cf-proxy-token:/etc/aqmas/cf-proxy-token", "LoadCredential=cf-minter-token:/etc/aqmas/cf-minter-token", "StateDirectory=aqmas", "ProtectSystem=strict"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("aqmasd.service lacks %q", want)
		}
	}
}
