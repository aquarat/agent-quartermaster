package config

import (
	"strings"
	"testing"
)

const minimalForCF = `
public_base_url = "https://aqmas.example.com"
owner_name = "owner"
tls_sans = ["192.0.2.5"]
`

// cfConfig: top goes into [cloudflare] itself, tables after the zone/D1 tables.
func cfConfig(top, tables string) string {
	return minimalForCF + `
[cloudflare]
` + top + `
enabled = true
account_id = "0123456789abcdef0123456789abcdef"
proxy_token_file = "/nonexistent/proxy"
[[cloudflare.zones]]
name = "example.com"
id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[[cloudflare.d1_databases]]
name = "app-db"
id = "11111111-2222-4333-8444-555555555555"
` + tables
}

func TestCloudflareDefaultsEmpty(t *testing.T) {
	c, err := Parse([]byte(cfConfig("", "")))
	if err != nil {
		t.Fatal(err)
	}
	cf := c.Cloudflare
	if len(cf.ProtectedAccessHostnames) != 0 || len(cf.ProtectedDNSNames) != 0 || cf.TraefikOrigin != "" || len(cf.TraefikPlainOrigins) != 0 || len(cf.ProtectedHostnames()) != 0 {
		t.Fatalf("site-specific defaults: %+v", cf)
	}
	if w := cf.Warnings(); len(w) != 2 || !strings.Contains(w[0], "protected_access_hostnames") {
		t.Fatalf("warnings %v", w)
	}
}

func TestCloudflareBindingsAndEmail(t *testing.T) {
	c, err := Parse([]byte(cfConfig(`
protected_access_hostnames = ["ID.example.com."]
protected_dns_names = ["id.example.com", "*.internal.example.com"]
email_forward_allow = ["owner@example.net"]`, `
[[cloudflare.worker_bindings]]
script = "hello"
allow = ["d1:app-db", "r2:assets", "kv:0123abcd"]
[[cloudflare.worker_bindings]]
pages_project = "site"
allow = ["service:auth"]
`)))
	if err != nil {
		t.Fatal(err)
	}
	cf := &c.Cloudflare
	if got := strings.Join(cf.ProtectedHostnames(), ","); got != "id.example.com,*.internal.example.com" {
		t.Fatalf("protected %q", got)
	}
	if got := strings.Join(cf.AllowedBindings("hello", false), ","); got != "d1:app-db,r2:assets,kv:0123abcd" {
		t.Fatalf("bindings %q", got)
	}
	if len(cf.AllowedBindings("hello", true)) != 0 || len(cf.AllowedBindings("site", true)) != 1 {
		t.Fatal("pages bindings")
	}
	if len(cf.Warnings()) != 1 {
		t.Fatalf("warnings %v", cf.Warnings())
	}
	bad := []string{
		"[[cloudflare.worker_bindings]]\nallow = [\"r2:x\"]\n",
		"[[cloudflare.worker_bindings]]\nscript = \"a\"\npages_project = \"b\"\n",
		"[[cloudflare.worker_bindings]]\nscript = \"a\"\nallow = [\"d1:unknown-db\"]\n",
		"[[cloudflare.worker_bindings]]\nscript = \"a\"\nallow = [\"bogus:x\"]\n",
		"[[cloudflare.worker_bindings]]\nscript = \"a\"\nallow = [\"r2\"]\n",
		"email_forward_allow = [\"not-an-address\"]\n",
		"protected_dns_names = [\"bad host/x\"]\n",
	}
	for _, b := range bad {
		cfg := cfConfig(b, "")
		if strings.HasPrefix(b, "[[") {
			cfg = cfConfig("", b)
		}
		if _, err := Parse([]byte(cfg)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}
