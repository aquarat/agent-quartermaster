package config

import (
	"strings"
	"testing"
)

const example = `
public_base_url = "https://approvals.example.com"
owner_name = "alice"
tls_sans = ["192.0.2.60", "bastion"]

[ttl]
max_seconds = 14400

[[targets]]
name = "db-1"
address = "192.0.2.61"
users = ["alice"]

[[targets]]
name = "forgejo"
address = "192.0.2.50"
port = 2222
users = ["git"]
forgejo_user = "alice"
`

func TestParse(t *testing.T) {
	c, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAgent != ":8443" || c.ListenWeb != "127.0.0.1:8080" || c.DataDir != "/var/lib/aqmas" || c.TTL.DefaultSeconds != 1800 || c.TTL.MaxSeconds != 14400 {
		t.Fatalf("defaults %+v", c)
	}
	n, _ := c.Target("db-1")
	f, _ := c.Target("forgejo")
	if n.Port != 22 || n.Principal("alice") != "alice@db-1" || f.Principal("git") != "alice" {
		t.Fatal("targets")
	}
	for name, bad := range map[string]string{
		"unknown key":  example + "\nbogus = 1\n",
		"http base":    strings.Replace(example, "https://approvals", "http://approvals", 1),
		"base path":    strings.Replace(example, "example.com\"", "example.com/x\"", 1),
		"bad user":     strings.Replace(example, `users = ["git"]`, `users = ["Git;rm"]`, 1),
		"access half":  example + "\n[access]\naud = \"x\"\n",
		"ttl inverted": strings.Replace(example, "max_seconds = 14400", "max_seconds = 10", 1),
		"dup target":   example + "\n[[targets]]\nname = \"db-1\"\naddress = \"x\"\nusers = [\"a\"]\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExampleConfigParses(t *testing.T) {
	c, err := Load("../../../deploy/bastion/config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicBaseURL != "https://approvals.example.com" || len(c.Targets) == 0 || c.Access.Enabled() {
		t.Fatalf("example config %+v", c)
	}
}
