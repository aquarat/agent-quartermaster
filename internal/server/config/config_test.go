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
principal = "alice@forgejo"
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
	if n.Port != 22 || n.Principal("alice") != "alice@db-1" || f.Principal("git") != "alice@forgejo" {
		t.Fatal("targets")
	}
	for name, bad := range map[string]string{
		"unknown key":    example + "\nbogus = 1\n",
		"http base":      strings.Replace(example, "https://approvals", "http://approvals", 1),
		"base path":      strings.Replace(example, "example.com\"", "example.com/x\"", 1),
		"bad user":       strings.Replace(example, `users = ["git"]`, `users = ["Git;rm"]`, 1),
		"bare principal": strings.Replace(example, `principal = "alice@forgejo"`, `principal = "alice"`, 1),
		"access half":    example + "\n[access]\naud = \"x\"\n",
		"ttl inverted":   strings.Replace(example, "max_seconds = 14400", "max_seconds = 10", 1),
		"dup target":     example + "\n[[targets]]\nname = \"db-1\"\naddress = \"x\"\nusers = [\"a\"]\n",
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

func TestPrincipalCollisionAndTTLCap(t *testing.T) {
	collide := example + `
[[targets]]
name = "backdoor"
address = "192.0.2.71"
users = ["git"]
principal = "alice@db-1"
`
	if _, err := Parse([]byte(collide)); err == nil || !strings.Contains(err.Error(), "alice@db-1") {
		t.Fatalf("principal collision accepted: %v", err)
	}
	plain := example + `
[[targets]]
name = "fake"
address = "192.0.2.71"
users = ["alice"]
principal = "alice@forgejo"
`
	if _, err := Parse([]byte(plain)); err == nil {
		t.Fatal("two targets issuing alice@forgejo accepted")
	}
	low := strings.Replace(example, `principal = "alice@forgejo"`, "principal = \"alice@forgejo\"\nmax_ttl_seconds = 30", 1)
	if _, err := Parse([]byte(low)); err == nil {
		t.Fatal("max_ttl_seconds below ttl.min_seconds accepted")
	}
}
