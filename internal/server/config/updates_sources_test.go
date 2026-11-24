package config

import (
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/release"
)

const updatesBase = "public_base_url = \"https://aqmas.example.com\"\n"

func TestUpdatesSources(t *testing.T) {
	// Nothing configured: GitHub alone, at its compiled address, and no second source.
	c, err := Parse([]byte(updatesBase))
	if err != nil {
		t.Fatal(err)
	}
	if src := c.Updates.Sources(); src.HasSecond() || src.GitHub.API != "" || strings.Join(src.Names(), ",") != "GitHub" || c.Updates.SecondIgnored() {
		t.Fatalf("default sources: %+v", src)
	}

	c, err = Parse([]byte(updatesBase + `
[updates]
repo = "https://github.com/example/fork.git"
check_minutes = 30
[updates.github]
api = "https://api.github.com/repos/example/fork"
token_file = "/etc/aqmas/github-read-token"
[updates.second]
api = "https://forge.example.com/api/v1/repos/example/fork"
token_file = "/etc/aqmas/second-read-token"
`))
	if err != nil {
		t.Fatal(err)
	}
	want := release.Sources{GitHub: release.Source{API: "https://api.github.com/repos/example/fork", TokenFile: "/etc/aqmas/github-read-token"},
		Second: release.Source{API: "https://forge.example.com/api/v1/repos/example/fork", TokenFile: "/etc/aqmas/second-read-token"}}
	if got := c.Updates.Sources(); got != want || got.Names()[1] != "second source (forge.example.com)" || c.Updates.Repo != "https://github.com/example/fork.git" {
		t.Fatalf("%+v", got)
	}

	// The table's name up to 0.8.1 still configures the second source.
	c, err = Parse([]byte(updatesBase + `
[updates]
repo = "ssh://git@forge.example.com:2222/example/agent-quartermaster.git"
deploy_key = "/etc/aqmas/repo-key"
[updates.forgejo]
api = "https://forge.example.com/api/v1/repos/example/agent-quartermaster"
token_file = "/etc/aqmas/forgejo-read-token"
`))
	if err != nil || c.Updates.Second != (release.Source{API: "https://forge.example.com/api/v1/repos/example/agent-quartermaster", TokenFile: "/etc/aqmas/forgejo-read-token"}) || c.Updates.Legacy != (release.Source{}) {
		t.Fatalf("legacy table: %v %+v", err, c)
	}

	// 0.8.1 fell back to a compiled address when the table had none. There is no such
	// address any more: the broker still starts, compares GitHub only, and can say so.
	c, err = Parse([]byte(updatesBase + "[updates.forgejo]\ntoken_file = \"/etc/aqmas/forgejo-read-token\"\n"))
	if err != nil || c.Updates.Sources().HasSecond() || !c.Updates.SecondIgnored() {
		t.Fatalf("token without an address: %v", err)
	}
}

func TestUpdatesSourcesRefused(t *testing.T) {
	for name, text := range map[string]string{
		"http second":            "[updates.second]\napi = \"http://forge.example.com/api/v1/repos/a/b\"\n",
		"credentials in second":  "[updates.second]\napi = \"https://user:secret@forge.example.com/api/v1/repos/a/b\"\n",
		"user in second":         "[updates.second]\napi = \"https://token@forge.example.com/api/v1/repos/a/b\"\n",
		"query in second":        "[updates.second]\napi = \"https://forge.example.com/api/v1/repos/a/b?token=x\"\n",
		"not a forge API":        "[updates.second]\napi = \"https://forge.example.com/a/b\"\n",
		"too long":               "[updates.second]\napi = \"https://forge.example.com/api/v1/repos/" + strings.Repeat("a", 500) + "\"\n",
		"relative token file":    "[updates.second]\napi = \"https://forge.example.com/api/v1/repos/a/b\"\ntoken_file = \"token\"\n",
		"http github":            "[updates.github]\napi = \"http://api.github.com/repos/a/b\"\n",
		"credentials in github":  "[updates.github]\napi = \"https://x:y@api.github.com/repos/a/b\"\n",
		"http repo":              "[updates]\nrepo = \"http://github.com/a/b.git\"\n",
		"credentials in repo":    "[updates]\nrepo = \"https://user:secret@github.com/a/b.git\"\n",
		"password in ssh repo":   "[updates]\nrepo = \"ssh://git:secret@forge.example.com/a/b.git\"\n",
		"local repo":             "[updates]\nrepo = \"/srv/git/a.git\"\n",
		"two names, two sources": "[updates.second]\napi = \"https://forge.example.com/api/v1/repos/a/b\"\n[updates.forgejo]\napi = \"https://other.example.com/api/v1/repos/a/b\"\n",
		"unknown key":            "[updates.second]\nurl = \"https://forge.example.com/api/v1/repos/a/b\"\n",
	} {
		if _, err := Parse([]byte(updatesBase + text)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
