package maint

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// approveUpdate is the owner's "update" approval for 0.3.1, bound to the installed identity.
func (b *lab) approveUpdate() Request {
	b.t.Helper()
	to := strings.Repeat("d", 40)
	a := canon.Action{Object: "update", Action: "approve", ID: to, Update: canon.Update{FromVersion: "0.3.0", FromCommit: b.facts.Commit, ToVersion: "0.3.1", ToCommit: to,
		DaemonHash: b.sums[release.Daemon], LinuxARM: b.sums["aqmas-linux-arm64"], LinuxAMD: b.sums["aqmas-linux-amd64"], DarwinARM: b.sums["aqmas-darwin-arm64"]}}
	text, err := canon.Build(a, canon.NewNonce(), time.Now())
	if err != nil {
		b.t.Fatal(err)
	}
	return Request{Canonical: text, Assertion: b.auth.Assert(canon.Challenge(text))}
}

// githubOnly are the sources of an installation with nothing extra: the public repository
// over HTTPS and GitHub's release API (the lab's stand-in).
func (b *lab) githubOnly() UpdatesParams {
	return UpdatesParams{Repo: "https://github.com/example/aqmas.git", GitHubAPI: b.forge.URL + "/gh/repos/example/aqmas", KnownHosts: []string{}}
}

func TestEffectiveSources(t *testing.T) {
	gh, second := "https://api.github.com/repos/example/fork", "https://forge.example.com/api/v1/repos/example/fork"
	for name, c := range map[string]struct {
		pin    *Sources
		cfg    config.Updates
		want   Sources
		origin string
	}{
		"nothing configured": {nil, config.Updates{CacheDir: "/x"}, Sources{Repo: release.GitHubRepo, GitHubAPI: release.GitHubAPI}, SourcesDefault},
		"fork in config":     {nil, config.Updates{GitHub: release.Source{API: gh}}, Sources{Repo: "https://github.com/example/fork.git", GitHubAPI: gh}, SourcesConfig},
		"second in config": {nil, config.Updates{Repo: "ssh://git@forge.example.com/example/fork.git", Second: release.Source{API: second}},
			Sources{Repo: "ssh://git@forge.example.com/example/fork.git", GitHubAPI: release.GitHubAPI, SecondAPI: second}, SourcesConfig},
		"pin wins": {&Sources{Repo: "https://github.com/example/fork.git"}, config.Updates{Second: release.Source{API: second}},
			Sources{Repo: "https://github.com/example/fork.git", GitHubAPI: release.GitHubAPI}, SourcesPinned},
	} {
		if got, origin := EffectiveSources(c.pin, c.cfg); got != c.want || origin != c.origin {
			t.Errorf("%s: %+v from %s", name, got, origin)
		}
	}
}

// A pin written by 0.8.1 names the second source "forgejo_api": it keeps its meaning.
func TestLegacyPinFile(t *testing.T) {
	var s Sources
	if err := json.Unmarshal([]byte(`{"repo":"ssh://git@forge.example.com/a/b.git","forgejo_api":"https://forge.example.com/api/v1/repos/a/b","github_api":"https://api.github.com/repos/a/b"}`), &s); err != nil ||
		s != (Sources{Repo: "ssh://git@forge.example.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", SecondAPI: "https://forge.example.com/api/v1/repos/a/b"}) {
		t.Fatalf("%+v %v", s, err)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "forgejo") || !strings.Contains(string(b), `"second_api":"https://forge.example.com/api/v1/repos/a/b"`) {
		t.Fatalf("written as %s", b)
	}
}

func TestUpdatesParamsShapes(t *testing.T) {
	key := "forge.example.com ssh-ed25519 " + strings.Repeat("A", 68)
	ok := []UpdatesParams{
		{Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{}},
		{Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", SecondAPI: "https://forge.example.com/api/v1/repos/a/b", KnownHosts: []string{}, GitHubToken: true, SecondToken: true},
		{Repo: "ssh://git@forge.example.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", SecondAPI: "https://forge.example.com/api/v1/repos/a/b", KnownHosts: []string{key}},
	}
	for _, p := range ok {
		if _, err := Canonical(TaskUpdates, p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := map[string]UpdatesParams{
		"http repo":              {Repo: "http://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{}},
		"password in repo":       {Repo: "https://user:pw@github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{}},
		"user in https repo":     {Repo: "https://token@github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{}},
		"host keys for https":    {Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{key}},
		"ssh without host keys":  {Repo: "ssh://git@forge.example.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{}},
		"no github":              {Repo: "https://github.com/a/b.git", KnownHosts: []string{}},
		"http second":            {Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", SecondAPI: "http://forge.example.com/api/v1/repos/a/b", KnownHosts: []string{}},
		"credentials in second":  {Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", SecondAPI: "https://u:p@forge.example.com/api/v1/repos/a/b", KnownHosts: []string{}},
		"second is not a forge":  {Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", SecondAPI: "https://forge.example.com/a/b", KnownHosts: []string{}},
		"token without a second": {Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{}, SecondToken: true},
		"long second":            {Repo: "https://github.com/a/b.git", GitHubAPI: "https://api.github.com/repos/a/b", SecondAPI: "https://forge.example.com/api/v1/repos/" + strings.Repeat("a", 300), KnownHosts: []string{}},
	}
	for name, p := range bad {
		if _, err := Canonical(TaskUpdates, p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// With nothing but GitHub: no deploy key, no host keys, no tokens, one published source and
// the machine's own rebuild.
func TestGitHubOnlyEnableAndUpgrade(t *testing.T) {
	b := newLab(t)
	b.releases("0.3.0", "0.3.1")
	b.hubOpen = true
	if b.read("etc", "repo-key") != "" {
		t.Fatal("maint-init made a deploy key nobody asked for")
	}
	// Nothing is fixed on this machine, so its sources are the compiled GitHub defaults: a
	// request cannot point it anywhere else, the lab's own stand-in included.
	b.queue(b.sign(TaskUpdates, b.githubOnly(), nil))
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpdates).Message, "fixed on this machine") {
		t.Fatalf("a request chose the release sources: %+v", b.last(TaskUpdates))
	}
	p := b.githubOnly()
	if err := Init(context.Background(), b.l, false, &Sources{Repo: p.Repo, GitHubAPI: p.GitHubAPI}, io.Discard); err != nil {
		t.Fatal(err)
	}
	// Nor can a request add a second source to a machine that has none.
	added := b.githubOnly()
	added.SecondAPI = b.forge.URL + "/api/v1/repos/example/aqmas"
	b.forgeOpen = true
	b.queue(b.sign(TaskUpdates, added, nil))
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpdates).Message, "fixed on this machine") {
		t.Fatalf("a request added a release source: %+v", b.last(TaskUpdates))
	}
	b.queue(b.sign(TaskUpdates, b.githubOnly(), nil))
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatal(err, b.last(TaskUpdates))
	}
	cfg, s := b.read("etc", "config.toml"), b.last(TaskUpdates)
	switch {
	case s.State != "done" || s.Result["sources"] != "GitHub" || s.Result["deploy_key"] != "" || !strings.Contains(s.Message, "1 published source (GitHub)"):
		t.Fatalf("%+v", s)
	case !strings.Contains(cfg, `repo = "https://github.com/example/aqmas.git"`) || strings.Contains(cfg, "deploy_key") || strings.Contains(cfg, "updates.second") || strings.Contains(cfg, "forgejo") || strings.Contains(cfg, "\ntoken_file"):
		t.Fatal("configuration:\n" + cfg)
	case b.read("etc", "repo-key") != "" || b.read("etc", "known_hosts") != "" || b.read("etc", "github-read-token") != "" || b.read("etc", "second-read-token") != "":
		t.Fatal("a GitHub-only setup left a key, a host key or a token")
	case !strings.Contains(b.read("releases", "latest.json"), `"sources":1`) || strings.Contains(b.read("releases", "latest.json"), "second") || b.read("releases", "0.3.0", "aqmas-linux-arm64") != "binary aqmas-linux-arm64":
		t.Fatal("release cache: " + b.read("releases", "latest.json"))
	}
	// The second source is not consulted at all: it may be down.
	b.secondDown = true
	b.queue(b.approveUpdate())
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatalf("upgrade: %v %+v", err, b.last(TaskUpgrade))
	}
	var m release.Metadata
	if err := json.Unmarshal([]byte(b.read("installed-metadata.json")), &m); err != nil || !m.Valid() || m.Version != "0.3.1" || m.Compared() != 1 || !m.GitHub.Agrees(b.sums) {
		t.Fatalf("installer was handed %s", b.read("installed-metadata.json"))
	}
	// The updater's environment: an HTTPS remote and no key.
	if log := b.read("hook.log"); !strings.Contains(log, "upgrade ") {
		t.Fatal("installer not run")
	}
}

// A configured second source is part of the check for good: when it disagrees or cannot be
// reached nothing is enabled or installed, and GitHub alone is never fallen back to.
func TestConfiguredSecondSourceBlocks(t *testing.T) {
	b := newLab(t)
	b.releases("0.3.0", "0.3.1")
	b.pinSources()
	tokens := map[string]string{"second_token": secretForge, "github_token": secretHub}
	before := b.read("etc", "config.toml")
	for name, set := range map[string]func(bool){"disagreeing": func(v bool) { b.secondBad = v }, "unreachable": func(v bool) { b.secondDown = v }} {
		set(true)
		b.queue(b.sign(TaskUpdates, b.updatesParams(), tokens))
		if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpdates).Message, "second source (") || b.read("etc", "config.toml") != before || b.read("releases", "latest.json") != "" {
			t.Fatalf("enabled with a %s second source: %+v", name, b.last(TaskUpdates))
		}
		set(false)
	}
	b.queue(b.sign(TaskUpdates, b.updatesParams(), tokens))
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatal(err, b.last(TaskUpdates))
	}
	cfg, s := b.read("etc", "config.toml"), b.last(TaskUpdates)
	host := strings.TrimPrefix(b.forge.URL, "http://")
	if s.Result["sources"] != "GitHub and second source ("+host+")" || !strings.Contains(s.Message, "2 published sources") || !strings.Contains(cfg, "[updates.second]\napi = \""+b.forge.URL+"/api/v1/repos/example/aqmas\"\ntoken_file = \""+b.path("etc", "second-read-token")+"\"") ||
		!strings.Contains(b.read("releases", "latest.json"), `"sources":2`) {
		t.Fatalf("%+v\n%s\n%s", s, cfg, b.read("releases", "latest.json"))
	}
	for name, set := range map[string]func(bool){"disagreeing": func(v bool) { b.secondBad = v }, "unreachable": func(v bool) { b.secondDown = v }} {
		set(true)
		b.queue(b.approveUpdate())
		if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpgrade).Message, "second source (") || b.read("installed-metadata.json") != "" {
			t.Fatalf("installed with a %s second source: %+v", name, b.last(TaskUpgrade))
		}
		set(false)
	}
	b.queue(b.approveUpdate())
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatalf("upgrade: %v %+v", err, b.last(TaskUpgrade))
	}
	var m release.Metadata
	if err := json.Unmarshal([]byte(b.read("installed-metadata.json")), &m); err != nil || !m.Valid() || m.Compared() != 2 {
		t.Fatalf("installer was handed %s", b.read("installed-metadata.json"))
	}
}

// The one installation that predates the optional second source: [updates.forgejo] in the
// configuration, "forgejo_api" in the pin, forgejo-read-token, and a release identity
// written by the 0.8.1 installer. It keeps both sources without any edit, and the next run
// of "Enable self-update" writes everything under its current name.
func TestLegacyInstallationKeepsItsSecondSource(t *testing.T) {
	b := newLab(t)
	b.releases("0.3.0", "0.3.1")
	p := b.updatesParams()
	b.write(0644, `{"repo":"`+p.Repo+`","forgejo_api":"`+p.SecondAPI+`","github_api":"`+p.GitHubAPI+`"}`+"\n", "etc", sourcesName)
	b.write(0440, secretForge+"\n", "etc", "forgejo-read-token")
	b.write(0440, secretHub+"\n", "etc", "github-read-token")
	b.write(0640, b.read("etc", "config.toml")+"\n[updates.forgejo]\napi = \""+p.SecondAPI+"\"\ntoken_file = \""+b.path("etc", "forgejo-read-token")+"\"\n[updates.github]\napi = \""+p.GitHubAPI+"\"\ntoken_file = \""+b.path("etc", "github-read-token")+"\"\n", "etc", "config.toml")
	b.write(0640, strings.Replace(b.read("etc", "config.toml"), "[updates]\n", "[updates]\nrepo = \""+p.Repo+"\"\ndeploy_key = \""+b.path("etc", "repo-key")+"\"\ncheck_minutes = 15\n", 1), "etc", "config.toml")
	if err := os.MkdirAll(b.path("releases"), 0755); err != nil {
		t.Fatal(err)
	}
	sums, _ := json.Marshal(b.sums)
	b.write(0644, `{"version":"0.3.0","commit":"`+b.facts.Commit+`","forgejo":`+string(sums)+`,"github":`+string(sums)+"}\n", "releases", "latest.json")

	r := b.runner()
	if got := r.cfg.Updates.Sources(); got.Second.API != p.SecondAPI || got.Second.TokenFile != b.path("etc", "forgejo-read-token") || r.cfg.Updates.CheckMinutes != 15 {
		t.Fatalf("legacy configuration read as %+v", r.cfg.Updates)
	}
	if got, origin := EffectiveSources(b.l.readSources(), r.cfg.Updates); origin != SourcesPinned || got.SecondAPI != p.SecondAPI {
		t.Fatalf("legacy pin read as %+v (%s)", got, origin)
	}
	// An upgrade still needs the second source, read with the old token file.
	b.secondDown = true
	b.queue(b.approveUpdate())
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpgrade).Message, "second source (") {
		t.Fatalf("the legacy second source was dropped: %+v", b.last(TaskUpgrade))
	}
	b.secondDown = false
	b.queue(b.approveUpdate())
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatalf("upgrade: %v %+v", err, b.last(TaskUpgrade))
	}
	var m release.Metadata
	if err := json.Unmarshal([]byte(b.read("installed-metadata.json")), &m); err != nil || m.Compared() != 2 {
		t.Fatalf("installer was handed %s", b.read("installed-metadata.json"))
	}
	// Running the task again renames everything and keeps the operator's interval.
	b.queue(b.sign(TaskUpdates, p, map[string]string{"second_token": secretForge, "github_token": secretHub}))
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatal(err, b.last(TaskUpdates))
	}
	cfg := b.read("etc", "config.toml")
	if strings.Contains(cfg, "forgejo") || !strings.Contains(cfg, "[updates.second]\napi = \""+p.SecondAPI+"\"") || !strings.Contains(cfg, "check_minutes = 15") || b.read("etc", "forgejo-read-token") != "" ||
		strings.TrimSpace(b.read("etc", "second-read-token")) != secretForge {
		t.Fatalf("not renamed:\n%s", cfg)
	}
}

// writeIdentity records an installed release as verified against one or two sources.
func (b *lab) writeIdentity(two bool) {
	b.t.Helper()
	m := release.Metadata{Version: "0.3.0", Commit: b.facts.Commit, GitHub: b.sums}
	if two {
		m.Second = b.sums
	}
	text, _ := json.Marshal(m)
	if err := os.MkdirAll(b.path("releases"), 0755); err != nil {
		b.t.Fatal(err)
	}
	b.write(0644, string(text)+"\n", "releases", "latest.json")
}

func (b *lab) setUpdates(tables string) {
	b.t.Helper()
	cfg := b.read("etc", "config.toml")
	if i := strings.Index(cfg, "\n# test sources\n"); i >= 0 {
		cfg = cfg[:i]
	}
	b.write(0640, cfg+"\n# test sources\n"+tables, "etc", "config.toml")
}

// The configuration alone cannot take a release source away: not by a missing line, not by
// a missing table, not by disagreeing with the pin, and not once the installed release has
// been verified against two sources. Only the owner at the machine can (--github-only).
func TestSecondSourceCannotBeDroppedByConfiguration(t *testing.T) {
	b := newLab(t)
	b.releases("0.3.0", "0.3.1")
	b.hubOpen, b.forgeOpen = true, true
	p := b.updatesParams()
	pin := `{"repo":"` + p.Repo + `","forgejo_api":"` + p.SecondAPI + `","github_api":"` + p.GitHubAPI + `"}` + "\n"
	base := b.read("etc", "config.toml")
	withRepo := strings.Replace(base, "[updates]\n", "[updates]\nrepo = \""+p.Repo+"\"\ndeploy_key = \""+b.path("etc", "repo-key")+"\"\n", 1)
	b.write(0640, withRepo, "etc", "config.toml")
	github := "[updates.github]\napi = \"" + p.GitHubAPI + "\"\n"
	refused := func(name, want string) {
		t.Helper()
		_ = os.Remove(b.path("installed-metadata.json"))
		b.queue(b.approveUpdate())
		if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpgrade).Message, want) || b.read("installed-metadata.json") != "" {
			t.Fatalf("%s: installed, or refused for another reason: %v %+v", name, err, b.last(TaskUpgrade))
		}
	}

	// A 0.8.1 pin with a second source, and a token-only table (0.8.1 supplied the address):
	// the configuration does not load at all, for the broker or the runner.
	b.write(0644, pin, "etc", sourcesName)
	b.writeIdentity(true)
	b.setUpdates("[updates.forgejo]\ntoken_file = \"" + b.path("etc", "forgejo-read-token") + "\"\n" + github)
	if _, err := New(b.l, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.Contains(err.Error(), "[updates.second]\napi = ") {
		t.Fatalf("token-only second-source table loaded: %v", err)
	}
	// The same pin and no table at all: GitHub only by configuration. Refused.
	b.setUpdates(github)
	refused("pin names a second source, configuration has none", "pinned on this machine include a second source")
	// Pin and configuration name different second sources. Refused.
	b.setUpdates("[updates.second]\napi = \"" + b.forge.URL + "/api/v1/repos/example/other\"\n" + github)
	refused("pin and configuration disagree", "names a different one")
	// No pin, but the installed release was verified against two sources. Refused.
	_ = os.Remove(b.path("etc", sourcesName))
	b.setUpdates(github)
	refused("two-source identity, one-source configuration", "verified against two published sources")
	// "Enable self-update" is not a way around it either (its sources are now the configuration's).
	one := UpdatesParams{Repo: p.Repo, GitHubAPI: p.GitHubAPI, KnownHosts: p.KnownHosts}
	b.queue(b.sign(TaskUpdates, one, nil))
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpdates).Message, "verified against two published sources") || !strings.Contains(b.read("releases", "latest.json"), `"sources":2`) {
		t.Fatalf("Enable self-update dropped the second source: %+v", b.last(TaskUpdates))
	}
	// Re-pinning without saying so does not drop it; --github-only does.
	if err := Init(context.Background(), b.l, false, &Sources{Repo: p.Repo, GitHubAPI: p.GitHubAPI}, io.Discard); err == nil || !strings.Contains(err.Error(), "--github-only") {
		t.Fatalf("a pin without --second-api dropped the second source: %v", err)
	}
	if err := Init(context.Background(), b.l, false, &Sources{Repo: p.Repo, GitHubAPI: p.GitHubAPI, SecondAPI: p.SecondAPI, GitHubOnly: true}, io.Discard); err == nil {
		t.Fatal("--github-only together with --second-api accepted")
	}
	if err := Init(context.Background(), b.l, false, &Sources{Repo: p.Repo, GitHubAPI: p.GitHubAPI, GitHubOnly: true}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.read("etc", sourcesName), "github_only") || !strings.Contains(b.read("etc", sourcesName), `"second_api":""`) {
		t.Fatalf("pin: %s", b.read("etc", sourcesName))
	}
	// The owner decided at the machine: one source is allowed now.
	b.queue(b.approveUpdate())
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatalf("upgrade after an explicit GitHub-only pin: %v %+v", err, b.last(TaskUpgrade))
	}
	var m release.Metadata
	if err := json.Unmarshal([]byte(b.read("installed-metadata.json")), &m); err != nil || m.Compared() != 1 {
		t.Fatalf("installer was handed %s", b.read("installed-metadata.json"))
	}
	// A configured second source is never dropped by leaving the flag out either.
	b.setUpdates("[updates.second]\napi = \"" + p.SecondAPI + "\"\n" + github)
	if err := Init(context.Background(), b.l, false, &Sources{Repo: p.Repo}, io.Discard); err == nil || !strings.Contains(err.Error(), "--github-only") {
		t.Fatalf("a pin without --second-api dropped a configured second source: %v", err)
	}
	if err := Init(context.Background(), b.l, false, &Sources{Repo: p.Repo, GitHubAPI: p.GitHubAPI, SecondAPI: p.SecondAPI}, io.Discard); err != nil {
		t.Fatal(err)
	}
}
