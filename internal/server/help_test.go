package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/release"
)

// The Help page's install commands: the CLI hashes come only from the verified record of
// the release that is running, and the download address from configuration, never a request.
func TestHelpInstallFields(t *testing.T) {
	e := newEnv(t)
	e.cfg.Updates.CacheDir = t.TempDir()
	oldV, oldC := release.Version, release.Commit
	commit := strings.Repeat("c", 40)
	release.Version, release.Commit = "1.2.3", commit
	t.Cleanup(func() { release.Version, release.Commit = oldV, oldC })
	e.setupOwner()
	sums := release.Sums{}
	for i, a := range release.Assets {
		sums[a] = strings.Repeat(string(rune('1'+i)), 64)
	}
	text, _ := json.Marshal(sums)
	record := func(version, commit string) string {
		return `{"version":"` + version + `","commit":"` + commit + `","github":` + string(text) + `,"sources":1}`
	}
	help := func(latest string) api.HelpConfig {
		t.Helper()
		path := filepath.Join(e.cfg.Updates.CacheDir, "latest.json")
		if latest == "" {
			_ = os.Remove(path)
		} else if err := os.WriteFile(path, []byte(latest), 0644); err != nil {
			t.Fatal(err)
		}
		var v api.HelpConfig
		mustStatus(t, "help", e.webDo("GET", "/api/ui/help", nil, &v), 200)
		return v
	}
	const github = "https://github.com/aquarat/agent-quartermaster/releases/download/v1.2.3"

	v := help(record("1.2.3", commit))
	if v.ReleaseVersion != "1.2.3" || v.CLIDownloadBaseURL != github || v.CLIDownloadSource != "github" || len(v.CLISHA256) != 3 {
		t.Fatalf("record present: %+v", v)
	}
	for _, a := range []string{"aqmas-darwin-arm64", "aqmas-linux-amd64", "aqmas-linux-arm64"} {
		if v.CLISHA256[a] != sums[a] {
			t.Fatalf("%s: %q", a, v.CLISHA256[a])
		}
	}
	if _, daemon := v.CLISHA256[release.Daemon]; daemon {
		t.Fatal("the daemon is not a CLI asset")
	}

	// How many sources agreed on those hashes is said too: a record of 0.8.1 or earlier
	// (digests under "forgejo", no count) always held two.
	if v.CLISHA256Sources != 1 {
		t.Fatalf("GitHub-only record: %+v", v)
	}
	for name, latest := range map[string]string{
		"two sources":      `{"version":"1.2.3","commit":"` + commit + `","github":` + string(text) + `,"second":` + string(text) + `,"sources":2}`,
		"written by 0.8.1": `{"version":"1.2.3","commit":"` + commit + `","forgejo":` + string(text) + `,"github":` + string(text) + `}`,
	} {
		if v := help(latest); v.CLISHA256Sources != 2 || len(v.CLISHA256) != 3 || v.CLISHA256["aqmas-linux-arm64"] != sums["aqmas-linux-arm64"] {
			t.Fatalf("%s: %+v", name, v)
		}
	}

	// A record with SHA256SUMS.extra adds the macOS x86-64 hash; one without leaves it out
	// (the page checks that build against the published file).
	extra := strings.Repeat("e", 64)
	if v := help(`{"version":"1.2.3","commit":"` + commit + `","github":` + string(text) + `,"extra":{"aqmas-darwin-amd64":"` + extra + `"},"sources":1}`); len(v.CLISHA256) != 4 || v.CLISHA256[release.DarwinAMD] != extra {
		t.Fatalf("record with extra: %+v", v)
	}
	if _, ok := help(record("1.2.3", commit)).CLISHA256[release.DarwinAMD]; ok {
		t.Fatal("a record without extra gave a macOS x86-64 hash")
	}

	for name, latest := range map[string]string{
		"no record":         "",
		"another version":   record("1.2.4", commit),
		"another commit":    record("1.2.3", strings.Repeat("d", 40)),
		"invalid record":    `{"version":"1.2.3","commit":"` + commit + `","github":{},"sources":1}`,
		"unreadable record": "{",
	} {
		if v := help(latest); v.CLISHA256 != nil || v.CLISHA256Sources != 0 || v.ReleaseVersion != "1.2.3" || v.CLIDownloadBaseURL != github || v.CLIDownloadSource != "github" {
			t.Fatalf("%s: %+v", name, v)
		}
	}

	// A fork's GitHub API gives the fork's releases; an API elsewhere gives no address.
	e.cfg.Updates.GitHub.API = "https://api.github.com/repos/example/fork"
	if v := help(""); v.CLIDownloadBaseURL != "https://github.com/example/fork/releases/download/v1.2.3" {
		t.Fatalf("fork: %+v", v)
	}
	// A read token means a private repository: its release downloads are not public.
	e.cfg.Updates.GitHub.TokenFile = "/etc/aqmas/github-read-token"
	if v := help(record("1.2.3", commit)); v.CLIDownloadBaseURL != "" || v.CLIDownloadSource != "" || len(v.CLISHA256) != 3 {
		t.Fatalf("private repository: %+v", v)
	}
	e.cfg.Updates.GitHub.TokenFile = ""
	e.cfg.Updates.GitHub.API = "https://git.example.com/api/v3/repos/example/fork"
	if v := help(record("1.2.3", commit)); v.CLIDownloadBaseURL != "" || v.CLIDownloadSource != "" || len(v.CLISHA256) != 3 {
		t.Fatalf("unknown source: %+v", v)
	}
	// The operator's address wins, with the hashes still the broker's.
	e.cfg.CLIDownloadBaseURL = "https://downloads.example.com/aqmas/"
	if v := help(record("1.2.3", commit)); v.CLIDownloadBaseURL != "https://downloads.example.com/aqmas" || v.CLIDownloadSource != "config" || len(v.CLISHA256) != 3 {
		t.Fatalf("configured: %+v", v)
	}

	// A development build names no release: no hashes even beside a record, no GitHub address.
	e.cfg.CLIDownloadBaseURL, e.cfg.Updates.GitHub.API = "", ""
	release.Version = "dev"
	if v := help(record("1.2.3", commit)); v.ReleaseVersion != "" || v.CLISHA256 != nil || v.CLIDownloadBaseURL != "" || v.CLIDownloadSource != "" {
		t.Fatalf("dev: %+v", v)
	}
}
