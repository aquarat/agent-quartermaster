package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/release"
)

// updateLab is everything update discovery talks to, on loopback: a git repository served
// over plain HTTP (as the public repository is over HTTPS), GitHub's release API and a
// second source's Forgejo-shaped one.
type updateLab struct {
	repo, running, tagged string
	github, second        *httptest.Server
	secondSums            release.Sums
	sums                  release.Sums
}

func newUpdateLab(t *testing.T) *updateLab {
	t.Helper()
	// The broker runs git with PATH=/usr/bin:/bin and nothing else.
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		t.Skip("no /usr/bin/git")
	}
	exe, err := exec.Command("/usr/bin/git", "--exec-path").Output()
	if err != nil {
		t.Skip("git --exec-path failed")
	}
	if _, err = os.Stat(filepath.Join(strings.TrimSpace(string(exe)), "git-remote-http")); err != nil {
		t.Skip("git has no HTTP transport here")
	}
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	git := func(wd string, args ...string) string {
		t.Helper()
		c := exec.Command("/usr/bin/git", args...)
		c.Dir = wd
		c.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C",
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com"}
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(version, note string) string {
		if err := os.WriteFile(filepath.Join(work, "VERSION"), []byte(version+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, "NOTES"), []byte(note+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		git(work, "add", "VERSION", "NOTES")
		git(work, "commit", "-q", "-m", "release "+version)
		return git(work, "rev-parse", "HEAD")
	}
	git(dir, "init", "-q", "-b", "main", work)
	l := &updateLab{sums: release.Sums{}}
	l.running = commit("1.0.0", "first")
	l.tagged = commit("1.0.1", "second")
	git(work, "tag", "v1.0.0", l.running)
	git(work, "tag", "v1.0.1", l.tagged)
	bare := filepath.Join(dir, "srv", "example", "aqmas.git")
	git(dir, "clone", "-q", "--bare", work, bare)
	git(bare, "update-server-info")
	files := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(dir, "srv"))))
	t.Cleanup(files.Close)
	l.repo = files.URL + "/example/aqmas.git"

	for _, a := range release.Assets {
		l.sums[a] = strings.Repeat("a", 64)
	}
	l.secondSums = maps.Clone(l.sums)
	const id = "00000000-0000-0000-0000-000000000001"
	serve := func(github bool, sums func() release.Sums) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Error("a token was sent although none is configured")
			}
			switch {
			case strings.HasSuffix(r.URL.Path, "/releases/tags/v1.0.1"):
				fmt.Fprintf(w, `{"tag_name":"v1.0.1","assets":[{"name":"SHA256SUMS","id":1,"uuid":%q}]}`, id)
			case github && strings.HasSuffix(r.URL.Path, "/releases/assets/1"), !github && r.URL.Path == "/attachments/"+id:
				fmt.Fprint(w, sums().Text())
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	l.github = serve(true, func() release.Sums { return l.sums })
	l.second = serve(false, func() release.Sums { return l.secondSums })
	return l
}

// discover runs one discovery pass the way pollUpdates does and publishes its result.
func (e *env) discoverNow() updateView {
	e.t.Helper()
	v := updateView{}
	if err := e.s.discover(e.t.Context(), &v); err != nil {
		v.Error = err.Error()
	}
	e.s.updates.Lock()
	e.s.updates.view = v
	e.s.updates.Unlock()
	var out updateView
	mustStatus(e.t, "updates view", e.webDo("GET", "/api/ui/updates", nil, &out), 200)
	return out
}

func updateEnv(t *testing.T, l *updateLab) *env {
	e := newEnv(t)
	e.cfg.Updates.Repo = l.repo
	e.cfg.Updates.GitHub.API = l.github.URL + "/repos/example/aqmas"
	e.cfg.Updates.SpoolDir, e.cfg.Updates.CacheDir = t.TempDir(), t.TempDir()
	oldV, oldC := release.Version, release.Commit
	release.Version, release.Commit = "1.0.0", l.running
	t.Cleanup(func() { release.Version, release.Commit = oldV, oldC })
	e.setupOwner()
	e.installRunner()
	return e
}

// With nothing but the public repository: discovery over anonymous HTTP(S), the diff, the
// hashes from GitHub alone, and the owner's approval reaching the runner's spool. No deploy
// key, no token, no second source.
func TestUpdateDiscoveryGitHubOnly(t *testing.T) {
	l := newUpdateLab(t)
	e := updateEnv(t, l)
	v := e.discoverNow()
	c := v.Candidate
	switch {
	case v.Error != "":
		t.Fatal(v.Error)
	case c.Version != "1.0.1" || c.Commit != l.tagged || !c.Valid() || c.Compared() != 1 || !c.GitHub.Agrees(l.sums):
		t.Fatalf("candidate %+v", c)
	case len(v.Sources) != 1 || v.Sources[0] != "GitHub":
		t.Fatalf("sources %v", v.Sources)
	case !strings.Contains(v.Diff, "+1.0.1") || !strings.Contains(v.Diff, "-first") || !strings.Contains(v.Stat, "VERSION"):
		t.Fatalf("diff:\n%s\n%s", v.Stat, v.Diff)
	}
	path := "/api/ui/updates/" + l.tagged
	mustStatus(t, "approve", e.approve(path, "decide", api.ChallengeRequest{Action: "approve"}), 200)
	b, err := os.ReadFile(maint.RequestPath(e.cfg.Updates.Spool()))
	if err != nil || !bytes.Contains(b, []byte(l.tagged)) || !bytes.Contains(b, []byte(l.sums[release.Daemon])) {
		t.Fatal("the approval did not reach the spool", err)
	}
	// A second pass reuses the bare repository.
	if v = e.discoverNow(); v.Error != "" || v.Candidate.Commit != l.tagged {
		t.Fatalf("second pass: %+v", v)
	}
}

// A configured second source is compared too, and it is not optional once configured.
func TestUpdateDiscoverySecondSource(t *testing.T) {
	l := newUpdateLab(t)
	e := updateEnv(t, l)
	e.cfg.Updates.Second.API = l.second.URL + "/api/v1/repos/example/aqmas"
	name := "second source (" + strings.TrimPrefix(l.second.URL, "http://") + ")"
	path := "/api/ui/updates/" + l.tagged

	v := e.discoverNow()
	if v.Error != "" || v.Candidate.Compared() != 2 || !v.Candidate.Valid() || len(v.Sources) != 2 || v.Sources[1] != name {
		t.Fatalf("two agreeing sources: %+v", v)
	}
	_, code := e.challenge(path, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "challenge with agreeing sources", code, 200)

	l.secondSums = maps.Clone(l.sums)
	l.secondSums["aqmas-linux-amd64"] = strings.Repeat("b", 64)
	if v = e.discoverNow(); !strings.Contains(v.Error, "disagree") || !strings.Contains(v.Error, name) {
		t.Fatalf("disagreeing second source: %+v", v)
	}
	_, code = e.challenge(path, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "challenge with disagreeing sources", code, 409)

	// Unreachable: the update is blocked, not offered on GitHub's word alone.
	l.secondSums = l.sums
	l.second.Close()
	if v = e.discoverNow(); !strings.Contains(v.Error, name) || v.Candidate.Valid() && v.Error == "" {
		t.Fatalf("unreachable second source: %+v", v)
	}
	_, code = e.challenge(path, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "challenge with an unreachable source", code, 409)
	if _, err := os.Stat(maint.RequestPath(e.cfg.Updates.Spool())); err == nil {
		t.Fatal("an update was queued")
	}
}

// What a fleet CLI is told: a 0.8.1 CLI needs "forgejo" equal to "github"; a current one
// reads how many sources the bastion compared.
func TestLatestReleaseWire(t *testing.T) {
	e := newEnv(t)
	e.cfg.Updates.CacheDir = t.TempDir()
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("agenthost")))
	sums := release.Sums{}
	for _, a := range release.Assets {
		sums[a] = strings.Repeat("a", 64)
	}
	commit := strings.Repeat("c", 40)
	text, _ := json.Marshal(sums)
	for name, tc := range map[string]struct {
		record   string
		compared int
	}{
		"GitHub only":      {`{"version":"1.2.3","commit":"` + commit + `","github":` + string(text) + `,"sources":1}`, 1},
		"second source":    {`{"version":"1.2.3","commit":"` + commit + `","github":` + string(text) + `,"second":` + string(text) + `,"sources":2}`, 2},
		"written by 0.8.1": {`{"version":"1.2.3","commit":"` + commit + `","forgejo":` + string(text) + `,"github":` + string(text) + `}`, 2},
	} {
		if err := os.WriteFile(filepath.Join(e.cfg.Updates.CacheDir, "latest.json"), []byte(tc.record), 0644); err != nil {
			t.Fatal(err)
		}
		var raw json.RawMessage
		st, err := agentDo(t, c, "GET", e.agent.URL+"/v1/releases/latest", nil, &raw)
		if err != nil || st != 200 {
			t.Fatal(name, st, err)
		}
		var old struct {
			Version         string
			Forgejo, GitHub release.Sums
		}
		var m release.Metadata
		if json.Unmarshal(raw, &old) != nil || old.Version != "1.2.3" || !old.Forgejo.Agrees(old.GitHub) {
			t.Errorf("%s: a 0.8.1 CLI refuses %s", name, raw)
		}
		if err := json.Unmarshal(raw, &m); err != nil || !m.Valid() || m.Compared() != tc.compared {
			t.Errorf("%s: a current CLI reads %+v (%v)", name, m, err)
		}
	}
}

// The Setup page is told which sources apply and where they were decided.
func TestSetupSources(t *testing.T) {
	type out struct {
		setupOut
		Sources setupSources `json:"update_sources"`
	}
	view := func(e *env) out {
		var v out
		mustStatus(t, "view", e.webDo("GET", "/api/ui/setup", nil, &v), 200)
		return v
	}
	e := newEnv(t)
	e.setupOwner()
	e.installRunner()
	v := view(e)
	if s := v.Sources; s.Origin != maint.SourcesDefault || s.Repo != release.GitHubRepo || s.GitHubAPI != release.GitHubAPI || s.SecondAPI != "" || len(s.Compared) != 1 || s.Compared[0] != "GitHub" || len(s.Active) != 0 ||
		v.state("enable-updates") != "available:" {
		t.Fatalf("nothing configured: %+v %s", s, v.state("enable-updates"))
	}
	// Enabled, GitHub only: the page says so instead of staying silent.
	e.cfg.Updates.Repo = release.GitHubRepo
	if s := view(e).Sources; s.Origin != maint.SourcesConfig || len(s.Active) != 1 || !strings.Contains(s.Note, "No second release source") {
		t.Fatalf("GitHub only: %+v", s)
	}
	// A token for a second source without its address (a 0.8.1 configuration that relied on
	// the compiled address): not used, and said.
	e.cfg.Updates.Second.TokenFile = "/etc/aqmas/forgejo-read-token"
	if s := view(e).Sources; s.SecondAPI != "" || len(s.Active) != 1 || !strings.Contains(s.Note, "[updates.second]") {
		t.Fatalf("token without address: %+v", s)
	}
	e.cfg.Updates.Second.API = "https://forge.example.com/api/v1/repos/example/agent-quartermaster"
	if s := view(e).Sources; s.SecondAPI != e.cfg.Updates.Second.API || len(s.Active) != 2 || s.Active[1] != "second source (forge.example.com)" || s.Compared[1] != s.Active[1] || s.Note != "" {
		t.Fatalf("second source: %+v", s)
	}
	// A pin made at the machine wins over the configuration.
	p := newEnv(t)
	p.setupOwner()
	p.sources = &maint.Sources{Repo: "ssh://git@forge.example.com/example/agent-quartermaster.git", SecondAPI: "https://forge.example.com/api/v1/repos/example/agent-quartermaster"}
	p.installRunner()
	if s := view(p).Sources; s.Origin != maint.SourcesPinned || s.GitHubAPI != release.GitHubAPI || len(s.Compared) != 2 {
		t.Fatalf("pinned: %+v", s)
	}
	// ... and where the configuration lost the second source's address, the pin can restore it.
	p.cfg.Updates.Repo, p.cfg.Updates.Second.TokenFile = p.sources.Repo, "/etc/aqmas/forgejo-read-token"
	if s := view(p).Sources; len(s.Active) != 1 || len(s.Compared) != 2 || !strings.Contains(s.Note, "again does the same") {
		t.Fatalf("pinned second source, configuration without its address: %+v", s)
	}
	// The broker refuses, before any tap, a request for sources other than the fixed ones.
	for name, params := range map[string]map[string]any{
		"adds a second source": {"repo": release.GitHubRepo, "github_api": release.GitHubAPI, "second_api": "https://forge.example.com/api/v1/repos/a/b", "known_hosts": []string{}},
		"another repository":   {"repo": "https://github.com/example/other.git", "github_api": release.GitHubAPI, "second_api": "", "known_hosts": []string{}},
	} {
		n := newEnv(t)
		n.setupOwner()
		n.installRunner()
		mustStatus(t, name, n.webDo("POST", "/api/ui/setup/enable-updates/challenge", map[string]any{"params": params}, nil), 409)
		mustStatus(t, "the fixed sources", n.webDo("POST", "/api/ui/setup/enable-updates/challenge", map[string]any{"params": map[string]any{"repo": release.GitHubRepo, "github_api": release.GitHubAPI, "second_api": "", "known_hosts": []string{}}}, nil), 200)
	}
}
