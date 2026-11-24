package server

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/release"
)

func TestUpdateCeremony(t *testing.T) {
	e := newEnv(t)
	e.cfg.Updates.Repo = "ssh://git@example.com/example/aqmas.git"
	e.cfg.Updates.SpoolDir, e.cfg.Updates.CacheDir = t.TempDir(), t.TempDir()
	oldV, oldC := release.Version, release.Commit
	release.Version, release.Commit = "1.0.0", strings.Repeat("0", 40)
	defer func() { release.Version, release.Commit = oldV, oldC }()
	mustStatus(t, "private updates", e.webDo("GET", "/api/ui/updates", nil, nil), 401)
	e.setupOwner()
	e.installRunner()
	s := release.Sums{}
	for _, a := range release.Assets {
		s[a] = strings.Repeat("a", 64)
	}
	id := strings.Repeat("1", 40)
	m := release.Metadata{Version: "1.0.1", Commit: id, GitHub: s, Second: maps.Clone(s)}
	e.s.updates.view = updateView{Candidate: m}
	path := "/api/ui/updates/" + id
	choice := api.ChallengeRequest{Action: "approve"}
	c, code := e.challenge(path, choice)
	mustStatus(t, "challenge", code, 200)
	m.Second[release.Daemon] = strings.Repeat("b", 64)
	_, code = e.challenge(path, choice)
	mustStatus(t, "mismatch", code, 409)
	mustStatus(t, "changed since challenge", e.decide(path, "decide", c, nil), 409)
	m.Second[release.Daemon] = s[release.Daemon]
	c, code = e.challenge(path, choice)
	mustStatus(t, "challenge", code, 200)
	mustStatus(t, "queue", e.decide(path, "decide", c, nil), 200)
	mustStatus(t, "single use", e.decide(path, "decide", c, nil), 409)
	b, err := os.ReadFile(filepath.Join(e.cfg.Updates.SpoolDir, "approved"))
	if err != nil || !strings.Contains(string(b), "assertion") {
		t.Fatal("missing proof", err)
	}
}
