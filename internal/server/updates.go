package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

type updateView struct {
	Current   string           `json:"current"`
	Commit    string           `json:"commit"`
	Candidate release.Metadata `json:"candidate"`
	Stat      string           `json:"stat"`
	Diff      string           `json:"diff"`
	Error     string           `json:"error"`
	Status    string           `json:"status"`
}
type updateState struct {
	sync.RWMutex
	view updateView
}

func (s *Server) pollUpdates(ctx context.Context) {
	for ctx.Err() == nil {
		v := updateView{}
		attempt, cancel := context.WithTimeout(ctx, 3*time.Minute)
		err := s.discover(attempt, &v)
		cancel()
		if err != nil {
			v.Error = err.Error()
		}
		s.updates.Lock()
		s.updates.view = v
		s.updates.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.Updates.CheckInterval()):
		}
	}
}

// Git never checks out remote files in the broker. Closed output bounds matter even for
// an authenticated remote: kill git rather than buffering an arbitrarily large patch.
func gitOutput(ctx context.Context, dir, key string, limit int64, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "fetch.fsckObjects=true"}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_ALLOW_PROTOCOL=ssh", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=/nonexistent", "LC_ALL=C", "GIT_SSH_COMMAND=ssh -F /dev/null -oBatchMode=yes -oIdentitiesOnly=yes -oStrictHostKeyChecking=yes -oUserKnownHostsFile=/dev/null -oGlobalKnownHostsFile='/etc/ssh/ssh_known_hosts " + filepath.Join(filepath.Dir(key), "known_hosts") + "' -i " + key}
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return "", e
	}
	if e = cmd.Start(); e != nil {
		return "", e
	}
	b, e := release.ReadLimit(pipe, limit)
	if e != nil {
		_ = cmd.Process.Kill()
	}
	wait := cmd.Wait()
	if e != nil {
		return "", e
	}
	if wait != nil {
		return "", fmt.Errorf("git %s failed", args[0])
	}
	return string(b), nil
}

var keyPath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)

// JSON would replace invalid UTF-8, and browser layout can hide bidi controls or
// combining marks. Escape each line reversibly before crossing either boundary.
func quotePatch(text string) string {
	lines := strings.Split(text, "\n")
	for i, s := range lines {
		quoted := strconv.QuoteToASCII(s)
		lines[i] = quoted[1 : len(quoted)-1]
	}
	return strings.Join(lines, "\n")
}

func (s *Server) discover(ctx context.Context, v *updateView) error {
	cfg := s.cfg.Updates
	u, e := url.Parse(cfg.Repo)
	if e != nil || u.Scheme != "ssh" || u.Host == "" || !keyPath.MatchString(cfg.DeployKey) {
		return errors.New("updates require an SSH repo URL and absolute deploy_key")
	}
	dir := filepath.Join(s.cfg.DataDir, "update.git")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	git := func(limit int64, args ...string) (string, error) {
		return gitOutput(ctx, dir, cfg.DeployKey, limit, args...)
	}
	if _, e = git(4096, "init", "--bare", "--quiet"); e != nil {
		return e
	}
	if _, e = git(4096, "fetch", "--quiet", "--prune", "--no-tags", "--", cfg.Repo, "+refs/heads/main:refs/heads/main", "+refs/tags/v*:refs/tags/v*"); e != nil {
		return e
	}
	text, e := git(65, "show", "refs/heads/main:VERSION")
	if e != nil {
		return e
	}
	ver := strings.TrimSuffix(text, "\n")
	if !release.ValidVersion(ver) || !release.ValidVersion(release.Version) || !release.ValidCommit(release.Commit) {
		return errors.New("invalid main or running build identity")
	}
	if !release.Newer(ver, release.Version) {
		return nil
	}
	tags, e := git(1<<16, "tag", "--list", "v*")
	if e != nil {
		return e
	}
	latest := "0.0.0"
	for _, t := range strings.Fields(tags) {
		if n := strings.TrimPrefix(t, "v"); release.Newer(n, latest) {
			latest = n
		}
	}
	if latest != ver {
		return errors.New("latest tag does not match VERSION on main")
	}
	ref := "refs/tags/v" + ver
	sha, e := git(64, "rev-parse", "--verify", ref+"^{commit}")
	if e != nil {
		return e
	}
	sha = strings.TrimSpace(sha)
	if !release.ValidCommit(sha) {
		return errors.New("invalid tag commit")
	}
	v.Candidate = release.Metadata{Version: ver, Commit: sha}
	tagVersion, e := git(65, "show", sha+":VERSION")
	if e != nil || text != tagVersion {
		return errors.New("tag VERSION mismatch")
	}
	for _, pair := range [][2]string{{release.Commit, sha}, {sha, "refs/heads/main"}} {
		if _, e = git(256, "merge-base", "--is-ancestor", pair[0], pair[1]); e != nil {
			return errors.New("tag is not on the running commit to main ancestry path")
		}
	}
	diff := func(mode string, limit int64) (string, error) {
		return git(limit, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--ignore-submodules=none", mode, release.Commit, sha, "--")
	}
	if v.Stat, e = diff("--stat", 32<<10); e != nil {
		return e
	}
	// Text patch only: binary files (images) appear in the stat and as "Binary files differ".
	if v.Diff, e = diff("--patch", 4<<20); e != nil {
		return fmt.Errorf("cannot display complete diff: %w", e)
	}
	v.Stat, v.Diff = quotePatch(v.Stat), quotePatch(v.Diff)
	if v.Candidate.Forgejo, e = cfg.Forgejo.Hashes(ctx, ver, false); e != nil {
		return fmt.Errorf("Forgejo: %w", e)
	}
	if v.Candidate.GitHub, e = cfg.GitHub.Hashes(ctx, ver, true); e != nil {
		return fmt.Errorf("GitHub: %w", e)
	}
	if !v.Candidate.Valid() {
		return errors.New("release hashes disagree")
	}
	return nil
}
func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request, _ string) {
	s.updates.RLock()
	v := s.updates.view
	s.updates.RUnlock()
	v.Current, v.Commit = release.Version, release.Commit
	if s.cfg.Updates.Repo == "" {
		v.Error = "Update discovery is disabled"
	}
	if b, e := os.ReadFile(filepath.Join(s.cfg.Updates.Cache(), "status")); e == nil {
		v.Status = string(b)
	}
	writeJSON(w, 200, v)
}
func (s *Server) updateAction(id string) (canon.Action, error) {
	s.updates.RLock()
	defer s.updates.RUnlock()
	v := s.updates.view
	m := v.Candidate
	if s.cfg.Updates.Repo == "" || v.Error != "" || !m.Valid() || m.Commit != id {
		return canon.Action{}, errConflict("update is not available or sources disagree")
	}
	return canon.Action{Object: "update", ID: id, Action: "approve", Update: canon.Update{FromVersion: release.Version, FromCommit: release.Commit, ToVersion: m.Version, ToCommit: id, DaemonHash: m.Forgejo[release.Daemon], LinuxARM: m.Forgejo["aqmas-linux-arm64"], LinuxAMD: m.Forgejo["aqmas-linux-amd64"], DarwinARM: m.Forgejo["aqmas-darwin-arm64"]}}, nil
}
func (s *Server) queueUpdate(w http.ResponseWriter, r *http.Request, sg canon.Signed, assertion json.RawMessage, pkID int64) {
	a, e := s.updateAction(sg.ID)
	if e != nil || a != sg.Action {
		s.writeErr(w, r, errConflict("candidate changed"))
		return
	}
	text, e := canon.Build(a, sg.Nonce, sg.IssuedAt)
	if e == nil {
		sess, ok := s.sessionHash(r)
		if !ok {
			e = errUnauth("session ended")
		} else {
			e = s.spool(r, sess, pkID, "update_approve", "update:"+a.ID, maint.Request{Canonical: text, Assertion: assertion})
		}
	}
	if e != nil {
		s.writeErr(w, r, e)
		return
	}
	s.notify.Send("aqmas: update approved", fmt.Sprintf("%s (%s)", a.ToVersion, a.ID), s.cfg.PublicBaseURL)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) latestRelease(w http.ResponseWriter, r *http.Request, _ *store.Host) {
	b, e := os.ReadFile(filepath.Join(s.cfg.Updates.Cache(), "latest.json"))
	var m release.Metadata
	if e != nil || json.Unmarshal(b, &m) != nil || !m.Valid() {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, 200, m)
}
func (s *Server) releaseAsset(w http.ResponseWriter, r *http.Request, _ *store.Host) {
	v, a := r.PathValue("version"), r.PathValue("asset")
	if !release.ValidVersion(v) || a != "SHA256SUMS" && (a == release.Daemon || !slices.Contains(release.Assets[:], a)) {
		http.NotFound(w, r)
		return
	}
	root, err := os.OpenRoot(s.cfg.Updates.Cache())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer root.Close()
	f, err := root.Open(filepath.Join(v, a))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, a, st.ModTime(), f)
}
