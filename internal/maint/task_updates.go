package maint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "embed"

	"github.com/aquarat/agent-quartermaster/ci"
	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

//go:embed updater.sh
var updaterScript string

const buildUser = "aqmas-build"

// Commands the sandboxed rebuild needs, and the Fedora packages that provide them.
var buildCommands = []string{"bwrap", "setpriv", "git", "jq", "make", "gcc", "unzip", "curl", "ssh-keygen", "sha256sum"}
var buildPackages = []string{"bubblewrap", "util-linux", "git-core", "jq", "make", "gcc", "unzip", "curl", "openssh-clients", "coreutils", "ca-certificates"}

var deployKeyRE = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]{68}( [A-Za-z0-9@._-]{1,64})?$`)

func (l Layout) deployKey() string { return filepath.Join(l.ConfigDir, "repo-key") }

func readDeployKey(l Layout) string {
	b, err := os.ReadFile(l.deployKey() + ".pub")
	if err != nil || len(b) > 512 {
		return ""
	}
	line := strings.TrimSpace(string(b))
	if !deployKeyRE.MatchString(line) {
		return ""
	}
	return line
}

// ensureDeployKey creates the read-only repository key once. Only its public half is shown.
func (r *Runner) ensureDeployKey(ctx context.Context) error {
	key := r.l.deployKey()
	if _, err := os.Lstat(key); err != nil {
		_ = os.Remove(key + ".pub")
		if err := r.l.run(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "aqmas-deploy", "-f", key); err != nil {
			return err
		}
	}
	_, gid, err := r.l.serviceIDs()
	if err != nil {
		return err
	}
	if !r.l.test {
		if err = os.Chown(key, 0, gid); err != nil {
			return err
		}
	}
	if err = os.Chmod(key, 0440); err != nil {
		return err
	}
	if err = os.Chmod(key+".pub", 0644); err != nil {
		return err
	}
	if readDeployKey(r.l) == "" {
		return errors.New("deploy key is unreadable")
	}
	return nil
}

func (r *Runner) packages(ctx context.Context) error {
	var missing []string
	for _, c := range buildCommands {
		if _, err := exec.LookPath(c); err != nil {
			missing = append(missing, c)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if _, err := exec.LookPath("dnf"); err != nil {
		return errors.New("missing build tools (" + strings.Join(missing, ", ") + ") and no dnf to install them")
	}
	return r.l.run(ctx, "dnf", append([]string{"-y", "install"}, buildPackages...)...)
}

func (r *Runner) toolchains(ctx context.Context) error {
	version := func(bin string, arg string) string {
		c := exec.CommandContext(ctx, bin, arg)
		c.Env = cleanEnv
		b, _ := c.Output()
		return string(b)
	}
	if strings.Contains(version(filepath.Join(r.l.Tools, "go", "bin", "go"), "version"), ci.GoVersion+" ") &&
		strings.TrimSpace(version(filepath.Join(r.l.Tools, "bin", "bun"), "--version")) == ci.BunVersion {
		return nil
	}
	if _, err := os.Lstat(r.l.Tools); err == nil {
		if err := os.Rename(r.l.Tools, r.l.Tools+".old-"+r.now().UTC().Format("20060102T150405Z")); err != nil {
			return err
		}
	}
	c := command(ctx, "bash", "-s", "--", r.l.Tools)
	c.Stdin = strings.NewReader(ci.Toolchains)
	if err := c.Run(); err != nil {
		_ = os.RemoveAll(r.l.Tools)
		return errors.New("installing the pinned toolchains failed (network, or a changed download)")
	}
	return r.l.run(ctx, "chmod", "-R", "go-w", r.l.Tools)
}

func (r *Runner) trustHost(lines []string) error {
	b, err := os.ReadFile(r.l.KnownHosts)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	have := strings.Split(string(b), "\n")
	out := string(b)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	for _, line := range lines {
		if !slices.Contains(have, line) {
			out += line + "\n"
		}
	}
	if out == string(b) {
		return nil
	}
	return writeOwned(r.l.KnownHosts, []byte(out), 0, 0, 0644)
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// seed checks the installed broker against both published releases of its own version and
// fills the release cache. Nothing is trusted from one source alone.
func (r *Runner) seed(ctx context.Context, u config.Updates, f Facts) error {
	m := release.Metadata{Version: f.Version, Commit: f.Commit}
	if !release.ValidVersion(m.Version) || !release.ValidCommit(m.Commit) {
		return errors.New("the installed broker is not a release build")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var err error
	if m.Forgejo, err = u.Forgejo.Hashes(ctx, m.Version, false); err != nil {
		return errors.New("Forgejo release " + m.Version + ": " + err.Error())
	}
	if m.GitHub, err = u.GitHub.Hashes(ctx, m.Version, true); err != nil {
		return errors.New("GitHub release " + m.Version + ": " + err.Error())
	}
	if !m.Valid() {
		return errors.New("the two releases of " + m.Version + " disagree")
	}
	if got, err := fileHash(r.l.Bin); err != nil || got != m.Forgejo[release.Daemon] {
		return errors.New("the installed broker is not the published " + m.Version + " binary")
	}
	stage, err := os.MkdirTemp(r.l.Cache, ".seed-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, name := range release.Assets {
		if name == release.Daemon {
			continue
		}
		b, err := u.Forgejo.Asset(ctx, m.Version, name, false, 128<<20)
		if err != nil {
			if b, err = u.GitHub.Asset(ctx, m.Version, name, true, 128<<20); err != nil {
				return errors.New("could not download " + name)
			}
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != m.Forgejo[name] {
			return errors.New(name + " does not match the published digest")
		}
		if err = os.WriteFile(filepath.Join(stage, name), b, 0644); err != nil {
			return err
		}
	}
	if err = os.WriteFile(filepath.Join(stage, "SHA256SUMS"), []byte(m.Forgejo.Text()), 0644); err != nil {
		return err
	}
	if err = os.Chmod(stage, 0755); err != nil {
		return err
	}
	dst := filepath.Join(r.l.Cache, m.Version)
	_ = os.RemoveAll(dst)
	if err = os.Rename(stage, dst); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(r.l.Cache, "latest.json"), append(b, '\n'), 0644)
}

// enableUpdates prepares the machine for self-update and points the broker at its sources.
func (r *Runner) enableUpdates(ctx context.Context, p UpdatesParams, secrets map[string]string) (string, error) {
	f, err := r.l.facts(ctx)
	if err != nil {
		return "", err
	}
	if err = r.l.healthy(ctx, r.cfg.ListenWeb); err != nil {
		return "", errors.New("the broker is not healthy; fix that first")
	}
	u := config.Updates{Repo: p.Repo, DeployKey: r.l.deployKey()}
	u.Forgejo.API, u.GitHub.API = p.ForgejoAPI, p.GitHubAPI
	if p.ForgejoToken {
		u.Forgejo.TokenFile = filepath.Join(r.l.ConfigDir, "forgejo-read-token")
	}
	if p.GitHubToken {
		u.GitHub.TokenFile = filepath.Join(r.l.ConfigDir, "github-read-token")
	}
	next, err := setUpdates(r.raw, u)
	if err != nil {
		return "", err
	}
	if !r.l.test {
		r.step("Installing build tools")
		if err = r.packages(ctx); err != nil {
			return "", err
		}
		r.step("Creating the locked build user")
		if _, err := user.Lookup(buildUser); err != nil {
			if err := r.l.run(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", buildUser); err != nil {
				return "", err
			}
		}
		r.step("Installing the pinned Go and Bun toolchains")
		if err = r.toolchains(ctx); err != nil {
			return "", err
		}
	}
	r.step("Creating the read-only deploy key")
	if err = r.ensureDeployKey(ctx); err != nil {
		return "", err
	}
	r.st.Runner.DeployKey = readDeployKey(r.l)
	r.result("deploy_key", r.st.Runner.DeployKey)
	r.step("Trusting the forge's host key")
	if err = r.trustHost(p.KnownHosts); err != nil {
		return "", err
	}
	r.step("Storing the release-reading tokens")
	_, gid, err := r.l.serviceIDs()
	if err != nil {
		return "", err
	}
	for name, path := range map[string]string{"forgejo_token": u.Forgejo.TokenFile, "github_token": u.GitHub.TokenFile} {
		if path != "" {
			if err = writeOwned(path, []byte(secrets[name]+"\n"), 0, gid, 0440); err != nil {
				return "", errors.New("could not store a token")
			}
		}
	}
	r.step("Checking the installed broker against both published releases")
	if err = r.seed(ctx, u, f); err != nil {
		return "", err
	}
	r.result("release", f.Version+" ("+f.Commit[:12]+")")
	r.step("Adding the update sources to the configuration and restarting the broker")
	before := filepath.Join(r.l.State, "config.before-updates")
	if err = os.MkdirAll(filepath.Join(before, "config"), 0700); err == nil {
		err = os.WriteFile(filepath.Join(before, "config", filepath.Base(r.l.Config)), r.raw, 0600)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(before, "complete"), nil, 0600)
	}
	if err == nil {
		err = r.writeJournal(journal{Task: TaskUpdates, Backup: before})
	}
	if err != nil {
		return "", err
	}
	defer r.clearJournal()
	if err = replaceFile(r.l.Config, next); err != nil {
		return "", err
	}
	if err = r.restart(ctx); err != nil {
		r.step("The broker did not restart with the new configuration: restoring the old one")
		_ = r.l.stop(ctx)
		if rerr := r.restoreConfig(before); rerr == nil {
			rerr = r.restart(ctx)
			if rerr == nil {
				return "", errors.New("The broker refused the new configuration; the previous one was restored.")
			}
		}
		return "", errors.New("URGENT: the broker did not restart; check it on the machine.")
	}
	return "Self-update is ready. Register the deploy key on the forge (read-only) if you have not yet; new releases then appear under “Upgrade aqmas”.", nil
}

func (r *Runner) restart(ctx context.Context) error {
	if err := r.l.stop(ctx); err != nil {
		return err
	}
	if err := r.l.start(ctx, "serve"); err != nil {
		return err
	}
	return r.l.healthy(ctx, r.cfg.ListenWeb)
}

// syncPins replaces the root pin list with exactly the signed list, taking each public key
// from the broker's record only when it matches the signed digest.
func (r *Runner) syncPins(ctx context.Context, p PinsParams) (string, error) {
	f, err := r.l.facts(ctx)
	if err != nil {
		return "", err
	}
	r.step("Comparing each listed passkey with the broker's record")
	var pins []KeyPin
	for _, want := range p.Pins {
		found := false
		for _, k := range f.Passkeys {
			sum := sha256.Sum256(k.PublicKey)
			if base64.RawURLEncoding.EncodeToString(k.ID) == want.ID && hex.EncodeToString(sum[:]) == want.KeyHash {
				pins = append(pins, KeyPin{ID: k.ID, PublicKey: k.PublicKey})
				found = true
			}
		}
		if !found {
			return "", errors.New("a listed passkey is not (or no longer) registered with that key")
		}
	}
	r.step("Replacing the pinned list")
	b, err := json.Marshal(pins)
	if err != nil {
		return "", err
	}
	if err = writeAtomic(r.l.pins(), b, 0600); err != nil {
		return "", err
	}
	return "Pinned " + plural(len(pins), "passkey") + " for maintenance.", nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// upgrade re-verifies the approved release against both sources and the installed identity,
// then hands the already-verified metadata to the embedded installer.
func (r *Runner) upgrade(ctx context.Context, sg canon.Signed) (string, error) {
	u := r.cfg.Updates
	if u.Repo == "" {
		return "", errors.New("enable self-update first")
	}
	var current release.Metadata
	b, err := os.ReadFile(filepath.Join(r.l.Cache, "latest.json"))
	if err != nil || json.Unmarshal(b, &current) != nil || !current.Valid() {
		return "", errors.New("the installed release identity is missing; run “Enable self-update” again")
	}
	if sg.FromCommit != current.Commit || sg.FromVersion != current.Version {
		return "", errors.New("the approval is for another installed version")
	}
	r.step("Verifying both releases of " + sg.ToVersion)
	m := release.Metadata{Version: sg.ToVersion, Commit: sg.ToCommit}
	hctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if m.Forgejo, err = u.Forgejo.Hashes(hctx, m.Version, false); err != nil {
		return "", errors.New("Forgejo: " + err.Error())
	}
	if m.GitHub, err = u.GitHub.Hashes(hctx, m.Version, true); err != nil {
		return "", errors.New("GitHub: " + err.Error())
	}
	if !m.Valid() || !sg.Sums().Agrees(m.Forgejo) {
		return "", errors.New("the releases or the approval disagree")
	}
	if b, err = json.Marshal(m); err != nil {
		return "", err
	}
	meta := filepath.Join(r.l.State, "approved-metadata.json")
	if err = writeAtomic(meta, append(b, '\n'), 0600); err != nil {
		return "", err
	}
	defer os.Remove(meta)
	if err = r.runUpdater(ctx, meta); err != nil {
		return "", err
	}
	return "Installed and health-checked " + m.Version + ".", nil
}

// runUpdater runs the embedded installer (or, with no metadata, its interrupted-install
// recovery) and mirrors its one-line status into the task's progress.
func (r *Runner) runUpdater(ctx context.Context, metadata string) error {
	var c *exec.Cmd
	if r.l.test {
		c = exec.CommandContext(ctx, r.l.Hook, "upgrade", metadata)
	} else {
		c = exec.CommandContext(ctx, "/bin/bash", "-s")
		c.Stdin = strings.NewReader(updaterScript)
	}
	u := r.cfg.Updates
	c.Env = append(slices.Clone(cleanEnv), "CACHE="+r.l.Cache, "BIN="+r.l.Bin, "STATE="+r.l.State, "TOOLS="+r.l.Tools, "KNOWN_HOSTS="+r.l.KnownHosts,
		"REPO="+u.Repo, "DEPLOY_KEY="+u.DeployKey, "HEALTH_URL=http://"+r.cfg.ListenWeb+"/healthz", "METADATA="+metadata)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	statusFile := filepath.Join(r.l.Cache, "status")
	last := ""
	read := func() {
		if b, err := os.ReadFile(statusFile); err == nil && len(b) < 1024 {
			if s := strings.TrimSpace(string(b)); s != "" && s != last {
				last = s
				r.step(s)
			}
		}
	}
	if b, err := os.ReadFile(statusFile); err == nil {
		last = strings.TrimSpace(string(b))
	}
	for {
		select {
		case err := <-done:
			read()
			if err != nil {
				if last == "" {
					last = "The installer failed."
				}
				return errors.New(last)
			}
			return nil
		case <-time.After(r.poll):
			read()
		}
	}
}
