package maint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Layout is every path the runner touches. Production uses the constants below and nothing
// else; a test layout (never as root) relocates all of them under one directory.
type Layout struct {
	Bin        string // the installed aqmasd, which is also this runner
	Config     string // root-owned broker configuration
	ConfigDir  string // /etc/aqmas: tokens, deploy key (SSH remotes only), pins
	UnitDir    string // /etc/systemd/system
	RunDropIn  string // transient drop-in that selects a maintenance mode until reboot
	Spool      string // aqmasd writes signed requests here
	Cache      string // root-owned, world-readable: releases and status
	State      string // root only: replay records and the journal
	Backups    string // root only
	Tools      string // pinned toolchains
	AlertDir   string // lock-alert credentials
	Libexec    string
	KnownHosts string // forge host keys, used only by the broker's and the builder's git fetch
	User       string // the broker's service account
	// Root prefixes the system paths the bastion tasks touch (/etc/ssh, /boot): empty on an
	// installed bastion, a directory in a test layout.
	Root string
	// Hook replaces systemd in a test layout: `hook stop|start MODE|active`, and every
	// system tool of the bastion and routine tasks: `hook sys NAME ARGS...` (see sys).
	Hook string
	test bool
}

const (
	requestName = "approved"
	cancelName  = "cancel"
	statusName  = "setup-status.json"
	journalName = "journal.json"
	pinsName    = "update-passkeys.json"
	keyName     = "maint-secrets.key"
	sourcesName = "maint-sources.json"
	unitName    = "aqmasd.service"
	allowName   = "bastion-allow.json"
)

// Production returns the fixed layout of an installed bastion.
func Production() Layout {
	return Layout{Bin: "/usr/local/bin/aqmasd", Config: "/etc/aqmas/config.toml", ConfigDir: "/etc/aqmas", UnitDir: "/etc/systemd/system",
		RunDropIn: "/run/systemd/system/aqmasd.service.d/50-aqmas-maint.conf", Spool: "/var/spool/aqmas-update", Cache: "/var/lib/aqmas-releases",
		State: "/var/lib/aqmas-maint", Backups: "/var/lib/aqmas-backups", Tools: "/opt/aqmas-tools", AlertDir: "/etc/aqmas-alert",
		Libexec: "/usr/local/libexec", KnownHosts: "/etc/aqmas/known_hosts", User: "aqmas"}
}

// TestLayout relocates everything under dir. It refuses to exist for root, so no flag or
// file can point the privileged runner at other paths.
func TestLayout(dir, bin, hook string) (Layout, error) {
	if os.Geteuid() == 0 {
		return Layout{}, errors.New("test layout is not available to root")
	}
	if !filepath.IsAbs(dir) || !filepath.IsAbs(bin) || !filepath.IsAbs(hook) {
		return Layout{}, errors.New("test layout needs absolute paths")
	}
	j := func(p ...string) string { return filepath.Join(append([]string{dir}, p...)...) }
	return Layout{Bin: bin, Config: j("etc", "config.toml"), ConfigDir: j("etc"), UnitDir: j("systemd"), RunDropIn: j("run", "50-aqmas-maint.conf"),
		Spool: j("spool"), Cache: j("releases"), State: j("maint"), Backups: j("backups"), Tools: j("tools"), AlertDir: j("alert"),
		Libexec: j("libexec"), KnownHosts: j("etc", "known_hosts"), Root: j("sysroot"), Hook: hook, test: true}, nil
}

func (l Layout) request() string { return filepath.Join(l.Spool, requestName) }
func (l Layout) cancel() string  { return filepath.Join(l.Spool, cancelName) }
func (l Layout) status() string  { return filepath.Join(l.Cache, statusName) }
func (l Layout) journal() string { return filepath.Join(l.State, journalName) }
func (l Layout) pins() string    { return filepath.Join(l.ConfigDir, pinsName) }
func (l Layout) key() string     { return filepath.Join(l.ConfigDir, keyName) }
func (l Layout) unit() string    { return filepath.Join(l.UnitDir, unitName) }
func (l Layout) sources() string { return filepath.Join(l.ConfigDir, sourcesName) }

// Sources are the release sources "Enable self-update" may use: the git remote, the GitHub
// release API and, optionally, the release API of a second source ("" = GitHub only). They
// are decided at the machine and never by a request: pinned from a terminal
// (`maint-init --repo …`), else read from the root-owned configuration, else the compiled
// GitHub defaults.
type Sources struct {
	Repo      string `json:"repo"`
	GitHubAPI string `json:"github_api"`
	SecondAPI string `json:"second_api"`
	// GitHubOnly is `maint-init --github-only`: the owner, at the machine, drops a second
	// source this installation has been using. It is a request to Init, not part of the pin.
	GitHubOnly bool `json:"-"`
}

// UnmarshalJSON also reads a pin written by 0.8.1 or earlier, which called the second
// source "forgejo_api".
func (s *Sources) UnmarshalJSON(b []byte) error {
	var v struct {
		Repo      string `json:"repo"`
		GitHubAPI string `json:"github_api"`
		SecondAPI string `json:"second_api"`
		Legacy    string `json:"forgejo_api"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if v.SecondAPI == "" {
		v.SecondAPI = v.Legacy
	}
	*s = Sources{Repo: v.Repo, GitHubAPI: v.GitHubAPI, SecondAPI: v.SecondAPI}
	return nil
}

// Origins of the effective sources.
const (
	SourcesPinned  = "pinned"  // maint-init --repo …
	SourcesConfig  = "config"  // the [updates] table of the root-owned configuration
	SourcesDefault = "default" // nothing configured: the public GitHub repository alone
)

// EffectiveSources returns the sources "Enable self-update" accepts and where they come
// from. A pin wins; without one the configuration's own [updates] table is kept (so that
// running the task again never drops a configured second source); with neither it is GitHub
// alone. A missing GitHub address is the compiled default; a second source has no default.
func EffectiveSources(pinned *Sources, u config.Updates) (Sources, string) {
	s, origin := Sources{Repo: u.Repo, GitHubAPI: u.GitHub.API, SecondAPI: u.Second.API}, SourcesConfig
	if pinned != nil {
		s, origin = *pinned, SourcesPinned
	} else if s == (Sources{}) {
		origin = SourcesDefault
	}
	if s.GitHubAPI == "" {
		s.GitHubAPI = release.GitHubAPI
	}
	if s.Repo == "" {
		s.Repo = release.RepoFor(s.GitHubAPI)
	}
	return s, origin
}

func (l Layout) readSources() *Sources {
	var s Sources
	b, err := os.ReadFile(l.sources())
	if err != nil || json.Unmarshal(b, &s) != nil || s.Repo == "" {
		return nil
	}
	return &s
}

// ReadInstalled returns the installed release identity (latest.json in the release cache),
// or nil when there is none or it is not valid.
func ReadInstalled(cache string) *release.Metadata {
	var m release.Metadata
	b, err := os.ReadFile(filepath.Join(cache, "latest.json"))
	if err != nil || json.Unmarshal(b, &m) != nil || !m.Valid() {
		return nil
	}
	return &m
}

// SourcesProblem says why this machine must not look for or install a release with the
// sources its configuration names ("" when it may). The configuration alone cannot take a
// second source away, whether by an edit, a lost line or an upgrade that stopped supplying
// a default address:
//
//   - a pin made at the machine that names a second source must be matched by the
//     configuration exactly;
//   - an installation whose installed release was verified against two published sources
//     keeps needing two, until the owner pins GitHub alone at the machine
//     (`maint-init --repo … --github-only`).
//
// Both the root runner (before an install, and before "Enable self-update" changes the
// configuration) and the broker (discovery, the Setup page) apply it.
func SourcesProblem(pinned *Sources, u config.Updates, installed *release.Metadata) string {
	const repin = " or, to compare GitHub alone from now on, decide that at the machine: sudo aqmasd maint-init --repo URL --github-only."
	if pinned != nil && pinned.SecondAPI != "" && u.Second.API != pinned.SecondAPI {
		state := "does not name one"
		if u.Second.API != "" {
			state = "names a different one"
		}
		return "The release sources pinned on this machine include a second source, but its configuration " + state + ". Nothing is checked or installed until they agree. Add these two lines to /etc/aqmas/config.toml and restart aqmasd:\n[updates.second]\napi = \"" + pinned.SecondAPI + "\"\n(running “Enable self-update” again writes them for you)," + repin
	}
	if installed != nil && installed.Compared() == 2 && u.Second.API == "" && (pinned == nil || pinned.SecondAPI != "") {
		return "The installed release was verified against two published sources, but the configuration now names GitHub only. Nothing is checked or installed on fewer sources than before. Add the second source back to /etc/aqmas/config.toml and restart aqmasd:\n[updates.second]\napi = \"https://HOST/api/v1/repos/OWNER/NAME\"\n" + strings.TrimPrefix(repin, " ")
	}
	return ""
}

// AllowPath is the root-owned bastion allowlist next to the configuration.
func AllowPath(configDir string) string { return filepath.Join(configDir, allowName) }

// ReadAllow loads the bastion allowlist. Anything but a valid list written by the
// "bastion-allow" task reads as empty: nobody may ask for root.
func ReadAllow(path string) []AllowedHost {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 {
		return nil
	}
	// Exactly the canonical text the task signs and writes: nothing looser is a list.
	v, err := Parse(TaskBastionAllow, strings.TrimSuffix(string(b), "\n"))
	if err != nil {
		return nil
	}
	return v.(BastionAllowParams).Hosts
}

// StatusPath is where aqmasd reads the runner's public status.
func StatusPath(cache string) string { return filepath.Join(cache, statusName) }

// RequestPath and CancelPath are the two names aqmasd may create in the spool.
func RequestPath(spool string) string { return filepath.Join(spool, requestName) }
func CancelPath(spool string) string  { return filepath.Join(spool, cancelName) }

// Facts is what the broker's own (unprivileged) view of the database says. The runner uses
// it for prerequisites and progress, and never as proof of who may approve.
type Facts struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Schema   int    `json:"schema"`
	Manifest string `json:"seal_manifest_sha256,omitempty"`
	// The signed activation as the import process recorded it (schema 8 only).
	Activation      string          `json:"seal_activation,omitempty"`
	ActivationProof json.RawMessage `json:"seal_activation_assertion,omitempty"`
	Passkeys        []struct {
		ID        []byte `json:"id"`
		PublicKey []byte `json:"publicKey"`
	} `json:"passkeys"`
}

var cleanEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=/nonexistent"}

// command builds a fixed-argv command with a minimal environment. Output goes to the
// service journal, never into the status file.
func command(ctx context.Context, name string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = cleanEnv
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	c.WaitDelay = 10 * time.Second
	return c
}

func (l Layout) run(ctx context.Context, name string, args ...string) error {
	if err := command(ctx, name, args...).Run(); err != nil {
		return fmt.Errorf("%s failed", filepath.Base(name))
	}
	return nil
}

// asService drops to the broker's account for anything that reads service-owned state.
func (l Layout) asService(c *exec.Cmd) error {
	if l.test {
		return nil
	}
	u, err := user.Lookup(l.User)
	if err != nil {
		return err
	}
	uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
	if e1 != nil || e2 != nil || uid == 0 {
		return errors.New("unexpected service account")
	}
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	return nil
}

func (l Layout) facts(ctx context.Context) (Facts, error) {
	var f Facts
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, l.Bin, "-config", l.Config, "setup-facts")
	c.Env = cleanEnv
	c.Dir = "/"
	if err := l.asService(c); err != nil {
		return f, err
	}
	out, err := c.StdoutPipe()
	if err != nil {
		return f, err
	}
	if err = c.Start(); err != nil {
		return f, err
	}
	b, rerr := io.ReadAll(io.LimitReader(out, 1<<20))
	if err = c.Wait(); err != nil || rerr != nil {
		return f, errors.New("could not read broker facts")
	}
	if json.Unmarshal(b, &f) != nil {
		return f, errors.New("invalid broker facts")
	}
	return f, nil
}

// sysPath is a system path under Root ("/etc/ssh/x" on an installed bastion).
func (l Layout) sysPath(p ...string) string {
	return filepath.Join(append([]string{l.Root, "/"}, p...)...)
}

// maxSysOutput bounds what sysOut keeps of a tool's standard output.
const maxSysOutput = 4 << 20

// sysCmd builds the command for a system tool of the bastion and routine tasks. On an
// installed bastion that is the tool itself, found on the fixed PATH of cleanEnv, with a
// fixed argv. In a test layout it is the hook:
//
//	<Hook> sys NAME ARGS...
//
// with NAME the tool (useradd, usermod, userdel, passwd, getent, id, loginctl, rpm,
// systemd-run, systemctl, journalctl, df, sshd) and ARGS exactly the production argv. The
// hook's exit status and standard output stand in for the tool's; standard error goes to
// the runner's log. The host-trust installer reaches sshd the same way, through a wrapper
// that runs `<Hook> sys sshd -t|-T ...`.
func (l Layout) sysCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	var c *exec.Cmd
	if l.test {
		c = exec.CommandContext(ctx, l.Hook, append([]string{"sys", name}, args...)...)
	} else {
		c = exec.CommandContext(ctx, name, args...)
	}
	c.Env = cleanEnv
	c.Dir = "/"
	c.Stderr = os.Stderr
	c.WaitDelay = 10 * time.Second
	return c
}

// sys runs a system tool; its output goes to the service journal.
func (l Layout) sys(ctx context.Context, name string, args ...string) error {
	c := l.sysCmd(ctx, name, args...)
	c.Stdout = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s failed", name)
	}
	return nil
}

// sysOut runs a system tool and returns at most maxSysOutput bytes of its standard output.
func (l Layout) sysOut(ctx context.Context, name string, args ...string) (string, error) {
	c := l.sysCmd(ctx, name, args...)
	out, err := c.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err = c.Start(); err != nil {
		return "", fmt.Errorf("%s failed", name)
	}
	b, rerr := io.ReadAll(io.LimitReader(out, maxSysOutput+1))
	_, _ = io.Copy(io.Discard, out)
	if err = c.Wait(); err != nil || rerr != nil {
		return string(b), fmt.Errorf("%s failed", name)
	}
	if len(b) > maxSysOutput {
		return "", fmt.Errorf("%s printed too much", name)
	}
	return string(b), nil
}

func (l Layout) systemctl(ctx context.Context, args ...string) error {
	return l.run(ctx, "systemctl", args...)
}

func (l Layout) hook(ctx context.Context, args ...string) error {
	c := exec.CommandContext(ctx, l.Hook, args...)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	return c.Run()
}

// stop stops the broker and waits for the process to exit.
func (l Layout) stop(ctx context.Context) error {
	if l.test {
		return l.hook(ctx, "stop")
	}
	if err := l.systemctl(ctx, "stop", unitName); err != nil {
		return err
	}
	_ = l.systemctl(ctx, "reset-failed", unitName)
	if l.active(ctx) {
		return errors.New("broker did not stop")
	}
	return nil
}

func (l Layout) active(ctx context.Context) bool {
	if l.test {
		return l.hook(ctx, "active") == nil
	}
	return command(ctx, "systemctl", "is-active", "--quiet", unitName).Run() == nil
}

// start starts the broker in mode: "serve" (the installed unit), or a maintenance mode
// selected by a drop-in under /run that disappears on reboot.
func (l Layout) start(ctx context.Context, mode string) error {
	if mode != "serve" && mode != "organisations-cutover" && mode != "seal-import" && mode != "bucket-migrate" {
		return errors.New("unknown broker mode")
	}
	if l.test {
		return l.hook(ctx, "start", mode)
	}
	if mode == "serve" {
		if err := os.Remove(l.RunDropIn); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		text := "# Written by the aqmas maintenance runner; removed when the task ends.\n[Service]\nExecStart=\nExecStart=" + l.Bin + " -require-root-config -config " + l.Config + " " + mode + "\nRestart=no\n"
		if err := os.MkdirAll(filepath.Dir(l.RunDropIn), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(l.RunDropIn, []byte(text), 0644); err != nil {
			return err
		}
	}
	if err := l.systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	_ = l.systemctl(ctx, "reset-failed", unitName)
	return l.systemctl(ctx, "start", unitName)
}

// healthy waits for the broker's own health endpoint (which pings the database).
func (l Layout) healthy(ctx context.Context, listenWeb string) error {
	client := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	url := "http://" + listenWeb + "/healthz"
	for i := 0; i < 30; i++ {
		if l.active(ctx) && l.runsInstalled(ctx) {
			if resp, err := client.Get(url); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 16))
				resp.Body.Close()
				if resp.StatusCode == 200 && bytes.Equal(bytes.TrimSpace(b), []byte("ok")) {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("broker is not healthy")
}

// runsInstalled checks that the serving process is the root-owned binary, not a leftover.
func (l Layout) runsInstalled(ctx context.Context) bool {
	if l.test {
		return true
	}
	c := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID", "--value", unitName)
	c.Env = cleanEnv
	out, err := c.Output()
	pid := strings.TrimSpace(string(out))
	if err != nil || pid == "" || pid == "0" {
		return false
	}
	a, e1 := os.Stat("/proc/" + pid + "/exe")
	b, e2 := os.Stat(l.Bin)
	return e1 == nil && e2 == nil && os.SameFile(a, b)
}

func hasPrefixPath(path, dir string) bool {
	return strings.HasPrefix(filepath.Clean(path), filepath.Clean(dir)+string(filepath.Separator))
}
