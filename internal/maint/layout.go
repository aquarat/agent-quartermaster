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
)

// Layout is every path the runner touches. Production uses the constants below and nothing
// else; a test layout (never as root) relocates all of them under one directory.
type Layout struct {
	Bin        string // the installed aqmasd, which is also this runner
	Config     string // root-owned broker configuration
	ConfigDir  string // /etc/aqmas: tokens, deploy key, pins
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
	// Hook replaces systemd in a test layout: `hook stop|start MODE|active`.
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
		Libexec: j("libexec"), KnownHosts: j("etc", "known_hosts"), Hook: hook, test: true}, nil
}

func (l Layout) request() string { return filepath.Join(l.Spool, requestName) }
func (l Layout) cancel() string  { return filepath.Join(l.Spool, cancelName) }
func (l Layout) status() string  { return filepath.Join(l.Cache, statusName) }
func (l Layout) journal() string { return filepath.Join(l.State, journalName) }
func (l Layout) pins() string    { return filepath.Join(l.ConfigDir, pinsName) }
func (l Layout) key() string     { return filepath.Join(l.ConfigDir, keyName) }
func (l Layout) unit() string    { return filepath.Join(l.UnitDir, unitName) }
func (l Layout) sources() string { return filepath.Join(l.ConfigDir, sourcesName) }

// Sources are release sources pinned from a terminal on the machine (`maint-init --repo …`).
// While they exist, "Enable self-update" accepts exactly these and nothing else.
type Sources struct {
	Repo       string `json:"repo"`
	ForgejoAPI string `json:"forgejo_api"`
	GitHubAPI  string `json:"github_api"`
}

func (l Layout) readSources() *Sources {
	var s Sources
	b, err := os.ReadFile(l.sources())
	if err != nil || json.Unmarshal(b, &s) != nil || s.Repo == "" {
		return nil
	}
	return &s
}

// AllowPath is the root-owned bastion allowlist next to the configuration.
func AllowPath(configDir string) string { return filepath.Join(configDir, allowName) }

// ReadAllow loads the bastion allowlist. Anything but a valid list written by the
// "bastion-allow" task reads as empty: nobody may ask for root.
func ReadAllow(path string) []AllowedHost {
	var p BastionAllowParams
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &p) != nil || p.validate() != nil {
		return nil
	}
	return p.Hosts
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
