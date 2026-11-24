package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"golang.org/x/sys/unix"
)

func (e *Env) agentSession() bool {
	for _, entry := range e.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "CLAUDECODE" || strings.HasPrefix(name, "OPENCODE") {
			return true
		}
	}
	return false
}
func (e *Env) UpdateNotice(ctx context.Context) {
	if !e.StdinIsTTY || e.agentSession() || !release.ValidVersion(Version) {
		return
	}
	_, c, err := e.authedClient()
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(e.Paths.ConfigDir, "update-check"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return
	}
	var last int64
	fmt.Fscan(f, &last)
	now := e.now()
	if now.Unix()-last < 86400 {
		return
	}
	if _, err = f.Seek(0, 0); err != nil {
		return
	}
	if err = f.Truncate(0); err != nil {
		return
	}
	if _, err = fmt.Fprintln(f, now.Unix()); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	var m release.Metadata
	if c.do(ctx, "GET", "/v1/releases/latest", nil, &m) == nil && m.Valid() && release.Newer(m.Version, Version) {
		e.logf("version %s available; run aqmas upgrade", m.Version)
	}
}
func (e *Env) Upgrade(ctx context.Context, check, yes, single bool, expect string, stderrTTY bool) error {
	if yes && !release.ValidHash(expect) || expect != "" && !release.ValidHash(expect) {
		return &UsageError{Msg: "--yes requires --expect-sha256 with a 64-character lowercase digest"}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) && os.Geteuid() == 0 && e.Getenv("SUDO_UID") != "" {
			return fmt.Errorf("no aqmas enrolment found for the user who ran sudo (looked in that user's ~/.config/aqmas) or for root. "+
				"Enrol as the user first, or name the enrolment: sudo AQMAS_CONFIG_DIR=/path/to/.config/aqmas aqmas upgrade (%w)", err)
		}
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	return e.upgrade(ctx, c, cfg.GitHub, path, Version, check, yes, single, expect, stderrTTY)
}
func (e *Env) upgrade(ctx context.Context, c *APIClient, source release.Source, path, current string, check, yes, single bool, expect string, tty bool) error {
	original, err := os.Lstat(path)
	if err != nil {
		return err
	}
	var m release.Metadata
	if err = c.do(ctx, "GET", "/v1/releases/latest", nil, &m); err != nil {
		return err
	}
	if !m.Valid() || !release.ValidVersion(current) {
		return errors.New("invalid running version or unverified release metadata")
	}
	if !release.Newer(m.Version, current) {
		e.logf("no newer verified release (running %s)", current)
		return nil
	}
	// Before anything is verified or downloaded: can this run replace the executable at all?
	if !check {
		if err = e.canInstall(path); err != nil {
			return err
		}
	}
	// The bastion has already compared the published sources it is configured with (GitHub,
	// and a second source where one exists) with its own rebuild. This host asks GitHub
	// itself, with its own HTTPS client, so that the bastion alone is never believed.
	compared := "GitHub"
	if m.Second != nil {
		compared = "GitHub and a second source"
	}
	asset := "aqmas-" + runtime.GOOS + "-" + runtime.GOARCH
	if e.goos != "" {
		asset = "aqmas-" + e.goos + "-" + e.goarch
	}
	gh, err := source.Hashes(ctx, m.Version, true)
	// A build listed in SHA256SUMS.extra (macOS x86-64) is checked against GitHub's copy of
	// that file as well, the same way.
	if err == nil && slices.Contains(release.ExtraAssets[:], asset) {
		var extra release.Sums
		if extra, err = source.ExtraHashes(ctx, m.Version, true); err == nil && !maps.Equal(extra, m.Extra) {
			return errors.New("the bastion's verified release and GitHub's " + release.ExtraSums + " disagree (or the bastion has no record of " + asset + " for this release yet)")
		}
	}
	switch {
	case single && errors.Is(err, release.ErrOffline):
		e.logf("WARNING: SINGLE SOURCE — GitHub unreachable; trusting only the bastion")
	case err != nil:
		return fmt.Errorf("GitHub verification: %w", err)
	case !m.GitHub.Agrees(gh):
		return errors.New("the bastion's verified release and GitHub's SHA256SUMS disagree")
	default:
		e.logf("bastion verified %s against %s and its own rebuild; GitHub agrees", m.Version, compared)
	}
	want := m.Hash(asset)
	if want == "" {
		if slices.Contains(release.ExtraAssets[:], asset) {
			return fmt.Errorf("the bastion has no verified record of %s for %s (it is recorded from the bastion's next update on); install that release by hand from the Help page", asset, m.Version)
		}
		return errors.New("unsupported platform")
	}
	e.logf("%s version %s SHA-256 %s", asset, m.Version, want)
	if expect != "" && expect != want {
		return errors.New("expected SHA-256 differs")
	}
	if check {
		return nil
	}
	if !yes && (!e.StdinIsTTY || !tty || e.agentSession()) {
		return errors.New("not prompting outside an interactive owner terminal; use --check or --yes --expect-sha256 HEX")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/v1/releases/"+m.Version+"/"+asset, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("asset download: HTTP %d", resp.StatusCode)
	}
	confirm := func() bool {
		if yes {
			return true
		}
		fmt.Fprint(e.Stderr, "Install this verified binary? [y/N] ")
		answer, _ := bufio.NewReader(e.Stdin).ReadString('\n')
		return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
	}
	if e.Elevate != nil {
		// Everything so far ran as the user who called sudo. Only the replacement is root's.
		if err = e.Elevate(); err != nil {
			return err
		}
	}
	return replaceBinary(path, original, resp.Body, want, confirm)
}

// rootControlled is the condition for replacing an executable as root: its directory and
// every parent belong to root and nobody else can rename things in them.
func rootControlled(dir string) error {
	for p := dir; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		const elsewhere = "This check is not relaxed; install aqmas in your own ~/.local/bin instead and upgrade it there without sudo"
		switch {
		case e != nil || !st.IsDir():
			return fmt.Errorf("privileged upgrade requires a root-controlled install directory and parents (%s cannot be checked). %s", p, elsewhere)
		case st.Sys().(*syscall.Stat_t).Uid != 0:
			return fmt.Errorf("privileged upgrade requires a root-controlled install directory and parents: %s is not owned by root. An install in a user's own directory is upgraded without sudo", p)
		case st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0:
			who := "a group other than root"
			if st.Mode().Perm()&0002 != 0 {
				who = "everyone"
			} else if st.Sys().(*syscall.Stat_t).Gid == 0 {
				who = "group root"
			}
			return fmt.Errorf("privileged upgrade requires a root-controlled install directory and parents: %s (mode %04o) is writable by %s, whose members could swap the executable. %s", p, st.Mode().Perm(), who, elsewhere)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// installCheck is rootControlled (a variable so that tests can stand in for root).
var installCheck = rootControlled

// sudoHint is the one way to upgrade a system-wide install.
func sudoHint(path string) string {
	return fmt.Sprintf("run `sudo %s upgrade` with the same flags: it uses this user's enrolment and verifies exactly as now, and only the final replacement runs as root", path)
}

// canInstall refuses, before any verification or download, an upgrade that cannot end in a
// replaced executable. A run that will take root back for the replacement (Elevate) is
// judged as root will be; any other run needs to be able to write the install directory.
func (e *Env) canInstall(path string) error {
	dir := filepath.Dir(path)
	if e.Elevate != nil || os.Geteuid() == 0 {
		return installCheck(dir)
	}
	if err := unix.Access(dir, unix.W_OK); err != nil {
		return fmt.Errorf("%s is a system-wide install: %s is not writable by %s, and nothing was downloaded. To upgrade it, %s", path, dir, e.userName(), sudoHint(path))
	}
	return nil
}

func (e *Env) userName() string {
	if e.User != "" {
		return e.User
	}
	return "this user"
}

func replaceBinary(path string, original os.FileInfo, body io.Reader, want string, confirm func() bool) error {
	dir := filepath.Dir(path)
	if os.Geteuid() == 0 {
		if err := rootControlled(dir); err != nil {
			return err
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = unix.Flock(int(d.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("another upgrade in progress: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !original.Mode().IsRegular() || !os.SameFile(current, original) {
		return errors.New("installed executable changed; retry")
	}
	stage, err := os.MkdirTemp(dir, ".aqmas-upgrade-")
	if err != nil {
		return fmt.Errorf("cannot stage upgrade in %s (for a system-wide install, %s): %w", dir, sudoHint(path), err)
	}
	defer os.RemoveAll(stage)
	tmp := filepath.Join(stage, "new")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	const max = 128 << 20
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(body, max+1))
	if err != nil {
		return err
	}
	if n > max || fmt.Sprintf("%x", hash.Sum(nil)) != want {
		return errors.New("downloaded executable SHA-256 mismatch")
	}
	if err = f.Chmod(0755); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		if exec.Command("/usr/bin/xattr", "-p", "com.apple.quarantine", tmp).Run() == nil {
			if err = exec.Command("/usr/bin/xattr", "-d", "com.apple.quarantine", tmp).Run(); err != nil {
				return err
			}
		}
		if err = exec.Command("/usr/bin/codesign", "--verify", tmp).Run(); err != nil {
			return errors.New("release lacks valid ad-hoc signature (re-signing would change the approved SHA-256)")
		}
	}
	if !confirm() {
		return ErrCancelled
	}
	fd := int(d.Fd())
	base := filepath.Base(path)
	backup := filepath.Join(filepath.Base(stage), "previous")
	if err = unix.Linkat(fd, base, fd, backup, 0); err != nil {
		return err
	}
	linked, err := os.Lstat(filepath.Join(dir, backup))
	if err != nil || !os.SameFile(original, linked) || linked.Size() != original.Size() || !linked.ModTime().Equal(original.ModTime()) {
		return errors.New("installed executable changed during confirmation; retry")
	}
	if err = unix.Renameat(fd, backup, fd, base+".prev"); err != nil {
		return err
	}
	if err = d.Sync(); err != nil {
		return err
	}
	if err = unix.Renameat(fd, filepath.Join(filepath.Base(stage), "new"), fd, base); err != nil {
		return err
	}
	return d.Sync()
}
