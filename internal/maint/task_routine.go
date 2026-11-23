package maint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Routine maintenance (docs/BASTION-ACCESS.md §7). Every command is a fixed argv; the only
// request-derived values are a boolean (the presence of fixed arguments) and an integer the
// runner formats itself. None of these tasks keeps a journal.

// bootExcludes are left alone by an update unless the owner allows kernel changes: the
// kernel, its modules and everything between the firmware and the kernel.
var bootExcludes = []string{"kernel*", "kmod-*", "akmod-*", "grub2*", "shim*", "dracut*", "systemd-boot*", "sdubby*", "linux-firmware*", "m1n1*", "uboot*", "asahi-*"}

const (
	excludeFile    = "os-update-exclude"
	bootMarker     = "boot-changed"
	maxSummary     = 60
	updateTimeout  = 90 * time.Minute
	maxBootEntries = 20000
)

var excludeRE = regexp.MustCompile(`^[A-Za-z0-9._*+-]{1,64}$`)

func (l Layout) bootMarker() string { return filepath.Join(l.State, bootMarker) }

// siteExcludes reads the optional root-owned list of further package globs a site pins.
func (l Layout) siteExcludes() ([]string, error) {
	p := filepath.Join(l.ConfigDir, excludeFile)
	st, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	bad := errors.New(excludeFile + " must be a root-owned file of package globs, one per line")
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 || st.Mode().Perm()&0022 != 0 {
		return nil, bad
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !l.test && (!ok || sys.Uid != 0) {
		return nil, bad
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, bad
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !excludeRE.MatchString(line) || len(out) >= 64 {
			return nil, bad
		}
		out = append(out, line)
	}
	return out, nil
}

// installed lists what is installed: name → version-release.arch (several joined, sorted,
// when a name is installed more than once, as kernels are).
func (r *Runner) installed(ctx context.Context) (map[string]string, error) {
	out, err := r.l.sysOut(ctx, "rpm", "-qa", "--qf", `%{NAME}\t%{EVR}.%{ARCH}\n`)
	if err != nil {
		return nil, errors.New("the installed packages could not be listed")
	}
	many := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		name, ver, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name == "" {
			continue
		}
		many[name] = append(many[name], ver)
	}
	pkgs := map[string]string{}
	for name, v := range many {
		sort.Strings(v)
		pkgs[name] = strings.Join(v, ",")
	}
	return pkgs, nil
}

// bootFingerprint is a digest of the boot files: every name, size, mode and time under
// /boot, and the contents of the files that choose what boots.
func (l Layout) bootFingerprint() (string, error) {
	root := l.sysPath("boot")
	h := sha256.New()
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root && os.IsNotExist(err) {
				return filepath.SkipAll
			}
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if n++; n > maxBootEntries {
			return errors.New("too many files under /boot")
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%q %d %v %d\n", rel, st.Size(), st.Mode(), st.ModTime().UnixNano())
		base := d.Name()
		if st.Mode().IsRegular() && st.Size() <= 4<<20 && (base == "grub.cfg" || base == "grubenv" || base == "loader.conf" || base == "extlinux.conf" || strings.Contains(rel, filepath.Join("loader", "entries"))) {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(h, io.LimitReader(f, 4<<20))
			f.Close()
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", errors.New("the boot files could not be read")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func matchesAny(globs []string, name string) bool {
	return slices.ContainsFunc(globs, func(g string) bool { ok, _ := path.Match(g, name); return ok })
}

func (r *Runner) osUpdate(ctx context.Context, p OSUpdateParams) (string, error) {
	r.step("Recording the installed packages and the boot files")
	excludes := slices.Clone(bootExcludes)
	site, err := r.l.siteExcludes()
	if err != nil {
		return "", err
	}
	excludes = append(excludes, site...)
	before, err := r.installed(ctx)
	if err != nil {
		return "", err
	}
	bootBefore, err := r.l.bootFingerprint()
	if err != nil {
		return "", err
	}
	// Outside the runner's sandbox (no private devices, no memory cap): package scripts
	// expect the real machine. Still a fixed argv.
	argv := []string{"--wait", "--collect", "--quiet", "--pipe", "--unit=aqmas-os-update", "--description=aqmas: system package update",
		"--property=TimeoutStartSec=" + strconv.Itoa(int(updateTimeout/time.Second)), "--", "dnf", "-y", "--refresh", "upgrade"}
	if !p.Kernel {
		for _, g := range excludes {
			argv = append(argv, "--exclude="+g)
		}
	}
	r.step("Running dnf upgrade outside the runner's sandbox")
	uctx, cancel := context.WithTimeout(ctx, updateTimeout+time.Minute)
	runErr := r.l.sys(uctx, "systemd-run", argv...)
	cancel()
	r.step("Comparing before and after")
	after, err := r.installed(ctx)
	if err != nil {
		return "", err
	}
	bootAfter, err := r.l.bootFingerprint()
	if err != nil {
		return "", err
	}
	var names []string
	for name := range before {
		names = append(names, name)
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	changed, guarded := 0, []string{}
	for _, name := range names {
		a, b := before[name], after[name]
		if a == b {
			continue
		}
		changed++
		if matchesAny(excludes, name) {
			guarded = append(guarded, name)
		}
		if changed <= maxSummary {
			switch {
			case a == "":
				r.step("installed " + name + " " + b)
			case b == "":
				r.step("removed " + name + " " + a)
			default:
				r.step(name + " " + a + " → " + b)
			}
		}
	}
	if changed > maxSummary {
		r.step("… and " + strconv.Itoa(changed-maxSummary) + " more")
	}
	r.result("packages_changed", strconv.Itoa(changed))
	r.result("kernel_allowed", strconv.FormatBool(p.Kernel))
	bootChanged := bootBefore != bootAfter
	r.result("boot_files_changed", strconv.FormatBool(bootChanged))
	if len(guarded) > 0 {
		r.result("kernel_or_boot_packages_changed", strings.Join(guarded, " "))
	}
	if p.Kernel {
		// The owner accepted kernel and boot changes: an earlier warning is settled.
		if err := os.Remove(r.l.bootMarker()); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	} else if bootChanged || len(guarded) > 0 {
		what := "the boot files changed"
		if len(guarded) > 0 {
			what = "kernel or boot-chain packages changed (" + strings.Join(guarded, ", ") + ")"
		}
		_ = os.MkdirAll(r.l.State, 0700)
		if err := writeAtomic(r.l.bootMarker(), []byte(stamp(r.now())+" "+clean(what)+"\n"), 0600); err != nil {
			return "", err
		}
		return "", errors.New("Although they were excluded, " + what + ". Look at the machine before it restarts: the restart task is refused until an update with “allow kernel” accepts the change.")
	}
	if runErr != nil {
		return "", errors.New("dnf upgrade failed (details in the journal); " + plural(changed, "package") + " changed before it stopped")
	}
	if b := r.cfg.Bastion; b.Enabled() {
		r.step("Checking sshd still confines the inspect account")
		if err := r.installTrust(ctx, b.Name, b.AdminUser, r.l.installedCA(), ""); err != nil {
			return "", errors.New("the packages were updated, but sshd no longer confines the inspect account as installed. Run “Allow aqmas access to the bastion” again, or remove the access.")
		}
	}
	if changed == 0 {
		return "Nothing to update.", nil
	}
	msg := plural(changed, "package") + " updated."
	if !p.Kernel {
		msg += " The kernel and boot chain were left alone."
	}
	return msg, nil
}

// restartMachine refuses while an update left the boot path changed without the owner's
// consent; otherwise the status is written first and the machine restarts afterwards.
func (r *Runner) restartMachine(ctx context.Context) (string, error) {
	r.step("Recording the request")
	if b, err := os.ReadFile(r.l.bootMarker()); err == nil {
		return "", errors.New("Refused: the last update changed the kernel or boot files without permission (" + clean(strings.TrimSpace(string(b))) + "). Run the update with “allow kernel” to accept that, or look at the machine first.")
	}
	r.after = func(ctx context.Context) {
		if err := r.l.sys(ctx, "systemctl", "reboot"); err != nil {
			r.log.Error("restart request failed", "error", err)
		}
	}
	return "The bastion is restarting. It comes back with nothing open: every bucket closed, every approval window ended.", nil
}

var tunnelUnits = []string{"cloudflared-aqmas.service", "cloudflared.service"}

func (r *Runner) restartTunnel(ctx context.Context) (string, error) {
	r.step("Restarting the tunnel service")
	unit := ""
	for _, u := range tunnelUnits {
		// LoadState only: a unit file or status could show the tunnel's token.
		if out, err := r.l.sysOut(ctx, "systemctl", "show", "--property=LoadState", "--value", u); err == nil && strings.TrimSpace(out) == "loaded" {
			unit = u
			break
		}
	}
	if unit == "" {
		return "", errors.New("no cloudflared service is installed on this machine")
	}
	if err := r.l.sys(ctx, "systemctl", "restart", unit); err != nil {
		return "", errors.New("the tunnel service did not restart")
	}
	r.step("Checking it is running")
	for i := 0; ; i++ {
		if r.l.sys(ctx, "systemctl", "is-active", "--quiet", unit) == nil {
			break
		}
		if i >= 15 {
			return "", errors.New("the tunnel service is not running after the restart")
		}
		time.Sleep(r.poll)
	}
	r.result("unit", unit)
	return "cloudflared was restarted and is running.", nil
}

func (r *Runner) restartBroker(ctx context.Context) (string, error) {
	r.step("Stopping the broker and waiting for it to exit")
	if err := r.l.stop(ctx); err != nil {
		return "", err
	}
	r.step("Starting it and checking it is healthy")
	if err := r.l.start(ctx, "serve"); err != nil {
		return "", errors.New("the broker did not start")
	}
	if err := r.l.healthy(ctx, r.cfg.ListenWeb); err != nil {
		return "", err
	}
	return "aqmasd was restarted and is healthy. Nothing is open.", nil
}

// usage measures the file systems and the journal. Everything reported is a size.
func (r *Runner) usage(ctx context.Context) (map[string]string, error) {
	out, err := r.l.sysOut(ctx, "df", "-P", "-h", "/", r.cfg.DataDir, "/var/log")
	if err != nil && out == "" {
		return nil, errors.New("disk usage could not be measured")
	}
	res := map[string]string{}
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 6 {
			continue
		}
		mount := f[len(f)-1]
		res["disk "+mount] = f[2] + " of " + f[1] + " used (" + f[4] + "), " + f[3] + " free"
	}
	if j, err := r.l.sysOut(ctx, "journalctl", "--disk-usage"); err == nil {
		res["journal"] = strings.TrimSpace(j)
	}
	return res, nil
}

func (r *Runner) diskUsage(ctx context.Context) (string, error) {
	r.step("Measuring")
	res, err := r.usage(ctx)
	if err != nil {
		return "", err
	}
	var keys []string
	for k, v := range res {
		r.result(k, v)
		keys = append(keys, k+": "+v)
	}
	sort.Strings(keys)
	return strings.Join(keys, "; "), nil
}

func (r *Runner) journalVacuum(ctx context.Context, p JournalVacuumParams) (string, error) {
	if p.KeepDays < 1 || p.KeepDays > 365 {
		return "", errors.New("keep_days must be between 1 and 365")
	}
	before, _ := r.usage(ctx)
	r.step("Rotating the journal")
	if err := r.l.sys(ctx, "journalctl", "--rotate"); err != nil {
		return "", err
	}
	r.step("Deleting entries older than " + plural(p.KeepDays, "day"))
	if err := r.l.sys(ctx, "journalctl", "--vacuum-time="+strconv.Itoa(p.KeepDays)+"d"); err != nil {
		return "", err
	}
	r.step("Reporting the space freed")
	after, _ := r.usage(ctx)
	r.result("journal_before", before["journal"])
	r.result("journal_after", after["journal"])
	r.result("keep_days", strconv.Itoa(p.KeepDays))
	return "Journal trimmed to the last " + plural(p.KeepDays, "day") + ". " + after["journal"], nil
}
