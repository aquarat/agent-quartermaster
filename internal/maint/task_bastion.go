package maint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/deploy/hosts"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Access to the bastion itself (docs/BASTION-ACCESS.md §3). Everything here is additive to
// sshd: certificate logins for two accounts. authorized_keys files are never read or written.

const (
	inspectGroup = "systemd-journal"
	hostKeyFile  = "ssh_host_ed25519_key.pub"
	caPubFile    = "ssh_user_ca.pub"
)

func (l Layout) sshDir() string         { return l.sysPath("etc", "ssh") }
func (l Layout) principalsDir() string  { return filepath.Join(l.sshDir(), "aqmas_principals") }
func (l Layout) installedCA() string    { return filepath.Join(l.sshDir(), "aqmas_user_ca.pub") }
func (l Layout) inspectCommand() string { return l.Bin + " inspect" }

// oneEd25519 accepts exactly one plain ssh-ed25519 public key line and returns it without
// its comment, with its fingerprint.
func oneEd25519(b []byte) (string, string, error) {
	text := strings.TrimSpace(string(b))
	if text == "" || strings.ContainsAny(text, "\r\n") {
		return "", "", errors.New("expected one public key line")
	}
	key, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil || len(opts) != 0 || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return "", "", errors.New("expected one ssh-ed25519 public key")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), ssh.FingerprintSHA256(key), nil
}

// signedCA returns the SSH user CA's public key line, but only if it is the key the owner
// signed, and in a sealed store only if that is also the CA of the activation manifest whose
// digest root pinned in the configuration: the broker owns the file and renders the card, so
// neither alone proves anything against it.
func (r *Runner) signedCA(ctx context.Context, want string) (string, error) {
	b, err := readRooted(filepath.Join(r.cfg.DataDir, "ca"), caPubFile, 4096)
	if err != nil {
		return "", errors.New("the SSH user CA public key could not be read")
	}
	line, fp, err := oneEd25519(b)
	if err != nil {
		return "", errors.New("the SSH user CA file is not one ssh-ed25519 public key")
	}
	if fp != want {
		return "", errors.New("the SSH user CA on this machine is not the one you signed (" + fp + ")")
	}
	if pin := r.cfg.Seal.Manifest; pin != "" {
		f, err := r.l.facts(ctx)
		if err != nil {
			return "", err
		}
		var act struct {
			Manifest string `json:"manifest"`
		}
		var m struct {
			SSHCA string `json:"ssh_ca"`
		}
		if len(f.Activation) > 2<<20 || json.Unmarshal([]byte(f.Activation), &act) != nil || act.Manifest == "" {
			return "", errors.New("the activation manifest could not be read")
		}
		sum := sha256.Sum256([]byte(act.Manifest))
		if hex.EncodeToString(sum[:]) != pin || json.Unmarshal([]byte(act.Manifest), &m) != nil {
			return "", errors.New("the stored activation manifest is not the one pinned in the configuration")
		}
		if m.SSHCA != want {
			return "", errors.New("the SSH user CA you signed is not the CA of the pinned activation manifest")
		}
	}
	return line, nil
}

// checkAdmin: the admin account must exist and be an ordinary account of a person.
func (l Layout) checkAdmin(name string) error {
	if !config.ValidUser(name) || config.ReservedBastionUser(name) {
		return errors.New("admin_user is not an account that can be used")
	}
	if l.test {
		return nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return errors.New("the admin account does not exist on this machine")
	}
	if uid, err := strconv.Atoi(u.Uid); err != nil || uid < 1000 {
		return errors.New("the admin account must be an ordinary account (uid 1000 or above)")
	}
	return nil
}

// ensureInspect creates the read-only account, or verifies one that exists: a system
// account in no group but its own and the journal's. It never gets a home or a password.
func (r *Runner) ensureInspect(ctx context.Context) error {
	u := config.InspectUser
	out, err := r.l.sysOut(ctx, "getent", "passwd", u)
	if err != nil || strings.TrimSpace(out) == "" {
		if err := r.l.sys(ctx, "useradd", "--system", "--no-create-home", "--home-dir", "/", "--shell", "/bin/sh", "--groups", inspectGroup, u); err != nil {
			return errors.New("the inspect account could not be created")
		}
	} else {
		f := strings.Split(strings.TrimSpace(out), ":")
		if len(f) < 7 || f[0] != u {
			return errors.New("the inspect account's record could not be read")
		}
		if uid, err := strconv.Atoi(f[2]); err != nil || uid == 0 || uid >= 1000 {
			return errors.New("an account named " + u + " exists and is not a system account; remove it first")
		}
		groups, err := r.l.sysOut(ctx, "id", "-Gn", u)
		if err != nil {
			return errors.New("the inspect account's groups could not be read")
		}
		for _, g := range strings.Fields(groups) {
			if g != u && g != inspectGroup {
				return errors.New("the existing " + u + " account is in group " + clean(g) + "; it may only be in " + inspectGroup)
			}
		}
		if err := r.l.sys(ctx, "usermod", "--home", "/", "--shell", "/bin/sh", "--groups", inspectGroup, u); err != nil {
			return errors.New("the inspect account could not be adjusted")
		}
	}
	if err := r.l.sys(ctx, "passwd", "-l", u); err != nil {
		return errors.New("the inspect account's password could not be locked")
	}
	return nil
}

// hostTrust runs the embedded host-trust installer with fixed arguments. The words that
// come from a request (name, admin user) passed the task's patterns and the installer's own.
func (r *Runner) hostTrust(ctx context.Context, args ...string) error {
	if err := os.MkdirAll(r.l.State, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(r.l.State, "host-trust-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "install-host-trust.sh")
	if err = os.WriteFile(script, hosts.InstallScript, 0700); err == nil {
		err = os.WriteFile(filepath.Join(dir, "10-aqmas.conf"), hosts.TrustConf, 0600)
	}
	if err != nil {
		return err
	}
	argv := []string{script, "--bastion-self", "--inspect-user", config.InspectUser, "--inspect-command", r.l.inspectCommand()}
	if r.l.test {
		// The test layout's sshd is the hook, like every other system tool.
		wrapper := filepath.Join(dir, "sshd")
		if !safeWord(r.l.Hook) {
			return errors.New("test hook path is not plain")
		}
		if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec '"+r.l.Hook+"' sys sshd \"$@\"\n"), 0700); err != nil {
			return err
		}
		argv = append(argv, "--root", r.l.Root, "--sshd", wrapper)
	}
	c := command(ctx, "bash", append(argv, args...)...)
	c.Dir = "/"
	if err := c.Run(); err != nil {
		return errors.New("the sshd configuration check or change failed; the previous files are in place (details in the journal)")
	}
	return nil
}

func safeWord(s string) bool {
	return s != "" && !strings.ContainsAny(s, "'\"\\$`\n ")
}

func (r *Runner) installTrust(ctx context.Context, name, admin, caFile, fingerprint string) error {
	args := []string{"--name", name, "--ca-key", caFile, "--admin-user", admin, "--apply"}
	if fingerprint != "" {
		args = append(args, "--ca-fingerprint", fingerprint)
	}
	return r.hostTrust(ctx, args...)
}

func (r *Runner) uninstallTrust(ctx context.Context) error {
	return r.hostTrust(ctx, "--uninstall", "--apply")
}

// writePrincipals writes the admin account's principals file from root's allowlist: one
// line that sshd honours only from the listed addresses. No list, no file, no root login.
func (l Layout) writePrincipals(b config.Bastion, allowed []AllowedHost) error {
	path := filepath.Join(l.principalsDir(), b.AdminUser)
	if len(allowed) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	var from []string
	for _, h := range allowed {
		if !slices.Contains(from, h.Address) {
			from = append(from, h.Address)
		}
	}
	if err := os.MkdirAll(l.principalsDir(), 0755); err != nil {
		return err
	}
	if err := os.Chmod(l.principalsDir(), 0755); err != nil {
		return err
	}
	return writeOwned(path, []byte(`from="`+strings.Join(from, ",")+`" `+b.Principal(config.LevelRoot)+"\n"), 0, 0, 0644)
}

// swapConfig replaces the configuration, keeping a root-only copy of the old one.
func (r *Runner) swapConfig(raw []byte, label string) error {
	if err := os.MkdirAll(r.l.Backups, 0700); err != nil {
		return err
	}
	keep := filepath.Join(r.l.Backups, "config-"+r.now().UTC().Format("20060102T150405.000000000Z")+"-"+label+".toml")
	if err := os.WriteFile(keep, r.raw, 0600); err != nil {
		return err
	}
	if err := replaceFile(r.l.Config, raw); err != nil {
		return err
	}
	return r.loadConfig()
}

// restartServe restarts the broker on the current configuration and waits for health.
func (r *Runner) restartServe(ctx context.Context) error {
	if err := r.l.stop(ctx); err != nil {
		return err
	}
	if err := r.l.start(ctx, "serve"); err != nil {
		return errors.New("the broker did not start")
	}
	return r.l.healthy(ctx, r.cfg.ListenWeb)
}

func (r *Runner) bastionAccess(ctx context.Context, p BastionAccessParams) (string, error) {
	r.step("Checking the admin account and the SSH CA against what you signed")
	if err := r.l.checkAdmin(p.AdminUser); err != nil {
		return "", err
	}
	hk, err := os.ReadFile(filepath.Join(r.l.sshDir(), hostKeyFile))
	if err != nil {
		return "", errors.New("this machine has no Ed25519 SSH host key to pin")
	}
	hostKey, hostFP, err := oneEd25519([]byte(strings.Join(firstFields(string(hk), 2), " ")))
	if err != nil {
		return "", errors.New("this machine's SSH host key could not be read")
	}
	b := config.Bastion{Name: p.Name, Address: p.Address, Port: p.Port, AdminUser: p.AdminUser, HostKey: hostKey}
	// The new configuration is built and proved before anything on the machine changes.
	oldRaw, old := slices.Clone(r.raw), r.cfg.Bastion
	newRaw, err := addBastion(r.raw, b)
	if err != nil {
		return "", err
	}
	caLine, err := r.signedCA(ctx, p.SSHCA)
	if err != nil {
		return "", err
	}
	r.step("Creating the locked-down inspect account")
	if err := r.ensureInspect(ctx); err != nil {
		return "", err
	}
	r.step("Installing the CA, the principals files and the forced-command block; validating and reloading sshd")
	caFile := filepath.Join(r.l.State, "bastion-ca.pub")
	if err := os.WriteFile(caFile, []byte(caLine+"\n"), 0600); err != nil {
		return "", err
	}
	defer os.Remove(caFile)
	if err := r.installTrust(ctx, p.Name, p.AdminUser, caFile, p.SSHCA); err != nil {
		return "", err
	}
	undo := func() {
		if !old.Enabled() {
			_ = os.Remove(filepath.Join(r.l.principalsDir(), b.AdminUser))
			_ = r.uninstallTrust(ctx)
		}
	}
	if old.Enabled() && old.AdminUser != b.AdminUser {
		_ = os.Remove(filepath.Join(r.l.principalsDir(), old.AdminUser))
	}
	if err := r.l.writePrincipals(b, ReadAllow(AllowPath(r.l.ConfigDir))); err != nil {
		undo()
		return "", err
	}
	r.step("Recording this machine as a destination in the configuration")
	if err := r.swapConfig(newRaw, "bastion-access"); err != nil {
		undo()
		return "", err
	}
	r.step("Restarting the broker and checking it is healthy")
	if err := r.restartServe(ctx); err != nil {
		// Back to the configuration that worked, and no trust left behind.
		if rerr := replaceFile(r.l.Config, oldRaw); rerr == nil {
			_ = r.loadConfig()
			_ = r.restartServe(ctx)
		}
		undo()
		return "", errors.New("the broker was not healthy with the new configuration; the previous configuration and sshd files were restored")
	}
	r.result("name", b.Name)
	r.result("address", b.Address+":"+strconv.Itoa(b.Port))
	r.result("admin_user", b.AdminUser)
	r.result("inspect_user", config.InspectUser)
	r.result("host_key", hostFP)
	r.result("ssh_ca", p.SSHCA)
	return "aqmas can now issue certificates for this machine. Nobody may ask for root until you set who may. Your emergency keys were not touched.", nil
}

func firstFields(s string, n int) []string {
	f := strings.Fields(s)
	if len(f) > n {
		f = f[:n]
	}
	return f
}

func (r *Runner) bastionAllow(ctx context.Context, p BastionAllowParams) (string, error) {
	b := r.cfg.Bastion
	if !b.Enabled() {
		return "", errors.New("access to the bastion is not installed")
	}
	text, err := Canonical(TaskBastionAllow, p)
	if err != nil {
		return "", err
	}
	r.step("Writing the root-owned list")
	_, gid, err := r.l.serviceIDs()
	if err != nil {
		return "", err
	}
	if err := writeOwned(AllowPath(r.l.ConfigDir), []byte(text+"\n"), 0, gid, 0640); err != nil {
		return "", err
	}
	r.step("Rewriting the admin account's principals file with the listed addresses")
	if err := r.l.writePrincipals(b, p.Hosts); err != nil {
		// Never leave the list wider than what sshd enforces.
		_ = os.Remove(AllowPath(r.l.ConfigDir))
		_ = r.l.writePrincipals(b, nil)
		return "", errors.New("the principals file could not be written; nobody may ask for root now")
	}
	var names []string
	for _, h := range p.Hosts {
		names = append(names, h.Name+" ("+h.Address+")")
	}
	r.result("hosts", strconv.Itoa(len(p.Hosts)))
	if len(names) == 0 {
		return "Nobody may ask for root on the bastion.", nil
	}
	return "May ask for root on the bastion: " + strings.Join(names, ", ") + ".", nil
}

func (r *Runner) bastionRemove(ctx context.Context) (string, error) {
	b := r.cfg.Bastion
	if b.Enabled() {
		r.step("Removing this machine as a destination from the configuration and restarting the broker")
		oldRaw := slices.Clone(r.raw)
		newRaw, err := removeBastion(r.raw)
		if err != nil {
			return "", err
		}
		if err := r.swapConfig(newRaw, "bastion-remove"); err != nil {
			return "", err
		}
		if err := r.restartServe(ctx); err != nil {
			if rerr := replaceFile(r.l.Config, oldRaw); rerr == nil {
				_ = r.loadConfig()
				_ = r.restartServe(ctx)
			}
			return "", errors.New("the broker was not healthy without the bastion entry; the previous configuration was restored and nothing else was changed")
		}
		if err := os.Remove(filepath.Join(r.l.principalsDir(), b.AdminUser)); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	if err := os.Remove(AllowPath(r.l.ConfigDir)); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	r.step("Removing the CA, principals files and forced-command block; validating and reloading sshd")
	if err := r.uninstallTrust(ctx); err != nil {
		return "", err
	}
	r.step("Ending the inspect account's sessions and deleting the account")
	if out, err := r.l.sysOut(ctx, "getent", "passwd", config.InspectUser); err == nil && strings.TrimSpace(out) != "" {
		_ = r.l.sys(ctx, "loginctl", "terminate-user", config.InspectUser)
		if err := r.l.sys(ctx, "userdel", config.InspectUser); err != nil {
			r.result("inspect_account", "could not be deleted; it can no longer log in")
		}
	}
	return "This machine no longer accepts aqmas certificates. A root session that is already open is not ended.", nil
}
