package maint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/deploy/bastion"
	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// The two private CA files the sealed store replaces (internal/server/pki).
var retiredCA = []string{"ca/ssh_user_ca", "ca/client_ca.key"}

// source is one plaintext Cloudflare parent credential to retire after activation.
type source struct {
	credential string // systemd LoadCredential name ("" for a plain file)
	path       string
}

var loadCredential = regexp.MustCompile(`^[ \t]*LoadCredential[ \t]*=[ \t]*([A-Za-z0-9_.-]+):(/[^\s]+)[ \t]*$`)

func (r *Runner) unitFiles() []string {
	files := []string{r.l.unit()}
	if more, err := filepath.Glob(filepath.Join(r.l.unit()+".d", "*.conf")); err == nil {
		files = append(files, more...)
	}
	return files
}

// cfSources lists the plaintext parent-token sources named by the configuration and the
// unit. Each must be a file this runner may delete, or sealing is refused before it starts.
func (r *Runner) cfSources() ([]source, error) {
	cf := r.cfg.Cloudflare
	var out []source
	names := map[string]bool{}
	for _, n := range []string{cf.ProxyTokenCredential, cf.MinterTokenCredential} {
		if n != "" {
			names[n] = true
		}
	}
	for _, p := range []string{cf.ProxyTokenFile, cf.MinterTokenFile} {
		if p != "" {
			out = append(out, source{path: p})
		}
	}
	for _, file := range r.unitFiles() {
		b, err := os.ReadFile(file)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if m := loadCredential.FindStringSubmatch(line); m != nil && names[m[1]] {
				out = append(out, source{m[1], m[2]})
			}
		}
	}
	for _, s := range out {
		if !hasPrefixPath(s.path, r.l.ConfigDir) && !hasPrefixPath(s.path, r.cfg.DataDir) {
			return nil, errors.New("a Cloudflare parent token lives outside the broker's directories; move it under the configuration directory first")
		}
	}
	return out, nil
}

// retire deletes the plaintext sources and their LoadCredential lines. Paths under the
// service-owned data directory are removed through an os.Root, so a planted link cannot
// redirect root's unlink elsewhere.
func (r *Runner) retire(ctx context.Context, sources []source) error {
	root, err := os.OpenRoot(r.cfg.DataDir)
	if err != nil {
		return err
	}
	defer root.Close()
	remove := func(path string) error {
		var err error
		if hasPrefixPath(path, r.cfg.DataDir) {
			rel, _ := filepath.Rel(r.cfg.DataDir, path)
			err = root.Remove(rel)
		} else {
			err = os.Remove(path)
		}
		if err != nil && !os.IsNotExist(err) {
			return errors.New("could not delete a retired plaintext file")
		}
		return nil
	}
	for _, rel := range retiredCA {
		if err := remove(filepath.Join(r.cfg.DataDir, rel)); err != nil {
			return err
		}
	}
	names := map[string]bool{}
	for _, s := range sources {
		if err := remove(s.path); err != nil {
			return err
		}
		if s.credential != "" {
			names[s.credential] = true
		}
	}
	if len(names) == 0 {
		return nil
	}
	for _, file := range r.unitFiles() {
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var keep []string
		changed := false
		for _, line := range strings.Split(string(b), "\n") {
			if m := loadCredential.FindStringSubmatch(line); m != nil && names[m[1]] {
				changed = true
				continue
			}
			keep = append(keep, line)
		}
		if changed {
			if err := replaceFile(file, []byte(strings.Join(keep, "\n"))); err != nil {
				return err
			}
		}
	}
	if r.l.test {
		return nil
	}
	return r.l.systemctl(ctx, "daemon-reload")
}

func (r *Runner) stageDirs() []string {
	dirs, _ := filepath.Glob(filepath.Join(r.cfg.DataDir, "seal-stage-*"))
	return dirs
}

func (r *Runner) removeStages() {
	root, err := os.OpenRoot(r.cfg.DataDir)
	if err != nil {
		return
	}
	defer root.Close()
	for _, d := range r.stageDirs() {
		_ = root.RemoveAll(filepath.Base(d))
	}
}

func (r *Runner) alertFiles() (string, string) {
	return filepath.Join(r.l.AlertDir, "topic-url"), filepath.Join(r.l.AlertDir, "publish-token")
}

// seal runs the supervised seal import. The owner's passkey ceremonies, the recovery drill
// and the activation signature happen in the browser against the import-mode broker.
func (r *Runner) seal(ctx context.Context, p SealParams, secrets map[string]string) (string, error) {
	f, err := r.l.facts(ctx)
	if err != nil {
		return "", err
	}
	if f.Schema < 6 {
		return "", errors.New("switch to organisations first")
	}
	if f.Schema > 7 || r.cfg.Seal != (config.Seal{}) {
		return "", errors.New("this installation is already sealed or staged for sealing")
	}
	if len(f.Passkeys) == 0 {
		return "", errors.New("register a passkey first")
	}
	staged, err := addSeal(r.raw, p.Recipient)
	if err != nil {
		return "", err
	}
	if _, err = pinSeal(staged, strings.Repeat("0", 64)); err != nil {
		return "", err
	}
	if _, err = r.cfSources(); err != nil {
		return "", err
	}
	if err = r.l.healthy(ctx, r.cfg.ListenWeb); err != nil {
		return "", errors.New("the broker is not healthy; fix that first")
	}
	r.step("Stopping the broker")
	if err = r.l.stop(ctx); err != nil {
		return "", r.resume(ctx, err)
	}
	r.step("Backing up the database, keys and configuration")
	dir, err := r.backup(ctx, "seal")
	if err != nil {
		return "", r.resume(ctx, err)
	}
	j := journal{Task: TaskSeal, Backup: dir, Purge: p.PurgeBackups, LockAlert: p.LockAlert}
	if err = r.writeJournal(j); err != nil {
		return "", r.resume(ctx, err)
	}
	if p.LockAlert {
		r.step("Storing the lock-alert credential (root only)")
		topic, token := r.alertFiles()
		err = os.MkdirAll(r.l.AlertDir, 0700)
		if err == nil {
			err = writeOwned(topic, []byte(secrets["ntfy_topic_url"]+"\n"), 0, 0, 0600)
		}
		if err == nil {
			err = writeOwned(token, []byte(secrets["ntfy_token"]+"\n"), 0, 0, 0600)
		}
		if err != nil {
			return "", r.unseal(ctx, j, errors.New("could not store the lock-alert credential"))
		}
	}
	r.step("Recording the recovery key in the configuration")
	if err = replaceFile(r.l.Config, staged); err != nil {
		return "", r.unseal(ctx, j, err)
	}
	r.step("Starting the broker in import mode")
	if err = r.l.start(ctx, "seal-import"); err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err != nil {
		return "", r.unseal(ctx, j, errors.New("the import mode did not start"))
	}
	deadline := r.now().Add(r.SealWait)
	r.wait("seal", "Waiting for you: create and test the passkey wrap, prove the recovery key, then activate", deadline)
	if o := r.await(ctx, deadline, func(f Facts) bool { return f.Schema == 8 }); o != reached {
		return "", r.unseal(ctx, j, errors.New("Sealing "+o.reason()+": the store is unchanged and unsealed."))
	}
	time.Sleep(2 * r.poll)
	return r.finishSeal(ctx, j)
}

// unseal undoes a seal import that was not activated.
func (r *Runner) unseal(ctx context.Context, j journal, cause error) error {
	r.step("Not activated: restoring the configuration")
	_ = r.l.stop(ctx)
	if f, err := r.l.facts(ctx); err == nil && f.Schema == 8 {
		// Activation committed while we were giving up: the only safe direction is forward.
		_, err := r.finishSeal(ctx, j)
		return err
	}
	if err := r.restoreConfig(j.Backup); err != nil {
		return errors.New(cause.Error() + " URGENT: the configuration could not be restored; the broker is stopped.")
	}
	r.removeStages()
	if j.LockAlert {
		topic, token := r.alertFiles()
		_ = os.Remove(topic)
		_ = os.Remove(token)
	}
	err := r.l.start(ctx, "serve")
	if err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	r.clearJournal()
	if err != nil {
		return errors.New(cause.Error() + " URGENT: the broker did not come back; check it on the machine.")
	}
	return cause
}

// finishSeal is everything after the signed activation. It only moves forward and can be
// repeated: the journal stays until the broker is serving locked.
func (r *Runner) finishSeal(ctx context.Context, j journal) (string, error) {
	fail := func(err error) (string, error) {
		return "", errors.New("Activated, but finishing failed (" + err.Error() + "). The runner retries automatically; if this persists run `aqmasd maint-run` as root on the machine.")
	}
	r.step("Activated. Pinning the activation in the configuration")
	_ = r.l.stop(ctx)
	f, err := r.l.facts(ctx)
	if err != nil {
		return fail(err)
	}
	if f.Schema != 8 || !release.ValidHash(f.Manifest) {
		return fail(errors.New("activation record is missing"))
	}
	if err = r.loadConfig(); err != nil {
		return fail(err)
	}
	if r.cfg.Seal.Manifest == "" {
		pinned, err := pinSeal(r.raw, f.Manifest)
		if err == nil {
			err = replaceFile(r.l.Config, pinned)
		}
		if err == nil {
			err = r.loadConfig()
		}
		if err != nil {
			return fail(err)
		}
	} else if r.cfg.Seal.Manifest != f.Manifest {
		return fail(errors.New("configuration pins another activation"))
	}
	r.result("manifest_sha256", f.Manifest)
	r.result("recipient", r.cfg.Seal.Recipient)

	r.step("Keeping the encrypted recovery bundle and removing staging files")
	for _, stage := range r.stageDirs() {
		keep := filepath.Join(r.l.Backups, "sealed-"+f.Manifest[:16])
		if err := os.MkdirAll(keep, 0700); err != nil {
			return fail(err)
		}
		for _, name := range []string{"inventory.json", "manifest.json"} {
			if err := copyFile(filepath.Join(keep, name), filepath.Join(stage, name), 1<<20, 0600); err != nil && !os.IsNotExist(err) {
				return fail(err)
			}
		}
		r.result("recovery_bundle", keep)
	}
	r.removeStages()

	r.step("Deleting the plaintext key files and parent tokens")
	sources, err := r.cfSources()
	if err == nil {
		err = r.retire(ctx, sources)
	}
	if err != nil {
		return fail(err)
	}
	if j.LockAlert {
		r.step("Setting up the lock alert")
		if err := r.lockAlert(ctx); err != nil {
			r.result("lock_alert", "not installed: "+err.Error())
		} else {
			r.result("lock_alert", "installed")
		}
	}
	r.step("Starting the sealed broker (locked)")
	if err = r.l.start(ctx, "serve"); err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err != nil {
		return fail(errors.New("the sealed broker did not start"))
	}
	if j.Purge {
		r.step("Deleting older backups that still contain plaintext keys")
		entries, _ := os.ReadDir(r.l.Backups)
		n := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "sealed-") {
				continue
			}
			if os.RemoveAll(filepath.Join(r.l.Backups, e.Name())) == nil {
				n++
			}
		}
		r.result("backups_deleted", strconv.Itoa(n))
	} else {
		r.result("plaintext_backups", r.l.Backups+" still holds pre-seal copies of the private keys")
	}
	r.clearJournal()
	return "Sealed. The broker is locked: unlock it with your passkey.", nil
}

// lockAlert installs the separate alert service. Its credentials are already in place.
func (r *Runner) lockAlert(ctx context.Context) error {
	topic, token := r.alertFiles()
	for _, p := range []string{topic, token} {
		if _, err := os.Lstat(p); err != nil {
			return errors.New("credential files are missing")
		}
	}
	if err := os.MkdirAll(r.l.Libexec, 0755); err != nil {
		return err
	}
	if err := writeOwned(filepath.Join(r.l.Libexec, "aqmas-lock-alert.py"), bastion.LockAlertScript, 0, 0, 0755); err != nil {
		return err
	}
	if err := writeOwned(filepath.Join(r.l.UnitDir, "aqmas-lock-alert.service"), bastion.LockAlertUnit, 0, 0, 0644); err != nil {
		return err
	}
	if r.l.test {
		return nil
	}
	_ = r.l.run(ctx, "restorecon", filepath.Join(r.l.Libexec, "aqmas-lock-alert.py"), filepath.Join(r.l.UnitDir, "aqmas-lock-alert.service"))
	if err := r.l.systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	return r.l.systemctl(ctx, "enable", "--now", "aqmas-lock-alert.service")
}
