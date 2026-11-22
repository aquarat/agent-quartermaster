package maint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/aquarat/agent-quartermaster/deploy/bastion"
)

// Init installs the runner on a bastion (root, idempotent): directories, the key pasted
// secrets are sealed to, the deploy key, the systemd units and, when none exist yet, the
// maintenance pins. The first pins are the passkeys the broker has registered at this
// moment, which is why Init is run by the owner from a terminal and never by a request.
// repin replaces existing pins the same way (the out-of-band recovery for lost keys).
func Init(ctx context.Context, l Layout, repin bool, out io.Writer) error {
	r, err := New(l, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return err
	}
	_, gid, err := l.serviceIDs()
	if err != nil {
		return err
	}
	// A running broker whose unit could not see the spool at start (ProtectSystem=strict
	// with the optional ReadWritePaths entry) keeps a read-only view of it.
	_, statErr := os.Lstat(l.Spool)
	newSpool := statErr != nil
	for _, d := range []struct {
		path string
		mode os.FileMode
		gid  int
	}{{l.Spool, 0730, gid}, {l.Cache, 0755, 0}, {l.State, 0700, 0}, {l.Backups, 0700, 0}, {l.Libexec, 0755, 0}} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if !l.test {
			if err := os.Chown(d.path, 0, d.gid); err != nil {
				return err
			}
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(l.key()); err != nil {
		k, err := NewKey()
		if err != nil {
			return err
		}
		b, err := k.Bytes()
		if err != nil {
			return err
		}
		if err = writeOwned(l.key(), b, 0, 0, 0600); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(l.pins()); err != nil || repin {
		f, err := l.facts(ctx)
		if err != nil {
			return err
		}
		if len(f.Passkeys) == 0 {
			return errors.New("register the owner passkey first, then run maint-init again")
		}
		var pins []KeyPin
		for _, k := range f.Passkeys {
			pins = append(pins, KeyPin{ID: k.ID, PublicKey: k.PublicKey})
			fmt.Fprintf(out, "pinned passkey %s\n", base64.RawURLEncoding.EncodeToString(k.ID))
		}
		b, err := json.Marshal(pins)
		if err != nil {
			return err
		}
		if err = writeAtomic(l.pins(), b, 0600); err != nil {
			return err
		}
	}
	if err := r.ensureDeployKey(ctx); err != nil {
		return err
	}
	for name, body := range map[string][]byte{"aqmas-maint.service": bastion.MaintUnit, "aqmas-maint.path": bastion.MaintPath} {
		if err := writeOwned(filepath.Join(l.UnitDir, name), body, 0, 0, 0644); err != nil {
			return err
		}
	}
	r.st = ReadStatus(l.status())
	r.refreshInfo()
	r.save()
	if !l.test {
		_ = l.run(ctx, "restorecon", "-R", l.ConfigDir, l.Spool, l.Cache, l.State, filepath.Join(l.UnitDir, "aqmas-maint.service"), filepath.Join(l.UnitDir, "aqmas-maint.path"))
		if err := l.systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
		if err := l.systemctl(ctx, "enable", "--now", "aqmas-maint.path"); err != nil {
			return err
		}
	}
	if newSpool && !l.test && l.active(ctx) {
		fmt.Fprintln(out, "restarting aqmasd so that it can write the new spool")
		if err := l.systemctl(ctx, "try-restart", unitName); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "maintenance runner ready; deploy key: %s\n", r.st.Runner.DeployKey)
	return nil
}

// recover finishes or undoes a task whose runner died (crash, reboot).
func (r *Runner) recover(ctx context.Context, j journal) (string, error) {
	f, err := r.l.facts(ctx)
	if err != nil {
		return "", err
	}
	switch j.Task {
	case TaskCutover:
		defer r.clearJournal()
		if err := r.restart(ctx); err != nil {
			return "", errors.New("URGENT: the broker did not come back after an interrupted cutover; check it on the machine.")
		}
		if f.Schema >= 6 {
			return "The cutover was interrupted after activation; organisations are active.", nil
		}
		return "", errors.New("The cutover was interrupted before activation; nothing was changed.")
	case TaskSeal:
		// finishSeal keeps the journal on failure so the next start tries again.
		if f.Schema == 8 {
			return r.finishSeal(ctx, j)
		}
		return "", r.unseal(ctx, j, errors.New("Sealing was interrupted before activation: the store is unchanged and unsealed."))
	case TaskUpdates:
		defer r.clearJournal()
		_ = r.l.stop(ctx)
		if err := r.restoreConfig(j.Backup); err != nil {
			return "", err
		}
		if err := r.restart(ctx); err != nil {
			return "", err
		}
		return "", errors.New("Enabling self-update was interrupted; the previous configuration was restored.")
	}
	r.clearJournal()
	return "", errors.New("unknown interrupted task; inspect the machine")
}
