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
	"strings"

	"github.com/aquarat/agent-quartermaster/deploy/bastion"
	"github.com/aquarat/agent-quartermaster/internal/release"
)

// Init installs the runner on a bastion (root, idempotent): directories, the key pasted
// secrets are sealed to, the systemd units and, when none exist yet, the
// maintenance pins. The first pins are the passkeys the broker has registered at this
// moment, which is why Init is run by the owner from a terminal and never by a request.
// repin replaces existing pins the same way (the out-of-band recovery for lost keys).
//
// sources, when given, pins the release sources "Enable self-update" may use. Without a pin
// the task uses the configuration's [updates] table, or the public GitHub repository alone;
// in every case a request from the web page can neither choose nor change them. The
// read-only deploy key is created only when the repository is an SSH remote.
func Init(ctx context.Context, l Layout, repin bool, sources *Sources, out io.Writer) error {
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
	if sources != nil {
		// Typed at the machine by its owner: validated for shape, not for policy.
		full, _ := EffectiveSources(sources, r.cfg.Updates)
		*sources = full
		p := UpdatesParams{Repo: sources.Repo, GitHubAPI: sources.GitHubAPI, SecondAPI: sources.SecondAPI}
		if release.GitProtocol(p.Repo) == "ssh" {
			p.KnownHosts = []string{KnownHost(sources.Repo) + " ssh-ed25519 " + strings.Repeat("A", 68)}
		}
		if err := p.validate(); err != nil {
			return err
		}
		b, err := json.Marshal(sources)
		if err != nil {
			return err
		}
		if err = writeOwned(l.sources(), append(b, '\n'), 0, 0, 0644); err != nil {
			return err
		}
		second := "none (GitHub only)"
		if sources.SecondAPI != "" {
			second = sources.SecondAPI
		}
		fmt.Fprintf(out, "release sources pinned: repository %s, GitHub %s, second source %s\n", sources.Repo, sources.GitHubAPI, second)
	}
	effective, _ := EffectiveSources(l.readSources(), r.cfg.Updates)
	if release.GitProtocol(effective.Repo) == "ssh" {
		if err := r.ensureDeployKey(ctx); err != nil {
			return err
		}
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
	if r.st.Runner.DeployKey != "" {
		fmt.Fprintf(out, "maintenance runner ready; deploy key: %s\n", r.st.Runner.DeployKey)
	} else {
		fmt.Fprintln(out, "maintenance runner ready")
	}
	return nil
}

// recover finishes or undoes a task whose runner died or was stopped (crash, reboot, unit
// stop). Each branch removes the journal only when the broker is in a consistent state and
// serving; otherwise the journal stays and the runner is started again.
func (r *Runner) recover(ctx context.Context, j journal) (string, error) {
	switch j.Task {
	case TaskCutover, TaskSeal, TaskBuckets, TaskUpdates:
	default:
		// Nothing this release knows how to finish: do not touch the broker.
		r.clearJournal()
		return "", errors.New("unknown interrupted task; inspect the machine")
	}
	// A broker that is up now (say after a reboot) may have served since the task was
	// interrupted: then an old backup is no longer safe to put back.
	served := r.l.active(ctx)
	_ = r.l.stop(ctx)
	f, err := r.l.facts(ctx)
	if err != nil {
		return "", errors.New("the database could not be checked; the runner keeps trying")
	}
	switch j.Task {
	case TaskCutover:
		if f.Schema >= 6 {
			if served {
				j.Backup = ""
			}
			return r.finishCutover(ctx, j.Backup)
		}
		return "", r.resume(ctx, errors.New("The cutover was interrupted before activation; nothing was changed."))
	case TaskSeal:
		if f.Schema == schemaBuckets {
			return r.finishSeal(ctx, j)
		}
		return "", r.unseal(ctx, j, errors.New("Sealing was interrupted before activation: the store is unchanged and unsealed."))
	case TaskBuckets:
		if f.Schema == schemaBuckets {
			return r.finishBuckets(ctx, j)
		}
		return "", r.unmigrate(ctx, j, errors.New("The move to buckets was interrupted before activation: the store is unchanged."))
	}
	// TaskUpdates. A missing copy means the task had already finished its switch.
	msg := "Enabling self-update was interrupted; the previous configuration was restored."
	if complete(j.Backup) != nil {
		msg = "Enabling self-update was interrupted at its very end; check the task and run it again if needed."
	} else if err := r.restoreConfig(j.Backup); err != nil {
		return "", err
	}
	r.tokens().rollback()
	if err := r.restart(ctx); err != nil {
		return "", errors.New("the broker did not come back yet; the runner keeps trying")
	}
	r.clearJournal()
	_ = os.RemoveAll(j.Backup)
	return "", errors.New(msg)
}
