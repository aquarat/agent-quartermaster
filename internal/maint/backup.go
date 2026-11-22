package maint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// backup copies the stopped broker's state, configuration and unit to a new root-only
// directory. Until sealing, that copy contains the private CA keys.
func (r *Runner) backup(ctx context.Context, label string) (string, error) {
	if err := os.MkdirAll(r.l.Backups, 0700); err != nil {
		return "", err
	}
	dir := filepath.Join(r.l.Backups, r.now().UTC().Format("20060102T150405.000000000Z")+"-"+label)
	if err := os.Mkdir(dir, 0700); err != nil {
		return "", err
	}
	if err := r.l.run(ctx, "cp", "-a", "--reflink=auto", "--", r.cfg.DataDir, filepath.Join(dir, "state")); err != nil {
		return "", err
	}
	if err := r.l.run(ctx, "cp", "-a", "--", r.l.ConfigDir, filepath.Join(dir, "config")); err != nil {
		return "", err
	}
	for name, src := range map[string]string{"unit": r.l.unit(), "unit.d": r.l.unit() + ".d"} {
		if _, err := os.Lstat(src); err == nil {
			if err := r.l.run(ctx, "cp", "-a", "--", src, filepath.Join(dir, name)); err != nil {
				return "", err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "complete"), nil, 0600); err != nil {
		return "", err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return dir, nil
}

func complete(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, "complete")); err != nil {
		return errors.New("backup is missing or incomplete")
	}
	return nil
}

// restoreConfig puts back the configuration file from a backup.
func (r *Runner) restoreConfig(dir string) error {
	if err := complete(dir); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(dir, "config", filepath.Base(r.l.Config)))
	if err != nil {
		return err
	}
	if err = replaceFile(r.l.Config, b); err != nil {
		return err
	}
	return r.loadConfig()
}

// restoreAll puts back state and configuration. The displaced state is kept beside the data
// directory (same filesystem, so the swap is a rename), never deleted. The broker must be
// stopped.
func (r *Runner) restoreAll(ctx context.Context, dir string) error {
	if err := complete(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(r.cfg.DataDir); err == nil {
		aside := r.cfg.DataDir + ".displaced-" + r.now().UTC().Format("20060102T150405.000000000Z")
		if err = os.Rename(r.cfg.DataDir, aside); err != nil {
			return err
		}
		r.result("displaced_state", aside)
	}
	if err := r.l.run(ctx, "cp", "-a", "--reflink=auto", "--", filepath.Join(dir, "state"), r.cfg.DataDir); err != nil {
		return err
	}
	return r.restoreConfig(dir)
}
