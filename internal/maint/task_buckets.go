package maint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// schemaBuckets is the database schema of a store sealed in per-credential buckets.
const schemaBuckets = 9

// buckets moves a format-1 sealed store (schema 8, v0.4.1) to per-credential buckets
// (docs/BUCKETS.md §8). The owner's taps, the recovery drill and the activation signature
// happen in the browser against the bucket-migrate broker; this only fences, backs up,
// waits and finishes. One-way: after activation it only moves forward.
func (r *Runner) buckets(ctx context.Context, p BucketsParams) (string, error) {
	f, err := r.l.facts(ctx)
	if err != nil {
		return "", err
	}
	if f.Schema == schemaBuckets {
		return "", errors.New("this store already uses per-credential buckets")
	}
	if f.Schema != 8 || !r.cfg.Seal.Required || !release.ValidHash(r.cfg.Seal.Manifest) || f.Manifest != r.cfg.Seal.Manifest {
		return "", errors.New("only a store sealed by aqmas 0.4.1 (format 1, pinned) can be moved")
	}
	if err = r.l.healthy(ctx, r.cfg.ListenWeb); err != nil {
		return "", errors.New("the broker is not healthy; fix that first")
	}
	// The journal comes first: from here on a crash or a stop is recovered by the next start.
	j := journal{Task: TaskBuckets, Purge: p.PurgeBackups}
	if err = r.writeJournal(j); err != nil {
		return "", err
	}
	r.step("Stopping the broker")
	if err = r.l.stop(ctx); err != nil {
		return "", r.unmigrate(ctx, j, err)
	}
	r.step("Backing up the database, keys and configuration")
	if j.Backup, err = r.backup(ctx, "buckets"); err != nil {
		return "", r.unmigrate(ctx, j, err)
	}
	if err = r.writeJournal(j); err != nil {
		return "", r.unmigrate(ctx, j, err)
	}
	r.step("Starting the broker in migration mode")
	if err = r.l.start(ctx, "bucket-migrate"); err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err != nil {
		return "", r.unmigrate(ctx, j, errors.New("the migration mode did not start"))
	}
	deadline := r.now().Add(r.SealWait)
	r.wait("bucket-migrate", "Waiting for you: open the old store, create and test your passkey's scope keys, prove the recovery key, then activate", deadline)
	switch o := r.await(ctx, deadline, func(f Facts) bool { return f.Schema == schemaBuckets }); o {
	case reached:
	case interrupted:
		return "", errInterrupted
	default:
		return "", r.unmigrate(ctx, j, errors.New("The move to buckets "+o.reason()+": the store is unchanged."))
	}
	time.Sleep(2 * r.poll)
	return r.finishBuckets(ctx, j)
}

// unmigrate returns to the format-1 broker after a failure before activation. If the
// database cannot be read it changes nothing and leaves the journal for another try; if the
// activation did commit, the only direction is forward.
func (r *Runner) unmigrate(ctx context.Context, j journal, cause error) error {
	r.step("Not activated: returning to the previous store")
	_ = r.l.stop(ctx)
	f, err := r.l.facts(ctx)
	if err != nil {
		return errors.New(cause.Error() + " The database could not be checked, so nothing was undone yet; the runner keeps trying.")
	}
	if f.Schema == schemaBuckets {
		_, err := r.finishBuckets(ctx, j)
		return err
	}
	if j.Backup != "" {
		if err := r.restoreConfig(j.Backup); err != nil {
			return errors.New(cause.Error() + " URGENT: the configuration could not be restored; the broker is stopped.")
		}
	}
	r.removeStages()
	err = r.l.start(ctx, "serve")
	if err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err != nil {
		return errors.New(cause.Error() + " The broker did not come back yet; the runner keeps trying.")
	}
	r.clearJournal()
	return cause
}

// finishBuckets is everything after the signed activation. It only moves forward and can be
// repeated: the journal stays until the broker serves the new store.
func (r *Runner) finishBuckets(ctx context.Context, j journal) (string, error) {
	fail := func(err error) (string, error) {
		return "", errors.New("Activated, but finishing failed (" + err.Error() + "). The runner retries by itself.")
	}
	r.step("Activated. Checking the signed activation")
	_ = r.l.stop(ctx)
	f, err := r.l.facts(ctx)
	if err != nil {
		return fail(err)
	}
	if f.Schema != schemaBuckets || !release.ValidHash(f.Manifest) {
		return fail(errors.New("activation record is missing"))
	}
	if err = r.loadConfig(); err != nil {
		return fail(err)
	}
	pins, err := r.readPins()
	if err == nil {
		err = verifyActivation(f, r.cfg.Seal.Recipient, r.cfg.PublicBaseURL, pins)
	}
	if err != nil {
		return fail(err)
	}
	if r.cfg.Seal.Manifest != f.Manifest {
		r.step("Pinning the new activation in the configuration")
		pinned, err := repinSeal(r.raw, r.cfg.Seal.Manifest, f.Manifest)
		if err == nil {
			err = replaceFile(r.l.Config, pinned)
		}
		if err == nil {
			err = r.loadConfig()
		}
		if err != nil {
			return fail(err)
		}
	}
	r.result("manifest_sha256", f.Manifest)
	keep := "sealed-" + f.Manifest[:16]
	for _, stage := range r.stageDirs() {
		dir := filepath.Join(r.l.Backups, keep)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fail(err)
		}
		b, err := readRooted(r.cfg.DataDir, filepath.Join(stage, "manifest.json"), 1<<20)
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600)
		}
		if err != nil && !os.IsNotExist(err) {
			r.result("manifest_note", "manifest.json could not be copied; the database holds it")
		}
	}
	r.removeStages()
	r.step("Starting the broker (every bucket closed)")
	if err = r.l.start(ctx, "serve"); err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err != nil {
		return fail(errors.New("the broker did not start"))
	}
	if j.Purge {
		// They hold format-1 data: anyone with a copy and one tap for an old salt gets the MK.
		r.step("Deleting the format-1 backups of this store")
		n, err := r.purgeFormat1(j.Backup, keep)
		if err != nil {
			r.result("format1_backups", "nothing was deleted ("+err.Error()+"): delete the format-1 copies in "+r.l.Backups+" yourself")
		}
		r.result("backups_deleted", strconv.Itoa(n))
		if aside, _ := filepath.Glob(r.cfg.DataDir + ".displaced-*"); len(aside) > 0 {
			r.result("displaced_kept", "state set aside by an earlier restore is kept beside the data directory; delete it once you no longer need it")
		}
	} else {
		r.result("format1_backups", r.l.Backups+" still holds format-1 copies of the store: delete them once you have checked the new one")
	}
	r.clearJournal()
	return "Moved to per-credential buckets. Nothing is open: each approval opens only the credentials it needs.", nil
}

// purgeFormat1 deletes only the backups of this store in format 1: those whose
// configuration pins the same format-1 manifest as the pre-migration backup
// (pre) of this task. Other backups (unsealed copies, rollback points of other
// tasks taken after the move, the new manifest copy keep) and state that a
// restore set aside beside the data directory are kept: they are other tasks'
// rollback points, and the owner decides about them (docs/SETUP.md).
func (r *Runner) purgeFormat1(pre, keep string) (int, error) {
	pin := func(dir string) string {
		b, err := readRooted(dir, filepath.Join("config", filepath.Base(r.l.Config)), 1<<20)
		if err != nil {
			return ""
		}
		cfg, err := config.Parse(b)
		if err != nil || !cfg.Seal.Required || !release.ValidHash(cfg.Seal.Manifest) {
			return ""
		}
		return cfg.Seal.Manifest
	}
	if pre == "" || complete(pre) != nil {
		return 0, errors.New("the pre-migration backup is missing")
	}
	old := pin(pre)
	if old == "" || old == r.cfg.Seal.Manifest {
		return 0, errors.New("the pre-migration backup names no format-1 pin")
	}
	entries, err := os.ReadDir(r.l.Backups)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		dir := filepath.Join(r.l.Backups, e.Name())
		if e.Name() == keep || !e.IsDir() || pin(dir) != old {
			continue
		}
		if os.RemoveAll(dir) == nil {
			n++
		}
	}
	return n, nil
}
