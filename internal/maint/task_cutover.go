package maint

import (
	"context"
	"errors"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// cutover runs the supervised organisations cutover: one approval starts it, and the owner
// then signs the activation itself against the plan and recovery point in fenced mode.
func (r *Runner) cutover(ctx context.Context) (string, error) {
	f, err := r.l.facts(ctx)
	if err != nil {
		return "", err
	}
	if f.Schema != 5 {
		return "", errors.New("this broker already uses organisations")
	}
	if r.cfg.Seal != (config.Seal{}) {
		return "", errors.New("the configuration has a [seal] section; the cutover needs an unsealed legacy broker")
	}
	if err = r.l.healthy(ctx, r.cfg.ListenWeb); err != nil {
		return "", errors.New("the broker is not healthy; fix that first")
	}
	r.step("Stopping the broker")
	if err = r.l.stop(ctx); err != nil {
		return "", r.resume(ctx, err)
	}
	r.step("Backing up the database, keys and configuration")
	dir, err := r.backup(ctx, "cutover")
	if err != nil {
		return "", r.resume(ctx, err)
	}
	r.result("backup", dir)
	if err = r.writeJournal(journal{Task: TaskCutover, Backup: dir}); err != nil {
		return "", r.resume(ctx, err)
	}
	defer r.clearJournal()
	r.step("Starting the broker fenced for review")
	if err = r.l.start(ctx, "organisations-cutover"); err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err != nil {
		return "", r.resume(ctx, errors.New("the fenced review mode did not start"))
	}
	deadline := r.now().Add(r.CutoverWait)
	r.wait("activation", "Waiting for you to review the plan and activate it", deadline)
	if o := r.await(ctx, deadline, func(f Facts) bool { return f.Schema >= 6 }); o != reached {
		return "", r.resume(ctx, errors.New("Cutover "+o.reason()+": nothing was changed."))
	}
	time.Sleep(2 * r.poll) // let the activation response reach the browser
	return r.finishCutover(ctx, dir)
}

// resume returns to normal serving after a failure before activation.
func (r *Runner) resume(ctx context.Context, cause error) error {
	r.step("Returning the broker to normal service")
	_ = r.l.stop(ctx)
	err := r.l.start(ctx, "serve")
	if err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err != nil {
		return errors.New(cause.Error() + " URGENT: the broker did not come back; check it on the machine.")
	}
	return cause
}

func (r *Runner) finishCutover(ctx context.Context, backup string) (string, error) {
	r.step("Activated. Restarting the broker")
	err := r.l.stop(ctx)
	if err == nil {
		err = r.l.start(ctx, "serve")
	}
	if err == nil {
		err = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if err == nil {
		var f Facts
		if f, err = r.l.facts(ctx); err == nil && f.Schema < 6 {
			err = errors.New("activation is missing")
		}
	}
	if err == nil {
		return "Organisations are active. Your hosts are in the personal organisation.", nil
	}
	// Nothing was served since the backup: restoring it loses no approval or revocation.
	r.step("The broker is unhealthy after activation: restoring the backup")
	_ = r.l.stop(ctx)
	rerr := r.restoreAll(ctx, backup)
	if rerr == nil {
		rerr = r.l.start(ctx, "serve")
	}
	if rerr == nil {
		rerr = r.l.healthy(ctx, r.cfg.ListenWeb)
	}
	if rerr != nil {
		return "", errors.New("URGENT: the broker is unhealthy after the cutover and restoring the backup failed; see the backup directory on the machine.")
	}
	return "", errors.New("The broker was unhealthy after the cutover. The backup was restored and the legacy broker is serving again.")
}
