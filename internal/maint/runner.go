package maint

import (
	"context"
	"crypto/hpke"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Runner executes at most one request per start. systemd (or the test harness) starts it
// when a request, an interrupted task's journal or an interrupted upgrade exists.
type Runner struct {
	l    Layout
	log  *slog.Logger
	now  func() time.Time
	st   Status
	cfg  *config.Config
	raw  []byte // configuration text as loaded
	key  hpke.PrivateKey
	poll time.Duration
	// Waits for the owner. Tests shorten them.
	CutoverWait, SealWait time.Duration
}

// journal survives a crash or reboot in the middle of a task. It holds no secrets.
type journal struct {
	Task      string `json:"task"`
	Backup    string `json:"backup"`
	Purge     bool   `json:"purge_backups,omitempty"`
	LockAlert bool   `json:"lock_alert,omitempty"`
	Started   string `json:"started_at"`
}

// New prepares a runner. Production layouts require root and the unit's fixed spool/cache.
func New(l Layout, log *slog.Logger) (*Runner, error) {
	if !l.test && os.Geteuid() != 0 {
		return nil, errors.New("the maintenance runner must run as root")
	}
	if l.test && os.Geteuid() == 0 {
		return nil, errors.New("test layout is not available to root")
	}
	r := &Runner{l: l, log: log, now: time.Now, poll: time.Second, CutoverWait: 20 * time.Minute, SealWait: 30 * time.Minute}
	if l.test {
		r.poll = 100 * time.Millisecond
	}
	if err := r.loadConfig(); err != nil {
		return nil, err
	}
	if r.cfg.Updates.Spool() != l.Spool || r.cfg.Updates.Cache() != l.Cache {
		return nil, errors.New("configuration relocates the spool or cache; the runner uses its fixed paths")
	}
	return r, nil
}

func (r *Runner) loadConfig() error {
	b, err := os.ReadFile(r.l.Config)
	if err != nil {
		return err
	}
	cfg, err := config.Parse(b)
	if err != nil {
		return err
	}
	r.raw, r.cfg = b, cfg
	return nil
}

func (r *Runner) readPins() ([]KeyPin, error) {
	var pins []KeyPin
	b, err := os.ReadFile(r.l.pins())
	if err != nil {
		return nil, errors.New("no pinned maintenance passkeys")
	}
	if json.Unmarshal(b, &pins) != nil {
		return nil, errors.New("invalid pin file")
	}
	return pins, nil
}

func (r *Runner) refreshInfo() {
	r.st.Runner.Version = release.Version
	r.st.Runner.Pins = []string{}
	if pins, err := r.readPins(); err == nil {
		for _, p := range pins {
			r.st.Runner.Pins = append(r.st.Runner.Pins, base64.RawURLEncoding.EncodeToString(p.ID))
		}
	}
	r.st.Runner.SecretsKey = ""
	if b, err := os.ReadFile(r.l.key()); err == nil {
		if k, err := LoadKey(b); err == nil {
			r.key, r.st.Runner.SecretsKey = k, PublicKey(k)
		}
	}
	r.st.Runner.DeployKey = readDeployKey(r.l)
}

// consume opens the request without following links, unlinks it, then reads the open file:
// whatever the spool's owner does next cannot change what was read.
func consume(path string) (Request, error) {
	var req Request
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = os.Remove(path)
		return req, err
	}
	defer f.Close()
	if err = os.Remove(path); err != nil {
		return req, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return req, errors.New("request is not a regular file")
	}
	b, err := release.ReadLimit(f, 64<<10)
	if err != nil {
		return req, err
	}
	if json.Unmarshal(b, &req) != nil {
		return req, errors.New("request is not valid JSON")
	}
	return req, nil
}

// spend records a challenge so the same signed request can never run twice.
func (r *Runner) spend(canonical string) error {
	dir := filepath.Join(r.l.State, "used")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, hex.EncodeToString(canon.Challenge(canonical))), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("this approval was already used")
	}
	err = f.Sync()
	if ce := f.Close(); err == nil {
		err = ce
	}
	return err
}

// Run handles one start: finish or undo an interrupted task, then at most one new request.
func (r *Runner) Run(ctx context.Context) error {
	if err := os.MkdirAll(r.l.State, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(r.l.State, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another maintenance run is active")
	}
	r.st = ReadStatus(r.l.status())
	r.st.Current = nil
	r.refreshInfo()
	r.save()

	var first error
	if j, ok := r.readJournal(); ok {
		r.begin(j.Task)
		r.step("Recovering a task that was interrupted")
		msg, err := r.recover(ctx, j)
		r.finish(err, msg)
		first = err
	}
	if _, err := os.Lstat(filepath.Join(r.l.State, "pending-rollback.json")); err == nil {
		r.begin(TaskUpgrade)
		r.step("Restoring the previous broker after an interrupted upgrade")
		err := r.runUpdater(ctx, "")
		r.finish(err, "Previous broker restored after an interrupted upgrade.")
		if first == nil {
			first = err
		}
	}
	if _, err := os.Lstat(r.l.request()); err != nil {
		return first
	}
	req, err := consume(r.l.request())
	if err != nil {
		return r.refuse(err)
	}
	pins, err := r.readPins()
	if err != nil {
		return r.refuse(err)
	}
	v, err := Verify(req, r.cfg.PublicBaseURL, pins, r.now())
	if err != nil {
		return r.refuse(err)
	}
	secrets, err := OpenSecrets(r.key, v.Task, v.Params, req.Secrets)
	if err != nil {
		return r.refuse(err)
	}
	defer func() {
		for k := range secrets {
			secrets[k] = ""
		}
	}()
	if err = r.spend(req.Canonical); err != nil {
		return r.refuse(err)
	}
	_ = os.Remove(r.l.cancel())
	r.st.Refused = nil
	r.begin(v.Task)
	done := "Done."
	switch p := v.Params.(type) {
	case CutoverParams:
		done, err = r.cutover(ctx)
	case SealParams:
		done, err = r.seal(ctx, p, secrets)
	case UpdatesParams:
		done, err = r.enableUpdates(ctx, p, secrets)
	case PinsParams:
		done, err = r.syncPins(ctx, p)
	default:
		done, err = r.upgrade(ctx, v.Signed)
	}
	r.refreshInfo()
	r.finish(err, done)
	return err
}

// refuse records why a request was not run. The text is fixed wording from this package.
func (r *Runner) refuse(err error) error {
	r.st.Refused = &Refusal{At: stamp(r.now()), Reason: clean(err.Error())}
	r.save()
	r.log.Error("request refused", "error", err)
	return err
}

func (r *Runner) writeJournal(j journal) error {
	j.Started = stamp(r.now())
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeAtomic(r.l.journal(), b, 0600)
}

func (r *Runner) readJournal() (journal, bool) {
	var j journal
	b, err := os.ReadFile(r.l.journal())
	if err != nil {
		return j, false
	}
	if json.Unmarshal(b, &j) != nil {
		j = journal{}
	}
	return j, true
}

func (r *Runner) clearJournal() {
	if err := os.Remove(r.l.journal()); err != nil && !os.IsNotExist(err) {
		r.log.Error("could not remove journal", "error", err)
	}
}

type outcome int

const (
	reached outcome = iota
	cancelled
	timedOut
	died
)

// await polls the broker's facts until done reports true, the owner cancels (aqmasd drops
// an unsigned marker: cancelling only ever returns to the previous state), the maintenance
// process exits, or the deadline passes.
func (r *Runner) await(ctx context.Context, deadline time.Time, done func(Facts) bool) outcome {
	for {
		if f, err := r.l.facts(ctx); err == nil && done(f) {
			return reached
		}
		if _, err := os.Lstat(r.l.cancel()); err == nil {
			_ = os.Remove(r.l.cancel())
			return cancelled
		}
		if !r.l.active(ctx) {
			// The process may have exited right after committing.
			if f, err := r.l.facts(ctx); err == nil && done(f) {
				return reached
			}
			return died
		}
		if !r.now().Before(deadline) || ctx.Err() != nil {
			return timedOut
		}
		time.Sleep(r.poll)
	}
}

func (o outcome) reason() string {
	switch o {
	case cancelled:
		return "cancelled"
	case timedOut:
		return "not completed in time"
	}
	return "the maintenance process stopped unexpectedly"
}

// serviceIDs returns the broker account's ids (the current user in a test layout).
func (l Layout) serviceIDs() (int, int, error) {
	if l.test {
		return os.Getuid(), os.Getgid(), nil
	}
	u, err := user.Lookup(l.User)
	if err != nil {
		return 0, 0, err
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(u.Gid)
	if e1 != nil || e2 != nil || uid == 0 {
		return 0, 0, errors.New("unexpected service account")
	}
	return uid, gid, nil
}

// replaceFile atomically replaces a root-owned file, keeping its owner and mode.
func replaceFile(path string, data []byte) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chown(int(sys.Uid), int(sys.Gid))
	}
	if err == nil {
		err = f.Chmod(st.Mode().Perm())
	}
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// writeOwned creates or replaces a small file with the given owner and mode.
func writeOwned(path string, data []byte, uid, gid int, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil && os.Geteuid() == 0 {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func copyFile(dst, src string, limit int64, mode os.FileMode) error {
	in, err := os.OpenFile(src, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	b, err := release.ReadLimit(in, limit)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}
