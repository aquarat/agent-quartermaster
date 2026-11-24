package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// Sessions on the bastion itself and routine maintenance queued for the owner
// (docs/BASTION-ACCESS.md §4, §7, §9). Inspect behaves like any SSH grant: cached and reused.
// Root is the opposite on purpose: nothing is cached, the key and certificate live in a
// private temporary directory for one ssh and are deleted when it exits.

// BastionInspectUser is the bastion's read-only account (the server's constant; used here
// only to find a cached inspect certificate while the server is unreachable).
const BastionInspectUser = "aqmas-inspect"

// InspectHelp lists what the forced command accepts.
const InspectHelp = `inspect commands (after --): help | logs <unit> [since=<n><m|h|d>] [lines=<n>] | status [<unit>] | failed | disk | version
units: aqmasd maint cloudflared firewall lock-alert sshd kernel`

// BastionTasks are the maintenance tasks a host may queue (aqmas bastion task ...).
var BastionTasks = []string{"os-update", "reboot", "restart-cloudflared", "restart-broker", "disk-usage", "journal-vacuum"}

const (
	// MinKeepDays is the server's floor for a queued journal trim.
	MinKeepDays     = 7
	DefaultKeepDays = 14
	rootTempPrefix  = ".bastion-root-"
)

var inspectCommandRE = regexp.MustCompile(`^[A-Za-z0-9 ._=-]*$`)

// Bastion levels, as the server names them.
const (
	LevelInspect = api.LevelInspect
	LevelRoot    = api.LevelRoot
)

// BastionOptions are the flags of `aqmas ssh bastion`.
type BastionOptions struct {
	Host string // the name the user typed
	// User is the user part of the target when one was typed ("" otherwise): it must be the
	// level's own account. The server derives the login user from the level.
	User    string
	Level   string // inspect (default) or root
	TTL     time.Duration
	Why     string
	Fresh   bool
	Command []string
}

func checkWhy(why string) (string, error) {
	why = strings.TrimSpace(why)
	if why == "" {
		return "", &UsageError{Msg: "--why \"...\" is required (say what you need on the bastion)"}
	}
	if len(why) > MaxReasonLen {
		return "", &UsageError{Msg: fmt.Sprintf("--why is longer than %d bytes", MaxReasonLen)}
	}
	if !utf8.ValidString(why) || sanitize(why) != why {
		return "", &UsageError{Msg: "--why must be plain single-line text"}
	}
	return why, nil
}

// InspectCommand joins and validates the words after "--" for the bastion's forced command;
// none means "help".
func InspectCommand(words []string) (string, error) {
	cmd := strings.Join(words, " ")
	if strings.TrimSpace(cmd) == "" {
		return "help", nil
	}
	// The bastion decides; this only spares the owner a card for something it would refuse.
	verb := strings.Fields(cmd)[0]
	if len(cmd) > 200 || !inspectCommandRE.MatchString(cmd) || !slices.Contains([]string{"help", "logs", "status", "failed", "disk", "version"}, verb) {
		return "", &UsageError{Msg: "not an inspect command (letters, digits, space and ._=- only, at most 200 bytes)\n" + InspectHelp}
	}
	return cmd, nil
}

func validBastionInfo(info *api.BastionInfo) error {
	if !hostNameRE.MatchString(info.Name) || validateEndpoint(info.Address, info.Port) != nil || !loginUserRE.MatchString(info.InspectUser) || !loginUserRE.MatchString(info.AdminUser) {
		return errors.New("server sent an invalid description of the bastion")
	}
	return nil
}

// IsBastion reports whether host is the name under which the server offers the bastion
// itself. Any failure (not installed, old server, unreachable) is "no".
func (e *Env) IsBastion(ctx context.Context, host string) bool {
	_, c, err := e.authedClient()
	if err != nil {
		return false
	}
	info, err := c.BastionInfo(ctx)
	return err == nil && validBastionInfo(info) == nil && info.Name == host
}

// NotATarget reports the errors with which the server says "no SSH target of that name":
// the cue to ask whether the name is the bastion's.
func NotATarget(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.HTTPStatus == 404 || ae.HTTPStatus == 400) && !NotAdmitted(err)
}

func bastionLevel(o BastionOptions) (string, error) {
	switch o.Level {
	case "", api.LevelInspect:
		return api.LevelInspect, nil
	case api.LevelRoot:
		return api.LevelRoot, nil
	}
	return "", &UsageError{Msg: "--level is inspect or root"}
}

// bastionStart does what both levels share before a request: flags, the server's description
// of the bastion and the name and user checks.
func (e *Env) bastionStart(ctx context.Context, o BastionOptions) (level, why string, cfg *Config, c *APIClient, info *api.BastionInfo, err error) {
	if level, err = bastionLevel(o); err != nil {
		return
	}
	if why, err = checkWhy(o.Why); err != nil {
		return
	}
	if cfg, c, err = e.authedClient(); err != nil {
		return
	}
	if info, err = c.BastionInfo(ctx); err != nil {
		if plainNotFound(err) {
			err = errors.New("access to the bastion is not installed on this aqmasd (the owner installs it under Settings → Bastion access)")
		}
		return
	}
	if err = validBastionInfo(info); err != nil {
		return
	}
	if o.Host != info.Name {
		err = &UsageError{Msg: fmt.Sprintf("--level is for the bastion itself, which this aqmasd calls %q", info.Name)}
		return
	}
	want := info.InspectUser
	if level == api.LevelRoot {
		want = info.AdminUser
	}
	if o.User != "" && o.User != want {
		err = &UsageError{Msg: fmt.Sprintf("level %s logs in as %s; leave the user out", level, want)}
	}
	return
}

// requestBastion creates the request, waits for the owner and returns the approved status
// with the ephemeral key. Ctrl-C withdraws the request.
func (e *Env) requestBastion(ctx context.Context, cfg *Config, c *APIClient, info *api.BastionInfo, level, why string, ttl time.Duration) (*api.RequestCreated, *api.RequestStatus, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, nil, err
	}
	req := &api.BastionRequest{Level: level, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), Reason: why,
		TTLSeconds: int(ttl / time.Second), Requester: e.Requester()}
	created, err := c.CreateBastionRequest(ctx, req)
	if err != nil {
		return nil, nil, nil, err
	}
	if !safeID(created.ID) {
		return nil, nil, nil, fmt.Errorf("server returned an invalid request id %q", sanitize(created.ID))
	}
	e.logf("request %s (Ref %s): bastion %s (%s) for %s by %s on %s: %s", created.ID, RefCode(created.ID), level, info.Name, ttl, req.Requester.Tool, cfg.HostName, why)
	if created.Status == api.StatusPending {
		e.logf("approve at: %s  (waiting; Ctrl-C cancels)", sanitize(created.ApproveURL))
	}
	st, err := e.waitRequestWith(ctx, created, c.BastionRequestStatus)
	if err != nil {
		if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) {
			e.cancelBastion(c, created)
		}
		return nil, nil, nil, err
	}
	if st.Grant == nil || st.Grant.SSH == nil || st.Grant.SSH.TargetAddress != info.Address || st.Grant.SSH.TargetPort != info.Port {
		return nil, nil, nil, errors.New("grant does not match the bastion's address")
	}
	return created, st, priv, nil
}

func (e *Env) cancelBastion(c *APIClient, created *api.RequestCreated) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.CancelBastionRequest(ctx, created.ID)
	switch {
	case err == nil && st.Status == api.StatusCancelled:
		e.logf("cancelled request %s (the key was not saved)", created.ID)
	case err == nil:
		e.logf("request %s is already %s; nothing to cancel", created.ID, sanitize(st.Status))
	default:
		e.logf("could not cancel request %s (%v); it stays pending until %s", created.ID, err, created.ExpiresAt.Local().Format("15:04:05"))
	}
}

func (e *Env) sshCA(ctx context.Context, c *APIClient) (ssh.PublicKey, error) {
	ca, err := c.SSHCA(ctx)
	if err != nil {
		e.logf("warning: could not fetch the SSH CA to check the certificate's signer: %v", err)
		return nil, nil
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("server sent an unreadable SSH CA key: %w", err)
	}
	return key, nil
}

// EnsureBastionInspect returns a key and certificate for the bastion's inspect account,
// reusing a cached one the server still approves or asking the owner for a new one.
func (e *Env) EnsureBastionInspect(ctx context.Context, o BastionOptions) (*Prepared, error) {
	if level, err := bastionLevel(o); err != nil {
		return nil, err
	} else if level != api.LevelInspect {
		return nil, &UsageError{Msg: "a root session on the bastion is never cached: use aqmas ssh"}
	}
	_, why, cfg, c, info, err := e.bastionStart(ctx, o)
	if err != nil {
		// aqmasd down is exactly when its logs are wanted: a cached certificate still works.
		var offline *UnreachableError
		if !errors.As(err, &offline) || o.Fresh || !hostNameRE.MatchString(o.Host) {
			return nil, err
		}
		t := Target{User: BastionInspectUser, Host: o.Host}
		dir, derr := e.targetDir(t)
		if derr != nil {
			return nil, err
		}
		p, lerr := e.loadCached(dir, t)
		if lerr != nil {
			return nil, err
		}
		e.logf("warning: cannot reach the server (%v); using the cached inspect certificate %s", err, p.Grant.GrantID)
		return p, nil
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = time.Duration(info.InspectDefault) * time.Second
	}
	if ttl < time.Minute || int(ttl/time.Second) > info.InspectMaxSeconds {
		return nil, &UsageError{Msg: fmt.Sprintf("--ttl must be between 1m and %ds", info.InspectMaxSeconds)}
	}
	t := Target{User: info.InspectUser, Host: info.Name}
	dir, err := e.targetDir(t)
	if err != nil {
		return nil, err
	}
	unlock, err := e.lockDir(ctx.Done(), dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if !o.Fresh {
		if p, err := e.loadCached(dir, t); err == nil && p.Grant.TargetAddress == info.Address && p.Grant.TargetPort == info.Port && e.bastionStillGranted(ctx, c, p) {
			e.logf("reusing grant %s for %s, valid until %s", p.Grant.GrantID, t, p.ValidBefore.Local().Format("15:04:05"))
			return p, nil
		}
	}
	created, st, priv, err := e.requestBastion(ctx, cfg, c, info, api.LevelInspect, why, ttl)
	if err != nil {
		return nil, err
	}
	caKey, err := e.sshCA(ctx, c)
	if err != nil {
		return nil, err
	}
	p, err := e.storeGrant(dir, t, created.ID, priv, st.Grant, caKey)
	if err != nil {
		return nil, err
	}
	e.logf("approved: grant %s valid until %s", p.Grant.GrantID, p.ValidBefore.Local().Format("15:04:05"))
	return p, nil
}

// bastionStillGranted is stillGranted against the bastion's own status endpoint.
func (e *Env) bastionStillGranted(ctx context.Context, c *APIClient, p *Prepared) bool {
	if p.Grant.RequestID == "" {
		return false
	}
	st, err := c.BastionRequestStatus(ctx, p.Grant.RequestID, 0)
	if err != nil {
		var ue *UnreachableError
		if errors.As(err, &ue) {
			e.logf("warning: cannot check grant %s with the server (%v); using the cached certificate", p.Grant.GrantID, err)
			return true
		}
		e.logf("cached grant %s not confirmed by the server (%v); requesting a new one", p.Grant.GrantID, err)
		return false
	}
	if st.Status != api.StatusApproved {
		e.logf("cached grant %s is %s on the server; requesting a new one", p.Grant.GrantID, sanitize(st.Status))
		return false
	}
	return true
}

// BuildInspectArgv is the ssh argv of an inspect session: no terminal (the certificate
// permits none) and the inspect command as the remote command.
func BuildInspectArgv(p *Prepared, words []string) ([]string, error) {
	cmd, err := InspectCommand(words)
	if err != nil {
		return nil, err
	}
	argv, err := BuildSSHArgv(p, []string{cmd})
	if err != nil {
		return nil, err
	}
	return append([]string{argv[0], "-T"}, argv[1:]...), nil
}

// RunSSH runs argv as a child and returns its exit status.
type RunSSH func(argv []string) (int, error)

// RunChild is the real RunSSH: ssh on this terminal, as a child, so the caller can clean up
// when it exits. Interrupts go to ssh (the terminal sends them to both); termination and
// hang-up are passed on.
func RunChild(argv []string) (int, error) {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sig)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sig:
				if s != os.Interrupt {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	err = cmd.Wait()
	close(done)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code, nil
		}
		return 255, nil // killed by a signal
	}
	return 0, err
}

// BastionRoot asks for a root session on the bastion and runs one ssh with it. Nothing
// touches the certificate cache: key, certificate and known_hosts are written to a fresh
// private directory that is removed when ssh has exited or anything fails. The returned
// code is ssh's own.
func (e *Env) BastionRoot(ctx context.Context, o BastionOptions, run RunSSH) (int, error) {
	o.Level = api.LevelRoot
	_, why, cfg, c, info, err := e.bastionStart(ctx, o)
	if err != nil {
		return 0, err
	}
	if o.TTL != 0 && (o.TTL < time.Minute || int(o.TTL/time.Second) > info.RootMaxSeconds) {
		return 0, &UsageError{Msg: fmt.Sprintf("--ttl for a root session is between 1m and %ds", info.RootMaxSeconds)}
	}
	if !info.RootAllowed {
		return 0, errors.New("this host (at this address) may not ask for root on the bastion; the owner sets who may under Settings → Bastion access")
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = min(30*time.Minute, time.Duration(info.RootMaxSeconds)*time.Second)
	}
	e.logf("This asks for ROOT on the bastion; the owner will see a red card.")
	created, st, priv, err := e.requestBastion(ctx, cfg, c, info, api.LevelRoot, why, ttl)
	if err != nil {
		return 0, err
	}
	if st.Grant.SSH.Certificate == "" {
		note := st.DecisionNote
		if note == "" {
			note = "the server sent no certificate"
		}
		return 0, fmt.Errorf("root session approved, but %s; ask again", sanitize(note))
	}
	caKey, err := e.sshCA(ctx, c)
	if err != nil {
		return 0, err
	}
	if err := ensurePrivateDir(e.Paths.CacheDir); err != nil {
		return 0, err
	}
	e.sweepRootTemp()
	tmp, err := os.MkdirTemp(e.Paths.CacheDir, rootTempPrefix)
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return 0, err
	}
	p, err := e.storeGrant(tmp, Target{User: info.AdminUser, Host: info.Name}, created.ID, priv, st.Grant, caKey)
	if err != nil {
		return 0, err
	}
	argv, err := BuildSSHArgv(p, o.Command)
	if err != nil {
		return 0, err
	}
	e.logf("approved: ROOT session on %s as %s; the certificate is valid until %s and is not kept", info.Name, info.AdminUser, p.ValidBefore.Local().Format("15:04:05"))
	return run(argv)
}

// sweepRootTemp removes directories a killed root run left behind (their certificates are
// long expired: a root certificate lives an hour at most).
func (e *Env) sweepRootTemp() {
	ents, err := os.ReadDir(e.Paths.CacheDir)
	if err != nil {
		return
	}
	for _, ent := range ents {
		if !ent.IsDir() || !strings.HasPrefix(ent.Name(), rootTempPrefix) {
			continue
		}
		if fi, err := ent.Info(); err == nil && e.now().Sub(fi.ModTime()) > 65*time.Minute {
			os.RemoveAll(filepath.Join(e.Paths.CacheDir, ent.Name()))
		}
	}
}

// BastionShow runs `aqmas bastion`: what this host may ask for.
func (e *Env) BastionShow(ctx context.Context) error {
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	info, err := c.BastionInfo(ctx)
	if err != nil {
		if plainNotFound(err) {
			fmt.Fprintln(e.Stdout, "bastion      access to the bastion is not installed on this aqmasd")
			fmt.Fprintf(e.Stdout, "tasks        %s (aqmas bastion task NAME --why \"...\")\n", strings.Join(BastionTasks, " "))
			return nil
		}
		return err
	}
	if err := validBastionInfo(info); err != nil {
		return err
	}
	w := e.Stdout
	fmt.Fprintf(w, "bastion      %s (%s port %d)\n", info.Name, info.Address, info.Port)
	fmt.Fprintf(w, "inspect      as %s, read-only commands, up to %s (default %s): aqmas ssh %s --why \"...\" -- logs aqmasd\n",
		info.InspectUser, time.Duration(info.InspectMaxSeconds)*time.Second, time.Duration(info.InspectDefault)*time.Second, info.Name)
	root := "NOT allowed from this host (the owner sets who may ask under Settings → Bastion access)"
	if info.RootAllowed {
		root = fmt.Sprintf("allowed from this host, up to %s, red card every time: aqmas ssh %s --level root --why \"...\"", time.Duration(info.RootMaxSeconds)*time.Second, info.Name)
	}
	fmt.Fprintf(w, "root         as %s: %s\n", info.AdminUser, root)
	tasks := make([]string, 0, len(info.Tasks))
	for _, t := range info.Tasks {
		tasks = append(tasks, sanitize(t))
	}
	fmt.Fprintf(w, "tasks        %s (aqmas bastion task NAME --why \"...\")\n", strings.Join(tasks, " "))
	return nil
}

// TaskOptions are the flags of `aqmas bastion task`.
type TaskOptions struct {
	Task     string
	Why      string
	KeepDays int // journal-vacuum; 0 = DefaultKeepDays
}

// TaskError is a queued task that ran and failed, or that the runner refused.
type TaskError struct {
	Task, State, Message string
}

func (e *TaskError) Error() string {
	s := fmt.Sprintf("task %s %s", e.Task, e.State)
	if e.Message != "" {
		s += ": " + sanitize(e.Message)
	}
	return s
}

func taskParams(o TaskOptions) (json.RawMessage, error) {
	if !slices.Contains(BastionTasks, o.Task) {
		return nil, &UsageError{Msg: fmt.Sprintf("unknown task %q; tasks: %s", o.Task, strings.Join(BastionTasks, ", "))}
	}
	if o.KeepDays != 0 && o.Task != "journal-vacuum" {
		return nil, &UsageError{Msg: "--keep-days belongs to journal-vacuum"}
	}
	switch o.Task {
	case "os-update":
		// Kernel and boot-chain updates are the owner's to start, on the approval page.
		return json.RawMessage(`{"kernel":false}`), nil
	case "journal-vacuum":
		days := o.KeepDays
		if days == 0 {
			days = DefaultKeepDays
		}
		if days < MinKeepDays || days > 365 {
			return nil, &UsageError{Msg: fmt.Sprintf("--keep-days is between %d and 365: a queued journal trim keeps at least the last week (the owner can trim further on the approval page)", MinKeepDays)}
		}
		return json.RawMessage(fmt.Sprintf(`{"keep_days":%d}`, days)), nil
	}
	return json.RawMessage(`{}`), nil
}

// BastionTask queues a routine maintenance task, waits for the owner's decision and then
// follows the runner. Progress goes to stderr, the results (key: value, sorted) to stdout.
func (e *Env) BastionTask(ctx context.Context, o TaskOptions) error {
	params, err := taskParams(o)
	if err != nil {
		return err
	}
	why, err := checkWhy(o.Why)
	if err != nil {
		return err
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	req := &api.SetupRequest{Task: o.Task, Params: params, Reason: why, Requester: e.Requester()}
	created, err := c.CreateSetupRequest(ctx, req)
	if err != nil {
		return err
	}
	if !safeID(created.ID) {
		return fmt.Errorf("server returned an invalid request id %q", sanitize(created.ID))
	}
	what := "task request " + created.ID
	e.logf("request %s (Ref %s): bastion task %s %s by %s on %s: %s", created.ID, RefCode(created.ID), o.Task, params, req.Requester.Tool, cfg.HostName, why)
	e.logf("approve at: %s  (waiting; Ctrl-C cancels; nothing runs before the owner's tap)", sanitize(created.ApproveURL))

	var deadline time.Time
	if !created.ExpiresAt.IsZero() {
		left := min(max(created.ExpiresAt.Sub(e.now()), 0), 24*time.Hour)
		deadline = time.Now().Add(left + 2*time.Minute)
	}
	approved, after, shown, failures := false, "", "", 0
	for {
		start := time.Now()
		st, err := c.SetupRequestStatus(ctx, created.ID, 25*time.Second, after)
		if err != nil {
			if transient(err) && failures < 5 {
				failures++
				if serr := sleepCtx(ctx, time.Duration(failures)*e.retryBase()); serr == nil {
					continue
				}
				err = ErrCancelled
			}
			if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return e.taskInterrupted(c, created, approved)
			}
			return err
		}
		failures = 0
		switch st.Status {
		case api.StatusPending:
			if !deadline.IsZero() && time.Now().After(deadline) {
				return &DecisionError{Status: api.StatusExpired, What: what, Note: "no decision before it expired"}
			}
		case api.StatusApproved:
			if !approved {
				approved = true
				e.logf("approved: the bastion's maintenance runner takes it from here")
			}
			run := st.Run
			if run == nil {
				run = &api.SetupRunStatus{State: "queued"}
			}
			if line := run.State + " " + run.Step; line != shown {
				shown = line
				if run.Step != "" {
					e.logf("%s: %s", sanitize(run.State), sanitize(run.Step))
				} else {
					e.logf("%s", sanitize(run.State))
				}
			}
			after = run.State
			switch run.State {
			case "done":
				e.logf("done: %s", sanitize(run.Message))
				e.printResult(run.Result)
				return nil
			case "failed", "refused":
				e.printResult(run.Result)
				return &TaskError{Task: o.Task, State: run.State, Message: run.Message}
			}
		case api.StatusDenied, api.StatusExpired, api.StatusCancelled, api.StatusRevoked:
			return &DecisionError{Status: st.Status, What: what, Note: st.DecisionNote}
		default:
			return fmt.Errorf("%s: unexpected status %q", what, sanitize(st.Status))
		}
		if err := sleepCtx(ctx, e.pollDelay(created.PollAfterMS, time.Since(start))); err != nil {
			return e.taskInterrupted(c, created, approved)
		}
	}
}

func (e *Env) printResult(result map[string]string) {
	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(e.Stdout, "%s: %s\n", sanitize(k), sanitize(result[k]))
	}
}

// taskInterrupted handles Ctrl-C: an undecided request is withdrawn; an approved task is
// the runner's now and continues.
func (e *Env) taskInterrupted(c *APIClient, created *api.RequestCreated, approved bool) error {
	if approved {
		e.logf("stopped following; the task continues on the bastion (its result is on the approval page)")
		return ErrCancelled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.CancelSetupRequest(ctx, created.ID)
	switch {
	case err == nil && st.Status == api.StatusCancelled:
		e.logf("cancelled request %s", created.ID)
	case err == nil:
		e.logf("request %s is already %s; nothing to cancel", created.ID, sanitize(st.Status))
	default:
		e.logf("could not cancel request %s (%v); it stays pending until %s", created.ID, err, created.ExpiresAt.Local().Format("15:04:05"))
	}
	return ErrCancelled
}
