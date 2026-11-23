package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// MaxReasonLen is the server's limit on AccessRequest.Reason, in UTF-8 bytes.
const MaxReasonLen = api.MaxReasonBytes

// SSHOptions are the flags of `aqmas ssh` / `aqmas cert`.
type SSHOptions struct {
	CanonicalOnly bool // generated ssh-config snippet: cache path must equal the selector
	Target        Target
	TTL           time.Duration // 0: config default
	Why           string
	Fresh         bool // ignore a cached certificate
}

// EnsureSSHCert returns a key + certificate for o.Target, reusing a cached one that is valid
// for at least MinRemaining, or requesting a new grant and waiting for the owner's decision.
func (e *Env) EnsureSSHCert(ctx context.Context, o SSHOptions) (*Prepared, error) {
	why := strings.TrimSpace(o.Why)
	if why == "" && !e.StdinIsTTY {
		return nil, &UsageError{Msg: "--why \"...\" is required when stdin is not a terminal (say what you need the access for)"}
	}
	if len(why) > MaxReasonLen {
		return nil, &UsageError{Msg: fmt.Sprintf("--why is longer than %d bytes", MaxReasonLen)}
	}
	if !utf8.ValidString(why) || sanitize(why) != why {
		return nil, &UsageError{Msg: "--why must be plain single-line text"}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return nil, err
	}
	ttl := o.TTL
	if ttl == 0 {
		if ttl, err = cfg.TTL(); err != nil {
			return nil, err
		}
	}
	resolved, resolveErr := c.Resolve(ctx, o.Target)
	canonical := o.Target
	if resolveErr != nil {
		var offline *UnreachableError
		if !errors.As(resolveErr, &offline) || o.Fresh || !hostNameRE.MatchString(canonical.Host) {
			return nil, resolveErr
		}
	} else {
		if !hostNameRE.MatchString(resolved.Name) || validateEndpoint(resolved.Address, resolved.Port) != nil {
			return nil, fmt.Errorf("invalid SSH target resolution")
		}
		canonical.Host = resolved.Name
		if o.CanonicalOnly && canonical.Host != o.Target.Host {
			return nil, &UsageError{Msg: "target name changed: regenerate the ssh-config snippet"}
		}
		if ttl < time.Minute || ttl/time.Second > time.Duration(resolved.MaxSeconds) {
			return nil, &UsageError{Msg: fmt.Sprintf("--ttl must be between 1m and %ds", resolved.MaxSeconds)}
		}
	}
	dir, err := e.targetDir(canonical)
	if err != nil {
		return nil, err
	}
	unlock, err := e.lockDir(ctx.Done(), dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if !o.Fresh {
		if p, err := e.loadCached(dir, canonical); err == nil && (resolveErr != nil || (p.Grant.TargetAddress == resolved.Address && p.Grant.TargetPort == resolved.Port)) && e.stillGranted(ctx, c, p) {
			e.logf("reusing grant %s for %s, valid until %s", p.Grant.GrantID, o.Target, p.ValidBefore.Local().Format("15:04:05"))
			return p, nil
		}
	}

	if resolveErr != nil {
		return nil, resolveErr
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	req := &api.AccessRequest{
		Kind: api.KindSSH,
		SSH: &api.SSHRequest{
			TargetHost: o.Target.Host,
			LoginUser:  o.Target.User,
			PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		},
		Reason:     why,
		TTLSeconds: int(ttl / time.Second),
		Requester:  e.Requester(),
	}
	created, err := c.CreateRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if !safeID(created.ID) {
		return nil, fmt.Errorf("server returned an invalid request id %q", sanitize(created.ID))
	}
	shownWhy := why
	if shownWhy == "" {
		shownWhy = "(no reason given)"
	}
	e.logf("request %s (Ref %s): ssh %s for %s by %s on %s: %s", created.ID, RefCode(created.ID), o.Target, ttl, req.Requester.Tool, cfg.HostName, shownWhy)
	if created.Status == api.StatusPending {
		e.logf("approve at: %s  (waiting; Ctrl-C cancels)", sanitize(created.ApproveURL))
	}

	st, err := e.waitRequest(ctx, c, created)
	if err != nil {
		if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) {
			e.cancelRequest(c, created)
		}
		return nil, err
	}
	// Check the certificate is signed by the SSH CA the server publishes (best effort: an
	// unreachable endpoint only warns; a different CA is refused).
	var caKey ssh.PublicKey
	if ca, err := c.SSHCA(ctx); err != nil {
		e.logf("warning: could not fetch the SSH CA to check the certificate's signer: %v", err)
	} else if caKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(ca.PublicKey)); err != nil {
		return nil, fmt.Errorf("server sent an unreadable SSH CA key: %w", err)
	}
	if st.Grant == nil || st.Grant.SSH == nil || st.Grant.SSH.TargetAddress != resolved.Address || st.Grant.SSH.TargetPort != resolved.Port {
		return nil, fmt.Errorf("grant does not match resolved SSH destination")
	}
	p, err := e.storeGrant(dir, canonical, created.ID, priv, st.Grant, caKey)
	if err != nil {
		return nil, err
	}
	e.logf("approved: grant %s valid until %s", p.Grant.GrantID, p.ValidBefore.Local().Format("15:04:05"))
	return p, nil
}

// stillGranted asks the server whether a cached grant's request is still approved, so a grant
// the owner revoked is not reused by later aqmas runs (the certificate itself stays valid until
// it expires; this only stops honest reuse). When the server is unreachable the cached
// certificate is still used, with a warning: a new request would fail anyway, and existing
// grants keep working during an aqmasd outage.
func (e *Env) stillGranted(ctx context.Context, c *APIClient, p *Prepared) bool {
	if p.Grant.RequestID == "" {
		return false
	}
	st, err := c.RequestStatus(ctx, p.Grant.RequestID, 0)
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

// cancelRequest withdraws a request after Ctrl-C so it leaves the owner's queue. It uses its
// own short context: the command's context is already cancelled.
func (e *Env) cancelRequest(c *APIClient, created *api.RequestCreated) {
	e.cancelRequestNote(c, created, " (the key was not saved)")
}

// cancelRequestNote is cancelRequest with the note appended to each message.
func (e *Env) cancelRequestNote(c *APIClient, created *api.RequestCreated, note string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.CancelRequest(ctx, created.ID)
	switch {
	case err == nil && st.Status == api.StatusCancelled:
		e.logf("cancelled request %s%s", created.ID, note)
	case err == nil:
		e.logf("request %s is already %s; nothing to cancel%s", created.ID, sanitize(st.Status), note)
	default:
		e.logf("could not cancel request %s (%v); it stays pending until %s%s",
			created.ID, err, created.ExpiresAt.Local().Format("15:04:05"), note)
	}
}

// transient reports errors worth retrying while waiting: the server unreachable, or a
// 502-504 (aqmasd answers 502 when minting a child token failed; polling again retries it).
func transient(err error) bool {
	var ue *UnreachableError
	if errors.As(err, &ue) {
		return true
	}
	var ae *APIError
	if errors.As(err, &ae) {
		switch ae.HTTPStatus {
		case 502, 503, 504:
			return true
		}
	}
	return false
}

func (e *Env) waitRequest(ctx context.Context, c *APIClient, created *api.RequestCreated) (*api.RequestStatus, error) {
	return e.waitRequestWith(ctx, created, c.RequestStatus)
}

// waitRequestWith is waitRequest for a request whose status has an endpoint of its own
// (a bastion session).
func (e *Env) waitRequestWith(ctx context.Context, created *api.RequestCreated, status func(context.Context, string, time.Duration) (*api.RequestStatus, error)) (*api.RequestStatus, error) {
	what := "request " + created.ID
	// Local backstop in case the server never reports "expired": measured on the monotonic
	// clock from now, so clock skew between this host and the bastion does not matter.
	var deadline time.Time
	if !created.ExpiresAt.IsZero() {
		left := min(max(created.ExpiresAt.Sub(e.now()), 0), 24*time.Hour)
		deadline = time.Now().Add(left + 2*time.Minute)
	}
	failures := 0
	first := true
	lockNotice := false
	for {
		wait := 25 * time.Second
		if first && created.Status != api.StatusPending {
			wait = 0
		}
		first = false
		start := time.Now()
		st, err := status(ctx, created.ID, wait)
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.HTTPStatus == 423 && ae.Code == "locked" {
				if !lockNotice {
					e.logf("%s", lockedNotice(ae))
					lockNotice = true
				}
				if !deadline.IsZero() && time.Now().After(deadline) {
					return nil, &DecisionError{Status: api.StatusExpired, What: what, Note: "deadline passed while the credential was closed"}
				}
				if err = sleepCtx(ctx, 2*time.Second); err != nil {
					return nil, err
				}
				continue
			}
			if transient(err) && failures < 5 {
				failures++
				if err := sleepCtx(ctx, time.Duration(failures)*e.retryBase()); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		failures = 0
		switch st.Status {
		case api.StatusApproved:
			return st, nil
		case api.StatusDenied, api.StatusExpired, api.StatusRevoked, api.StatusCancelled:
			return nil, &DecisionError{Status: st.Status, What: what, Note: st.DecisionNote}
		case api.StatusPending:
			if !deadline.IsZero() && time.Now().After(deadline) {
				return nil, &DecisionError{Status: api.StatusExpired, What: what, Note: "no decision before it expired"}
			}
		default:
			return nil, fmt.Errorf("%s: unexpected status %q", what, sanitize(st.Status))
		}
		if err := sleepCtx(ctx, e.pollDelay(created.PollAfterMS, time.Since(start))); err != nil {
			return nil, err
		}
	}
}

// RefCode is the short reference the approval UI shows on each card (web/src/app.ts
// refCode: id.slice(-6).toUpperCase()), printed here so the owner can match the card to this
// terminal. Ids are ASCII (safeID), so bytes and UTF-16 units agree.
func RefCode(id string) string {
	if len(id) > 6 {
		id = id[len(id)-6:]
	}
	return strings.ToUpper(id)
}

// BuildSSHArgv returns the argv (argv[0] = "ssh") that logs in with p's certificate only.
// Every server-provided value is re-validated here, and the destination follows "--" so
// nothing can be read as an ssh option.
func BuildSSHArgv(p *Prepared, command []string) ([]string, error) {
	g := p.Grant
	if !loginUserRE.MatchString(g.LoginUser) {
		return nil, fmt.Errorf("invalid login user %q", sanitize(g.LoginUser))
	}
	if err := validateEndpoint(g.TargetAddress, g.TargetPort); err != nil {
		return nil, err
	}
	for _, path := range []string{p.KeyPath, p.CertPath, p.KnownHostsPath} {
		if path != "" && !safePathRE.MatchString(path) {
			return nil, fmt.Errorf("cache path %q contains characters ssh would reinterpret; set AQMAS_CACHE_DIR to a plain path", path)
		}
	}
	argv := []string{"ssh",
		// No ssh_config at all: nothing from ~/.ssh/config (IdentityFile, CertificateFile,
		// ControlMaster/ControlPath, ProxyCommand, HostName...) may add another identity,
		// reuse a connection made with another key, or redirect the connection.
		"-F", "none",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PreferredAuthentications=publickey",
		"-i", p.KeyPath,
		"-o", "CertificateFile=" + p.CertPath,
	}
	if p.KnownHostsPath != "" {
		argv = append(argv, "-o", "UserKnownHostsFile="+p.KnownHostsPath)
	}
	argv = append(argv,
		"-o", "StrictHostKeyChecking=yes",
		"-p", strconv.Itoa(g.TargetPort),
		"--", g.LoginUser+"@"+g.TargetAddress,
	)
	return append(argv, command...), nil
}

// mosh interprets --ssh as a command string. BuildSSHArgv permits only plain
// absolute paths, a validated endpoint and a numeric port in these words.
func BuildMoshArgv(p *Prepared, args []string) ([]string, error) {
	if err := CheckMoshArgs(args); err != nil {
		return nil, err
	}
	ssh, err := BuildSSHArgv(p, nil)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"mosh"}, args...)
	return append(argv, "--ssh="+strings.Join(ssh[:len(ssh)-2], " "), "--", ssh[len(ssh)-1]), nil
}

// CheckMoshArgs allows transport and prediction settings only. A positional
// host, --local, or a bootstrap override would bypass the signed destination.
func CheckMoshArgs(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-4", "-6", "--predict=always", "--predict=never", "--predict=adaptive", "--predict=experimental", "--no-init":
			continue
		}
		p, ok := strings.CutPrefix(arg, "--port=")
		if !ok && (arg == "-p" || arg == "--port") && i+1 < len(args) {
			i++
			p = args[i]
			ok = true
		}
		if ok {
			lo, hi, rng := strings.Cut(p, ":")
			if !rng {
				hi = lo
			}
			a, e := strconv.Atoi(lo)
			b, f := strconv.Atoi(hi)
			if e == nil && f == nil && a >= 1 && a <= b && b <= 65535 && strconv.Itoa(a) == lo && strconv.Itoa(b) == hi {
				continue
			}
		}
		return &UsageError{Msg: "unsupported mosh option: " + sanitize(arg)}
	}
	return nil
}
