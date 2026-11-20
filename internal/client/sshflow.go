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

// MaxReasonLen matches the server's limit on AccessRequest.Reason.
const MaxReasonLen = 500

// SSHOptions are the flags of `aqmas ssh` / `aqmas cert`.
type SSHOptions struct {
	Target Target
	TTL    time.Duration // 0: config default
	Why    string
	Fresh  bool // ignore a cached certificate
}

// EnsureSSHCert returns a key + certificate for o.Target, reusing a cached one that is valid
// for at least MinRemaining, or requesting a new grant and waiting for the owner's decision.
func (e *Env) EnsureSSHCert(ctx context.Context, o SSHOptions) (*Prepared, error) {
	why := strings.TrimSpace(o.Why)
	if why == "" && !e.StdinIsTTY {
		return nil, &UsageError{Msg: "--why \"...\" is required when stdin is not a terminal (say what you need the access for)"}
	}
	if utf8.RuneCountInString(why) > MaxReasonLen {
		return nil, &UsageError{Msg: fmt.Sprintf("--why is longer than %d characters", MaxReasonLen)}
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
	if ttl < time.Minute || ttl > MaxTTL {
		return nil, &UsageError{Msg: fmt.Sprintf("--ttl must be between 1m and %s", MaxTTL)}
	}

	dir, err := e.targetDir(o.Target)
	if err != nil {
		return nil, err
	}
	unlock, err := e.lockDir(ctx.Done(), dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if !o.Fresh {
		if p, err := e.loadCached(dir, o.Target); err == nil {
			e.logf("reusing grant %s for %s, valid until %s", p.Grant.GrantID, o.Target, p.ValidBefore.Local().Format("15:04:05"))
			return p, nil
		}
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
		if errors.Is(err, ErrCancelled) {
			e.logf("cancelled; request %s stays pending on the server until %s (the key was not saved)",
				created.ID, created.ExpiresAt.Local().Format("15:04:05"))
		}
		return nil, err
	}
	p, err := e.storeGrant(dir, o.Target, created.ID, priv, st.Grant)
	if err != nil {
		return nil, err
	}
	e.logf("approved: grant %s valid until %s", p.Grant.GrantID, p.ValidBefore.Local().Format("15:04:05"))
	return p, nil
}

func (e *Env) waitRequest(ctx context.Context, c *APIClient, created *api.RequestCreated) (*api.RequestStatus, error) {
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
	for {
		wait := 25 * time.Second
		if first && created.Status != api.StatusPending {
			wait = 0
		}
		first = false
		start := time.Now()
		st, err := c.RequestStatus(ctx, created.ID, wait)
		if err != nil {
			var ue *UnreachableError
			if errors.As(err, &ue) && failures < 5 {
				failures++
				if err := sleepCtx(ctx, time.Duration(failures)*2*time.Second); err != nil {
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
		case api.StatusDenied, api.StatusExpired, api.StatusRevoked:
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
