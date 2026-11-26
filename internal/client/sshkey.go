package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// SSH keys held by aqmas (docs/SSH-KEYS.md). `aqmas ssh-agent` is the
// preferred way to use one: it runs a command with SSH_AUTH_SOCK pointing at a
// private agent socket that offers exactly that key and forwards each login's
// signature request to aqmasd under one owner-approved, time-boxed grant. The
// private key never reaches this host. `aqmas ssh-key` is for the cases where
// that cannot work: the owner allowed hand-out for the key, approves a red
// card, and the key is written here as a file.

// SSHAgentDefaultTTL is the login grant asked for when --ttl is not given.
const SSHAgentDefaultTTL = 10 * time.Minute

// SSHAgentOptions are the flags of `aqmas ssh-agent`.
type SSHAgentOptions struct {
	Path  string
	Why   string
	TTL   int // seconds; 0 asks for SSHAgentDefaultTTL
	Count int // logins the grant covers (0: the broker's default, 20)
	// Command is what runs with the agent socket in its environment.
	Command []string
	// Socket serves the agent until interrupted or the grant ends instead of
	// running a command, and prints SSH_AUTH_SOCK=... for a script to read.
	Socket bool
	// Run replaces starting Command (the MCP tool captures its output). It gets
	// the resolved executable, the arguments and the environment to use.
	Run func(exe string, argv, env []string) (int, error)
}

// sshKey fetches an SSH key's public half and checks that the broker's public
// line and fingerprint are those of the key in the binding.
func (e *Env) sshKey(ctx context.Context, c *APIClient, path string) (signer.SSHKey, signer.Scheme, ssh.PublicKey, error) {
	var k signer.SSHKey
	if !envset.ValidPath(path) {
		return k, signer.Scheme{}, nil, &UsageError{Msg: "expected an exact org/service/key path"}
	}
	err := c.do(ctx, "GET", "/v2/ssh/key?path="+url.QueryEscape(path), nil, &k)
	if err != nil {
		if plainNotFound(err) {
			return k, signer.Scheme{}, nil, fmt.Errorf("%w (no SSH key %s for this host: check `aqmas ls`; a deleted key, a path this host may not see and a path that never existed look the same)", err, sanitize(path))
		}
		return k, signer.Scheme{}, nil, err
	}
	b := k.Binding
	sc, ok := signer.Lookup(b.Scheme)
	if b.Path != path || b.Org == "" || b.Service == "" || b.Set == "" || b.Enrollment == "" || len(b.PublicKey) == 0 {
		return k, sc, nil, errors.New("unexpected SSH key binding")
	}
	if !ok || !sc.SSH {
		return k, sc, nil, fmt.Errorf("this aqmas does not know SSH key type %q; upgrade", sanitize(b.Scheme))
	}
	pub, err := signer.SSHPublicKey(b.Scheme, b.PublicKey)
	if err != nil {
		return k, sc, nil, errors.New("unexpected SSH key binding")
	}
	line, err := signer.AuthorizedKey(b.Scheme, b.PublicKey, k.Comment)
	if err != nil || line != k.AuthorizedKey || k.Fingerprint != ssh.FingerprintSHA256(pub) {
		return k, sc, nil, errors.New("the broker's public key line does not match the key")
	}
	return k, sc, pub, nil
}

// SSHKeyPublic runs `aqmas ssh-key PATH --public`: the authorized_keys line,
// which is public and needs no approval.
func (e *Env) SSHKeyPublic(ctx context.Context, path string) error {
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	k, _, _, err := e.sshKey(ctx, c, path)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(e.Stdout, k.AuthorizedKey)
	return err
}

// sshWait polls a pending SSH key request until the owner decides.
func (e *Env) sshWait(ctx context.Context, c *APIClient, v signer.Request, b signer.Binding, what string) (signer.Request, error) {
	id := v.ID
	end := time.Now().Add(min(time.Until(time.UnixMilli(v.Deadline))+2*time.Minute, 24*time.Hour))
	for {
		if err := sleepCtx(ctx, time.Second); err != nil {
			return v, err
		}
		v = signer.Request{}
		if err := c.do(ctx, "GET", "/v2/sign/requests/"+id, nil, &v); err != nil {
			if plainNotFound(err) {
				// The key was deleted or changed, or the host's admission ended, while waiting.
				return v, &DecisionError{Status: "expired", What: what}
			}
			return v, err
		}
		if !sameJSON(v.Binding, b) || v.ID != id {
			return v, errors.New("SSH key request changed")
		}
		switch v.Status {
		case "pending":
			if time.Now().After(end) {
				return v, &DecisionError{Status: "expired", What: what}
			}
		case "approved":
			if !safeID(v.Grant) || v.Until <= e.now().UnixMilli() {
				return v, errors.New("invalid SSH key grant")
			}
			return v, nil
		default:
			return v, &DecisionError{Status: v.Status, What: what}
		}
	}
}

// sshRequest files a request and waits for the decision. A cancelled wait
// withdraws the request.
func (e *Env) sshRequest(ctx context.Context, c *APIClient, k signer.SSHKey, use, why string, ttl, count int, what, notice string) (signer.Request, error) {
	why, err := e.checkWhy(why)
	if err != nil {
		return signer.Request{}, err
	}
	var v signer.Request
	if err = c.do(ctx, "POST", "/v2/ssh/requests", map[string]any{"binding": k.Binding, "reason": why, "use": use, "ttl_seconds": ttl, "max_signatures": count}, &v); err != nil {
		return v, err
	}
	if !sameJSON(v.Binding, k.Binding) || v.Status != "pending" || v.Use != use || !safeID(v.ID) || len(v.Items) != 0 {
		return v, errors.New("invalid SSH key request response")
	}
	id := v.ID
	e.logf("%s; open the approval page · Ref %s", notice, RefCode(id))
	defer func() {
		if ctx.Err() != nil {
			bg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = c.do(bg, "POST", "/v2/sign/requests/"+id+"/cancel", nil, nil)
		}
	}()
	return e.sshWait(ctx, c, v, k.Binding, what)
}

func (e *Env) sshSlot(cfg *Config, path string) (string, error) {
	slot, err := e.signSlot(cfg, path)
	return "ssh-" + strings.TrimPrefix(slot, "sign-"), err
}

// sshGrant returns a live login grant for the key: the one an earlier call
// left open on this host, or a new one the owner approves now.
func (e *Env) sshGrant(ctx context.Context, cfg *Config, c *APIClient, k signer.SSHKey, o SSHAgentOptions) (signer.Request, error) {
	slot, err := e.sshSlot(cfg, o.Path)
	if err != nil {
		return signer.Request{}, err
	}
	dir, err := trustedDir(e.Paths.ConfigDir, true)
	if err != nil {
		return signer.Request{}, err
	}
	defer dir.Close()
	if r, err := readRecord(dir, slot); err == nil && r.Mode == signer.UseSSHAgent && r.Path == o.Path && r.Until > e.now().Add(5*time.Second).UnixMilli() && safeID(r.Grant) {
		var v signer.Request
		err = c.do(ctx, "GET", "/v2/sign/grants/"+r.Grant, nil, &v)
		var ae *APIError
		switch {
		case err == nil && v.Status == "approved" && v.Use == signer.UseSSHAgent && v.Used < v.Max && v.Until > e.now().Add(5*time.Second).UnixMilli() && sameJSON(v.Binding, k.Binding):
			e.logf("using the open SSH login grant for %s (%d of %d logins used, until %s)", o.Path, v.Used, v.Max, time.UnixMilli(v.Until).Local().Format(time.RFC3339))
			return v, nil
		case err == nil || errors.As(err, &ae) && (ae.HTTPStatus == 404 || ae.HTTPStatus == 409):
			_ = unlinkAt(dir, slot)
		default:
			return v, err
		}
	} else if err == nil {
		_ = unlinkAt(dir, slot)
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = int(SSHAgentDefaultTTL / time.Second)
	}
	v, err := e.sshRequest(ctx, c, k, signer.UseSSHAgent, o.Why, ttl, o.Count, "SSH login request",
		fmt.Sprintf("awaiting approval for SSH logins with %s (%s) for %s", o.Path, k.Fingerprint, time.Duration(ttl)*time.Second))
	if err != nil {
		return v, err
	}
	_ = unlinkAt(dir, slot)
	if err := writeNewAt(dir, slot, mustMetadata(checkoutRecord{Path: o.Path, Mode: signer.UseSSHAgent, Grant: v.Grant, Until: v.Until})); err != nil {
		e.logf("could not remember the SSH login grant: %s", sanitize(err.Error()))
	}
	e.logf("SSH login grant open until %s (up to %d logins); further `aqmas ssh-agent %s` calls need no approval; end it with `aqmas ssh-agent %s --end`", time.UnixMilli(v.Until).Local().Format(time.RFC3339), v.Max, o.Path, o.Path)
	return v, nil
}

// SSHAgentEnd runs `aqmas ssh-agent PATH --end`: give back an open login grant.
func (e *Env) SSHAgentEnd(ctx context.Context, path string) error {
	if !envset.ValidPath(path) {
		return &UsageError{Msg: "expected an exact org/service/key path"}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	slot, err := e.sshSlot(cfg, path)
	if err != nil {
		return err
	}
	dir, err := trustedDir(e.Paths.ConfigDir, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	r, err := readRecord(dir, slot)
	if err != nil || r.Mode != signer.UseSSHAgent || r.Path != path {
		return errors.New("no open SSH login grant recorded for " + path)
	}
	_ = unlinkAt(dir, slot)
	err = c.do(ctx, "POST", "/v2/sign/grants/"+r.Grant+"/end", nil, nil)
	var ae *APIError
	if errors.As(err, &ae) && (ae.HTTPStatus == 404 || ae.HTTPStatus == 409) {
		err = nil // already over
	}
	return err
}

var errAgentReadOnly = errors.New("aqmas ssh-agent offers one key and signs SSH logins with it; it holds no keys to add, remove or lock")

// loginAgent is the SSH agent behind the private socket. It lists exactly one
// public key and forwards signature requests for SSH logins with it to
// aqmasd. Every other agent operation fails; it implements no extensions, so
// the protocol server answers those with a failure as well.
type loginAgent struct {
	e       *Env
	ctx     context.Context
	c       *APIClient
	sc      signer.Scheme
	raw     []byte // the raw public key the broker signs with
	key     ssh.PublicKey
	comment string
	path    string
	grant   string

	mu   sync.Mutex
	told bool // the "grant is over" line was printed
}

func (a *loginAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{Format: a.key.Type(), Blob: a.key.Marshal(), Comment: a.comment}}, nil
}

func (a *loginAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if key == nil || !bytes.Equal(key.Marshal(), a.key.Marshal()) {
		return nil, errors.New("aqmas ssh-agent: not the key this agent offers")
	}
	it := signer.SSHItem(data)
	// Refused here before anything leaves this host; the broker checks again.
	if _, err := a.sc.SSHLogin(a.raw, it); err != nil {
		a.e.logf("refused to sign with %s: %s", a.path, err)
		return nil, err
	}
	var out signer.Signed
	deadline := time.Now().Add(time.Minute)
	notice := false
	for {
		err := a.e.signCall(a.ctx, a.c, a.grant, []signer.Item{it}, &out)
		var ae *APIError
		if errors.As(err, &ae) && ae.HTTPStatus == 423 && ae.Code == "locked" && time.Now().Before(deadline) {
			if !notice {
				a.e.logf("%s", lockedNotice(ae))
				notice = true
			}
			if sleepCtx(a.ctx, time.Second) != nil {
				return nil, a.ctx.Err()
			}
			continue
		}
		if err != nil {
			a.mu.Lock()
			if errors.As(err, &ae) && (ae.HTTPStatus == 404 || ae.HTTPStatus == 409) {
				if !a.told {
					a.e.logf("the SSH login grant for %s is over (used up, expired, revoked, or the key was deleted): this login was not signed; run the command again to ask anew", a.path)
				}
				a.told = true
			} else {
				a.e.logf("SSH login with %s was not signed: %s", a.path, sanitize(err.Error()))
			}
			a.mu.Unlock()
			return nil, err
		}
		break
	}
	if len(out.Signatures) != 1 || out.Signatures[0].SHA256 != it.SHA256 || !a.sc.Verify(a.raw, it, out.Signatures[0].Signature) {
		return nil, errors.New("aqmas ssh-agent: the broker's signature does not verify against the key")
	}
	return a.sc.SSHSignature(out.Signatures[0].Signature)
}
func (a *loginAgent) Add(agent.AddedKey) error       { return errAgentReadOnly }
func (a *loginAgent) Remove(ssh.PublicKey) error     { return errAgentReadOnly }
func (a *loginAgent) RemoveAll() error               { return errAgentReadOnly }
func (a *loginAgent) Lock([]byte) error              { return errAgentReadOnly }
func (a *loginAgent) Unlock([]byte) error            { return errAgentReadOnly }
func (a *loginAgent) Signers() ([]ssh.Signer, error) { return nil, errAgentReadOnly }

// agentSocket makes a private directory (0700) with a listening socket (0600)
// in it. Unix socket paths are short (about 100 bytes), so the directory is
// made under the runtime directory or, when that would be too long, /tmp.
func (e *Env) agentSocket() (net.Listener, string, func(), error) {
	var lastErr error
	for _, base := range []string{e.Getenv("XDG_RUNTIME_DIR"), os.TempDir(), "/tmp"} {
		if base == "" || !filepath.IsAbs(base) {
			continue
		}
		dir, err := os.MkdirTemp(base, "aqmas-ssh-")
		if err != nil {
			lastErr = err
			continue
		}
		sock := filepath.Join(dir, "agent.sock")
		if len(sock) > 100 {
			os.RemoveAll(dir)
			lastErr = errors.New("socket path too long")
			continue
		}
		// The directory is ours alone before the socket exists; the socket is made 0600.
		old := syscall.Umask(0o177)
		l, err := net.Listen("unix", sock)
		syscall.Umask(old)
		if err != nil {
			os.RemoveAll(dir)
			lastErr = err
			continue
		}
		if err = os.Chmod(sock, 0o600); err != nil {
			l.Close()
			os.RemoveAll(dir)
			lastErr = err
			continue
		}
		return l, sock, func() { l.Close(); os.RemoveAll(dir) }, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no directory for the agent socket")
	}
	return nil, "", nil, fmt.Errorf("cannot create the SSH agent socket: %w", lastErr)
}

func serveAgent(l net.Listener, a agent.Agent) {
	// The protocol server reports each refused request through the standard
	// logger; this command says what matters itself, in its own words.
	log.SetOutput(io.Discard)
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = agent.ServeAgent(a, conn)
		}()
	}
}

// agentEnviron is the environment for a command that uses the agent: this
// process's own, with the socket replacing any other agent.
func agentEnviron(env []string, sock string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") || strings.HasPrefix(kv, "SSH_AGENT_PID=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "SSH_AUTH_SOCK="+sock)
}

// SSHAgent runs `aqmas ssh-agent`. It returns the command's exit status.
func (e *Env) SSHAgent(ctx context.Context, o SSHAgentOptions) (int, error) {
	if o.Socket == (len(o.Command) > 0) {
		return 0, &UsageError{Msg: "usage: aqmas ssh-agent ORG/SERVICE/KEY --why REASON [--ttl 10m] [--count N] -- COMMAND... (or --socket to serve the agent for a script)"}
	}
	exe := ""
	if !o.Socket {
		var err error
		if exe, err = exec.LookPath(o.Command[0]); err != nil {
			return 0, err // before the owner is asked for anything
		}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return 0, err
	}
	k, sc, pub, err := e.sshKey(ctx, c, o.Path)
	if err != nil {
		return 0, err
	}
	v, err := e.sshGrant(ctx, cfg, c, k, o)
	if err != nil {
		return 0, err
	}
	l, sock, cleanup, err := e.agentSocket()
	if err != nil {
		return 0, err
	}
	defer cleanup()
	// Signatures are asked for under their own context: the command may still be
	// finishing a login while this process is being told to stop.
	actx, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	go serveAgent(l, &loginAgent{e: e, ctx: actx, c: c, sc: sc, raw: k.Binding.PublicKey, key: pub, comment: k.Comment, path: o.Path, grant: v.Grant})
	if o.Socket {
		if _, err := fmt.Fprintf(e.Stdout, "SSH_AUTH_SOCK=%s\n", sock); err != nil {
			return 0, err
		}
		e.logf("serving %s on that socket until %s or until interrupted", k.Fingerprint, time.UnixMilli(v.Until).Local().Format(time.RFC3339))
		select {
		case <-ctx.Done():
		case <-time.After(time.Until(time.UnixMilli(v.Until))):
			e.logf("the SSH login grant for %s has expired", o.Path)
		}
		return 0, nil
	}
	env := agentEnviron(e.Environ(), sock)
	if o.Run != nil {
		return o.Run(exe, o.Command, env)
	}
	return runWithEnv(exe, o.Command, env)
}

// runWithEnv runs a command on this terminal as a child and returns its exit
// status. Interrupts reach it from the terminal; termination, hang-up and quit
// are passed on.
func runWithEnv(exe string, argv, env []string) (int, error) {
	cmd := exec.Command(exe)
	cmd.Args, cmd.Env = argv, env
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
	err := cmd.Wait()
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

// SSHKeyOptions are the flags of `aqmas ssh-key`.
type SSHKeyOptions struct {
	Path  string
	Why   string
	Out   string // the private key file; "" picks ~/.ssh/aqmas-ORG-SERVICE-KEY
	Force bool
	Home  string // the user's home directory (for the default Out)
}

// SSHKeyHandout runs `aqmas ssh-key PATH --why ...`: the private key is
// delivered once, after the owner approved exactly that, and written 0600
// with its .pub beside it. Refused before any request when the owner has not
// allowed hand-out for the key.
func (e *Env) SSHKeyHandout(ctx context.Context, o SSHKeyOptions) error {
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	k, _, pub, err := e.sshKey(ctx, c, o.Path)
	if err != nil {
		return err
	}
	if !k.Handout {
		return fmt.Errorf("the owner does not allow %s to be handed out. Use the key where it is: aqmas ssh-agent %s --why \"...\" -- COMMAND (git, ssh, scp, rsync). If a tool really needs the key file, ask the owner to allow hand-out for this key in the Vault", o.Path, o.Path)
	}
	out := o.Out
	if out == "" {
		if o.Home == "" {
			return &UsageError{Msg: "name the file to write with --out FILE"}
		}
		out = filepath.Join(o.Home, ".ssh", "aqmas-"+strings.ReplaceAll(o.Path, "/", "-"))
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	for _, p := range []string{out, out + ".pub"} {
		if st, err := os.Lstat(p); err == nil {
			if !o.Force {
				return fmt.Errorf("%s exists; remove it or pass --force", p)
			}
			if !st.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file; remove it first", p)
			}
		}
	}
	v, err := e.sshRequest(ctx, c, k, signer.UseSSHHandout, o.Why, 0, 0, "SSH key hand-out request",
		fmt.Sprintf("awaiting approval to HAND OUT the private SSH key %s (%s) to this host: it leaves aqmas and cannot be recalled", o.Path, k.Fingerprint))
	if err != nil {
		return err
	}
	var got signer.SSHHandout
	notice := false
	for {
		got = signer.SSHHandout{}
		err = c.do(ctx, "POST", "/v2/ssh/grants/"+v.Grant+"/key", map[string]any{}, &got)
		var ae *APIError
		if errors.As(err, &ae) && ae.HTTPStatus == 423 && ae.Code == "locked" && v.Until > e.now().UnixMilli() {
			if !notice {
				e.logf("%s", lockedNotice(ae))
				notice = true
			}
			if err = sleepCtx(ctx, time.Second); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	file := []byte(got.PrivateKey)
	defer clear(file)
	got.PrivateKey = ""
	parsed, err := ssh.ParsePrivateKey(file)
	if err != nil || !bytes.Equal(parsed.PublicKey().Marshal(), pub.Marshal()) || got.AuthorizedKey != k.AuthorizedKey {
		return errors.New("the delivered key is not the private half of " + o.Path + "; nothing written")
	}
	if err = writeFresh(out, file, 0o600, o.Force); err != nil {
		return err
	}
	if err = writeFresh(out+".pub", []byte(k.AuthorizedKey+"\n"), 0o644, o.Force); err != nil {
		return err
	}
	e.logf("the private key of %s is now a file on this host. aqmas cannot recall it: delete the file when the task is done, and tell the owner if it may have been copied", o.Path)
	q := shellQuote(out)
	_, err = fmt.Fprintf(e.Stdout, "private key  %s\npublic key   %s.pub\nfingerprint  %s\nssh          ssh -i %s -o IdentitiesOnly=yes USER@HOST\ngit          GIT_SSH_COMMAND=%s git clone ssh://git@forge.example.com/OWNER/REPO.git\n",
		out, out, k.Fingerprint, q, shellQuote("ssh -i "+q+" -o IdentitiesOnly=yes"))
	return err
}

// writeFresh creates path with exactly mode. An existing regular file is
// replaced only with force; a link is never followed.
func writeFresh(path string, b []byte, mode os.FileMode, force bool) error {
	if force {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if err = f.Chmod(mode); err == nil { // whatever the umask says
		_, err = f.Write(b)
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
