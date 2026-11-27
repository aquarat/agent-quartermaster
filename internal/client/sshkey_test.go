package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// fakeSSH is the broker's side of one SSH key: it signs login requests for
// the key under a grant and hands the key out when that is allowed.
type fakeSSH struct {
	path     string
	seed     []byte
	pub      []byte
	comment  string
	handout  bool
	gone     bool   // the key was deleted
	decision string // approved (default), denied
	reqs     map[string]*signer.Request
	uses     []string
	signed   [][]byte
	wrongKey bool // hand out another key than the one named
}

const testSSHPath = "acme/forge/deploy-key"

func (f *fakeServer) setupSSH(mux *http.ServeMux) {
	seed := make([]byte, 32)
	rand.Read(seed)
	f.ssh = fakeSSH{path: testSSHPath, seed: seed, pub: ed25519.NewKeyFromSeed(seed)[32:], comment: "aqmas:" + testSSHPath, reqs: map[string]*signer.Request{}}
	key := func(w http.ResponseWriter, r *http.Request) (signer.SSHKey, bool) {
		var k signer.SSHKey
		host, ok := f.host(w, r)
		if !ok {
			return k, false
		}
		if f.ssh.gone || r.URL.Query().Get("path") != f.ssh.path && r.Method == "GET" {
			apiErr(w, 404, api.ErrNotFound, "not found")
			return k, false
		}
		k = signer.SSHKey{Binding: signer.Binding{Path: f.ssh.path, Title: "Deploy key", Org: "o", Service: "s", Set: "set-ssh", ServiceRevision: 1, PolicyRevision: 1, Generation: 1, Enrollment: "e1", Host: host, Class: "agent", Scheme: signer.SSHEd25519, PublicKey: f.ssh.pub, Default: 600, Soft: 3600}, Comment: f.ssh.comment, Handout: f.ssh.handout}
		k.AuthorizedKey, _ = signer.AuthorizedKey(signer.SSHEd25519, f.ssh.pub, f.ssh.comment)
		k.Fingerprint, _ = signer.SSHFingerprint(signer.SSHEd25519, f.ssh.pub)
		return k, true
	}
	mux.HandleFunc("GET /v2/ssh/key", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if k, ok := key(w, r); ok {
			writeJSON(w, 200, k)
		}
	})
	mux.HandleFunc("GET /v2/sign/key", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if k, ok := key(w, r); ok {
			writeJSON(w, 200, k.Binding)
		}
	})
	mux.HandleFunc("POST /v2/ssh/requests", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		k, ok := key(w, r)
		if !ok {
			return
		}
		var in struct {
			Binding signer.Binding
			Reason  string
			Use     string
			TTL     int `json:"ttl_seconds"`
			Max     int `json:"max_signatures"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Use == signer.UseSSHHandout && !f.ssh.handout {
			apiErr(w, 403, "forbidden", "the owner does not allow this SSH key to be handed out")
			return
		}
		if in.Max == 0 {
			in.Max = 20
		}
		if in.Use == signer.UseSSHHandout {
			in.Max = 1
		}
		id := fmt.Sprintf("SSHREQ%04d", len(f.ssh.reqs)+1)
		req := &signer.Request{Binding: k.Binding, ID: id, Peer: "127.0.0.1", Reason: in.Reason, Items: []signer.Item{}, TTL: in.TTL, Max: in.Max, Deadline: time.Now().Add(10 * time.Minute).UnixMilli(), Status: "pending", Use: in.Use}
		f.ssh.reqs[id] = req
		f.ssh.uses = append(f.ssh.uses, in.Use)
		writeJSON(w, 200, req)
	})
	find := func(w http.ResponseWriter, r *http.Request, grant bool) *signer.Request {
		if _, ok := f.host(w, r); !ok {
			return nil
		}
		id := r.PathValue("id")
		if grant {
			id = strings.TrimPrefix(id, "G")
		}
		req := f.ssh.reqs[id]
		if req == nil || f.ssh.gone {
			apiErr(w, 404, api.ErrNotFound, "not found")
			return nil
		}
		return req
	}
	mux.HandleFunc("GET /v2/sign/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		req := find(w, r, false)
		if req == nil {
			return
		}
		if req.Status == "pending" {
			switch f.ssh.decision {
			case "denied":
				req.Status = "denied"
			case "pending":
			default:
				req.Status, req.Grant, req.Until = "approved", "G"+req.ID, time.Now().Add(time.Duration(max(req.TTL, 600))*time.Second).UnixMilli()
			}
		}
		writeJSON(w, 200, req)
	})
	mux.HandleFunc("POST /v2/sign/requests/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if req := f.ssh.reqs[r.PathValue("id")]; req != nil {
			req.Status = "cancelled"
		}
		writeJSON(w, 200, api.OK{OK: true})
	})
	mux.HandleFunc("GET /v2/sign/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if req := find(w, r, true); req != nil {
			writeJSON(w, 200, req)
		}
	})
	mux.HandleFunc("POST /v2/sign/grants/{id}/end", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if req := find(w, r, true); req != nil {
			req.Status = "revoked"
			writeJSON(w, 200, api.OK{OK: true})
		}
	})
	mux.HandleFunc("POST /v2/sign/grants/{id}/sign", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		req := find(w, r, true)
		if req == nil {
			return
		}
		var in struct{ Items []signer.Item }
		_ = json.NewDecoder(r.Body).Decode(&in)
		sc, _ := signer.Lookup(signer.SSHEd25519)
		if req.Status != "approved" || req.Use != signer.UseSSHAgent || req.Used+len(in.Items) > req.Max {
			apiErr(w, 409, "conflict", "grant expired, revoked or used up")
			return
		}
		out := signer.Signed{}
		for _, it := range in.Items {
			if _, err := sc.SSHLogin(f.ssh.pub, it); err != nil {
				apiErr(w, 400, "bad_request", err.Error())
				return
			}
			sig, err := sc.Sign(f.ssh.seed, it)
			if err != nil {
				apiErr(w, 400, "bad_request", err.Error())
				return
			}
			f.ssh.signed = append(f.ssh.signed, it.Message)
			out.Signatures = append(out.Signatures, signer.Signature{Name: it.Name, SHA256: it.SHA256, Signature: sig})
		}
		req.Used += len(in.Items)
		if req.Used >= req.Max {
			req.Status = "used"
		}
		out.Request = *req
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /v2/ssh/grants/{id}/key", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		req := find(w, r, true)
		if req == nil {
			return
		}
		if req.Status != "approved" || req.Use != signer.UseSSHHandout || req.Used != 0 {
			apiErr(w, 409, "conflict", "grant expired, revoked or already collected")
			return
		}
		seed := f.ssh.seed
		if f.ssh.wrongKey {
			seed = bytes.Repeat([]byte{3}, 32)
		}
		file, _ := signer.OpenSSHPrivate(signer.SSHEd25519, seed, f.ssh.comment)
		line, _ := signer.AuthorizedKey(signer.SSHEd25519, f.ssh.pub, f.ssh.comment)
		req.Used, req.Status = 1, "used"
		writeJSON(w, 200, signer.SSHHandout{Request: *req, PrivateKey: string(file), AuthorizedKey: line})
	})
}

func (f *fakeServer) sshKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, err := signer.SSHPublicKey(signer.SSHEd25519, f.ssh.pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sshServer is an in-process SSH server that accepts exactly one public key
// and reports the user that logged in.
func sshServer(t *testing.T, accept ssh.PublicKey) (addr string, users chan string) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewSignerFromKey(hostPriv)
	users = make(chan string, 8)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), accept.Marshal()) {
			return nil, fmt.Errorf("unknown key")
		}
		return &ssh.Permissions{}, nil
	}}
	cfg.AddHostKey(hostKey)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					conn.Close()
					return
				}
				users <- sc.User()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "test server")
				}
			}()
		}
	}()
	return l.Addr().String(), users
}

// The agent socket offers exactly the one key, signs SSH logins with it
// through the broker and refuses everything else an SSH agent can be asked.
func TestSSHAgentProtocol(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	key := f.sshKey(t)
	addr, users := sshServer(t, key)
	ctx := context.Background()
	e.Environ = func() []string {
		return []string{"HOME=/home/alice", "SSH_AUTH_SOCK=/run/other-agent.sock", "SSH_AGENT_PID=77", "PATH=" + os.Getenv("PATH")}
	}

	var sock string
	inside := func(exe string, argv, env []string) (int, error) {
		joined := "\n" + strings.Join(env, "\n") + "\n"
		if strings.Contains(joined, "other-agent") || strings.Contains(joined, "SSH_AGENT_PID") || !strings.Contains(joined, "\nHOME=/home/alice\n") {
			t.Errorf("environment: %q", env)
		}
		for _, kv := range env {
			if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
				sock = strings.TrimPrefix(kv, "SSH_AUTH_SOCK=")
			}
		}
		// Private: the socket 0600 in a directory 0700 that is ours.
		if got := mode(t, sock); got != 0o600 {
			t.Errorf("socket mode %04o", got)
		}
		if got := mode(t, filepath.Dir(sock)); got != 0o700 {
			t.Errorf("socket directory mode %04o", got)
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ag := agent.NewClient(conn)

		// List: exactly the one public key, with its comment.
		keys, err := ag.List()
		if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Marshal(), key.Marshal()) || keys[0].Comment != "aqmas:"+testSSHPath {
			t.Fatalf("list: %v %v", keys, err)
		}
		// A real SSH login with the agent's key.
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "git", Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("ssh login through the agent: %v\n%s", err, e.stderr)
		}
		client.Close()
		if u := <-users; u != "git" {
			t.Fatalf("logged in as %q", u)
		}
		// Not a general signing oracle: anything but a login request for this key is
		// refused on this host, before the broker is asked.
		before := len(f.ssh.signed)
		other, _ := signer.SSHPublicKey(signer.SSHEd25519, bytes.Repeat([]byte{9}, 32))
		for name, data := range map[string][]byte{
			"arbitrary data": []byte("sign this release manifest, please"),
			"an SSHSIG blob": append([]byte("SSHSIG\x00\x00\x00\x04file"), bytes.Repeat([]byte{1}, 64)...),
			"empty data":     {},
		} {
			if _, err := ag.Sign(key, data); err == nil {
				t.Errorf("the agent signed %s", name)
			}
		}
		if _, err := ag.Sign(other, f.ssh.signed[0]); err == nil {
			t.Error("the agent signed for a key it does not offer")
		}
		if len(f.ssh.signed) != before {
			t.Error("a refused request reached the broker")
		}
		// No other agent operation: add, remove, lock, unlock, extensions.
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := ag.Add(agent.AddedKey{PrivateKey: priv}); err == nil {
			t.Error("a key was added to the agent")
		}
		if err := ag.Remove(key); err == nil {
			t.Error("the key was removed from the agent")
		}
		if err := ag.RemoveAll(); err == nil {
			t.Error("RemoveAll succeeded")
		}
		if err := ag.Lock([]byte("x")); err == nil {
			t.Error("the agent was locked")
		}
		if err := ag.Unlock([]byte("x")); err == nil {
			t.Error("the agent was unlocked")
		}
		if _, err := ag.Extension("session-bind@openssh.com", []byte("x")); err == nil {
			t.Error("an extension request succeeded")
		}
		if _, err := ag.Extension("query", nil); err == nil {
			t.Error("the extension query succeeded")
		}
		if keys, err := ag.List(); err != nil || len(keys) != 1 {
			t.Errorf("the agent's key list changed: %v %v", keys, err)
		}
		return 7, nil
	}
	code, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Why: "clone the deploy repository", TTL: 600, Count: 3, Command: []string{"true"}, Run: inside})
	if err != nil || code != 7 {
		t.Fatalf("ssh-agent: %d %v\n%s", code, err, e.stderr)
	}
	if _, err := os.Stat(filepath.Dir(sock)); !os.IsNotExist(err) {
		t.Fatalf("the socket directory was not removed: %v", err)
	}
	// The standard logger was quiet only while the socket was served.
	if log.Writer() == io.Discard {
		t.Fatal("the process's logger stays silenced after the agent ended")
	}
	if len(f.ssh.uses) != 1 || f.ssh.uses[0] != signer.UseSSHAgent || f.ssh.reqs["SSHREQ0001"].TTL != 600 || f.ssh.reqs["SSHREQ0001"].Max != 3 || f.ssh.reqs["SSHREQ0001"].Reason != "clone the deploy repository" {
		t.Fatalf("request: %+v", f.ssh.reqs["SSHREQ0001"])
	}
	fp, _ := signer.SSHFingerprint(signer.SSHEd25519, f.ssh.pub)
	for _, want := range []string{"awaiting approval for SSH logins with " + testSSHPath + " (" + fp + ") for 10m0s", "Ref ", "SSH login grant open until", "an SSH key signs SSH login requests only"} {
		if !strings.Contains(e.stderr.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, e.stderr)
		}
	}
	// What the broker signed was a login request: user, service and this key.
	u, err := signer.ParseUserAuth(f.ssh.signed[0])
	if err != nil || u.User != "git" || u.Service != "ssh-connection" || !bytes.Equal(u.PublicKey, key.Marshal()) {
		t.Fatalf("signed data: %+v %v", u, err)
	}

	// Within the grant: no new request, no --why needed.
	e.stderr.Reset()
	login := func(want bool) func(string, []string, []string) (int, error) {
		return func(exe string, argv, env []string) (int, error) {
			conn, err := net.Dial("unix", strings.TrimPrefix(env[len(env)-1], "SSH_AUTH_SOCK="))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "deploy", Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(conn).Signers)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
			if (err == nil) != want {
				t.Errorf("login succeeded=%t, want %t: %v", err == nil, want, err)
			}
			if err == nil {
				client.Close()
				<-users
				return 0, nil
			}
			return 255, nil
		}
	}
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Command: []string{"true"}, Run: login(true)}); err != nil {
		t.Fatalf("second call: %v\n%s", err, e.stderr)
	}
	if len(f.ssh.uses) != 1 || !strings.Contains(e.stderr.String(), "using the open SSH login grant for "+testSSHPath+" (1 of 3 logins used") {
		t.Fatalf("the open grant was not reused (%d requests): %s", len(f.ssh.uses), e.stderr)
	}
	// The third login spends the grant; the next call asks anew, and needs --why.
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Command: []string{"true"}, Run: login(true)}); err != nil {
		t.Fatal(err)
	}
	var ue *UsageError
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Command: []string{"true"}, Run: login(true)}); !errorsAs(err, &ue) || len(f.ssh.uses) != 1 {
		t.Fatalf("a spent grant, no --why: %v (%d requests)", err, len(f.ssh.uses))
	}
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Why: "second deploy", Command: []string{"true"}, Run: login(true)}); err != nil || len(f.ssh.uses) != 2 {
		t.Fatalf("new grant: %v (%d requests)", err, len(f.ssh.uses))
	}
	if f.ssh.reqs["SSHREQ0002"].TTL != int(SSHAgentDefaultTTL/time.Second) {
		t.Fatalf("default duration: %d", f.ssh.reqs["SSHREQ0002"].TTL)
	}
	// The key is deleted while a command runs: the next login is not signed, and says why.
	e.stderr.Reset()
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Command: []string{"true"}, Run: func(exe string, argv, env []string) (int, error) {
		f.mu.Lock()
		f.ssh.gone = true
		f.mu.Unlock()
		return login(false)(exe, argv, env)
	}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.stderr.String(), "the SSH login grant for "+testSSHPath+" is over") {
		t.Fatalf("no explanation for the refused login: %s", e.stderr)
	}
	// Gone for good: not_found, with what that can mean.
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Why: "x", Command: []string{"true"}, Run: login(false)}); err == nil || !plainNotFound(err) || !strings.Contains(err.Error(), "a deleted key") {
		t.Fatalf("a deleted key: %v", err)
	}
	f.ssh.gone = false

	// --end gives the grant back; a denial is exit code 3; usage errors ask nothing.
	if err := e.SSHAgentEnd(ctx, testSSHPath); err != nil || f.ssh.reqs["SSHREQ0002"].Status != "revoked" {
		t.Fatalf("--end: %v %+v", err, f.ssh.reqs["SSHREQ0002"])
	}
	if err := e.SSHAgentEnd(ctx, testSSHPath); err == nil {
		t.Fatal("--end twice")
	}
	f.ssh.decision = "denied"
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Why: "x", Command: []string{"true"}, Run: login(false)}); ExitCode(err) != ExitDenied {
		t.Fatalf("denied: %v", err)
	}
	n := len(f.ssh.uses)
	for name, o := range map[string]SSHAgentOptions{
		"no command":           {Path: testSSHPath, Why: "x"},
		"command and --socket": {Path: testSSHPath, Why: "x", Command: []string{"true"}, Socket: true},
		"a bad path":           {Path: "deploy-key", Why: "x", Command: []string{"true"}},
	} {
		if _, err := e.SSHAgent(ctx, o); !errorsAs(err, &ue) || len(f.ssh.uses) != n {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Why: "x", Command: []string{"no-such-command-aqmas-test"}}); err == nil || len(f.ssh.uses) != n {
		t.Errorf("a missing command asked the owner first: %v", err)
	}
	// `aqmas sign` and `aqmas signer` say what the key is for.
	if err := e.Sign(ctx, SignOptions{Path: testSSHPath, Why: "x", Files: []string{"-"}}); err == nil || !strings.Contains(err.Error(), "aqmas ssh-agent "+testSSHPath) {
		t.Fatalf("aqmas sign with an SSH key: %v", err)
	}
	// The public line needs no approval.
	e.stdout.Reset()
	line, _ := signer.AuthorizedKey(signer.SSHEd25519, f.ssh.pub, f.ssh.comment)
	if err := e.SSHKeyPublic(ctx, testSSHPath); err != nil || e.stdout.String() != line+"\n" || len(f.ssh.uses) != n {
		t.Fatalf("--public: %v %q", err, e.stdout)
	}
}

// --socket serves the agent for a script until it is interrupted.
func TestSSHAgentSocketMode(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	addr, users := sshServer(t, f.sshKey(t))
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	e.Stdout = pw
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := e.SSHAgent(ctx, SSHAgentOptions{Path: testSSHPath, Why: "nightly mirror", TTL: 300, Socket: true})
		done <- err
	}()
	buf := make([]byte, 512)
	n, err := pr.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "SSH_AUTH_SOCK=/") || !strings.HasSuffix(string(buf[:n]), "\n") {
		t.Fatalf("socket line: %q %v\n%s", buf[:n], err, e.stderr)
	}
	sock := strings.TrimSpace(strings.TrimPrefix(string(buf[:n]), "SSH_AUTH_SOCK="))
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "mirror", Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(conn).Signers)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("login through the served socket: %v", err)
	}
	client.Close()
	conn.Close()
	<-users
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("--socket: %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("the socket was left behind: %v", err)
	}
}

// Hand-out: refused without asking when the owner has not allowed it; when
// allowed and approved, the key file is 0600 and is exactly the key.
func TestSSHKeyHandoutCommand(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	ctx := context.Background()
	home := t.TempDir()
	out := filepath.Join(home, "keys", "deploy")
	os.MkdirAll(filepath.Dir(out), 0o700)

	err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "the tool reads a key file", Out: out})
	if err == nil || !strings.Contains(err.Error(), "aqmas ssh-agent "+testSSHPath) || len(f.ssh.uses) != 0 {
		t.Fatalf("hand-out of a key that may not be handed out: %v (%d requests)", err, len(f.ssh.uses))
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a file was written")
	}
	f.ssh.handout = true
	// An existing file is refused before the owner is asked.
	os.WriteFile(out, []byte("keep me"), 0o600)
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: out}); err == nil || !strings.Contains(err.Error(), "--force") || len(f.ssh.uses) != 0 {
		t.Fatalf("overwrite without --force: %v", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "keep me" {
		t.Fatal("the existing file was touched")
	}
	// The broker delivering another key than the one named: nothing is written.
	f.ssh.wrongKey = true
	os.Remove(out)
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: out}); err == nil || !strings.Contains(err.Error(), "nothing written") {
		t.Fatalf("a wrong key was accepted: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a wrong key was written")
	}
	f.ssh.wrongKey = false

	old := syscall.Umask(0)
	err = e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "the tool reads a key file", Out: out})
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("hand-out: %v\n%s", err, e.stderr)
	}
	if f.ssh.uses[len(f.ssh.uses)-1] != signer.UseSSHHandout {
		t.Fatalf("uses: %v", f.ssh.uses)
	}
	if got := mode(t, out); got != 0o600 {
		t.Fatalf("private key mode %04o", got)
	}
	if got := mode(t, out+".pub"); got != 0o644 {
		t.Fatalf("public key mode %04o", got)
	}
	file, _ := os.ReadFile(out)
	parsed, err := ssh.ParsePrivateKey(file)
	if err != nil || !bytes.Equal(parsed.PublicKey().Marshal(), f.sshKey(t).Marshal()) {
		t.Fatalf("the written file is not the key: %v", err)
	}
	line, _ := signer.AuthorizedKey(signer.SSHEd25519, f.ssh.pub, f.ssh.comment)
	if pub, _ := os.ReadFile(out + ".pub"); string(pub) != line+"\n" {
		t.Fatalf("public file: %q", pub)
	}
	for _, want := range []string{"private key  " + out, "ssh -i " + out + " -o IdentitiesOnly=yes", "GIT_SSH_COMMAND='ssh -i " + out + " -o IdentitiesOnly=yes' git clone"} {
		if !strings.Contains(e.stdout.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, e.stdout)
		}
	}
	if strings.Contains(e.stdout.String()+e.stderr.String(), "PRIVATE KEY") {
		t.Fatal("the private key was printed")
	}
	if !strings.Contains(e.stderr.String(), "HAND OUT the private SSH key "+testSSHPath) || !strings.Contains(e.stderr.String(), "cannot recall it") {
		t.Fatalf("stderr: %s", e.stderr)
	}
	// --force replaces both files; the default name is under ~/.ssh.
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "again", Out: out, Force: true}); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "default name", Home: home}); err != nil {
		t.Fatalf("default name: %v", err)
	}
	def := filepath.Join(home, ".ssh", "aqmas-acme-forge-deploy-key")
	if got := mode(t, def); got != 0o600 {
		t.Fatalf("default file mode %04o", got)
	}
	if got := mode(t, filepath.Dir(def)); got != 0o700 {
		t.Fatalf("~/.ssh mode %04o", got)
	}
	// A link in the way is never followed.
	target := filepath.Join(home, "elsewhere")
	os.Remove(out)
	os.Symlink(target, out)
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: out, Force: true}); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("the link's target was written")
	}
	f.ssh.decision = "denied"
	os.Remove(out)
	os.Remove(out + ".pub")
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: out}); ExitCode(err) != ExitDenied {
		t.Fatalf("denied: %v", err)
	}
	// --force replaces a key only with a delivered, verified key: a denial, or a
	// broker that delivers another key, leaves the existing files as they were.
	os.WriteFile(out, []byte("the old key"), 0o600)
	os.WriteFile(out+".pub", []byte("the old line"), 0o644)
	intact := func(what string) {
		t.Helper()
		a, _ := os.ReadFile(out)
		b, _ := os.ReadFile(out + ".pub")
		if string(a) != "the old key" || string(b) != "the old line" {
			t.Fatalf("%s: --force destroyed the existing key (%q, %q)", what, a, b)
		}
		left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".*aqmas-*"))
		if len(left) != 0 {
			t.Fatalf("%s: temporary files left behind: %v", what, left)
		}
	}
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: out, Force: true}); ExitCode(err) != ExitDenied {
		t.Fatalf("denied with --force: %v", err)
	}
	intact("denied")
	f.ssh.decision, f.ssh.wrongKey = "approved", true
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: out, Force: true}); err == nil {
		t.Fatal("a wrong key was accepted with --force")
	}
	intact("a wrong key")
	f.ssh.wrongKey = false
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.SSHKeyHandout(cctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: out, Force: true}); err == nil {
		t.Fatal("a cancelled hand-out succeeded")
	}
	intact("cancelled")
	// An unwritable destination directory is found before the owner is asked.
	n := len(f.ssh.uses)
	if err := e.SSHKeyHandout(ctx, SSHKeyOptions{Path: testSSHPath, Why: "x", Out: filepath.Join(home, "no-such-dir", "key")}); err == nil || len(f.ssh.uses) != n {
		t.Fatalf("a missing directory cost a request: %v", err)
	}
}

// The real ssh client logs in to a real sshd with nothing but the agent
// socket: the key in authorized_keys is the line aqmas shows.
func TestSSHAgentWithRealSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
			if _, err := os.Stat(p); err == nil {
				sshd = p
			}
		}
	}
	sshBin, err2 := exec.LookPath("ssh")
	keygen, err3 := exec.LookPath("ssh-keygen")
	if sshd == "" || err2 != nil || err3 != nil {
		t.Skip("sshd/ssh/ssh-keygen not installed")
	}
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	dir := t.TempDir()
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "hostkey")).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	hostPub, _ := os.ReadFile(filepath.Join(dir, "hostkey.pub"))
	line, _ := signer.AuthorizedKey(signer.SSHEd25519, f.ssh.pub, f.ssh.comment)
	os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(line+"\n"), 0o600)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, hostPub)), 0o600)
	cfg := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %[2]s/hostkey\nPidFile %[2]s/sshd.pid\nAuthorizedKeysFile %[2]s/authorized_keys\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nLogLevel VERBOSE\n", port, dir)
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(cfg), 0o600)
	sshdLog := &lockedBuffer{}
	cmd := exec.Command(sshd, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	cmd.Stdout, cmd.Stderr = sshdLog, sshdLog
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sshd: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	up := false
	for i := 0; i < 50 && !up; i++ {
		if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			c.Close()
			up = true
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !up {
		t.Skipf("unprivileged sshd did not start: %s", sshdLog.String())
	}
	e.Environ = os.Environ
	argv := []string{sshBin, "-F", "none", "-p", strconv.Itoa(port), "-o", "BatchMode=yes", "-o", "IdentityFile=none", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"), "-o", "PreferredAuthentications=publickey", currentUser() + "@127.0.0.1", "echo", "aqmas-agent-ok"}
	var out []byte
	run := func(exe string, a, env []string) (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, exe, a[1:]...)
		c.Env = env
		var err error
		out, err = c.CombinedOutput()
		if err != nil {
			return 1, nil
		}
		return 0, nil
	}
	code, err := e.SSHAgent(context.Background(), SSHAgentOptions{Path: testSSHPath, Why: "real ssh", Command: argv, Run: run})
	if err != nil || code != 0 || !strings.Contains(string(out), "aqmas-agent-ok") {
		t.Fatalf("ssh through the agent: %d %v\n%s\naqmas: %s\nsshd log:\n%s", code, err, out, e.stderr, sshdLog.String())
	}
	if !strings.Contains(sshdLog.String(), "Accepted publickey for "+currentUser()) {
		t.Errorf("sshd did not log a public-key login:\n%s", sshdLog.String())
	}
	if len(f.ssh.signed) != 1 {
		t.Fatalf("%d signatures for one login", len(f.ssh.signed))
	}
}

func TestMCPWithSSHKey(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	e.Environ = os.Environ
	s := startMCP(t, e.Env)
	text, isErr := s.tool("aqmas_with_ssh_key", map[string]any{"path": testSSHPath, "why": "show the agent's key", "command": []string{"sh", "-c", `test -S "$SSH_AUTH_SOCK" && echo socket-ok`}, "ttl_seconds": 120, "count": 2})
	var res runResult
	if isErr || json.Unmarshal([]byte(text), &res) != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "socket-ok" {
		t.Fatalf("aqmas_with_ssh_key: %s", text)
	}
	if req := f.ssh.reqs["SSHREQ0001"]; req == nil || req.TTL != 120 || req.Max != 2 || req.Use != signer.UseSSHAgent {
		t.Fatalf("request: %+v", req)
	}
	if !strings.Contains(res.Note, "Ref ") {
		t.Fatalf("the result does not carry the Ref line: %q", res.Note)
	}
	for name, args := range map[string]map[string]any{
		"no why":     {"path": testSSHPath, "command": []string{"true"}},
		"no command": {"path": testSSHPath, "why": "x"},
		"a long ttl": {"path": testSSHPath, "why": "x", "command": []string{"true"}, "ttl_seconds": 90000},
	} {
		if text, isErr := s.tool("aqmas_with_ssh_key", args); !isErr || !strings.Contains(text, "exit code: 2") {
			t.Errorf("%s: %s", name, text)
		}
	}
	// No tool hands out a private key.
	for _, name := range mcpToolNames() {
		if strings.Contains(name, "handout") || name == "aqmas_ssh_key" {
			t.Fatalf("tool %s", name)
		}
	}
}
