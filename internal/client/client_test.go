package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func enroll(t *testing.T, f *fakeServer, e *testEnv) {
	t.Helper()
	if err := e.Enroll(context.Background(), EnrollOptions{Name: "build-box", Server: f.URL(), CAPin: f.pin()}); err != nil {
		t.Fatalf("enroll: %v\nstderr: %s", err, e.stderr)
	}
}

func TestEnrollWithPin(t *testing.T) {
	f := newFakeServer(t)
	f.enrollPending = 2
	e := newTestEnv(t)
	enroll(t, f, e)

	cfg, err := LoadConfig(e.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HostName != "build-box" || cfg.Server != f.URL() || cfg.ServerCASHA256 != f.pin() {
		t.Fatalf("config = %+v", cfg)
	}
	if got := mode(t, e.Paths.ConfigDir); got != 0o700 {
		t.Errorf("config dir mode %04o", got)
	}
	for _, p := range []string{e.Paths.ConfigFile(), cfg.ClientKey, cfg.ClientCert, cfg.ClientCA, cfg.ServerCA} {
		if got := mode(t, p); got != 0o600 {
			t.Errorf("%s mode %04o, want 0600", p, got)
		}
	}
	// The saved server CA is the pinned one, and later connections use it with mTLS.
	tr, err := LoadTrust(cfg)
	if err != nil || !tr.CA.Equal(f.serverCA.cert) {
		t.Fatalf("trust: %v", err)
	}
	if !strings.Contains(e.stderr.String(), "approve at: https://aqmas.example/enroll/ENR0001") {
		t.Errorf("stderr lacks approve URL: %s", e.stderr)
	}
	key, _ := os.ReadFile(cfg.ClientKey)
	if strings.Contains(e.stderr.String(), string(key)) || strings.Contains(e.stderr.String(), "PRIVATE KEY") {
		t.Error("private key printed")
	}
	// Second enroll without --force is refused.
	err = e.Enroll(context.Background(), EnrollOptions{Name: "build-box", Server: f.URL(), CAPin: f.pin()})
	if ExitCode(err) != ExitUsage {
		t.Errorf("re-enroll without --force: %v", err)
	}
}

func TestEnrollWrongPin(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	other := newTestCA(t, "someone else")
	err := e.Enroll(context.Background(), EnrollOptions{Name: "build-box", Server: f.URL(), CAPin: FormatPin(CertPin(other.cert))})
	if ExitCode(err) != ExitUnreachable {
		t.Fatalf("wrong pin: err=%v code=%d", err, ExitCode(err))
	}
	if f.enrollPosts != 0 {
		t.Error("request reached the server despite the wrong pin")
	}
	if _, err := os.Stat(e.Paths.ConfigFile()); !os.IsNotExist(err) {
		t.Error("config written after failed enroll")
	}
}

func TestEnrollTOFU(t *testing.T) {
	f := newFakeServer(t)

	// Not a TTY: refused, nothing sent.
	e := newTestEnv(t)
	err := e.Enroll(context.Background(), EnrollOptions{Name: "build-box", Server: f.URL()})
	if ExitCode(err) != ExitUsage || f.enrollPosts != 0 {
		t.Fatalf("non-tty TOFU: %v posts=%d", err, f.enrollPosts)
	}

	// TTY, user declines.
	e = newTestEnv(t)
	e.StdinIsTTY = true
	e.Stdin = strings.NewReader("no\n")
	if err := e.Enroll(context.Background(), EnrollOptions{Name: "build-box", Server: f.URL()}); err == nil || f.enrollPosts != 0 {
		t.Fatalf("declined TOFU: %v posts=%d", err, f.enrollPosts)
	}
	if !strings.Contains(e.stderr.String(), f.pin()) {
		t.Errorf("fingerprint not shown: %s", e.stderr)
	}

	// TTY, user confirms: the CA (not the leaf) is pinned.
	e = newTestEnv(t)
	e.StdinIsTTY = true
	e.Stdin = strings.NewReader("yes\n")
	if err := e.Enroll(context.Background(), EnrollOptions{Name: "build-box", Server: f.URL()}); err != nil {
		t.Fatalf("TOFU: %v\n%s", err, e.stderr)
	}
	cfg, _ := LoadConfig(e.Paths)
	if cfg.ServerCASHA256 != f.pin() {
		t.Errorf("pinned %s, want CA %s", cfg.ServerCASHA256, f.pin())
	}
}

func TestEnrollDenied(t *testing.T) {
	f := newFakeServer(t)
	f.enrollDecision = api.StatusDenied
	e := newTestEnv(t)
	err := e.Enroll(context.Background(), EnrollOptions{Name: "build-box", Server: f.URL(), CAPin: f.pin()})
	if ExitCode(err) != ExitDenied {
		t.Fatalf("got %v", err)
	}
}

func TestTrustVerify(t *testing.T) {
	ca := newTestCA(t, "server CA")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ip := []net.IP{net.ParseIP("192.0.2.60")}
	good := ca.issue(t, "aqmasd", &key.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ip)
	clientOnly := ca.issue(t, "db-1", &key.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ip)
	otherIP := ca.issue(t, "aqmasd", &key.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("192.0.2.50")})
	now := time.Now()

	pinOnly := &Trust{Pin: CertPin(ca.cert)}
	if err := pinOnly.verify("192.0.2.60", []*x509.Certificate{good, ca.cert}, now); err != nil {
		t.Errorf("good chain with pin: %v", err)
	}
	if err := pinOnly.verify("192.0.2.60", []*x509.Certificate{good}, now); err == nil {
		t.Error("pin-only trust accepted a chain without the pinned CA")
	}
	withCA := &Trust{CA: ca.cert, Pin: CertPin(ca.cert)}
	for name, tc := range map[string]struct {
		chain []*x509.Certificate
		ok    bool
	}{
		"good leaf only":         {[]*x509.Certificate{good}, true},
		"client cert as server":  {[]*x509.Certificate{clientOnly}, false},
		"wrong address":          {[]*x509.Certificate{otherIP}, false},
		"self-signed other CA":   {[]*x509.Certificate{newTestCA(t, "evil").cert}, false},
		"empty":                  {nil, false},
		"leaf signed by evil CA": {[]*x509.Certificate{newTestCA(t, "evil").issue(t, "aqmasd", &key.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ip)}, false},
	} {
		err := withCA.verify("192.0.2.60", tc.chain, now)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, tc.ok)
		}
	}
	if _, err := ParsePin("sha256:abc"); err == nil {
		t.Error("short pin accepted")
	}
	if _, err := ParsePin("SHA256:" + strings.Repeat("ab:", 31) + "ab"); err != nil {
		t.Errorf("colon pin: %v", err)
	}
}

func sshOpts(why string) SSHOptions {
	return SSHOptions{Target: Target{User: "alice", Host: "db-1"}, Why: why}
}

func TestSSHFlowApproved(t *testing.T) {
	f := newFakeServer(t)
	f.requestPending = 3
	e := newTestEnv(t)
	enroll(t, f, e)

	p, err := e.EnsureSSHCert(context.Background(), sshOpts("check backups"))
	if err != nil {
		t.Fatalf("ssh: %v\n%s", err, e.stderr)
	}
	if p.Reused || f.created != 1 {
		t.Fatalf("reused=%v created=%d", p.Reused, f.created)
	}
	fr := f.requests["REQ0001"]
	if fr.host != "build-box" || fr.req.Reason != "check backups" || fr.req.TTLSeconds != 1800 {
		t.Errorf("request = %+v host=%s", fr.req, fr.host)
	}
	want := api.Requester{Tool: ToolClaudeCode, SessionID: "sess-1", CWD: "/home/alice/Projects/x", PID: 4242, User: "alice"}
	if fr.req.Requester != want {
		t.Errorf("requester = %+v", fr.req.Requester)
	}
	stderr := e.stderr.String()
	for _, s := range []string{"request REQ0001: ssh alice@db-1 for 30m0s by claude-code on build-box: check backups", "approve at: https://aqmas.example/r/REQ0001", "approved: grant GREQ0001"} {
		if !strings.Contains(stderr, s) {
			t.Errorf("stderr lacks %q:\n%s", s, stderr)
		}
	}
	if strings.Contains(stderr, "PRIVATE KEY") {
		t.Error("private key printed")
	}
	dir := filepath.Join(e.Paths.CacheDir, "alice@db-1")
	if mode(t, e.Paths.CacheDir) != 0o700 || mode(t, dir) != 0o700 {
		t.Error("cache dirs not 0700")
	}
	for _, n := range []string{keyFile, certFile, knownHostsFile, grantFile} {
		if got := mode(t, filepath.Join(dir, n)); got != 0o600 {
			t.Errorf("%s mode %04o", n, got)
		}
	}
	kh, _ := os.ReadFile(p.KnownHostsPath)
	if !strings.HasPrefix(string(kh), "192.0.2.61,aqmas.db-1 ssh-ed25519 ") || strings.Count(string(kh), "\n") != 1 {
		t.Errorf("known_hosts = %q", kh)
	}

	argv, err := BuildSSHArgv(p, []string{"uptime", "-p"})
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"ssh",
		"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=publickey",
		"-i", filepath.Join(dir, "id_ed25519"),
		"-o", "CertificateFile=" + filepath.Join(dir, "id_ed25519-cert.pub"),
		"-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"),
		"-o", "StrictHostKeyChecking=yes",
		"-p", "22", "--", "alice@192.0.2.61", "uptime", "-p"}
	if !reflect.DeepEqual(argv, wantArgv) {
		t.Errorf("argv =\n%q\nwant\n%q", argv, wantArgv)
	}

	// Reuse: no new request while >= 2 min remain.
	p2, err := e.EnsureSSHCert(context.Background(), sshOpts("again"))
	if err != nil || !p2.Reused || f.created != 1 {
		t.Fatalf("reuse: %v reused=%v created=%d", err, p2 != nil && p2.Reused, f.created)
	}
	// --fresh forces a new request.
	o := sshOpts("fresh")
	o.Fresh = true
	if _, err := e.EnsureSSHCert(context.Background(), o); err != nil || f.created != 2 {
		t.Fatalf("fresh: %v created=%d", err, f.created)
	}
	// Close to expiry: a new request is made.
	e.Now = func() time.Time { return time.Now().Add(29 * time.Minute) }
	if p3, err := e.EnsureSSHCert(context.Background(), sshOpts("near expiry")); err != nil || p3.Reused || f.created != 3 {
		t.Fatalf("near expiry: %v created=%d", err, f.created)
	}

	// list and status work against the server.
	e.Now = time.Now
	if err := e.List(context.Background(), false); err != nil || !strings.Contains(e.stdout.String(), "alice@db-1") {
		t.Errorf("list: %v %s", err, e.stdout)
	}
	e.stdout.Reset()
	if err := e.Status(context.Background(), "REQ0001"); err != nil || !strings.Contains(e.stdout.String(), "approved") {
		t.Errorf("status id: %v %s", err, e.stdout)
	}
	e.stdout.Reset()
	if err := e.Status(context.Background(), ""); err != nil || !strings.Contains(e.stdout.String(), "alice@db-1") {
		t.Errorf("status: %v %s", err, e.stdout)
	}
}

func TestSSHShortCertNotReused(t *testing.T) {
	f := newFakeServer(t)
	f.certTTL = 90 * time.Second
	e := newTestEnv(t)
	enroll(t, f, e)
	if _, err := e.EnsureSSHCert(context.Background(), sshOpts("x")); err != nil {
		t.Fatal(err)
	}
	if p, err := e.EnsureSSHCert(context.Background(), sshOpts("x")); err != nil || p.Reused || f.created != 2 {
		t.Fatalf("short cert reused: %v created=%d", err, f.created)
	}
}

func TestSSHDecisions(t *testing.T) {
	for _, tc := range []struct {
		status string
		code   int
	}{{api.StatusDenied, ExitDenied}, {api.StatusExpired, ExitExpired}, {api.StatusRevoked, ExitDenied}} {
		t.Run(tc.status, func(t *testing.T) {
			f := newFakeServer(t)
			f.requestPending = 1
			f.requestDecision = tc.status
			f.decisionNote = "not now\x1b]0;pwned\x07"
			e := newTestEnv(t)
			enroll(t, f, e)
			_, err := e.EnsureSSHCert(context.Background(), sshOpts("x"))
			if ExitCode(err) != tc.code {
				t.Fatalf("err=%v code=%d want %d", err, ExitCode(err), tc.code)
			}
			if strings.ContainsAny(err.Error(), "\x1b\x07") {
				t.Errorf("control characters from the server reach the terminal: %q", err.Error())
			}
			if _, err := os.Stat(filepath.Join(e.Paths.CacheDir, "alice@db-1", keyFile)); !os.IsNotExist(err) {
				t.Error("key saved for a request that was not approved")
			}
		})
	}
}

func TestSSHCancel(t *testing.T) {
	f := newFakeServer(t)
	f.requestPending = 1 << 30
	e := newTestEnv(t)
	enroll(t, f, e)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := e.EnsureSSHCert(ctx, sshOpts("x"))
	if ExitCode(err) != ExitCancelled {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
	if _, err := os.Stat(filepath.Join(e.Paths.CacheDir, "alice@db-1", keyFile)); !os.IsNotExist(err) {
		t.Error("key saved after cancel")
	}
	if !strings.Contains(e.stderr.String(), "cancelled; request REQ0001 stays pending") {
		t.Errorf("stderr: %s", e.stderr)
	}
}

func TestSSHWhyRequiredWithoutTTY(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	if _, err := e.EnsureSSHCert(context.Background(), sshOpts("")); ExitCode(err) != ExitUsage {
		t.Fatalf("no --why without tty: %v", err)
	}
	if _, err := e.EnsureSSHCert(context.Background(), sshOpts("two\nlines")); ExitCode(err) != ExitUsage {
		t.Fatalf("multi-line --why: %v", err)
	}
	if _, err := e.EnsureSSHCert(context.Background(), sshOpts(strings.Repeat("x", 501))); ExitCode(err) != ExitUsage {
		t.Fatalf("long --why: %v", err)
	}
	e.StdinIsTTY = true
	if _, err := e.EnsureSSHCert(context.Background(), sshOpts("")); err != nil {
		t.Fatalf("tty without --why: %v", err)
	}
	if f.requests["REQ0001"].req.Requester.Tool != ToolClaudeCode {
		t.Error("tool")
	}
}

func TestUnreachableAndAPIErrors(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)

	// Unknown target: api.Error is surfaced, sanitized, exit 1.
	o := sshOpts("x")
	o.Target.Host = "unknownhost"
	_, err := e.EnsureSSHCert(context.Background(), o)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "not_found" || ExitCode(err) != ExitError || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("api error: %v", err)
	}

	// Server gone: exit 5.
	f.srv.Close()
	if _, err := e.EnsureSSHCert(context.Background(), sshOpts("x")); ExitCode(err) != ExitUnreachable {
		t.Fatalf("closed server: %v code=%d", err, ExitCode(err))
	}
}

func TestNotEnrolled(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.EnsureSSHCert(context.Background(), sshOpts("x")); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("got %v", err)
	}
}

func TestConfigRefusesWritableFiles(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	os.Chmod(e.Paths.ConfigFile(), 0o666)
	if _, err := LoadConfig(e.Paths); err == nil {
		t.Error("world-writable config accepted")
	}
	os.Chmod(e.Paths.ConfigFile(), 0o600)
	cfg, _ := LoadConfig(e.Paths)
	os.Chmod(cfg.ClientKey, 0o644)
	if _, _, err := e.authedClient(); err == nil {
		t.Error("world-readable client key accepted")
	}
}

// Grants with hostile or inconsistent fields are refused before anything reaches ssh.
func TestGrantValidation(t *testing.T) {
	cases := map[string]func(*api.SSHGrant){
		"option address":    func(g *api.SSHGrant) { g.TargetAddress = "-oProxyCommand=touch /tmp/pwned" },
		"space address":     func(g *api.SSHGrant) { g.TargetAddress = "1.2.3.4 -v" },
		"zone address":      func(g *api.SSHGrant) { g.TargetAddress = "fe80::1%eth0" },
		"port 0":            func(g *api.SSHGrant) { g.TargetPort = 0 },
		"port high":         func(g *api.SSHGrant) { g.TargetPort = 70000 },
		"other user":        func(g *api.SSHGrant) { g.LoginUser = "root" },
		"other host":        func(g *api.SSHGrant) { g.TargetHost = "web-1" },
		"two known_hosts":   func(g *api.SSHGrant) { g.KnownHostsLine += "\n" + g.KnownHostsLine },
		"revoked marker":    func(g *api.SSHGrant) { g.KnownHostsLine = "@revoked " + g.KnownHostsLine },
		"garbage known":     func(g *api.SSHGrant) { g.KnownHostsLine = "db-1 ssh-ed25519 !!!" },
		"no certificate":    func(g *api.SSHGrant) { g.Certificate = "" },
		"plain key as cert": func(g *api.SSHGrant) { g.Certificate = strings.SplitN(g.KnownHostsLine, " ", 2)[1] },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeServer(t)
			f.mutateGrant = mut
			e := newTestEnv(t)
			enroll(t, f, e)
			if _, err := e.EnsureSSHCert(context.Background(), sshOpts("x")); err == nil {
				t.Fatal("hostile grant accepted")
			}
			if _, err := os.Stat(filepath.Join(e.Paths.CacheDir, "alice@db-1", grantFile)); !os.IsNotExist(err) {
				t.Error("grant stored")
			}
		})
	}

	// Allowed variants: hostname address, non-standard port, no known_hosts line, IPv6.
	for name, tc := range map[string]struct {
		mut  func(*api.SSHGrant)
		want []string
	}{
		"forgejo port": {func(g *api.SSHGrant) { g.TargetAddress = "build-box"; g.TargetPort = 2222 },
			[]string{"-p", "2222", "--", "alice@build-box"}},
		"no known_hosts": {func(g *api.SSHGrant) { g.KnownHostsLine = "" }, []string{"--", "alice@192.0.2.61"}},
		"ipv6":           {func(g *api.SSHGrant) { g.TargetAddress = "fd00::7" }, []string{"--", "alice@fd00::7"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeServer(t)
			f.mutateGrant = tc.mut
			e := newTestEnv(t)
			enroll(t, f, e)
			p, err := e.EnsureSSHCert(context.Background(), sshOpts("x"))
			if err != nil {
				t.Fatal(err)
			}
			argv, err := BuildSSHArgv(p, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(argv[len(argv)-len(tc.want):], tc.want) {
				t.Errorf("argv tail %q, want %q", argv, tc.want)
			}
			hasKH := strings.Contains(strings.Join(argv, " "), "UserKnownHostsFile")
			if hasKH != (p.KnownHostsPath != "") {
				t.Errorf("UserKnownHostsFile present=%v, known_hosts path %q", hasKH, p.KnownHostsPath)
			}
		})
	}
}

func TestBuildSSHArgvRejectsUnsafe(t *testing.T) {
	base := Prepared{KeyPath: "/run/user/1000/aqmas/a@b/id_ed25519", CertPath: "/run/user/1000/aqmas/a@b/id_ed25519-cert.pub",
		Grant: StoredGrant{LoginUser: "alice", TargetAddress: "192.0.2.61", TargetPort: 22}}
	if _, err := BuildSSHArgv(&base, nil); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Prepared){
		"user option":  func(p *Prepared) { p.Grant.LoginUser = "-oProxyCommand=x" },
		"addr option":  func(p *Prepared) { p.Grant.TargetAddress = "-oProxyCommand=x" },
		"space path":   func(p *Prepared) { p.KeyPath = "/home/a b/key" },
		"percent path": func(p *Prepared) { p.CertPath = "/home/%d/cert" },
		"relative":     func(p *Prepared) { p.KeyPath = "key" },
	} {
		p := base
		mut(&p)
		if _, err := BuildSSHArgv(&p, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseTarget(t *testing.T) {
	if tg, err := ParseTarget("db-1", "alice"); err != nil || tg != (Target{"alice", "db-1"}) {
		t.Errorf("%v %v", tg, err)
	}
	if tg, err := ParseTarget("git@forgejo", "alice"); err != nil || tg != (Target{"git", "forgejo"}) {
		t.Errorf("%v %v", tg, err)
	}
	for _, bad := range []string{"-oProxyCommand=x", "a@-b", "a b", "../x", "root@host;id", "Db-1", "a@b@c", ""} {
		if _, err := ParseTarget(bad, "alice"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDetectTool(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if DetectTool(env(map[string]string{"CLAUDECODE": "1"}), nil, true) != ToolClaudeCode {
		t.Error("claude")
	}
	if DetectTool(env(nil), []string{"OPENCODE_SESSION=1"}, true) != ToolOpenCode {
		t.Error("opencode")
	}
	if DetectTool(env(nil), nil, true) != ToolOwnerCLI || DetectTool(env(nil), nil, false) != ToolOther {
		t.Error("owner/other")
	}
}

// A certificate made the way ssh-keygen -s makes one is parsed and its window checked.
func TestCertValidity(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	upk, _ := ssh.NewPublicKey(userPub)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	opk, _ := ssh.NewPublicKey(otherPub)
	now := time.Unix(1_800_000_000, 0)

	mk := func(after, before time.Time, typ uint32) []byte {
		c := &ssh.Certificate{Key: upk, CertType: typ, KeyId: "aqmas:G1:build-box:db-1", Serial: 1,
			ValidPrincipals: []string{"alice@db-1"}, ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix()),
			Permissions: ssh.Permissions{CriticalOptions: map[string]string{"source-address": "192.0.2.50/32"}, Extensions: map[string]string{"permit-pty": ""}}}
		if err := c.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		return ssh.MarshalAuthorizedKey(c)
	}
	good := mk(now.Add(-time.Minute), now.Add(30*time.Minute), ssh.UserCert)
	c, err := CertValidity(good, upk, now)
	if err != nil || c.KeyId != "aqmas:G1:build-box:db-1" || c.CriticalOptions["source-address"] != "192.0.2.50/32" {
		t.Fatalf("good cert: %v", err)
	}
	if _, err := CertValidity(good, opk, now); err == nil {
		t.Error("cert for another key accepted")
	}
	if _, err := CertValidity(mk(now.Add(-time.Hour), now.Add(-time.Minute), ssh.UserCert), upk, now); err == nil {
		t.Error("expired cert accepted")
	}
	if _, err := CertValidity(mk(now.Add(time.Minute), now.Add(time.Hour), ssh.UserCert), upk, now); err == nil {
		t.Error("not-yet-valid cert accepted")
	}
	if _, err := CertValidity(mk(now.Add(-time.Minute), now.Add(time.Hour), ssh.HostCert), upk, now); err == nil {
		t.Error("host cert accepted")
	}
	inf := &ssh.Certificate{Key: upk, CertType: ssh.UserCert, ValidPrincipals: []string{"alice@db-1"}, ValidBefore: ssh.CertTimeInfinity}
	if err := inf.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if _, err := CertValidity(ssh.MarshalAuthorizedKey(inf), upk, now); err == nil {
		t.Error("unbounded cert accepted")
	}

	// And one signed by the real ssh-keygen, when it is installed.
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		if out, err := exec.Command(keygen, args...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
		}
	}
	run("-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "ca"))
	run("-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "user"))
	run("-q", "-s", filepath.Join(dir, "ca"), "-I", "aqmas:G2:build-box:db-1", "-n", "alice@db-1",
		"-V", "-1m:+30m", "-O", "source-address=192.0.2.50/32", filepath.Join(dir, "user.pub"))
	certText, _ := os.ReadFile(filepath.Join(dir, "user-cert.pub"))
	userText, _ := os.ReadFile(filepath.Join(dir, "user.pub"))
	upk2, _, _, _, _ := ssh.ParseAuthorizedKey(userText)
	c, err = CertValidity(certText, upk2, time.Now())
	if err != nil || c.ValidPrincipals[0] != "alice@db-1" {
		t.Fatalf("ssh-keygen cert: %v", err)
	}
}

func TestKnownHostsFor(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	for _, tc := range []struct {
		line, addr string
		port       int
		want       string
	}{
		{"db-1 " + key, "192.0.2.61", 22, "192.0.2.61,aqmas.db-1 " + key + "\n"},
		{"|1|abc=|def= " + key + " comment", "192.0.2.50", 2222, "[192.0.2.50]:2222,aqmas.db-1 " + key + "\n"},
		{"@cert-authority *.lan " + key, "192.0.2.61", 22, "@cert-authority 192.0.2.61,aqmas.db-1 " + key + "\n"},
	} {
		got, err := KnownHostsFor(tc.line, tc.addr, tc.port, "db-1")
		if err != nil || string(got) != tc.want {
			t.Errorf("KnownHostsFor(%q) = %q, %v; want %q", tc.line, got, err, tc.want)
		}
	}
}

func TestSSHConfigSnippet(t *testing.T) {
	e := newTestEnv(t)
	e.Paths.CacheDir = "/run/user/1000/aqmas"
	s, err := e.SSHConfigSnippet([]string{"db-1", "dev-1"}, "/home/alice/.local/bin/aqmas")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Match originalhost db-1 exec "/home/alice/.local/bin/aqmas cert --quiet --why 'ssh-config: %r@db-1' %r@db-1"`,
		"    CertificateFile /run/user/1000/aqmas/%r@dev-1/id_ed25519-cert.pub",
		"    HostKeyAlias aqmas.dev-1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("snippet lacks %q:\n%s", want, s)
		}
	}
	if _, err := e.SSHConfigSnippet([]string{"bad host"}, "/x"); err == nil {
		t.Error("bad host accepted")
	}
	if _, err := e.SSHConfigSnippet(nil, "/x"); err == nil {
		t.Error("no hosts accepted")
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("ok\x1b[31m\u202ered\n"); got != "ok?[31m?red?" {
		t.Errorf("sanitize = %q", got)
	}
}
