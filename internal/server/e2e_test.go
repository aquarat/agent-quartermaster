package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// TestEndToEnd: in-process server, owner passkey via a software authenticator, host enrollment
// (key + CSR), SSH request approved with a per-action assertion, certificate verified with
// x/crypto/ssh.
func TestEndToEnd(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()

	var state api.UIState
	mustStatus(t, "state", e.webDo("GET", "/api/ui/state", nil, &state), 200)
	if state.Owner.Passkeys != 1 {
		t.Fatalf("passkeys = %d", state.Owner.Passkeys)
	}

	cert := e.enrollHost("build-box")
	host := e.agentClient(&cert)

	rc, pub, st := e.request(host, "db-1", "alice", 600)
	mustStatus(t, "create request", st, 201)
	if rc.Status != "pending" || rc.ApproveURL != testBase+"/requests/"+rc.ID {
		t.Fatalf("created %+v", rc)
	}

	// The UI sees it pending.
	mustStatus(t, "state", e.webDo("GET", "/api/ui/state", nil, &state), 200)
	if len(state.Pending) != 1 || state.Pending[0].ID != rc.ID || state.Pending[0].RequestingHost != "build-box" ||
		state.Pending[0].RequestingAddress != "127.0.0.1" || state.Pending[0].SSH.KeyFingerprint != ssh.FingerprintSHA256(pub) {
		t.Fatalf("pending %+v", state.Pending)
	}

	// Approval happens later than the request: validity must start from approval.
	e.clock.Advance(3 * time.Minute)
	approvedAt := e.clock.Now()
	cr, st := e.challenge("/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300})
	mustStatus(t, "challenge", st, 200)
	for _, want := range []string{`"action":"approve"`, `"id":"` + rc.ID + `"`, `"ttl_seconds":300`, `"login_user":"alice"`, `"target":"db-1"`, `"requesting_host":"build-box"`} {
		if !strings.Contains(cr.Canonical, want) {
			t.Fatalf("canonical %s lacks %s", cr.Canonical, want)
		}
	}
	var decided api.RequestStatus
	mustStatus(t, "decide", e.decide("/api/ui/requests/"+rc.ID, "decide", cr, &decided), 200)
	if decided.Status != "approved" || decided.Grant != nil {
		t.Fatalf("decide response %+v (must not carry the certificate)", decided)
	}

	rs, st := e.status(host, rc.ID, "5s")
	mustStatus(t, "status", st, 200)
	if rs.Status != "approved" || rs.Grant == nil || rs.Grant.SSH == nil {
		t.Fatalf("status %+v", rs)
	}
	g := rs.Grant.SSH
	if g.TargetAddress != "192.0.2.61" || g.TargetPort != 22 || g.LoginUser != "alice" || !strings.HasPrefix(g.KnownHostsLine, "db-1,192.0.2.61 ssh-ed25519 ") {
		t.Fatalf("grant %+v", g)
	}

	// Verify the certificate with x/crypto/ssh.
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(g.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	c, ok := k.(*ssh.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %T", k)
	}
	caPub := e.s.PKI().SSHSigner.PublicKey()
	checker := &ssh.CertChecker{
		IsUserAuthority:          func(auth ssh.PublicKey) bool { return string(auth.Marshal()) == string(caPub.Marshal()) },
		Clock:                    func() time.Time { return approvedAt.Add(time.Minute) },
		SupportedCriticalOptions: []string{"source-address"},
	}
	if !checker.IsUserAuthority(c.SignatureKey) {
		t.Fatal("certificate not signed by the aqmas SSH CA")
	}
	if err := checker.CheckCert("alice@db-1", c); err != nil {
		t.Fatalf("CheckCert: %v", err)
	}
	if string(c.Key.Marshal()) != string(pub.Marshal()) {
		t.Fatal("certificate is not for the requested key")
	}
	if c.CertType != ssh.UserCert || !slices.Equal(c.ValidPrincipals, []string{"alice@db-1"}) {
		t.Fatalf("type/principals %v %v", c.CertType, c.ValidPrincipals)
	}
	if got := c.CriticalOptions["source-address"]; got != "127.0.0.1/32" {
		t.Fatalf("source-address %q", got)
	}
	if !time.Unix(int64(c.ValidAfter), 0).Equal(approvedAt.Add(-time.Minute)) || !time.Unix(int64(c.ValidBefore), 0).Equal(approvedAt.Add(300*time.Second)) {
		t.Fatalf("validity %v..%v, approved %v", time.Unix(int64(c.ValidAfter), 0), time.Unix(int64(c.ValidBefore), 0), approvedAt)
	}
	if !strings.HasPrefix(c.KeyId, "aqmas:"+rs.Grant.ID+":build-box:db-1") || c.Serial == 0 {
		t.Fatalf("key id %q serial %d", c.KeyId, c.Serial)
	}
	if _, ok := c.Extensions["permit-pty"]; !ok {
		t.Fatal("permit-pty missing")
	}
	if _, ok := c.Extensions["permit-agent-forwarding"]; ok {
		t.Fatal("agent forwarding must be off")
	}
	// Expired outside its window.
	checker.Clock = func() time.Time { return approvedAt.Add(301 * time.Second) }
	if err := checker.CheckCert("alice@db-1", c); err == nil {
		t.Fatal("certificate valid after expiry")
	}
	// A real SSH handshake against an x/crypto/ssh server trusting the CA: accepted from the
	// requester's address, refused from another (source-address), refused for another principal.
	checker.Clock = func() time.Time { return approvedAt }
	priv := lastSSHPriv
	if err := sshLogin(t, checker, c, priv, "127.0.0.1", "alice@db-1"); err != nil {
		t.Fatalf("ssh login from requester address: %v", err)
	}
	if err := sshLogin(t, checker, c, priv, "127.0.0.2", "alice@db-1"); err == nil {
		t.Fatal("ssh login accepted from another source address")
	}
	if err := sshLogin(t, checker, c, priv, "127.0.0.1", "root@db-1"); err == nil {
		t.Fatal("ssh login accepted for another principal")
	}

	// Grants list shows it, without the certificate.
	var gl api.GrantList
	st, _ = agentDo(t, host, "GET", e.agent.URL+"/v1/grants?active=1", nil, &gl)
	mustStatus(t, "grants", st, 200)
	if len(gl.Grants) != 1 || gl.Grants[0].ID != rs.Grant.ID || gl.Grants[0].Status != "approved" {
		t.Fatalf("grants %+v", gl)
	}

	// Audit trail exists and holds no certificate or key material.
	mustStatus(t, "state", e.webDo("GET", "/api/ui/state", nil, &state), 200)
	for _, a := range state.Recent {
		if strings.Contains(a.Detail, "BEGIN") || strings.Contains(a.Detail, "-cert-v01") || strings.Contains(a.Detail, e.sess) {
			t.Fatalf("audit leaks material: %+v", a)
		}
	}
}

// sshLogin runs an SSH server (x/crypto/ssh) that authenticates users with checker, and logs in
// as user with cert from local address src. The SSH user name is the principal, as with an
// AuthorizedPrincipalsFile that lists "<user>@<host>".
func sshLogin(t *testing.T, checker *ssh.CertChecker, cert *ssh.Certificate, priv ed25519.PrivateKey, src, user string) error {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	scfg := &ssh.ServerConfig{PublicKeyCallback: checker.Authenticate}
	scfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc, chans, reqs, err := ssh.NewServerConn(conn, scfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				ch.Reject(ssh.Prohibited, "no")
			}
		}()
		sc.Wait()
	}()
	signer, _ := ssh.NewSignerFromKey(priv)
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatal(err)
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot dial from %s: %v", src, err)
	}
	ccfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()), Timeout: 5 * time.Second}
	cc, _, _, err := ssh.NewClientConn(conn, ln.Addr().String(), ccfg)
	if err != nil {
		conn.Close()
		return err
	}
	cc.Close()
	return nil
}
