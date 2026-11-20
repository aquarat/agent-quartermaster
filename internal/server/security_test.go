package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
)

// A valid assertion for challenge A must not decide action B; replays and expired challenges fail;
// decide never takes action parameters from the client.
func TestChallengeBinding(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	host := e.agentClient(ptr(e.enrollHost("build-box")))
	r1, _, _ := e.request(host, "db-1", "alice", 600)
	r2, _, _ := e.request(host, "db-1", "alice", 600)
	p1, p2 := "/api/ui/requests/"+r1.ID, "/api/ui/requests/"+r2.ID

	// Assertion over challenge A (approve r1) submitted with challenge B (deny r2): refused.
	ca, st := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "challenge A", st, 200)
	cb, st := e.challenge(p2, api.ChallengeRequest{Action: "deny"})
	mustStatus(t, "challenge B", st, 200)
	asA, _ := e.auth.AssertOptions(ca.PublicKey)
	mustStatus(t, "A's assertion with B's challenge", e.webDo("POST", p2+"/decide", api.DecideRequest{ChallengeID: cb.ChallengeID, Assertion: asA}, nil), 403)
	// B was consumed by the failed attempt.
	asB, _ := e.auth.AssertOptions(cb.PublicKey)
	mustStatus(t, "B after failed use", e.webDo("POST", p2+"/decide", api.DecideRequest{ChallengeID: cb.ChallengeID, Assertion: asB}, nil), 409)
	// A's challenge id on r2's decide path: refused (object mismatch), and A is spent.
	mustStatus(t, "A on r2 path", e.webDo("POST", p2+"/decide", api.DecideRequest{ChallengeID: ca.ChallengeID, Assertion: asA}, nil), 400)
	mustStatus(t, "A replay on r1", e.webDo("POST", p1+"/decide", api.DecideRequest{ChallengeID: ca.ChallengeID, Assertion: asA}, nil), 409)
	for _, id := range []string{r1.ID, r2.ID} {
		if rs, _ := e.status(host, id, ""); rs.Status != "pending" {
			t.Fatalf("%s decided by a mismatched assertion: %s", id, rs.Status)
		}
	}

	// Replay: the same valid assertion and challenge twice.
	cd, _ := e.challenge(p2, api.ChallengeRequest{Action: "deny"})
	asD, _ := e.auth.AssertOptions(cd.PublicKey)
	// Extra action parameters in the decide body are ignored: the stored action (deny) applies.
	body := map[string]any{"challenge_id": cd.ChallengeID, "assertion": asD, "action": "approve", "ttl_seconds": 28800, "standing_hours": 24}
	var rs api.RequestStatus
	mustStatus(t, "decide deny", e.webDo("POST", p2+"/decide", body, &rs), 200)
	if rs.Status != "denied" {
		t.Fatalf("stored action not applied: %s", rs.Status)
	}
	mustStatus(t, "replay", e.webDo("POST", p2+"/decide", body, nil), 409)

	// Expired challenge (2 min): refused, request stays pending.
	ce, _ := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	e.clock.Advance(2*time.Minute + time.Second)
	mustStatus(t, "expired", e.decide(p1, "decide", ce, nil), 410)
	if rs, _ := e.status(host, r1.ID, ""); rs.Status != "pending" {
		t.Fatalf("expired challenge decided: %s", rs.Status)
	}

	// No user verification: refused.
	cu, _ := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	noUV := e.auth.AssertWith(challengeBytes(t, cu.PublicKey), vauth.AssertOpts{Flags: vauth.FlagUP})
	mustStatus(t, "no UV", e.webDo("POST", p1+"/decide", api.DecideRequest{ChallengeID: cu.ChallengeID, Assertion: noUV}, nil), 403)
	// Wrong origin (phishing page): refused.
	co, _ := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	evil := e.auth.AssertWith(challengeBytes(t, co.PublicKey), vauth.AssertOpts{Origin: "https://aqmas.evil.example"})
	mustStatus(t, "wrong origin", e.webDo("POST", p1+"/decide", api.DecideRequest{ChallengeID: co.ChallengeID, Assertion: evil}, nil), 403)
	// Wrong RP ID: refused.
	cr, _ := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	badRP := e.auth.AssertWith(challengeBytes(t, cr.PublicKey), vauth.AssertOpts{RPID: "evil.example"})
	mustStatus(t, "wrong rp id", e.webDo("POST", p1+"/decide", api.DecideRequest{ChallengeID: cr.ChallengeID, Assertion: badRP}, nil), 403)
	// Sign count regression (cloned authenticator): refused.
	cc, _ := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	savedCount := e.auth.Counter
	e.auth.Counter = 0 // next assertion carries 1, below the stored count
	mustStatus(t, "counter regression", e.decide(p1, "decide", cc, nil), 403)
	e.auth.Counter = savedCount + 5
	// An unregistered authenticator: refused.
	other := vauth.New(testBase)
	other.RPID, other.UserHandle = e.auth.RPID, e.auth.UserHandle
	cx, _ := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "foreign passkey", e.webDo("POST", p1+"/decide", api.DecideRequest{ChallengeID: cx.ChallengeID, Assertion: other.Assert(challengeBytes(t, cx.PublicKey))}, nil), 403)

	// Approver can shorten, never lengthen.
	_, st = e.challenge(p1, api.ChallengeRequest{Action: "approve", TTLSeconds: 601})
	mustStatus(t, "lengthen ttl", st, 400)
	_, st = e.challenge(p1, api.ChallengeRequest{Action: "approve", StandingHours: 25})
	mustStatus(t, "standing too long", st, 400)

	// A challenge issued to one session can't be used from another.
	cs, _ := e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	first := e.sess
	e.login()
	if e.sess == first {
		t.Fatal("login did not rotate the session")
	}
	mustStatus(t, "other session", e.decide(p1, "decide", cs, nil), 403)
	// Logged out: no decisions at all.
	mustStatus(t, "logout", e.webDo("POST", "/api/ui/logout", map[string]any{}, nil), 200)
	_, st = e.challenge(p1, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "challenge after logout", st, 401)

	// A proper approval still works afterwards.
	e.login()
	mustStatus(t, "approve", e.approve(p1, "decide", api.ChallengeRequest{Action: "approve", TTLSeconds: 120}), 200)
	if rs, _ := e.status(host, r1.ID, ""); rs.Status != "approved" || rs.Grant.NotAfter.Sub(rs.Grant.NotBefore) != 3*time.Minute {
		t.Fatalf("approve: %+v", rs)
	}
	// And it can't be decided again.
	_, st = e.challenge(p1, api.ChallengeRequest{Action: "deny"})
	mustStatus(t, "challenge on decided", st, 409)
}

func challengeBytes(t *testing.T, opts json.RawMessage) []byte {
	t.Helper()
	var o struct {
		Challenge string `json:"challenge"`
	}
	json.Unmarshal(opts, &o)
	b, err := b64url(o.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ptr[T any](v T) *T { return &v }

func TestCSRFAndHeaders(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	post := func(hdr map[string]string) int {
		req, _ := http.NewRequest("POST", e.web.URL+"/api/ui/logout", strings.NewReader("{}"))
		req.Header.Set("Cookie", sessionCookie+"="+e.sess)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	mustStatus(t, "no custom header", post(map[string]string{"Content-Type": "application/json"}), 403)
	mustStatus(t, "form post", post(map[string]string{"X-Aqmas": "1", "Content-Type": "application/x-www-form-urlencoded"}), 400)
	mustStatus(t, "cross origin", post(map[string]string{"X-Aqmas": "1", "Content-Type": "application/json", "Origin": "https://evil.example"}), 403)
	mustStatus(t, "cross site", post(map[string]string{"X-Aqmas": "1", "Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}), 403)

	resp, err := http.Get(e.web.URL + "/requests/abc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("SPA route: %d %v", resp.StatusCode, resp.Header)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP %q", csp)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", resp.Header)
	}

	// Login sets a hardened cookie; only its hash is stored.
	req, _ := http.NewRequest("POST", e.web.URL+"/api/ui/login/begin", strings.NewReader("{}"))
	req.Header.Set("X-Aqmas", "1")
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	var begin ceremonyBegin
	json.NewDecoder(resp.Body).Decode(&begin)
	resp.Body.Close()
	pk, _ := json.Marshal(begin.PublicKey)
	as, _ := e.auth.AssertOptions(pk)
	b, _ := json.Marshal(map[string]any{"challenge_id": begin.ChallengeID, "assertion": as})
	req, _ = http.NewRequest("POST", e.web.URL+"/api/ui/login/finish", bytes.NewReader(b))
	req.Header.Set("X-Aqmas", "1")
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"__Host-aqmas_session=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(sc, want) {
			t.Fatalf("cookie %q lacks %s", sc, want)
		}
	}
	val := strings.TrimPrefix(strings.SplitN(sc, ";", 2)[0], sessionCookie+"=")
	var n int
	e.s.store.Q().ExpireStale(t.Context(), e.clock.Now())
	if err := e.s.store.DB().QueryRow("SELECT count(*) FROM web_sessions WHERE hash = ?", val).Scan(&n); err != nil || n != 0 {
		t.Fatalf("raw cookie value stored in DB (n=%d err=%v)", n, err)
	}
}

// mTLS attribution: certs from another CA are refused, revoked (replaced) hosts are refused.
func TestMTLSAttribution(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()

	// No client cert.
	_, _, st := e.request(e.agentClient(nil), "db-1", "alice", 0)
	mustStatus(t, "no client cert", st, 401)

	// A cert from another CA, even with an enrolled host's name: TLS handshake refused.
	good := e.enrollHost("build-box")
	rogue := selfSignedClient(t, "build-box")
	if st, err := agentDo(t, e.agentClient(&rogue), "GET", e.agent.URL+"/v1/grants", nil, nil); err == nil {
		t.Fatalf("certificate from another CA accepted (HTTP %d)", st)
	}
	// The server's own TLS certificate (same CA, serverAuth only) is not a client identity.
	srvCert := e.s.PKI().ServerCert
	if st, err := agentDo(t, e.agentClient(&srvCert), "GET", e.agent.URL+"/v1/grants", nil, nil); err == nil {
		t.Fatalf("server certificate accepted as a client certificate (HTTP %d)", st)
	}

	// Requests are attributed to the enrolled host.
	hc := e.agentClient(&good)
	rc, _, st := e.request(hc, "db-1", "alice", 0)
	mustStatus(t, "create", st, 201)
	var state api.UIState
	e.webDo("GET", "/api/ui/state", nil, &state)
	if state.Pending[0].ID != rc.ID || state.Pending[0].RequestingHost != "build-box" || state.Pending[0].TTLRequested != 1800 {
		t.Fatalf("attribution %+v", state.Pending[0])
	}

	// Re-enrolling the name replaces (revokes) the old identity.
	replacement := e.enrollHost("build-box")
	_, _, st = e.request(hc, "db-1", "alice", 0)
	mustStatus(t, "revoked host", st, 403)
	_, st = e.status(hc, rc.ID, "")
	mustStatus(t, "revoked host status", st, 403)
	_, _, st = e.request(e.agentClient(&replacement), "db-1", "alice", 0)
	mustStatus(t, "replacement host", st, 201)
}

func selfSignedClient(t *testing.T, cn string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestHostIsolation(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	a := e.agentClient(ptr(e.enrollHost("hosta")))
	b := e.agentClient(ptr(e.enrollHost("hostb")))
	ra, _, st := e.request(a, "db-1", "alice", 0)
	mustStatus(t, "create", st, 201)
	mustStatus(t, "approve", e.approve("/api/ui/requests/"+ra.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)

	_, st = e.status(b, ra.ID, "")
	mustStatus(t, "host B reads host A's request", st, 404)
	rs, st := e.status(a, ra.ID, "")
	mustStatus(t, "host A reads its request", st, 200)
	if rs.Grant == nil {
		t.Fatal("no grant for owner host")
	}
	var gl api.GrantList
	agentDo(t, b, "GET", e.agent.URL+"/v1/grants", nil, &gl)
	if len(gl.Grants) != 0 {
		t.Fatalf("host B sees grants %+v", gl)
	}
	_, st = e.status(b, "01NOTEXISTING00000000000000", "")
	mustStatus(t, "missing", st, 404)
}

func TestRequestValidation(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("build-box")))
	_, _, st := e.request(c, "unknown", "alice", 0)
	mustStatus(t, "unknown target", st, 400)
	_, _, st = e.request(c, "db-1", "root", 0)
	mustStatus(t, "user not configured", st, 400)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rp, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ep, _ := ssh.NewPublicKey(&ek.PublicKey)
	for name, line := range map[string]string{
		"rsa":   string(ssh.MarshalAuthorizedKey(rp)),
		"ecdsa": string(ssh.MarshalAuthorizedKey(ep)),
		"junk":  "ssh-ed25519 AAAA",
		"opts":  `command="x" ` + string(ssh.MarshalAuthorizedKey(rp)),
	} {
		st, _ := agentDo(t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{Kind: "ssh",
			SSH: &api.SSHRequest{TargetHost: "db-1", LoginUser: "alice", PublicKey: line}, Requester: api.Requester{Tool: "other"}}, nil)
		mustStatus(t, name+" key", st, 400)
	}
	_, line := newSSHKey(t)
	st, _ = agentDo(t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{Kind: "ssh",
		SSH: &api.SSHRequest{TargetHost: "db-1", LoginUser: "alice", PublicKey: line}, Reason: strings.Repeat("x", 501)}, nil)
	mustStatus(t, "long reason", st, 400)
	st, _ = agentDo(t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{Kind: "github"}, nil)
	mustStatus(t, "unknown kind", st, 400)

	// TTL is clamped to policy.
	rc, _, st := e.request(c, "db-1", "alice", 999999)
	mustStatus(t, "huge ttl", st, 201)
	var item api.PendingItem
	e.webDo("GET", "/api/ui/requests/"+rc.ID, nil, &item)
	if item.TTLRequested != 28800 {
		t.Fatalf("ttl not clamped: %d", item.TTLRequested)
	}
	rc, _, _ = e.request(c, "db-1", "alice", 5)
	e.webDo("GET", "/api/ui/requests/"+rc.ID, nil, &item)
	if item.TTLRequested != 60 {
		t.Fatalf("ttl not raised to min: %d", item.TTLRequested)
	}

	// Forgejo target: principal is the Forgejo user name.
	rc, _, _ = e.request(c, "forgejo", "git", 0)
	mustStatus(t, "approve forgejo", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
	rs, _ := e.status(c, rc.ID, "")
	if rs.Grant == nil || len(rs.Grant.SSH.Principals) != 1 || rs.Grant.SSH.Principals[0] != "alice" || rs.Grant.SSH.TargetPort != 2222 {
		t.Fatalf("forgejo grant %+v", rs.Grant)
	}
}

func TestStandingApproval(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	a := e.agentClient(ptr(e.enrollHost("hosta")))
	b := e.agentClient(ptr(e.enrollHost("hostb")))
	r0, _, _ := e.request(a, "db-1", "alice", 1200)
	mustStatus(t, "approve with standing", e.approve("/api/ui/requests/"+r0.ID, "decide",
		api.ChallengeRequest{Action: "approve", TTLSeconds: 600, StandingHours: 2}), 200)

	var state api.UIState
	e.webDo("GET", "/api/ui/state", nil, &state)
	if len(state.Standing) != 1 || state.Standing[0].MaxTTLSeconds != 600 || state.Standing[0].RequestingHost != "hosta" {
		t.Fatalf("standing %+v", state.Standing)
	}
	sid := state.Standing[0].ID

	r1, _, _ := e.request(a, "db-1", "alice", 600)
	if r1.Status != "approved" {
		t.Fatalf("matching request not auto-approved: %s", r1.Status)
	}
	if rs, _ := e.status(a, r1.ID, ""); rs.Grant == nil || rs.Grant.SSH.Certificate == "" {
		t.Fatal("auto-approved request has no certificate")
	}
	for name, c := range map[string]struct {
		cl     *http.Client
		target string
		user   string
		ttl    int
	}{
		"longer ttl":  {a, "db-1", "alice", 601},
		"other host":  {b, "db-1", "alice", 600},
		"other tgt":   {a, "forgejo", "git", 600},
		"default ttl": {a, "db-1", "alice", 0}, // 1800 > 600
	} {
		rc, _, _ := e.request(c.cl, c.target, c.user, c.ttl)
		if rc.Status != "pending" {
			t.Fatalf("%s: auto-approved", name)
		}
	}
	e.webDo("GET", "/api/ui/state", nil, &state)
	if state.Standing[0].Uses != 1 {
		t.Fatalf("uses %d", state.Standing[0].Uses)
	}
	found := false
	for _, en := range state.Recent {
		if en.Action == "auto_approve" && en.Object == "request:"+r1.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("auto-approval not audited")
	}

	// Revoke: subsequent matching requests are pending again.
	mustStatus(t, "revoke standing", e.approve("/api/ui/standing/"+sid, "revoke", api.ChallengeRequest{Action: "revoke"}), 200)
	if rc, _, _ := e.request(a, "db-1", "alice", 600); rc.Status != "pending" {
		t.Fatal("revoked standing approval still used")
	}

	// Expiry.
	r2, _, _ := e.request(a, "db-1", "alice", 600)
	mustStatus(t, "approve with standing", e.approve("/api/ui/requests/"+r2.ID, "decide",
		api.ChallengeRequest{Action: "approve", StandingHours: 1}), 200)
	if rc, _, _ := e.request(a, "db-1", "alice", 600); rc.Status != "approved" {
		t.Fatal("new standing approval not used")
	}
	e.clock.Advance(time.Hour + time.Second)
	e.login()
	if rc, _, _ := e.request(a, "db-1", "alice", 600); rc.Status != "pending" {
		t.Fatal("expired standing approval still used")
	}
}

func TestEnrollmentAndPasskeyBootstrap(t *testing.T) {
	e := newEnv(t)
	// No passkey: login impossible, register without a code refused.
	mustStatus(t, "login without passkey", e.webDo("POST", "/api/ui/login/begin", map[string]any{}, nil), 409)
	mustStatus(t, "register without code", e.webDo("POST", "/api/ui/passkeys/register/begin", map[string]any{}, nil), 403)
	mustStatus(t, "register bad code", e.webDo("POST", "/api/ui/passkeys/register/begin", map[string]any{"enroll_code": "AAAA-BBBB"}, nil), 403)
	code, err := NewEnrollCode(e.cfg.DataDir, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(16 * time.Minute)
	mustStatus(t, "expired code", e.webDo("POST", "/api/ui/passkeys/register/begin", map[string]any{"enroll_code": code}, nil), 403)

	e.setupOwner()
	// A second enroll code can't add a passkey once one exists (needs session + assertion).
	code2, _ := NewEnrollCode(e.cfg.DataDir, e.clock.Now())
	saved := e.sess
	e.sess = ""
	mustStatus(t, "code with passkey present", e.webDo("POST", "/api/ui/passkeys/register/begin", map[string]any{"enroll_code": code2}, nil), 401)
	e.sess = saved
	mustStatus(t, "session without assertion", e.webDo("POST", "/api/ui/passkeys/register/begin", map[string]any{}, nil), 400)
	// With an assertion over a passkey/register challenge it works.
	cr, st := e.challenge("/api/ui/passkeys", api.ChallengeRequest{Action: "register"})
	mustStatus(t, "passkey challenge", st, 200)
	as, _ := e.auth.AssertOptions(cr.PublicKey)
	var begin struct {
		ChallengeID string          `json:"challenge_id"`
		PublicKey   json.RawMessage `json:"public_key"`
	}
	mustStatus(t, "second passkey begin", e.webDo("POST", "/api/ui/passkeys/register/begin", map[string]any{"challenge_id": cr.ChallengeID, "assertion": as}, &begin), 200)
	second := vauth.New(testBase)
	cred, _ := second.Register(begin.PublicKey)
	mustStatus(t, "second passkey finish", e.webDo("POST", "/api/ui/passkeys/register/finish", map[string]any{"challenge_id": begin.ChallengeID, "credential": cred}, nil), 200)
	var state api.UIState
	e.webDo("GET", "/api/ui/state", nil, &state)
	if state.Owner.Passkeys != 2 {
		t.Fatalf("passkeys %d", state.Owner.Passkeys)
	}

	// Enrollment certificate is returned once; denied enrollments yield nothing.
	anon := e.agentClient(nil)
	_, csr := newCSR(t, "x")
	var er api.EnrollResponse
	st, _ = agentDo(t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: "Bad_Name", CSRPEM: csr}, nil)
	mustStatus(t, "bad hostname", st, 400)
	st, _ = agentDo(t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: "newhost", CSRPEM: "junk"}, nil)
	mustStatus(t, "bad csr", st, 400)
	agentDo(t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: "newhost", CSRPEM: csr}, &er)
	mustStatus(t, "deny enrollment", e.approve("/api/ui/enrollments/"+er.ID, "decide", api.ChallengeRequest{Action: "deny"}), 200)
	var es api.EnrollStatus
	agentDo(t, anon, "GET", e.agent.URL+"/v1/enroll/"+er.ID, nil, &es)
	if es.Status != "denied" || es.ClientCertPEM != "" {
		t.Fatalf("denied enrollment %+v", es)
	}
	agentDo(t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: "newhost", CSRPEM: csr}, &er)
	mustStatus(t, "approve enrollment", e.approve("/api/ui/enrollments/"+er.ID, "decide", api.ChallengeRequest{Action: "approve"}), 200)
	agentDo(t, anon, "GET", e.agent.URL+"/v1/enroll/"+er.ID, nil, &es)
	if es.ClientCertPEM == "" {
		t.Fatal("no cert on first fetch")
	}
	es = api.EnrollStatus{}
	agentDo(t, anon, "GET", e.agent.URL+"/v1/enroll/"+er.ID, nil, &es)
	if es.Status != "approved" || es.ClientCertPEM != "" {
		t.Fatalf("cert returned twice: %+v", es)
	}
}

func TestLongPollWakesOnDecision(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("build-box")))
	rc, _, _ := e.request(c, "db-1", "alice", 0)
	done := make(chan api.RequestStatus, 1)
	start := time.Now()
	go func() {
		rs, _ := e.status(c, rc.ID, "20s")
		done <- rs
	}()
	time.Sleep(200 * time.Millisecond)
	mustStatus(t, "deny", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "deny"}), 200)
	select {
	case rs := <-done:
		if rs.Status != "denied" || time.Since(start) > 10*time.Second {
			t.Fatalf("long poll: %+v after %v", rs, time.Since(start))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("long poll did not wake")
	}
}
