package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
)

const testBase = "https://aqmas.example.com"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// env is one in-process aqmasd with its listeners and an owner passkey.
type env struct {
	t     *testing.T
	s     *Server
	cfg   *config.Config
	clock *fakeClock
	agent *httptest.Server // TLS, client certs verified if given
	web   *httptest.Server // plain HTTP (cloudflared side)
	auth  *vauth.Authenticator
	sess  string // session cookie value
}

func testConfig(dir string) *config.Config {
	cfg := config.Defaults()
	cfg.DataDir = dir
	cfg.PublicBaseURL = testBase
	cfg.OwnerName = "owner"
	cfg.TLSSANs = []string{"127.0.0.1", "localhost"}
	cfg.Targets = []config.Target{
		{Name: "db-1", Address: "192.0.2.61", Port: 22, Users: []string{"alice"},
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGilJAtWZP1K8q90h5+KBdPRC0+wBFVVtHkOZQLmI9jB"},
		{Name: "forgejo", Address: "192.0.2.50", Port: 2222, Users: []string{"git"}, PrincipalOverride: "alice@forgejo"},
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := testConfig(t.TempDir())
	clk := &fakeClock{t: time.Now().UTC().Truncate(time.Second)}
	var logOut io.Writer = io.Discard
	if testing.Verbose() {
		logOut = os.Stderr
	}
	s, err := New(Options{Config: cfg, Now: clk.Now, Logger: slog.New(slog.NewTextHandler(logOut, nil))})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, s: s, cfg: cfg, clock: clk}
	e.agent = httptest.NewUnstartedServer(s.AgentHandler())
	e.agent.TLS = s.PKI().TLSConfig()
	e.agent.StartTLS()
	e.web = httptest.NewServer(s.WebHandler())
	t.Cleanup(func() {
		e.agent.Close()
		e.web.Close()
		s.Close()
	})
	return e
}

// ---- web helpers ----

func (e *env) webDo(method, path string, body any, out any) int {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.web.URL+path, rd)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Aqmas", "1")
		req.Header.Set("Origin", testBase)
	}
	if e.sess != "" {
		req.Header.Set("Cookie", sessionCookie+"="+e.sess)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			e.sess = c.Value
		}
	}
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: decode %q: %v", method, path, b, err)
		}
	}
	if resp.StatusCode/100 != 2 && testing.Verbose() {
		e.t.Logf("%s %s -> %d %s", method, path, resp.StatusCode, b)
	}
	return resp.StatusCode
}

// setupOwner registers the first passkey with an enroll code and logs in.
func (e *env) setupOwner() {
	e.t.Helper()
	code, err := NewEnrollCode(e.cfg.DataDir, e.clock.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	e.auth = vauth.New(testBase)
	var begin struct {
		ChallengeID string          `json:"challenge_id"`
		PublicKey   json.RawMessage `json:"public_key"`
	}
	if st := e.webDo("POST", "/api/ui/passkeys/register/begin", map[string]string{"enroll_code": strings.ToLower(code)}, &begin); st != 200 {
		e.t.Fatalf("register begin: %d", st)
	}
	cred, err := e.auth.Register(begin.PublicKey)
	if err != nil {
		e.t.Fatal(err)
	}
	if st := e.webDo("POST", "/api/ui/passkeys/register/finish", map[string]any{"challenge_id": begin.ChallengeID, "credential": cred, "name": "test"}, nil); st != 200 {
		e.t.Fatalf("register finish: %d", st)
	}
	e.login()
}

func (e *env) login() {
	e.t.Helper()
	var begin struct {
		ChallengeID string          `json:"challenge_id"`
		PublicKey   json.RawMessage `json:"public_key"`
	}
	if st := e.webDo("POST", "/api/ui/login/begin", map[string]any{}, &begin); st != 200 {
		e.t.Fatalf("login begin: %d", st)
	}
	as, err := e.auth.AssertOptions(begin.PublicKey)
	if err != nil {
		e.t.Fatal(err)
	}
	e.sess = ""
	if st := e.webDo("POST", "/api/ui/login/finish", map[string]any{"challenge_id": begin.ChallengeID, "assertion": as}, nil); st != 200 {
		e.t.Fatalf("login finish: %d", st)
	}
	if e.sess == "" {
		e.t.Fatal("no session cookie")
	}
}

// challenge asks for a per-action challenge; returns the response and HTTP status.
func (e *env) challenge(path string, req api.ChallengeRequest) (challengeResp, int) {
	var cr challengeResp
	st := e.webDo("POST", path+"/challenge", req, &cr)
	if st == 200 {
		uiCheck(e.t, cr)
	}
	return cr, st
}

type challengeResp struct {
	ChallengeID string          `json:"challenge_id"`
	Canonical   string          `json:"canonical"`
	PublicKey   json.RawMessage `json:"public_key"`
}

// decide signs the challenge's options with the owner's authenticator and submits it.
func (e *env) decide(path, verb string, cr challengeResp, out any) int {
	e.t.Helper()
	as, err := e.auth.AssertOptions(cr.PublicKey)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.webDo("POST", path+"/"+verb, api.DecideRequest{ChallengeID: cr.ChallengeID, Assertion: as}, out)
}

// approve runs challenge + decide for an object path ("/api/ui/requests/<id>").
func (e *env) approve(path, verb string, req api.ChallengeRequest) int {
	e.t.Helper()
	cr, st := e.challenge(path, req)
	if st != 200 {
		return st
	}
	return e.decide(path, verb, cr, nil)
}

// ---- agent helpers ----

func (e *env) agentClient(cert *tls.Certificate) *http.Client {
	tc := &tls.Config{RootCAs: e.s.PKI().ClientCAPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
	if cert != nil {
		// Always present the certificate, even when the server's acceptable-CA list doesn't name
		// its issuer, so tests exercise the server's verification rather than the client's choice.
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 40 * time.Second}
}

// testPollToken is the enrollment poll token agentDo adds to every enrollment (and presents on
// every GET /v1/enroll/{id}) unless the test sets its own.
const testPollToken = "test-poll-token-0123456789abcdefghij"

func agentDo(t *testing.T, c *http.Client, method, url string, body any, out any) (int, error) {
	t.Helper()
	if er, ok := body.(api.EnrollRequest); ok && er.PollToken == "" {
		er.PollToken = testPollToken
		body = er
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Content-Type", "application/json")
	if method == http.MethodGet && strings.Contains(url, "/v1/enroll/") {
		req.Header.Set(api.EnrollTokenHeader, testPollToken)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("decode %q: %v", b, err)
		}
	}
	return resp.StatusCode, nil
}

func newCSR(t *testing.T, cn string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// enrollHost enrolls a host through the API and the owner's passkey; returns its client cert.
func (e *env) enrollHost(name string) tls.Certificate {
	e.t.Helper()
	key, csr := newCSR(e.t, name)
	anon := e.agentClient(nil)
	var er api.EnrollResponse
	st, err := agentDo(e.t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: name, CSRPEM: csr, Note: "test"}, &er)
	if err != nil || st != 201 {
		e.t.Fatalf("enroll: %d %v", st, err)
	}
	if er.ApproveURL != testBase+"/#r="+er.ID {
		e.t.Fatalf("approve url %q", er.ApproveURL)
	}
	// As the UI does: the card's enrollment.replaces_existing must equal canonical "replaces".
	var state struct {
		Pending []struct {
			ID         string `json:"id"`
			Enrollment *struct {
				CSRFingerprint   string `json:"csr_fingerprint"`
				ReplacesExisting bool   `json:"replaces_existing"`
			} `json:"enrollment"`
		} `json:"pending"`
	}
	e.webDo("GET", "/api/ui/state", nil, &state)
	var card *struct {
		CSRFingerprint   string `json:"csr_fingerprint"`
		ReplacesExisting bool   `json:"replaces_existing"`
	}
	for _, p := range state.Pending {
		if p.ID == er.ID {
			card = p.Enrollment
		}
	}
	if card == nil {
		e.t.Fatal("enrollment card missing from state")
	}
	cr, st := e.challenge("/api/ui/enrollments/"+er.ID, api.ChallengeRequest{Action: "approve"})
	if st != 200 {
		e.t.Fatalf("enrollment challenge: %d", st)
	}
	c := uiCheck(e.t, cr)
	if c["replaces"] != card.ReplacesExisting || c["key_fingerprint"] != card.CSRFingerprint || c["requesting_host"] != name || c["kind"] != "enrollment" {
		e.t.Fatalf("enrollment canonical %v vs card %+v", c, card)
	}
	if st := e.decide("/api/ui/enrollments/"+er.ID, "decide", cr, nil); st != 200 {
		e.t.Fatalf("approve enrollment: %d", st)
	}
	var es api.EnrollStatus
	if st, err := agentDo(e.t, anon, "GET", e.agent.URL+"/v1/enroll/"+er.ID+"?wait=1s", nil, &es); err != nil || st != 200 {
		e.t.Fatalf("enroll status: %d %v", st, err)
	}
	if es.Status != "approved" || es.ClientCertPEM == "" || es.CACertPEM == "" {
		e.t.Fatalf("enroll status %+v", es)
	}
	return certFromPEM(e.t, es.ClientCertPEM, key)
}

type tlsCert = tls.Certificate

func certFromPEM(t *testing.T, certPEM string, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatal("bad cert PEM")
	}
	return tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key}
}

func newSSHKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	lastSSHPriv = priv
	return sp, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

// lastSSHPriv is the private key of the most recent newSSHKey (tests are not parallel).
var lastSSHPriv ed25519.PrivateKey

// request creates an SSH access request as host cert.
func (e *env) request(c *http.Client, target, user string, ttl int) (api.RequestCreated, ssh.PublicKey, int) {
	e.t.Helper()
	pub, line := newSSHKey(e.t)
	var rc api.RequestCreated
	st, err := agentDo(e.t, c, "POST", e.agent.URL+"/v1/requests", api.AccessRequest{
		Kind: "ssh", SSH: &api.SSHRequest{TargetHost: target, LoginUser: user, PublicKey: line},
		Reason: "test", TTLSeconds: ttl, Requester: api.Requester{Tool: "other", User: "alice"},
	}, &rc)
	if err != nil {
		e.t.Fatal(err)
	}
	return rc, pub, st
}

func (e *env) status(c *http.Client, id string, wait string) (api.RequestStatus, int) {
	e.t.Helper()
	var rs api.RequestStatus
	u := e.agent.URL + "/v1/requests/" + id
	if wait != "" {
		u += "?wait=" + wait
	}
	st, err := agentDo(e.t, c, "GET", u, nil, &rs)
	if err != nil {
		e.t.Fatal(err)
	}
	return rs, st
}

func mustStatus(t *testing.T, what string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: HTTP %d, want %d", what, got, want)
	}
}

var _ = fmt.Sprintf

func b64url(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
