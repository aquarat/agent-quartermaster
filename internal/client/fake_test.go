package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// testCA is an x509 CA for tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64 = 100

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

// issue signs a leaf for pub.
func (ca *testCA) issue(t *testing.T, cn string, pub any, eku []x509.ExtKeyUsage, ips []net.IP) *x509.Certificate {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type fakeReq struct {
	req       api.AccessRequest
	host      string
	polls     int
	granted   *api.Grant
	cancelled bool
	revoked   bool
	auto      bool // approved at creation (cf.read / cf.cache.purge in proxy mode)
	delivered bool // token mode: the token went out once
}

// fakeServer implements the agent API (docs/API.md section 1) from internal/api types.
type fakeServer struct {
	t        *testing.T
	srv      *httptest.Server
	serverCA *testCA
	clientCA *testCA
	sshCA    ssh.Signer
	// publishedSSHCA, when set, is what GET /v1/ssh-ca returns instead of sshCA.
	publishedSSHCA ssh.Signer

	mu sync.Mutex
	// enrollment behaviour
	enrollPending  int    // pending answers before the decision
	enrollDecision string // approved / denied / expired
	enrollCSR      map[string]*x509.CertificateRequest
	enrollToken    map[string]string
	enrollPolls    map[string]int
	enrollPosts    int
	// request behaviour
	requestPending  int    // pending answers before the decision
	requestDecision string // approved / denied / expired
	decisionNote    string
	certTTL         time.Duration
	knownHostsLine  string
	targetAddress   string
	targetPort      int
	mutateGrant     func(*api.SSHGrant)
	requests        map[string]*fakeReq
	created         int
	unauthenticated int

	cf fakeCF // milestone 2: Cloudflare (cf_fake_test.go)
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshCA, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	hostPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := ssh.NewPublicKey(hostPub)
	f := &fakeServer{
		t:               t,
		serverCA:        newTestCA(t, "aqmas server CA"),
		clientCA:        newTestCA(t, "aqmas client CA"),
		sshCA:           sshCA,
		enrollDecision:  api.StatusApproved,
		enrollCSR:       map[string]*x509.CertificateRequest{},
		enrollToken:     map[string]string{},
		enrollPolls:     map[string]int{},
		requestDecision: api.StatusApproved,
		certTTL:         30 * time.Minute,
		knownHostsLine:  "db-1 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hk))),
		targetAddress:   "192.0.2.61",
		targetPort:      22,
		requests:        map[string]*fakeReq{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", f.handleEnroll)
	mux.HandleFunc("GET /v1/enroll/{id}", f.handleEnrollStatus)
	mux.HandleFunc("POST /v1/requests", f.handleCreate)
	mux.HandleFunc("GET /v1/requests/{id}", f.handleRequestStatus)
	mux.HandleFunc("GET /v1/grants", f.handleGrants)
	mux.HandleFunc("POST /v1/requests/{id}/cancel", f.handleCancel)
	mux.HandleFunc("GET /v1/ssh-ca", f.handleSSHCA)
	mux.HandleFunc("GET /v1/ssh-target", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		name := r.URL.Query().Get("target")
		if name == f.targetAddress || name == "db-alias" {
			name = "db-1"
		}
		writeJSON(w, 200, api.ResolvedTarget{Name: name, Address: f.targetAddress, Port: f.targetPort, MaxSeconds: 28800})
	})
	f.setupCF(mux)
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // handshake failures are expected in some tests

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := f.serverCA.issue(t, "aqmasd", &leafKey.PublicKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	pool := x509.NewCertPool()
	pool.AddCert(f.clientCA.cert)
	f.srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, f.serverCA.cert.Raw}, PrivateKey: leafKey, Leaf: leaf}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) URL() string { return f.srv.URL }
func (f *fakeServer) pin() string { return FormatPin(CertPin(f.serverCA.cert)) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, code int, c, msg string) {
	writeJSON(w, code, api.Error{Code: c, Message: msg})
}

func (f *fakeServer) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErr(w, 400, "bad_request", err.Error())
		return
	}
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil {
		apiErr(w, 400, "bad_request", "no csr")
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != req.Hostname {
		apiErr(w, 400, "bad_request", "bad csr")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrollPosts++
	id := fmt.Sprintf("ENR%04d", f.enrollPosts)
	f.enrollCSR[id] = csr
	if len(req.PollToken) < 32 {
		f.t.Errorf("fake server: enrollment without a poll token")
	}
	f.enrollToken[id] = req.PollToken
	writeJSON(w, 201, api.EnrollResponse{ID: id, Status: api.StatusPending, ApproveURL: "https://aqmas.example/enroll/" + id, PollAfterMS: 1})
}

func (f *fakeServer) handleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f.mu.Lock()
	defer f.mu.Unlock()
	csr, ok := f.enrollCSR[id]
	if !ok || r.Header.Get(api.EnrollTokenHeader) != f.enrollToken[id] {
		apiErr(w, 404, "not_found", "no such enrollment")
		return
	}
	f.enrollPolls[id]++
	if f.enrollPolls[id] <= f.enrollPending {
		writeJSON(w, 200, api.EnrollStatus{ID: id, Status: api.StatusPending})
		return
	}
	if f.enrollDecision != api.StatusApproved {
		writeJSON(w, 200, api.EnrollStatus{ID: id, Status: f.enrollDecision})
		return
	}
	if f.enrollPolls[id] > f.enrollPending+1 { // cert only once
		writeJSON(w, 200, api.EnrollStatus{ID: id, Status: api.StatusApproved})
		return
	}
	cert := f.clientCA.issue(f.t, csr.Subject.CommonName, csr.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	writeJSON(w, 200, api.EnrollStatus{
		ID: id, Status: api.StatusApproved,
		ClientCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		CACertPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.clientCA.cert.Raw})),
	})
}

func (f *fakeServer) host(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		f.mu.Lock()
		f.unauthenticated++
		f.mu.Unlock()
		apiErr(w, 401, "unauthenticated", "client certificate required")
		return "", false
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName, true
}

func (f *fakeServer) handleCreate(w http.ResponseWriter, r *http.Request) {
	host, ok := f.host(w, r)
	if !ok {
		return
	}
	var req api.AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErr(w, 400, "bad_request", "bad request")
		return
	}
	if req.Kind == api.KindCloudflare {
		f.createCF(w, host, req)
		return
	}
	if req.Kind != api.KindSSH || req.SSH == nil {
		apiErr(w, 400, "bad_request", "bad request")
		return
	}
	if req.SSH.TargetHost == "unknownhost" {
		apiErr(w, 404, "not_found", "unknown target \x1b[31mred")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created++
	id := fmt.Sprintf("REQ%04d", f.created)
	f.requests[id] = &fakeReq{req: req, host: host}
	writeJSON(w, 201, api.RequestCreated{ID: id, Status: api.StatusPending, ApproveURL: "https://aqmas.example/r/" + id, PollAfterMS: 1, ExpiresAt: time.Now().Add(10 * time.Minute)})
}

func (f *fakeServer) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	host, ok := f.host(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	f.mu.Lock()
	defer f.mu.Unlock()
	fr, ok := f.requests[id]
	if !ok || fr.host != host {
		apiErr(w, 404, "not_found", "no such request")
		return
	}
	fr.polls++
	if fr.req.Kind == api.KindCloudflare {
		f.statusCF(w, id, fr)
		return
	}
	if fr.cancelled {
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: api.KindSSH, Status: api.StatusCancelled})
		return
	}
	if fr.revoked {
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: api.KindSSH, Status: api.StatusRevoked})
		return
	}
	if fr.polls <= f.requestPending {
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: api.KindSSH, Status: api.StatusPending})
		return
	}
	if f.requestDecision != api.StatusApproved {
		now := time.Now()
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: api.KindSSH, Status: f.requestDecision, DecidedAt: &now, DecisionNote: f.decisionNote})
		return
	}
	if fr.granted == nil {
		fr.granted = f.sign(id, fr)
	}
	writeJSON(w, 200, api.RequestStatus{ID: id, Kind: api.KindSSH, Status: api.StatusApproved, Grant: fr.granted})
}

func (f *fakeServer) handleCancel(w http.ResponseWriter, r *http.Request) {
	host, ok := f.host(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	f.mu.Lock()
	defer f.mu.Unlock()
	fr, ok := f.requests[id]
	if !ok || fr.host != host {
		apiErr(w, 404, "not_found", "no such request")
		return
	}
	if fr.granted != nil {
		apiErr(w, 409, "conflict", "request is approved")
		return
	}
	fr.cancelled = true
	writeJSON(w, 200, api.RequestStatus{ID: id, Kind: api.KindSSH, Status: api.StatusCancelled})
}

func (f *fakeServer) handleSSHCA(w http.ResponseWriter, r *http.Request) {
	if _, ok := f.host(w, r); !ok {
		return
	}
	ca := f.sshCA
	if f.publishedSSHCA != nil {
		ca = f.publishedSSHCA
	}
	writeJSON(w, 200, api.SSHCA{PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey()))), Fingerprint: ssh.FingerprintSHA256(ca.PublicKey())})
}

func (f *fakeServer) sign(id string, fr *fakeReq) *api.Grant {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fr.req.SSH.PublicKey))
	if err != nil {
		f.t.Errorf("fake server: bad public key: %v", err)
		return nil
	}
	now := time.Now()
	principal := fr.req.SSH.LoginUser + "@" + fr.req.SSH.TargetHost
	cert := &ssh.Certificate{
		Key:             pk,
		Serial:          uint64(len(f.requests)),
		CertType:        ssh.UserCert,
		KeyId:           "aqmas:G" + id + ":" + fr.host + ":" + fr.req.SSH.TargetHost,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(f.certTTL).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"source-address": "127.0.0.1/32"},
			Extensions:      map[string]string{"permit-pty": "", "permit-port-forwarding": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, f.sshCA); err != nil {
		f.t.Errorf("fake server: sign: %v", err)
		return nil
	}
	sg := &api.SSHGrant{
		Certificate:    strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		Principals:     []string{principal},
		TargetHost:     fr.req.SSH.TargetHost,
		TargetAddress:  f.targetAddress,
		TargetPort:     f.targetPort,
		LoginUser:      fr.req.SSH.LoginUser,
		KnownHostsLine: f.knownHostsLine,
	}
	if f.mutateGrant != nil {
		f.mutateGrant(sg)
	}
	return &api.Grant{ID: "G" + id, Kind: api.KindSSH, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(f.certTTL), SSH: sg}
}

func (f *fakeServer) handleGrants(w http.ResponseWriter, r *http.Request) {
	host, ok := f.host(w, r)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := api.GrantList{Grants: []api.GrantSummary{}}
	for _, fr := range f.requests {
		if fr.host == host && fr.granted != nil && fr.req.Kind == api.KindCloudflare {
			if !fr.revoked && time.Now().Before(fr.granted.NotAfter) {
				cf := fr.granted.Cloudflare
				out.Grants = append(out.Grants, api.GrantSummary{ID: fr.granted.ID, Kind: api.KindCloudflare, Status: api.StatusApproved,
					NotBefore: fr.granted.NotBefore, NotAfter: fr.granted.NotAfter, Scope: cf.Scope, ScopeParams: cf.ScopeParams, Mode: cf.Mode})
			}
			continue
		}
		if fr.host == host && fr.granted != nil {
			out.Grants = append(out.Grants, api.GrantSummary{ID: fr.granted.ID, Kind: api.KindSSH, Status: api.StatusApproved,
				TargetHost: fr.req.SSH.TargetHost, LoginUser: fr.req.SSH.LoginUser, NotBefore: fr.granted.NotBefore, NotAfter: fr.granted.NotAfter})
		}
	}
	sort.Slice(out.Grants, func(i, j int) bool { return out.Grants[i].ID < out.Grants[j].ID })
	writeJSON(w, 200, out)
}

// testEnv is an Env on temp dirs with captured output.
type testEnv struct {
	*Env
	stdout, stderr *bytes.Buffer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	root := t.TempDir()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := map[string]string{"CLAUDECODE": "1", "CLAUDE_SESSION_ID": "sess-1"}
	e := &Env{
		Paths:   Paths{ConfigDir: filepath.Join(root, "config", "aqmas"), CacheDir: filepath.Join(root, "run", "aqmas")},
		Stdin:   strings.NewReader(""),
		Stdout:  out,
		Stderr:  errb,
		Getenv:  func(k string) string { return env[k] },
		Environ: func() []string { return []string{"CLAUDECODE=1"} },
		Now:     time.Now,
		Getwd:   func() (string, error) { return "/home/alice/Projects/x", nil },
		PID:     4242,
		User:    "alice",
		PollMin: time.Millisecond,
	}
	return &testEnv{Env: e, stdout: out, stderr: errb}
}
