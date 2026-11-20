package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func TestPendingCapsAndRevokedHost(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	var first api.RequestCreated
	for i := 0; i < MaxPendingPerHost; i++ {
		rc, _, st := e.request(c, "db-1", "alice", 0)
		mustStatus(t, "pending request", st, 201)
		if i == 0 {
			first = rc
		}
	}
	_, _, st := e.request(c, "db-1", "alice", 0)
	mustStatus(t, "pending cap", st, 429)

	// Per-address enrollment cap (all test enrollments come from 127.0.0.1).
	anon := e.agentClient(nil)
	for i := 0; i < MaxPendingEnrollsPerIP; i++ {
		_, csr := newCSR(t, "x")
		st, _ := agentDo(t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: "spam", CSRPEM: csr}, nil)
		mustStatus(t, "enroll", st, 201)
	}
	_, csr := newCSR(t, "x")
	st, _ = agentDo(t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: "spam", CSRPEM: csr}, nil)
	mustStatus(t, "per-ip enroll cap", st, 429)

	// A challenge issued before the host was revoked can't approve its request afterwards.
	cr, st := e.challenge("/api/ui/requests/"+first.ID, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "challenge", st, 200)
	if err := RevokeHost(e.cfg.DataDir, "hosta", e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, "approve for revoked host", e.decide("/api/ui/requests/"+first.ID, "decide", cr, nil), 409)
	var state api.UIState
	e.webDo("GET", "/api/ui/state", nil, &state)
	for _, p := range state.Pending {
		if p.RequestingHost == "hosta" {
			t.Fatal("revoked host's requests still pending")
		}
	}
	_, _, st = e.request(c, "db-1", "alice", 0)
	mustStatus(t, "revoked host", st, 403)
}

func TestGrantRevokeEndsItsStandingApproval(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	rc, _, _ := e.request(c, "db-1", "alice", 600)
	mustStatus(t, "approve", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve", StandingHours: 4}), 200)
	rs, _ := e.status(c, rc.ID, "")
	mustStatus(t, "revoke grant", e.approve("/api/ui/grants/"+rs.Grant.ID, "revoke", api.ChallengeRequest{Action: "revoke"}), 200)
	if r2, _, _ := e.request(c, "db-1", "alice", 600); r2.Status != "pending" {
		t.Fatal("standing approval survived revoking its grant")
	}
}

func TestDecisionNotification(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer ntfy.Close()
	e := newEnv(t)
	e.s.notify.TopicURL = ntfy.URL + "/topic"
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	rc, _, _ := e.request(c, "db-1", "alice", 600)
	mustStatus(t, "approve", e.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve", TTLSeconds: 300, StandingHours: 1}), 200)
	want := "aqmas: approve ssh alice@db-1 for hosta, ttl 300s, standing 1h [ref " + ref(rc.ID) + "]"
	for i := 0; i < 50; i++ {
		mu.Lock()
		joined := strings.Join(bodies, "\n")
		mu.Unlock()
		if strings.Contains(joined, want) {
			if strings.Contains(joined, "BEGIN") || strings.Contains(joined, "cert-v01") {
				t.Fatal("notification carries key material")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no decision push; got %q", bodies)
}

func TestSessionBoundToAccessIdentity(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kid": "k1", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}}})
	}))
	defer jwks.Close()
	tok := func(sub, email string) string {
		j := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://team.example.com", "aud": "AUD1", "sub": sub, "email": email, "exp": time.Now().Add(time.Hour).Unix()})
		j.Header["kid"] = "k1"
		s, _ := j.SignedString(k)
		return s
	}
	cfg := testConfig(t.TempDir())
	cfg.Access.TeamDomain, cfg.Access.AUD, cfg.Access.OwnerEmail = "team.example.com", "AUD1", "owner@example.com"
	clk := &fakeClock{t: time.Now().UTC().Truncate(time.Second)}
	s, err := New(Options{Config: cfg, Now: clk.Now, AccessCertsURL: jwks.URL, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := &env{t: t, s: s, cfg: cfg, clock: clk}
	e.web = httptest.NewServer(&headerInjector{h: s.WebHandler(), tok: tok("owner-sub", "owner@example.com")})
	defer e.web.Close()
	e.setupOwner() // registers and logs in under owner-sub

	inj := e.web.Config.Handler.(*headerInjector)
	mustStatus(t, "state as owner", e.webDo("GET", "/api/ui/state", nil, nil), 200)
	inj.tok = tok("other-sub", "owner@example.com")
	mustStatus(t, "stolen cookie, other Access identity", e.webDo("GET", "/api/ui/state", nil, nil), 401)
	inj.tok = tok("owner-sub", "someone@example.com")
	mustStatus(t, "Access identity not the owner", e.webDo("GET", "/api/ui/session", nil, nil), 403)
}

type headerInjector struct {
	h   http.Handler
	tok string
}

func (i *headerInjector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Cf-Access-Jwt-Assertion", i.tok)
	i.h.ServeHTTP(w, r)
}
