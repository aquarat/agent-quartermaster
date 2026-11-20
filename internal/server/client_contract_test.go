package server

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// The CLI pins the CA ("sha256:<hex of CA DER>") and expects it in the served chain.
func TestServerChainAndPin(t *testing.T) {
	e := newEnv(t)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(e.agent.URL, "https://"), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) != 2 || !chain[1].Equal(e.s.PKI().CACert) {
		t.Fatalf("served chain has %d certs, want leaf + CA", len(chain))
	}
	sum := sha256.Sum256(chain[1].Raw)
	if pin := e.s.PKI().CAPin(); pin != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("pin %s", pin)
	}
	// The leaf is serverAuth only and names the bastion address.
	if err := chain[0].VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestCancelAndSSHCA(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	a := e.agentClient(ptr(e.enrollHost("hosta")))
	b := e.agentClient(ptr(e.enrollHost("hostb")))
	rc, _, _ := e.request(a, "db-1", "alice", 0)
	st, _ := agentDo(t, b, "POST", e.agent.URL+"/v1/requests/"+rc.ID+"/cancel", map[string]any{}, nil)
	mustStatus(t, "cancel by another host", st, 404)
	var rs api.RequestStatus
	st, _ = agentDo(t, a, "POST", e.agent.URL+"/v1/requests/"+rc.ID+"/cancel", map[string]any{}, &rs)
	mustStatus(t, "cancel", st, 200)
	if rs.Status != StatusCancelled {
		t.Fatalf("status %q", rs.Status)
	}
	var state api.UIState
	e.webDo("GET", "/api/ui/state", nil, &state)
	if len(state.Pending) != 0 {
		t.Fatal("cancelled request still pending in the UI")
	}
	_, st = e.challenge("/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve"})
	mustStatus(t, "approve cancelled", st, 409)
	st, _ = agentDo(t, a, "POST", e.agent.URL+"/v1/requests/"+rc.ID+"/cancel", map[string]any{}, nil)
	mustStatus(t, "cancel twice", st, 409)

	var ca struct{ PublicKey, Fingerprint string }
	st, _ = agentDo(t, a, "GET", e.agent.URL+"/v1/ssh-ca", nil, &struct {
		PublicKey   *string `json:"public_key"`
		Fingerprint *string `json:"fingerprint"`
	}{&ca.PublicKey, &ca.Fingerprint})
	mustStatus(t, "ssh-ca", st, 200)
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil || ssh.FingerprintSHA256(k) != ca.Fingerprint || string(k.Marshal()) != string(e.s.PKI().SSHSigner.PublicKey().Marshal()) {
		t.Fatalf("ssh-ca %+v %v", ca, err)
	}
	_, _, st = e.request(e.agentClient(nil), "db-1", "alice", 0)
	mustStatus(t, "unauthenticated", st, 401)
}

func TestTargetPrincipalAndTTLCap(t *testing.T) {
	tg := config.Target{Name: "forgejo", Users: []string{"git"}, PrincipalOverride: "alice@forgejo"}
	if tg.Principal("git") != "alice@forgejo" {
		t.Fatal("principal override")
	}
	e := newEnv(t)
	for i := range e.cfg.Targets {
		if e.cfg.Targets[i].Name == "forgejo" {
			e.cfg.Targets[i].MaxTTLSeconds = 900
		}
	}
	e.setupOwner()
	c := e.agentClient(ptr(e.enrollHost("hosta")))
	rc, _, _ := e.request(c, "forgejo", "git", 7200)
	var item api.PendingItem
	e.webDo("GET", "/api/ui/requests/"+rc.ID, nil, &item)
	if item.TTLRequested != 900 {
		t.Fatalf("target ttl cap not applied: %d", item.TTLRequested)
	}
}
