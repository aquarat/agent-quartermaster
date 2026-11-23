package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
)

// Access to the bastion itself (docs/BASTION-ACCESS.md §12).

const bastionHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGilJAtWZP1K8q90h5+KBdPRC0+wBFVVtHkOZQLmI9jB"

var testBastion = config.Bastion{Name: "bastion", Address: "192.0.2.10", Port: 22, AdminUser: "alice", HostKey: bastionHostKey}

type bastionEnv struct {
	*env
	host       *http.Client
	enrollment string
	allowFile  string
}

func bastionConfig(dir string) *config.Config {
	cfg := testConfig(dir)
	cfg.Bastion = testBastion
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

func newBastion(t *testing.T, opt func(*config.Config)) *bastionEnv {
	t.Helper()
	cfg := bastionConfig(t.TempDir())
	if opt != nil {
		opt(cfg)
	}
	e := newEnvWith(t, cfg, nil)
	e.setupOwner()
	cert := e.enrollHost("dev-1")
	b := &bastionEnv{env: e, host: e.agentClient(&cert)}
	b.attach()
	return b
}

// attach points the (possibly restarted) broker at this test's allowlist file.
func (b *bastionEnv) attach() {
	b.t.Helper()
	h, err := b.s.store.Q().ActiveHostByName(b.t.Context(), "dev-1")
	requireNoError(b.t, err)
	b.enrollment = h.EnrollmentID
	if b.allowFile == "" {
		b.allowFile = filepath.Join(b.t.TempDir(), "bastion-allow.json")
	}
	b.s.bastionAllowFile = b.allowFile
}

// allow writes root's allowlist exactly as the bastion-allow task does.
func (b *bastionEnv) allow(hosts ...maint.AllowedHost) {
	b.t.Helper()
	if hosts == nil {
		hosts = []maint.AllowedHost{}
	}
	text, err := maint.Canonical(maint.TaskBastionAllow, maint.BastionAllowParams{Hosts: hosts})
	requireNoError(b.t, err)
	requireNoError(b.t, os.WriteFile(b.allowFile, []byte(text), 0o640))
}
func (b *bastionEnv) allowSelf() {
	b.allow(maint.AllowedHost{ID: b.enrollment, Name: "dev-1", Address: "127.0.0.1"})
}

func (b *bastionEnv) ask(c *http.Client, level string, ttl int) (api.RequestCreated, ssh.PublicKey, int) {
	b.t.Helper()
	pub, line := newSSHKey(b.t)
	var rc api.RequestCreated
	st, err := agentDo(b.t, c, "POST", b.agent.URL+"/v1/bastion/requests", api.BastionRequest{Level: level, PublicKey: line, Reason: "look at the logs", TTLSeconds: ttl,
		Requester: api.Requester{Tool: "other", User: "agent"}}, &rc)
	requireNoError(b.t, err)
	return rc, pub, st
}

func (b *bastionEnv) poll(c *http.Client, id string) (api.RequestStatus, int) {
	b.t.Helper()
	var rs api.RequestStatus
	st, err := agentDo(b.t, c, "GET", b.agent.URL+"/v1/bastion/requests/"+id, nil, &rs)
	requireNoError(b.t, err)
	return rs, st
}

func boolp(v bool) *bool { return &v }

func parseCert(t *testing.T, line string) *ssh.Certificate {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	requireNoError(t, err)
	c, ok := k.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	return c
}

// auditTrail returns the recent audit actions, oldest first.
func auditTrail(t *testing.T, s *Server) []string {
	t.Helper()
	rows, err := s.store.Q().RecentAudit(t.Context(), 50)
	requireNoError(t, err)
	var out []string
	for _, r := range rows {
		out = append(out, r.Action)
	}
	slices.Reverse(out)
	return out
}

func pendingBastion(t *testing.T, e *env, id string) (api.PendingItem, bool) {
	t.Helper()
	var state api.UIState
	mustStatus(t, "state", e.webDo("GET", "/api/ui/state", nil, &state), 200)
	for _, p := range state.Pending {
		if p.ID == id {
			return p, true
		}
	}
	return api.PendingItem{}, false
}

func TestBastionDisabledWithoutConfig(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	cert := e.enrollHost("dev-1")
	c := e.agentClient(&cert)
	st, _ := agentDo(t, c, "GET", e.agent.URL+"/v1/bastion", nil, nil)
	mustStatus(t, "info", st, 404)
	_, line := newSSHKey(t)
	st, _ = agentDo(t, c, "POST", e.agent.URL+"/v1/bastion/requests", api.BastionRequest{Level: "inspect", PublicKey: line, Reason: "x", Requester: api.Requester{Tool: "other", User: "a"}}, nil)
	mustStatus(t, "request", st, 404)
	// Before access is installed no host can queue a maintenance card either.
	st, _ = agentDo(t, c, "POST", e.agent.URL+"/v1/setup-requests", map[string]any{"task": maint.TaskDiskUsage, "reason": "x", "requester": map[string]any{"tool": "other", "user": "a"}}, nil)
	mustStatus(t, "queue", st, 404)
	var v api.BastionView
	mustStatus(t, "view", e.webDo("GET", "/api/ui/bastion", nil, &v), 200)
	if v.Enabled || len(v.Tasks) != 9 {
		t.Fatalf("view %+v", v)
	}
}

func TestBastionInspect(t *testing.T) {
	b := newBastion(t, nil)
	var info api.BastionInfo
	st, _ := agentDo(t, b.host, "GET", b.agent.URL+"/v1/bastion", nil, &info)
	mustStatus(t, "info", st, 200)
	if info.Name != "bastion" || info.InspectUser != "aqmas-inspect" || info.AdminUser != "alice" || info.RootAllowed || info.RootMaxSeconds != 3600 || info.InspectDefault != 3600 || len(info.Tasks) != 6 {
		t.Fatalf("info %+v", info)
	}
	// A reason is required, the level is one of two, and nothing else chooses the account.
	_, line := newSSHKey(t)
	for name, body := range map[string]any{
		"no reason": api.BastionRequest{Level: "inspect", PublicKey: line, Requester: api.Requester{Tool: "other", User: "a"}},
		"bad level": api.BastionRequest{Level: "admin", PublicKey: line, Reason: "x"},
	} {
		st, _ := agentDo(t, b.host, "POST", b.agent.URL+"/v1/bastion/requests", body, nil)
		mustStatus(t, name, st, 400)
	}
	// A request cannot name its account: whatever it says, inspect lands on the inspect account.
	var named api.RequestCreated
	st, _ = agentDo(t, b.host, "POST", b.agent.URL+"/v1/bastion/requests", map[string]any{"level": "inspect", "public_key": line, "reason": "x", "login_user": "alice", "principal": "alice@bastion"}, &named)
	mustStatus(t, "named account", st, 201)
	if it, _ := pendingBastion(t, b.env, named.ID); it.Bastion == nil || it.Bastion.LoginUser != "aqmas-inspect" || it.Bastion.Level != "inspect" {
		t.Fatalf("a request chose its account: %+v", it.Bastion)
	}
	st, _ = agentDo(t, b.host, "POST", b.agent.URL+"/v1/bastion/requests/"+named.ID+"/cancel", nil, nil)
	mustStatus(t, "cancel", st, 200)
	rc, pub, st := b.ask(b.host, "inspect", 0)
	mustStatus(t, "ask", st, 201)
	item, ok := pendingBastion(t, b.env, rc.ID)
	if !ok || item.Kind != "bastion" || item.Bastion == nil || item.Bastion.Level != "inspect" || item.Bastion.LoginUser != "aqmas-inspect" || item.Risk != "normal" ||
		item.TTLRequested != 3600 || item.Bastion.Principal != "aqmas-inspect@bastion" || len(item.Bastion.OpenBuckets) != 0 || item.Bastion.HostID != b.enrollment {
		t.Fatalf("card %+v %+v", item, item.Bastion)
	}
	path := "/api/ui/requests/" + rc.ID
	// No standing, indefinite or longer choice can even be asked for.
	for name, req := range map[string]api.ChallengeRequest{
		"standing hours": {Action: "approve", StandingHours: 1},
		"indefinite":     {Action: "approve", Indefinite: true},
		"longer":         {Action: "approve", TTLSeconds: 3601},
		"close":          {Action: "approve", CloseBuckets: boolp(true)},
		"deny with ttl":  {Action: "deny", TTLSeconds: 60},
	} {
		if _, st := b.challenge(path, req); st != 400 {
			t.Fatalf("%s: HTTP %d", name, st)
		}
	}
	cr, st := b.challenge(path, api.ChallengeRequest{Action: "approve", TTLSeconds: 600})
	mustStatus(t, "challenge", st, 200)
	c := uiCheck(t, cr)
	for k, want := range map[string]any{"kind": "bastion", "level": "inspect", "login_user": "aqmas-inspect", "principal": "aqmas-inspect@bastion", "target": "bastion",
		"target_address": "192.0.2.10", "cert_profile": "source-address;force-command", "open_buckets": "[]", "close_buckets": false, "alert_channel": false, "sealed": false,
		"requesting_host": "dev-1", "host_id": b.enrollment, "address": "127.0.0.1", "key_fingerprint": ssh.FingerprintSHA256(pub), "ssh_ca": b.s.sshPin(),
		"host_key": hostKeyFingerprint(bastionHostKey), "ttl_seconds": json.Number("600")} {
		if c[k] != want {
			t.Errorf("canonical %s = %v, want %v", k, c[k], want)
		}
	}
	if _, has := c["standing_hours"]; has {
		t.Fatal("a bastion request carries a standing field")
	}
	var dec api.BastionDecision
	mustStatus(t, "approve", b.decide(path, "decide", cr, &dec), 200)
	if dec.Level != "inspect" || dec.Status != "approved" || dec.Kind != "bastion" {
		t.Fatalf("decision %+v", dec)
	}
	// Delivered like an SSH grant: every poll, with a certificate that confines itself.
	for i := 0; i < 2; i++ {
		rs, st := b.poll(b.host, rc.ID)
		if st != 200 || rs.Status != "approved" || rs.Grant == nil || rs.Grant.Kind != "bastion" || rs.Grant.SSH.Certificate == "" || rs.Grant.SSH.LoginUser != "aqmas-inspect" ||
			rs.Grant.SSH.TargetAddress != "192.0.2.10" || !strings.Contains(rs.Grant.SSH.KnownHostsLine, "bastion,192.0.2.10 ssh-ed25519 ") {
			t.Fatalf("poll %d: %d %+v", i, st, rs)
		}
		cert := parseCert(t, rs.Grant.SSH.Certificate)
		if !slices.Equal(cert.ValidPrincipals, []string{"aqmas-inspect@bastion"}) || len(cert.Extensions) != 0 || cert.CriticalOptions["force-command"] != "/usr/local/bin/aqmasd inspect" ||
			cert.CriticalOptions["source-address"] != "127.0.0.1/32" || len(cert.CriticalOptions) != 2 || !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) ||
			time.Unix(int64(cert.ValidBefore), 0).Sub(b.clock.Now()) != 600*time.Second {
			t.Fatalf("certificate %+v", cert)
		}
	}
	// The generic request endpoints do not know this request, before or after approval.
	if _, st := b.status(b.host, rc.ID, ""); st != 404 {
		t.Fatalf("generic status: %d", st)
	}
	st, _ = agentDo(t, b.host, "POST", b.agent.URL+"/v1/requests/"+rc.ID+"/cancel", nil, nil)
	mustStatus(t, "generic cancel", st, 404)
	// Another host sees nothing.
	other := b.enrollHost("dev-2")
	if _, st := b.poll(b.agentClient(&other), rc.ID); st != 404 {
		t.Fatalf("other host: %d", st)
	}
	// The session shows on the Bastion access page and can be revoked like any grant.
	var v api.BastionView
	mustStatus(t, "view", b.webDo("GET", "/api/ui/bastion", nil, &v), 200)
	if !v.Enabled || len(v.Sessions) != 1 || v.Sessions[0].Level != "inspect" || v.Sessions[0].Status != "active" || v.RootUntil != nil || len(v.Hosts) != 2 || v.Hosts[0].Allowed {
		t.Fatalf("view %+v", v)
	}
	mustStatus(t, "revoke", b.approve("/api/ui/grants/"+v.Sessions[0].GrantID, "revoke", api.ChallengeRequest{Action: "revoke"}), 200)
	if rs, _ := b.poll(b.host, rc.ID); rs.Status != "revoked" || rs.Grant != nil {
		t.Fatalf("after revoke %+v", rs)
	}
	// Cancel and deny.
	rc, _, _ = b.ask(b.host, "inspect", 120)
	st, _ = agentDo(t, b.host, "POST", b.agent.URL+"/v1/bastion/requests/"+rc.ID+"/cancel", nil, nil)
	mustStatus(t, "cancel", st, 200)
	rc, _, _ = b.ask(b.host, "inspect", 120)
	mustStatus(t, "deny", b.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "deny"}), 200)
	if rs, _ := b.poll(b.host, rc.ID); rs.Status != "denied" {
		t.Fatalf("after deny %+v", rs)
	}
}

func TestBastionRootAllowlistAndCap(t *testing.T) {
	b := newBastion(t, nil)
	before := len(auditTrail(t, b.s))
	// Empty list, a list naming another enrollment, and the right enrollment at another
	// address: refused before anything is queued.
	for name, hosts := range map[string][]maint.AllowedHost{
		"empty":         nil,
		"other host":    {{ID: "01OTHERENROLLMENT0000000000", Name: "dev-9", Address: "127.0.0.1"}},
		"other address": {{ID: b.enrollment, Name: "dev-1", Address: "192.0.2.77"}},
	} {
		b.allow(hosts...)
		if _, _, st := b.ask(b.host, "root", 600); st != 403 {
			t.Fatalf("%s: HTTP %d", name, st)
		}
	}
	// A damaged or oversized list is an empty list.
	requireNoError(t, os.WriteFile(b.allowFile, []byte(`{"hosts":[{"id":"`+b.enrollment+`","name":"dev-1","address":"127.0.0.1"}],"extra":1}`), 0o640))
	if _, _, st := b.ask(b.host, "root", 600); st != 403 {
		t.Fatal("a list that is not what the task writes was honoured")
	}
	var state api.UIState
	mustStatus(t, "state", b.webDo("GET", "/api/ui/state", nil, &state), 200)
	if len(state.Pending) != 0 || len(auditTrail(t, b.s)) != before {
		t.Fatal("a refused root request left something behind")
	}
	b.allowSelf()
	var info api.BastionInfo
	agentDo(t, b.host, "GET", b.agent.URL+"/v1/bastion", nil, &info)
	if !info.RootAllowed {
		t.Fatal("info does not report the allowlist")
	}
	// Asked for two hours: clamped to one at create; more than one cannot be signed.
	rc, pub, st := b.ask(b.host, "root", 7200)
	mustStatus(t, "ask", st, 201)
	item, _ := pendingBastion(t, b.env, rc.ID)
	if item.TTLRequested != 3600 || item.Risk != "high" || item.Bastion.Level != "root" || item.Bastion.LoginUser != "alice" || item.Bastion.CertProfile != "source-address;permit-pty" || item.Bastion.Sealed {
		t.Fatalf("card %+v %+v", item, item.Bastion)
	}
	path := "/api/ui/requests/" + rc.ID
	for name, req := range map[string]api.ChallengeRequest{
		"over the cap":     {Action: "approve", TTLSeconds: 3601},
		"standing":         {Action: "approve", TTLSeconds: 600, StandingHours: 1},
		"close (unsealed)": {Action: "approve", TTLSeconds: 600, CloseBuckets: boolp(true)},
	} {
		if _, st := b.challenge(path, req); st != 400 {
			t.Fatalf("%s: HTTP %d", name, st)
		}
	}
	// Removed from the list after the card was signed: the apply transaction refuses.
	cr, st := b.challenge(path, api.ChallengeRequest{Action: "approve", TTLSeconds: 900})
	mustStatus(t, "challenge", st, 200)
	b.allow()
	mustStatus(t, "apply after removal", b.decide(path, "decide", cr, nil), 409)
	if _, st := b.challenge(path, api.ChallengeRequest{Action: "approve", TTLSeconds: 900}); st != 409 {
		t.Fatalf("challenge after removal: %d", st)
	}
	if rs, _ := b.poll(b.host, rc.ID); rs.Status != "pending" {
		t.Fatalf("request decided without the allowlist: %+v", rs)
	}
	b.allowSelf()
	cr, st = b.challenge(path, api.ChallengeRequest{Action: "approve", TTLSeconds: 900})
	mustStatus(t, "challenge", st, 200)
	c := uiCheck(t, cr)
	if c["level"] != "root" || c["login_user"] != "alice" || c["principal"] != "alice@bastion" || c["cert_profile"] != "source-address;permit-pty" || c["sealed"] != false ||
		c["open_buckets"] != "[]" || c["close_buckets"] != false || c["alert_channel"] != false || c["ttl_seconds"] != json.Number("900") {
		t.Fatalf("canonical %v", c)
	}
	var dec api.BastionDecision
	mustStatus(t, "approve", b.decide(path, "decide", cr, &dec), 200)
	if dec.Level != "root" || dec.Alert != "off" || dec.Closed != 0 {
		t.Fatalf("decision %+v", dec)
	}
	mustStatus(t, "state", b.webDo("GET", "/api/ui/state", nil, &state), 200)
	if state.BastionRootUntil == nil || !state.BastionRootUntil.Equal(b.clock.Now().Add(900*time.Second)) {
		t.Fatalf("no banner: %v", state.BastionRootUntil)
	}
	// One delivery: root's certificate, pty and nothing else; then never again.
	rs, st := b.poll(b.host, rc.ID)
	if st != 200 || rs.Status != "approved" || rs.Grant == nil || rs.Grant.SSH.Certificate == "" {
		t.Fatalf("delivery: %d %+v", st, rs)
	}
	cert := parseCert(t, rs.Grant.SSH.Certificate)
	if !slices.Equal(cert.ValidPrincipals, []string{"alice@bastion"}) || len(cert.Extensions) != 1 || len(cert.CriticalOptions) != 1 || cert.CriticalOptions["source-address"] != "127.0.0.1/32" ||
		!bytes.Equal(cert.Key.Marshal(), pub.Marshal()) || time.Unix(int64(cert.ValidBefore), 0).Sub(b.clock.Now()) != 900*time.Second {
		t.Fatalf("certificate %+v", cert)
	}
	if _, pty := cert.Extensions["permit-pty"]; !pty {
		t.Fatal("no pty")
	}
	rs, st = b.poll(b.host, rc.ID)
	if st != 200 || rs.Grant == nil || rs.Grant.SSH.Certificate != "" || !strings.Contains(rs.DecisionNote, "handed out once") {
		t.Fatalf("second delivery: %d %+v", st, rs)
	}
	got := auditTrail(t, b.s)
	i, j, k := slices.Index(got, "bastion_root"), slices.Index(got, "bastion_root_alert"), slices.Index(got, "bastion_cert_delivered")
	if i < 0 || !(i < j && j < k) {
		t.Fatalf("audit order: %v", got)
	}
	var v api.BastionView
	mustStatus(t, "view", b.webDo("GET", "/api/ui/bastion", nil, &v), 200)
	if len(v.Sessions) != 1 || v.Sessions[0].Level != "root" || v.Sessions[0].Alert != "off" || v.Sessions[0].DeliveredAt == nil || v.RootUntil == nil || v.AlertChannel ||
		!slices.ContainsFunc(v.Hosts, func(h api.BastionHost) bool {
			return h.ID == b.enrollment && h.Allowed && h.AllowedAddress == "127.0.0.1"
		}) {
		t.Fatalf("view %+v", v)
	}
	// A re-enrolled host is a new enrollment: no longer on the list.
	again := b.enrollHost("dev-1")
	if _, _, st := b.ask(b.agentClient(&again), "root", 600); st != 403 {
		t.Fatalf("re-enrolled host: %d", st)
	}
	mustStatus(t, "view", b.webDo("GET", "/api/ui/bastion", nil, &v), 200)
	if !slices.ContainsFunc(v.Hosts, func(h api.BastionHost) bool { return h.ID == b.enrollment && h.Gone && h.Allowed }) {
		t.Fatalf("the stale entry is not shown for removal: %+v", v.Hosts)
	}
}

// A root certificate that is not collected in time, or polled from another address, is not
// handed out.
func TestBastionRootCollection(t *testing.T) {
	b := newBastion(t, nil)
	b.allowSelf()
	rc, _, _ := b.ask(b.host, "root", 600)
	mustStatus(t, "approve", b.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve", TTLSeconds: 600}), 200)
	_, err := b.s.store.DB().Exec(`UPDATE requests SET peer_address='192.0.2.99' WHERE id=?`, rc.ID)
	requireNoError(t, err)
	if rs, st := b.poll(b.host, rc.ID); st != 409 || rs.Grant != nil {
		t.Fatalf("delivered to another address: %d %+v", st, rs)
	}
	_, err = b.s.store.DB().Exec(`UPDATE requests SET peer_address='127.0.0.1' WHERE id=?`, rc.ID)
	requireNoError(t, err)
	b.clock.Advance(bastionCollect + time.Second)
	rs, st := b.poll(b.host, rc.ID)
	if st != 200 || rs.Status != "revoked" || rs.Grant != nil {
		t.Fatalf("late collection: %d %+v", st, rs)
	}
	// An approval whose alert outcome was never recorded (the broker stopped in between)
	// stays "pending" for the requester and is void afterwards.
	rc, _, _ = b.ask(b.host, "root", 600)
	mustStatus(t, "approve", b.approve("/api/ui/requests/"+rc.ID, "decide", api.ChallengeRequest{Action: "approve", TTLSeconds: 600}), 200)
	_, err = b.s.store.DB().Exec(`UPDATE bastion_grants SET alert='',alert_at=NULL`)
	requireNoError(t, err)
	if rs, _ := b.poll(b.host, rc.ID); rs.Status != "pending" || rs.Grant != nil || rs.DecidedAt != nil {
		t.Fatalf("approval visible before the alert record: %+v", rs)
	}
	b.clock.Advance(bastionCollect + time.Second)
	if rs, _ := b.poll(b.host, rc.ID); rs.Status != "revoked" || rs.Grant != nil {
		t.Fatalf("unalerted grant delivered: %+v", rs)
	}
}

// The audit row and the grant commit together: when the audit write fails, nothing is issued.
func TestBastionRootAuditFailsClosed(t *testing.T) {
	b := newBastion(t, nil)
	b.allowSelf()
	rc, _, _ := b.ask(b.host, "root", 600)
	_, err := b.s.store.DB().Exec(`CREATE TRIGGER test_audit_down BEFORE INSERT ON audit WHEN NEW.action='bastion_root' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`)
	requireNoError(t, err)
	path := "/api/ui/requests/" + rc.ID
	if st := b.approve(path, "decide", api.ChallengeRequest{Action: "approve", TTLSeconds: 600}); st/100 == 2 {
		t.Fatalf("approved without an audit row: %d", st)
	}
	if rs, _ := b.poll(b.host, rc.ID); rs.Status != "pending" || rs.Grant != nil {
		t.Fatalf("request moved without an audit row: %+v", rs)
	}
	var n int
	requireNoError(t, b.s.store.DB().QueryRow(`SELECT (SELECT count(*) FROM grants)+(SELECT count(*) FROM bastion_grants)`).Scan(&n))
	if n != 0 {
		t.Fatal("a grant exists without its audit row")
	}
	_, err = b.s.store.DB().Exec(`DROP TRIGGER test_audit_down`)
	requireNoError(t, err)
	mustStatus(t, "approve", b.approve(path, "decide", api.ChallengeRequest{Action: "approve", TTLSeconds: 600}), 200)
}

// post is webDo without the test's Fatal, for use from another goroutine.
func (e *env) post(path string, body, out any) int {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.web.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aqmas", "1")
	req.Header.Set("Origin", testBase)
	req.Header.Set("Cookie", sessionCookie+"="+e.sess)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode/100 == 2 {
		_ = json.Unmarshal(text, out)
	}
	return resp.StatusCode
}

// The alert is attempted, and its outcome recorded, before the requester learns of the
// approval or can collect the certificate. A failed alert does not stop the session; it shows.
func TestBastionRootAlertBeforeCertificate(t *testing.T) {
	arrived, release := make(chan string, 4), make(chan int, 4)
	push := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Title") != "aqmas: ROOT ON THE BASTION" {
			return
		}
		body, _ := io.ReadAll(r.Body)
		arrived <- string(body)
		w.WriteHeader(<-release)
	}))
	defer push.Close()
	b := newBastion(t, func(cfg *config.Config) { cfg.Ntfy.TopicURL = push.URL + "/topic" })
	b.allowSelf()
	for _, tc := range []struct {
		code int
		want string
	}{{200, "sent"}, {500, "failed"}} {
		rc, _, _ := b.ask(b.host, "root", 600)
		path := "/api/ui/requests/" + rc.ID
		cr, st := b.challenge(path, api.ChallengeRequest{Action: "approve", TTLSeconds: 600})
		mustStatus(t, "challenge", st, 200)
		if c := uiCheck(t, cr); c["alert_channel"] != true {
			t.Fatal("the card does not say that an alert channel exists")
		}
		as, err := b.auth.AssertOptions(cr.PublicKey)
		requireNoError(t, err)
		type result struct {
			status int
			dec    api.BastionDecision
		}
		done := make(chan result, 1)
		go func() {
			var r result
			r.status = b.post(path+"/decide", api.DecideRequest{ChallengeID: cr.ChallengeID, Assertion: as}, &r.dec)
			done <- r
		}()
		text := <-arrived
		if !strings.Contains(text, "ROOT session on the bastion approved for dev-1 (127.0.0.1), 10 min") {
			t.Fatalf("alert text %q", text)
		}
		// The alert is in flight: committed and audited, but invisible to the requester.
		if got := auditTrail(t, b.s); !slices.Contains(got, "bastion_root") {
			t.Fatalf("no audit row before the alert: %v", got)
		}
		if rs, st := b.poll(b.host, rc.ID); st != 200 || rs.Status != "pending" || rs.Grant != nil {
			t.Fatalf("certificate reachable before the alert outcome: %d %+v", st, rs)
		}
		release <- tc.code
		r := <-done
		if r.status != 200 || r.dec.Alert != tc.want {
			t.Fatalf("decision %d %+v, want alert %s", r.status, r.dec, tc.want)
		}
		rs, _ := b.poll(b.host, rc.ID)
		if rs.Status != "approved" || rs.Grant == nil || rs.Grant.SSH.Certificate == "" {
			t.Fatalf("after the alert attempt (%s): %+v", tc.want, rs)
		}
		var v api.BastionView
		mustStatus(t, "view", b.webDo("GET", "/api/ui/bastion", nil, &v), 200)
		if v.Sessions[0].Alert != tc.want || !v.AlertChannel {
			t.Fatalf("view does not show the alert outcome: %+v", v.Sessions[0])
		}
	}
}

// No silent path can decide a bastion request: not a standing rule, not the generic request
// endpoint with its auto-approval, not a batch, not a window.
func TestBastionNeverSilent(t *testing.T) {
	b := newBastion(t, nil)
	b.allowSelf()
	ctx := t.Context()
	// Kind "bastion" is not accepted where standing rules and policy auto live.
	_, line := newSSHKey(t)
	st, _ := agentDo(t, b.host, "POST", b.agent.URL+"/v1/requests", map[string]any{"kind": "bastion", "ssh": map[string]any{"target_host": "bastion", "login_user": "alice", "public_key": line},
		"reason": "x", "ttl_seconds": 600, "requester": map[string]any{"tool": "other", "user": "a"}}, nil)
	mustStatus(t, "generic create", st, 400)
	st, _ = agentDo(t, b.host, "POST", b.agent.URL+"/v1/requests", api.AccessRequest{Kind: "ssh", SSH: &api.SSHRequest{TargetHost: "bastion", LoginUser: "alice", PublicKey: line},
		Reason: "x", TTLSeconds: 600, Requester: api.Requester{Tool: "other", User: "a"}}, nil)
	mustStatus(t, "bastion as an ssh target", st, 400)
	// Standing rules that claim to cover the bastion, forged straight into the database.
	h, err := b.s.store.Q().ActiveHostByName(ctx, "dev-1")
	requireNoError(t, err)
	first, _, _ := b.ask(b.host, "inspect", 600)
	mustStatus(t, "approve", b.approve("/api/ui/requests/"+first.ID, "decide", api.ChallengeRequest{Action: "approve", TTLSeconds: 600}), 200)
	now := b.clock.Now().UnixMilli()
	for i, row := range [][]string{{"bastion", "aqmas-inspect"}, {"bastion", "alice"}, {"ssh", "alice"}, {"ssh", "aqmas-inspect"}} {
		_, err = b.s.store.DB().Exec(`INSERT INTO standing(id,host_id,host_name,kind,target_host,login_user,max_ttl,created_at,expires_at,source_request_id,peer_address) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			ids.New()+string(rune('a'+i)), h.ID, "dev-1", row[0], "bastion", row[1], 86400, now, now+3600_000, first.ID, "127.0.0.1")
		requireNoError(t, err)
	}
	for _, level := range []string{"inspect", "root"} {
		rc, _, st := b.ask(b.host, level, 600)
		mustStatus(t, "ask "+level, st, 201)
		if rc.Status != "pending" {
			t.Fatalf("%s request was decided without a tap: %s", level, rc.Status)
		}
		if rs, _ := b.poll(b.host, rc.ID); rs.Status != "pending" || rs.Grant != nil {
			t.Fatalf("%s: %+v", level, rs)
		}
		// The shared decision path behind batches and windows refuses it.
		sess := mustSessionHash(b.env)
		pk, err := b.s.store.Q().SessionPasskeyID(ctx, sess)
		requireNoError(t, err)
		if _, err := b.s.ordinary(ctx, b.s.store.Q(), sess, pk, ordinaryChoice{rc.ID, "approve", 300}); err == nil {
			t.Fatalf("%s: the batch/window path accepted a bastion request", level)
		}
		// An attributed (batch or window) apply of a genuinely signed text is refused too.
		a, err := b.s.buildAction(ctx, canon.ObjectRequest, rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300})
		requireNoError(t, err)
		text, err := canon.Build(a, canon.NewNonce(), b.clock.Now())
		requireNoError(t, err)
		sg, err := canon.Parse(text)
		requireNoError(t, err)
		if err := b.s.applyOrdinary(ctx, b.s.store.Q(), sess, pk, text, "window=x"); err == nil {
			t.Fatalf("%s: applied through the window path", level)
		}
		if err := b.s.applyQ(ctx, b.s.store.Q(), sg, pk, "batch=x signed by test"); err == nil || !strings.Contains(err.Error(), "own passkey tap") {
			t.Fatalf("%s: attributed apply: %v", level, err)
		}
		if rs, _ := b.poll(b.host, rc.ID); rs.Status != "pending" {
			t.Fatalf("%s decided: %+v", level, rs)
		}
	}
	// What cannot be said cannot be signed.
	base := canon.Action{Action: "approve", Object: "request", ID: "x", Kind: "bastion", Level: "root", RequestingHost: "dev-1", Address: "127.0.0.1", Target: "bastion",
		TargetAddress: "192.0.2.10", TargetPort: 22, LoginUser: "alice", Principal: "alice@bastion", KeyFingerprint: "SHA256:k", TTLSeconds: 600, OpenBuckets: "[]"}
	base.HostID, base.SSHCA, base.HostKey, base.CertProfile = "E", "SHA256:c", "SHA256:h", "source-address;permit-pty"
	if _, err := canon.Build(base, canon.NewNonce(), b.clock.Now()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*canon.Action){
		"standing hours":     func(a *canon.Action) { a.StandingHours = 1 },
		"standing seconds":   func(a *canon.Action) { a.StandingSeconds = 60 },
		"indefinite":         func(a *canon.Action) { a.Indefinite = true },
		"over the cap":       func(a *canon.Action) { a.TTLSeconds = 3601 },
		"standing object":    func(a *canon.Action) { a.Object, a.Action = "standing", "revoke" },
		"org binding":        func(a *canon.Action) { a.OrgID = strings.Repeat("a", 32) },
		"inspect profile":    func(a *canon.Action) { a.CertProfile = "source-address;force-command" },
		"forwarding profile": func(a *canon.Action) { a.CertProfile = "source-address;permit-pty;permit-port-forwarding" },
		"other principal":    func(a *canon.Action) { a.Principal = "root@bastion" },
		"unsealed close":     func(a *canon.Action) { a.CloseBuckets = true },
		"unsealed open list": func(a *canon.Action) { a.OpenBuckets = `["SSH user CA"]` },
		"unsorted open list": func(a *canon.Action) { a.Sealed, a.OpenBuckets = true, `["b","a"]` },
		"padded open list":   func(a *canon.Action) { a.Sealed, a.OpenBuckets = true, `["a", "b"]` },
		"no open list":       func(a *canon.Action) { a.OpenBuckets = "" },
		"inspect with close": func(a *canon.Action) {
			a.Level, a.LoginUser, a.Principal, a.CertProfile, a.Sealed, a.CloseBuckets = "inspect", "aqmas-inspect", "aqmas-inspect@bastion", "source-address;force-command", true, true
		},
		"inspect with alert": func(a *canon.Action) {
			a.Level, a.LoginUser, a.Principal, a.CertProfile, a.AlertChannel = "inspect", "aqmas-inspect", "aqmas-inspect@bastion", "source-address;force-command", true
		},
		"deny with ttl":   func(a *canon.Action) { a.Action = "deny" },
		"unknown level":   func(a *canon.Action) { a.Level = "admin" },
		"no enrollment":   func(a *canon.Action) { a.HostID = "" },
		"zero ttl":        func(a *canon.Action) { a.TTLSeconds = 0 },
		"deny with close": func(a *canon.Action) { a.Action, a.TTLSeconds, a.Sealed, a.CloseBuckets = "deny", 0, true, true },
	} {
		a := base
		change(&a)
		if text, err := canon.Build(a, canon.NewNonce(), b.clock.Now()); err == nil {
			t.Errorf("%s: canonical text was built: %s", name, text)
		}
	}
}

// ---- sealed store, organisations mode ----

type sealedBastion struct {
	*vaultEnv
	b *bastionEnv
}

func newSealedBastion(t *testing.T) *sealedBastion {
	t.Helper()
	v := newVault(t)
	v.cfg.Bastion = testBastion
	requireNoError(t, v.cfg.Validate())
	v.restart(v.logs) // the catalogue's configuration fingerprint does not cover [bastion]
	v.agent = v.agentClient(v.agentCert())
	b := &bastionEnv{env: v.env, host: v.agent}
	h, err := v.s.store.Q().ActiveHostByName(t.Context(), "workload")
	requireNoError(t, err)
	b.enrollment, b.allowFile = h.EnrollmentID, filepath.Join(t.TempDir(), "bastion-allow.json")
	v.s.bastionAllowFile = b.allowFile
	b.allow(maint.AllowedHost{ID: b.enrollment, Name: "workload", Address: "127.0.0.1"})
	return &sealedBastion{v, b}
}

// tapDecide is decideTap that also returns the decision.
func (v *sealedBastion) tapDecide(path string, req api.ChallengeRequest) (tapResp, api.BastionDecision, int) {
	v.t.Helper()
	var r tapResp
	var dec api.BastionDecision
	if st := v.web("POST", path+"/challenge", req, &r); st != 200 {
		return r, dec, st
	}
	as, pkt := v.fix.tapWith(v.t, v.s, v.auth, r)
	return r, dec, v.web("POST", path+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, &dec)
}

// openEnv opens the env set's bucket with a hold that lasts (an approved, uncollected release).
func (v *sealedBastion) openEnv() {
	v.t.Helper()
	if v.revision() == 0 {
		v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "one"}}}, nil)
	}
	v.envApprove(v.envRelease())
}

// openWindow opens an approval window on the personal organisation (holds the SSH CA).
func (v *sealedBastion) openWindow() {
	v.t.Helper()
	t, s := v.t, v.s
	sess := ids.Hash(v.sess)
	pk, err := s.store.Q().SessionPasskeyID(t.Context(), sess)
	requireNoError(t, err)
	ctx := withAccess(t.Context(), s, sess)
	profiles, err := s.windowProfiles(ctx, s.store.Q(), sess, pk)
	requireNoError(t, err)
	var org string
	for _, p := range profiles {
		if p.Personal {
			org = p.Org
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public, _ := key.PublicKey.Bytes()
	res, err := s.windowOpenBegin(ctx, jsonReq(windowOpen{org, 300, encodeID(public), encodeID(v.auth.CredID)}), sess)
	requireNoError(t, err)
	cr := res.(api.ChallengeResponse)
	opts, _ := json.Marshal(cr.PublicKey)
	as, pkt := v.fix.tapWith(t, s, v.auth, tapResp{ChallengeID: cr.ChallengeID, Canonical: cr.Canonical, PublicKey: opts, Open: cr.Open})
	_, err = s.windowOpenFinish(ctx, jsonReq(api.DecideRequest{ChallengeID: cr.ChallengeID, Assertion: as, Open: pkt}), sess)
	requireNoError(t, err)
	restoreAccess(s, sess)
}

func (v *sealedBastion) windows() int {
	z := v.s.seal
	z.windows.Lock()
	defer z.windows.Unlock()
	return len(z.windows.active)
}

func canonicalOf(t *testing.T, text string) map[string]any {
	t.Helper()
	var m map[string]any
	requireNoError(t, json.Unmarshal([]byte(text), &m))
	return m
}

// The red card lists what is open; "close first" closes all of it before the certificate
// exists for the requester, and again when it is handed out.
func TestBastionRootClosesBuckets(t *testing.T) {
	v := newSealedBastion(t)
	v.openEnv()
	v.openWindow()
	if n := v.s.seal.pool.count(); n != 2 || v.windows() != 1 {
		t.Fatalf("fixture: %d buckets, %d windows open", n, v.windows())
	}
	rc, _, st := v.b.ask(v.agent, "root", 600)
	mustStatus(t, "ask", st, 201)
	// The status page keeps working in organisations mode with an unbound request on it.
	item, ok := pendingBastion(t, v.env, rc.ID)
	want := []string{"SSH user CA", "client-a/paas/staging"}
	if !ok || item.Bastion.Level != "root" || !item.Bastion.Sealed || !slices.Equal(item.Bastion.OpenBuckets, want) {
		t.Fatalf("card: %+v", item.Bastion)
	}
	path := "/api/ui/requests/" + rc.ID
	mustStatus(t, "the choice is required", v.web("POST", path+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 600}, nil), 400)
	// A batch cannot carry it.
	if st := v.web("POST", "/api/ui/seal/batch/challenge", map[string]any{"items": []ordinaryChoice{{rc.ID, "approve", 300}}}, nil); st/100 == 2 {
		t.Fatalf("batch accepted a bastion request: %d", st)
	}
	r, dec, st := v.tapDecide(path, api.ChallengeRequest{Action: "approve", TTLSeconds: 600, CloseBuckets: boolp(true)})
	mustStatus(t, "approve", st, 200)
	c := canonicalOf(t, r.Canonical)
	if c["open_buckets"] != `["SSH user CA","client-a/paas/staging"]` || c["close_buckets"] != true || c["sealed"] != true || c["level"] != "root" || c["v"] != float64(1) {
		t.Fatalf("canonical %v", c)
	}
	if r.Open == nil || !strings.Contains(r.Open.Descriptor, "ssh-ca") || strings.Contains(r.Open.Descriptor, "re-arms") {
		t.Fatalf("the tap must open the SSH CA for an instant and nothing else: %+v", r.Open)
	}
	if dec.Closed != 2 || dec.Level != "root" || dec.Alert == "" {
		t.Fatalf("decision %+v", dec)
	}
	if n := v.s.seal.pool.count(); n != 0 || v.windows() != 0 {
		t.Fatalf("after approval %d buckets and %d windows are still open", n, v.windows())
	}
	// Something is opened between approval and collection: it closes again at delivery.
	v.openEnv()
	if v.s.seal.pool.count() != 1 {
		t.Fatal("fixture: nothing reopened")
	}
	rs, st := v.b.poll(v.agent, rc.ID)
	if st != 200 || rs.Grant == nil || rs.Grant.SSH.Certificate == "" {
		t.Fatalf("delivery: %d %+v", st, rs)
	}
	if n := v.s.seal.pool.count(); n != 0 {
		t.Fatalf("%d buckets open when the certificate was handed out", n)
	}
	// Organisations mode: the page still renders with a bastion grant active, and it can be revoked.
	var state api.UIState
	mustStatus(t, "state", v.web("GET", "/api/ui/state", nil, &state), 200)
	if state.BastionRootUntil == nil || !slices.ContainsFunc(state.Grants, func(g api.GrantSummary) bool { return g.Kind == "bastion" }) {
		t.Fatalf("state %+v", state.Grants)
	}
}

// Without "close first" the signed list is a ceiling: anything opened after the card was
// shown stops the approval.
func TestBastionRootOpenListIsBinding(t *testing.T) {
	v := newSealedBastion(t)
	v.openEnv()
	rc, _, _ := v.b.ask(v.agent, "root", 600)
	path := "/api/ui/requests/" + rc.ID
	var r tapResp
	mustStatus(t, "challenge", v.web("POST", path+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 600, CloseBuckets: boolp(false)}, &r), 200)
	if c := canonicalOf(t, r.Canonical); c["open_buckets"] != `["client-a/paas/staging"]` || c["close_buckets"] != false {
		t.Fatalf("canonical %v", c)
	}
	v.openWindow() // the SSH CA opens after the card was built
	as, pkt := v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "stale card", v.web("POST", path+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil), 409)
	if rs, _ := v.b.poll(v.agent, rc.ID); rs.Status != "pending" {
		t.Fatalf("a stale card was applied: %+v", rs)
	}
	if v.s.seal.pool.count() != 2 {
		t.Fatal("a refused approval changed what is open")
	}
	// Reviewed again with the longer list, it goes through and leaves both open, as signed.
	r2, dec, st := v.tapDecide(path, api.ChallengeRequest{Action: "approve", TTLSeconds: 600, CloseBuckets: boolp(false)})
	mustStatus(t, "approve", st, 200)
	if c := canonicalOf(t, r2.Canonical); c["open_buckets"] != `["SSH user CA","client-a/paas/staging"]` {
		t.Fatalf("canonical %v", c)
	}
	if dec.Closed != 0 || v.s.seal.pool.count() != 2 {
		t.Fatalf("decision %+v, %d open", dec, v.s.seal.pool.count())
	}
	// A list that shrank is fine: fewer buckets are open than were signed.
	rc, _, _ = v.b.ask(v.agent, "root", 600)
	path = "/api/ui/requests/" + rc.ID
	r = tapResp{}
	mustStatus(t, "challenge", v.web("POST", path+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 600, CloseBuckets: boolp(false)}, &r), 200)
	v.s.closeAll()
	mustStatus(t, "challenge again", v.web("POST", path+"/challenge", api.ChallengeRequest{Action: "approve", TTLSeconds: 600, CloseBuckets: boolp(false)}, &r), 200)
	as, pkt = v.fix.tapWith(t, v.s, v.auth, r)
	mustStatus(t, "approve", v.web("POST", path+"/decide", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: as, Open: pkt}, nil), 200)
	// An inspect approval in a sealed store opens the CA for an instant and keeps nothing.
	rc, _, _ = v.b.ask(v.agent, "inspect", 600)
	_, _, st = v.tapDecide("/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 600})
	mustStatus(t, "inspect", st, 200)
	if v.s.seal.pool.count() != 0 {
		t.Fatal("an inspect approval left a bucket open")
	}
	if rs, _ := v.b.poll(v.agent, rc.ID); rs.Grant == nil || rs.Grant.SSH.Certificate == "" {
		t.Fatalf("inspect certificate: %+v", rs)
	}
}

// ---- routine maintenance queued by an agent ----

func TestSetupRequestsNeedTheTap(t *testing.T) {
	b := newBastion(t, nil)
	pins, _ := b.installRunner()
	_ = pins
	spool := maint.RequestPath(b.cfg.Updates.Spool())
	queue := func(c *http.Client, task string, params any) (api.RequestCreated, int) {
		t.Helper()
		var rc api.RequestCreated
		body := map[string]any{"task": task, "reason": "disk is filling up", "requester": map[string]any{"tool": "other", "user": "agent"}}
		if params != nil {
			body["params"] = params
		}
		st, err := agentDo(t, c, "POST", b.agent.URL+"/v1/setup-requests", body, &rc)
		requireNoError(t, err)
		return rc, st
	}
	// Only the routine tasks, only harmless parameters, always with a reason.
	for name, tc := range map[string]struct {
		task   string
		params any
		want   int
	}{
		"access task":       {maint.TaskBastionAccess, map[string]any{"name": "bastion", "address": "192.0.2.10", "port": 22, "admin_user": "alice", "ssh_ca": "SHA256:" + strings.Repeat("A", 43)}, 403},
		"allowlist task":    {maint.TaskBastionAllow, map[string]any{"hosts": []any{}}, 403},
		"removal task":      {maint.TaskBastionRemove, nil, 403},
		"seal":              {maint.TaskSeal, nil, 400},
		"upgrade":           {maint.TaskUpgrade, nil, 400},
		"unknown":           {"shell", nil, 400},
		"kernel update":     {maint.TaskOSUpdate, map[string]any{"kernel": true}, 403},
		"short journal":     {maint.TaskJournalVacuum, map[string]any{"keep_days": 3}, 403},
		"journal range":     {maint.TaskJournalVacuum, map[string]any{"keep_days": 9999}, 400},
		"unknown parameter": {maint.TaskOSUpdate, map[string]any{"kernel": false, "args": "--nogpgcheck"}, 400},
		"string for bool":   {maint.TaskOSUpdate, map[string]any{"kernel": "--installroot=/"}, 400},
		"stray parameter":   {maint.TaskDiskUsage, map[string]any{"path": "/etc/aqmas"}, 400},
	} {
		if _, st := queue(b.host, tc.task, tc.params); st != tc.want {
			t.Errorf("%s: HTTP %d, want %d", name, st, tc.want)
		}
	}
	st, _ := agentDo(t, b.host, "POST", b.agent.URL+"/v1/setup-requests", map[string]any{"task": maint.TaskDiskUsage, "requester": map[string]any{"tool": "other", "user": "a"}}, nil)
	mustStatus(t, "no reason", st, 400)

	rc, st := queue(b.host, maint.TaskJournalVacuum, map[string]any{"keep_days": 14})
	mustStatus(t, "queue", st, 201)
	if _, st := queue(b.host, maint.TaskDiskUsage, nil); st != 429 {
		t.Fatalf("second pending request from one host: %d", st)
	}
	// Queued is all it is: nothing in the spool, nothing running.
	if _, err := os.Lstat(spool); err == nil {
		t.Fatal("a queued request reached the runner's spool")
	}
	var rs api.SetupRequestStatus
	st, _ = agentDo(t, b.host, "GET", b.agent.URL+"/v1/setup-requests/"+rc.ID, nil, &rs)
	if st != 200 || rs.Status != "pending" || rs.Run != nil || rs.Task != maint.TaskJournalVacuum {
		t.Fatalf("status %d %+v", st, rs)
	}
	other := b.enrollHost("dev-2")
	st, _ = agentDo(t, b.agentClient(&other), "GET", b.agent.URL+"/v1/setup-requests/"+rc.ID, nil, nil)
	mustStatus(t, "other host", st, 404)
	item, ok := pendingBastion(t, b.env, rc.ID)
	if !ok || item.Kind != "setup" || item.Setup == nil || item.Setup.Task != maint.TaskJournalVacuum || item.Setup.Params != `{"keep_days":14}` || item.Setup.Blocked != "" ||
		item.RequestingHost != "dev-1" || item.Reason != "disk is filling up" || item.Setup.Title == "" {
		t.Fatalf("card %+v %+v", item, item.Setup)
	}
	// The owner's tap signs the task and its parameters. A signature for other parameters,
	// or for another task, does not answer this request.
	run := func(task string, params any, request string) int {
		t.Helper()
		var cr challengeResp
		mustStatus(t, "challenge", b.webDo("POST", "/api/ui/setup/"+task+"/challenge", map[string]any{"params": params}, &cr), 200)
		as, err := b.auth.AssertOptions(cr.PublicKey)
		requireNoError(t, err)
		return b.webDo("POST", "/api/ui/setup/"+task+"/run", map[string]any{"challenge_id": cr.ChallengeID, "assertion": as, "request": request}, nil)
	}
	mustStatus(t, "other parameters", run(maint.TaskJournalVacuum, map[string]any{"keep_days": 1}, rc.ID), 409)
	mustStatus(t, "other task", run(maint.TaskDiskUsage, map[string]any{}, rc.ID), 409)
	mustStatus(t, "unknown request", run(maint.TaskDiskUsage, map[string]any{}, "01NOSUCHREQUEST00000000000"), 404)
	if _, err := os.Lstat(spool); err == nil {
		t.Fatal("a refused answer was spooled")
	}
	mustStatus(t, "approve", run(maint.TaskJournalVacuum, map[string]any{"keep_days": 14}, rc.ID), 200)
	raw, err := os.ReadFile(spool)
	requireNoError(t, err)
	var spooled maint.Request
	requireNoError(t, json.Unmarshal(raw, &spooled))
	// What reached the runner is what it verifies itself: the signed task and parameters.
	verified, err := maint.Verify(spooled, testBase, pins, b.clock.Now())
	requireNoError(t, err)
	if p, ok := verified.Params.(maint.JournalVacuumParams); !ok || p.KeepDays != 14 || verified.Task != maint.TaskJournalVacuum {
		t.Fatalf("spooled %+v", verified)
	}
	st, _ = agentDo(t, b.host, "GET", b.agent.URL+"/v1/setup-requests/"+rc.ID, nil, &rs)
	if st != 200 || rs.Status != "approved" || rs.Run == nil || rs.Run.State != "queued" {
		t.Fatalf("after approval %d %+v %+v", st, rs, rs.Run)
	}
	// The runner's public status of that run, matched by the digest of the signed text.
	digest := ids.Hash(spooled.Canonical)[:16]
	status := maint.ReadStatus(maint.StatusPath(b.cfg.Updates.Cache()))
	status.Tasks[maint.TaskJournalVacuum] = &maint.TaskStatus{Task: maint.TaskJournalVacuum, Request: digest, State: "done", Message: "Journal trimmed.", Result: map[string]string{"freed": "120M"}}
	out, _ := json.Marshal(status)
	requireNoError(t, os.WriteFile(maint.StatusPath(b.cfg.Updates.Cache()), out, 0o644))
	rs = api.SetupRequestStatus{}
	agentDo(t, b.host, "GET", b.agent.URL+"/v1/setup-requests/"+rc.ID, nil, &rs)
	if rs.Run == nil || rs.Run.State != "done" || rs.Run.Result["freed"] != "120M" {
		t.Fatalf("run status %+v", rs.Run)
	}
	// A refusal is reported only to the request it refuses: another task's is not this host's news.
	delete(status.Tasks, maint.TaskJournalVacuum)
	status.Refused = &maint.Refusal{At: b.clock.Now().UTC().Format(time.RFC3339), Reason: "another task's refusal", Request: "0000000000000000"}
	out, _ = json.Marshal(status)
	requireNoError(t, os.WriteFile(maint.StatusPath(b.cfg.Updates.Cache()), out, 0o644))
	rs = api.SetupRequestStatus{}
	agentDo(t, b.host, "GET", b.agent.URL+"/v1/setup-requests/"+rc.ID, nil, &rs)
	if rs.Run == nil || rs.Run.State != "queued" {
		t.Fatalf("a foreign refusal was reported: %+v", rs.Run)
	}
	status.Refused.Request = digest
	out, _ = json.Marshal(status)
	requireNoError(t, os.WriteFile(maint.StatusPath(b.cfg.Updates.Cache()), out, 0o644))
	agentDo(t, b.host, "GET", b.agent.URL+"/v1/setup-requests/"+rc.ID, nil, &rs)
	if rs.Run == nil || rs.Run.State != "refused" {
		t.Fatalf("its own refusal was not reported: %+v", rs.Run)
	}
	// Dismiss and cancel only ever return to "nothing queued".
	requireNoError(t, os.Remove(spool))
	rc, st = queue(b.host, maint.TaskDiskUsage, nil)
	mustStatus(t, "queue", st, 201)
	mustStatus(t, "dismiss", b.webDo("POST", "/api/ui/setup-requests/"+rc.ID+"/dismiss", map[string]any{}, nil), 200)
	agentDo(t, b.host, "GET", b.agent.URL+"/v1/setup-requests/"+rc.ID, nil, &rs)
	if rs.Status != "denied" {
		t.Fatalf("after dismiss %+v", rs)
	}
	mustStatus(t, "answer a dismissed request", run(maint.TaskDiskUsage, map[string]any{}, rc.ID), 409)
	rc, st = queue(b.host, maint.TaskDiskUsage, nil)
	mustStatus(t, "queue", st, 201)
	st, _ = agentDo(t, b.host, "POST", b.agent.URL+"/v1/setup-requests/"+rc.ID+"/cancel", nil, nil)
	mustStatus(t, "cancel", st, 200)
	// A host that keeps asking is told to wait.
	if _, st := queue(b.host, maint.TaskDiskUsage, nil); st != 429 {
		t.Fatalf("no cooldown: %d", st)
	}
	if _, err := os.Lstat(spool); err == nil {
		t.Fatal("dismissed or cancelled requests reached the spool")
	}
}

// The new tasks on the Setup page: availability and parameter schema as the page sees it.
func TestBastionSetupTasks(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	e.installRunner()
	var v setupOut
	mustStatus(t, "view", e.webDo("GET", "/api/ui/setup", nil, &v), 200)
	if v.state(maint.TaskBastionAccess) != "available:" || !strings.HasPrefix(v.state(maint.TaskBastionRemove), "blocked:Access to the bastion") ||
		!strings.HasPrefix(v.state(maint.TaskBastionAllow), "blocked:") || v.state(maint.TaskOSUpdate) != "available:" || v.state(maint.TaskReboot) != "available:" {
		t.Fatalf("queue %+v", v)
	}
	good := map[string]any{"name": "bastion", "address": "192.0.2.10", "port": 22, "admin_user": "alice", "ssh_ca": e.s.sshPin()}
	with := func(k string, val any) map[string]any {
		m := map[string]any{}
		for key, v := range good {
			m[key] = v
		}
		m[k] = val
		return m
	}
	for name, tc := range map[string]struct {
		task   string
		params any
		want   int
	}{
		"access":                  {maint.TaskBastionAccess, good, 200},
		"access: root":            {maint.TaskBastionAccess, with("admin_user", "root"), 400},
		"access: inspect account": {maint.TaskBastionAccess, with("admin_user", "aqmas-inspect"), 400},
		"access: host name":       {maint.TaskBastionAccess, with("address", "bastion.example.com"), 400},
		"access: option in name":  {maint.TaskBastionAccess, with("name", "-oProxyCommand=id"), 400},
		"access: shell in user":   {maint.TaskBastionAccess, with("admin_user", "alice;id"), 400},
		"access: fingerprint":     {maint.TaskBastionAccess, with("ssh_ca", "SHA256:short"), 400},
		"access: extra key":       {maint.TaskBastionAccess, with("inspect_user", "bob"), 400},
		"allow: not installed":    {maint.TaskBastionAllow, map[string]any{"hosts": []any{}}, 409},
		"update":                  {maint.TaskOSUpdate, map[string]any{"kernel": true}, 200},
		"update: extra":           {maint.TaskOSUpdate, map[string]any{"kernel": false, "exclude": "*"}, 400},
		"vacuum":                  {maint.TaskJournalVacuum, map[string]any{"keep_days": 1}, 200},
		"vacuum: zero":            {maint.TaskJournalVacuum, map[string]any{"keep_days": 0}, 400},
		"vacuum: string":          {maint.TaskJournalVacuum, map[string]any{"keep_days": "1d --flush"}, 400},
		"restart: stray":          {maint.TaskRestartBroker, map[string]any{"unit": "sshd"}, 400},
	} {
		var cr challengeResp
		st := e.webDo("POST", "/api/ui/setup/"+tc.task+"/challenge", map[string]any{"params": tc.params}, &cr)
		if st != tc.want {
			t.Errorf("%s: HTTP %d, want %d", name, st, tc.want)
		}
		if st == 200 {
			sg, err := canon.Parse(cr.Canonical)
			if err != nil || sg.Object != canon.ObjectSetup || sg.ID != tc.task {
				t.Errorf("%s: canonical %s: %v", name, cr.Canonical, err)
			}
			if _, err := maint.Parse(tc.task, sg.Params); err != nil {
				t.Errorf("%s: the runner would refuse %s: %v", name, sg.Params, err)
			}
		}
	}
}
