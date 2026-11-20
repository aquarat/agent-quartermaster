package server

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// TestUIFlows runs the web UI's own flow code (ws/web: web/src/flows.ts, api.ts) against this
// server via testdata/ui_driver.ts under Bun, while this test plays the fleet host. Skipped
// unless AQMAS_WEB_DIR points at a web/ checkout (and bun is on PATH).
func TestUIFlows(t *testing.T) {
	webDir := os.Getenv("AQMAS_WEB_DIR")
	if webDir == "" {
		t.Skip("AQMAS_WEB_DIR not set")
	}
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("bun not found")
	}
	e := newEnv(t)
	code, err := NewEnrollCode(e.cfg.DataDir, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	driver, _ := filepath.Abs("testdata/ui_driver.ts")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bun, driver)
	cmd.Env = append(os.Environ(), "AQMAS_WEB_DIR="+webDir, "AQMAS_BASE="+e.web.URL, "AQMAS_ORIGIN="+testBase, "AQMAS_CODE="+code)
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			t.Log(sc.Text())
			lines <- sc.Text()
		}
		close(lines)
	}()

	// Host side: enroll, wait for the owner (driver) to approve, request SSH access.
	cert := e.enrollHostWaiting("uihost")
	host := e.agentClient(&cert)
	rc, pub, st := e.request(host, "db-1", "alice", 1800)
	mustStatus(t, "request", st, 201)
	var rs api.RequestStatus
	for i := 0; i < 10 && rs.Status != "approved"; i++ {
		rs, _ = e.status(host, rc.ID, "10s")
	}
	if rs.Status != "approved" || rs.Grant == nil {
		t.Fatalf("request not approved via UI: %+v", rs)
	}
	k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(rs.Grant.SSH.Certificate))
	c := k.(*ssh.Certificate)
	if string(c.Key.Marshal()) != string(pub.Marshal()) || c.ValidBefore-c.ValidAfter != 660 || c.ValidPrincipals[0] != "alice@db-1" {
		t.Fatalf("certificate %+v", c)
	}
	// Standing approval chosen in the UI auto-approves the next matching request.
	rc2, _, _ := e.request(host, "db-1", "alice", 600)
	if rc2.Status != "approved" {
		t.Fatalf("standing approval from UI not applied: %s", rc2.Status)
	}

	var revoked string
	for l := range lines {
		if after, ok := strings.CutPrefix(l, "REVOKED-GRANT "); ok {
			revoked = after
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("ui driver failed: %v", err)
	}
	if revoked != rs.Grant.ID {
		t.Fatalf("driver revoked %q, want first grant %q", revoked, rs.Grant.ID)
	}
	if rs, _ := e.status(host, rc.ID, ""); rs.Status != "revoked" {
		t.Fatalf("revoked grant's request status %q", rs.Status)
	}
	if rc3, _, _ := e.request(host, "db-1", "alice", 600); rc3.Status != "pending" {
		t.Fatal("standing approval still used after UI revoke")
	}
}

// enrollHostWaiting enrolls and long-polls until someone else (the UI) approves.
func (e *env) enrollHostWaiting(name string) (cert tlsCert) {
	e.t.Helper()
	key, csr := newCSR(e.t, name)
	anon := e.agentClient(nil)
	var er api.EnrollResponse
	if st, err := agentDo(e.t, anon, "POST", e.agent.URL+"/v1/enroll", api.EnrollRequest{Hostname: name, CSRPEM: csr}, &er); err != nil || st != 201 {
		e.t.Fatalf("enroll: %d %v", st, err)
	}
	var es api.EnrollStatus
	for i := 0; i < 10 && es.Status != "approved"; i++ {
		agentDo(e.t, anon, "GET", e.agent.URL+"/v1/enroll/"+er.ID+"?wait=10s", nil, &es)
	}
	if es.ClientCertPEM == "" {
		e.t.Fatalf("enrollment not approved via UI: %+v", es)
	}
	return certFromPEM(e.t, es.ClientCertPEM, key)
}
