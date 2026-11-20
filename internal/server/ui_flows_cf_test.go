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

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// TestUIFlowsCloudflare runs the web UI's own flow code (testdata/ui_driver_cf.ts) against a
// Cloudflare-enabled server (fake proxy and minter) while this test plays the fleet host: the
// canonical texts the server builds for kind "cloudflare" pass the UI's pre-signing checks, and
// what the owner signs is what gets applied. Skipped unless AQMAS_WEB_DIR is set.
func TestUIFlowsCloudflare(t *testing.T) {
	webDir := os.Getenv("AQMAS_WEB_DIR")
	if webDir == "" {
		t.Skip("AQMAS_WEB_DIR not set")
	}
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("bun not found")
	}
	e := newCFEnv(t, cfConfig(t, true))
	code, err := NewEnrollCode(e.cfg.DataDir, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	driver, _ := filepath.Abs("testdata/ui_driver_cf.ts")
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

	cert := e.enrollHostWaiting("cfhost")
	host := e.agentClient(&cert)
	waitApproved := func(id string) api.RequestStatus {
		t.Helper()
		var rs api.RequestStatus
		for i := 0; i < 10 && rs.Status != "approved"; i++ {
			rs, _ = e.status(host, id, "10s")
		}
		if rs.Status != "approved" || rs.Grant == nil || rs.Grant.Cloudflare == nil {
			t.Fatalf("request %s not approved via UI: %+v", id, rs)
		}
		return rs
	}
	dnsParams := map[string]string{"zone": "example.net", "name": "*.example.net"}
	rc, st := e.cfRequest(host, "cf.dns.edit", dnsParams, "", 7200)
	mustStatus(t, "dns request", st, 201)
	rs := waitApproved(rc.ID)
	if g := rs.Grant; g.NotAfter.Sub(g.NotBefore) != time.Hour || g.Cloudflare.Mode != "proxy" || g.Cloudflare.Token != "" {
		t.Fatalf("dns grant %+v %+v", g, g.Cloudflare)
	}
	if rc2, _ := e.cfRequest(host, "cf.dns.edit", dnsParams, "", 1800); rc2.Status != "approved" {
		t.Fatalf("standing approval from the UI not applied: %s", rc2.Status)
	}
	rc, _ = e.cfRequest(host, "cf.workers.deploy", map[string]string{"script": "my-worker"}, "token", 3600)
	rs = waitApproved(rc.ID)
	if rs.Grant.Cloudflare.Token == "" || rs.Grant.Cloudflare.TokenID == "" {
		t.Fatalf("token grant delivered no token: %+v", rs.Grant.Cloudflare)
	}
	tokenGrant, tokenID := rs.Grant.ID, rs.Grant.Cloudflare.TokenID
	rc, _ = e.cfRequest(host, "cf.admin", nil, "", 3600)
	rs = waitApproved(rc.ID)
	if d := rs.Grant.NotAfter.Sub(rs.Grant.NotBefore); d != 30*time.Minute {
		t.Fatalf("admin grant lasts %v, want the 30 min the owner chose", d)
	}

	var revokedGrant, revokedStanding string
	for l := range lines {
		if v, ok := strings.CutPrefix(l, "REVOKED-GRANT "); ok {
			revokedGrant = v
		}
		if v, ok := strings.CutPrefix(l, "REVOKED-STANDING "); ok {
			revokedStanding = v
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("ui driver failed: %v", err)
	}
	if revokedGrant != tokenGrant || revokedStanding == "" {
		t.Fatalf("driver revoked grant %q standing %q, want grant %q", revokedGrant, revokedStanding, tokenGrant)
	}
	if !e.minter.wasDeleted(tokenID) {
		t.Fatal("revoking the token grant did not delete the child token")
	}
	if rc3, _ := e.cfRequest(host, "cf.dns.edit", dnsParams, "", 600); rc3.Status != "pending" {
		t.Fatal("standing approval still used after the UI revoke")
	}
}
