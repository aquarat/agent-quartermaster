package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// A database at schema version 2 (milestone 1) migrates to 3 with its SSH rows intact and the
// Cloudflare columns empty.
func TestMigrationFromM1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aqmas.db")
	v := url.Values{}
	v.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range migrations[:2] {
		if _, err := db.Exec(m); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
	}
	now := time.Now().UnixMilli()
	for _, stmt := range []string{
		fmt.Sprintf(`INSERT INTO enrollments(id, hostname, csr_pem, key_fingerprint, peer_address, status, created_at, expires_at) VALUES ('E', 'hosta', 'csr', 'fp', '127.0.0.1', 'approved', %d, %d)`, now, now),
		fmt.Sprintf(`INSERT INTO hosts(id, name, cert_sha256, enrollment_id, created_at, not_after) VALUES (1, 'hosta', 'c', 'E', %d, %d)`, now, now+1e9),
		fmt.Sprintf(`INSERT INTO standing(id, host_id, host_name, kind, target_host, login_user, max_ttl, created_at, expires_at, source_request_id, peer_address) VALUES ('S', 1, 'hosta', 'ssh', 'db-1', 'alice', 600, %d, %d, 'R', '127.0.0.1')`, now, now+1e9),
		fmt.Sprintf(`INSERT INTO requests(id, host_id, host_name, peer_address, kind, target_host, login_user, public_key, key_fingerprint, reason, requester_json, ttl_requested, status, created_at, expires_at) VALUES ('R', 1, 'hosta', '127.0.0.1', 'ssh', 'db-1', 'alice', 'pk', 'SHA256:x', 'why', '{}', 600, 'approved', %d, %d)`, now, now+1e9),
		fmt.Sprintf(`INSERT INTO grants(id, request_id, host_id, host_name, kind, target_host, login_user, principals, certificate, not_before, not_after) VALUES ('G', 'R', 1, 'hosta', 'ssh', 'db-1', 'alice', '["alice@db-1"]', 'cert', %d, %d)`, now, now+1e9),
		"PRAGMA user_version = 2",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	var ver int
	st.DB().QueryRow("PRAGMA user_version").Scan(&ver)
	if ver != len(migrations) || ver < 3 {
		t.Fatalf("user_version %d", ver)
	}
	q := st.Q()
	r, err := q.GetRequest(ctx, "R")
	if err != nil || r.TargetHost != "db-1" || r.KeyFingerprint != "SHA256:x" || r.Scope != "" || r.Mode != "" || r.IPCondition != "" {
		t.Fatalf("request %+v %v", r, err)
	}
	g, err := q.GetGrant(ctx, "G")
	if err != nil || g.Certificate != "cert" || len(g.Principals) != 1 || g.Scope != "" || g.TokenID != "" || g.TokenDelivered || g.TokenDeletedAt != nil {
		t.Fatalf("grant %+v %v", g, err)
	}
	s, err := q.GetStanding(ctx, "S")
	if err != nil || s.TargetHost != "db-1" || s.Scope != "" {
		t.Fatalf("standing %+v %v", s, err)
	}
	// SSH grants are never Cloudflare grants.
	if ok, _ := q.HasActiveCFGrant(ctx, 1, time.Now()); ok {
		t.Fatal("ssh grant counted as cloudflare")
	}
	if gs, _ := q.ActiveProxyGrants(ctx, 1, []string{"G"}, time.Now()); len(gs) != 0 {
		t.Fatal("ssh grant offered to the proxy")
	}
}

func TestTokenGrantLifecycle(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "aqmas.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := q.InsertEnrollment(ctx, &Enrollment{ID: "E", Hostname: "hosta", PeerAddress: "x", CreatedAt: now, ExpiresAt: now}); err != nil {
		t.Fatal(err)
	}
	hid, _ := q.InsertHost(ctx, &Host{Name: "hosta", CertSHA256: "c", EnrollmentID: "E", CreatedAt: now, NotAfter: now.Add(time.Hour)})
	q.InsertRequest(ctx, &Request{ID: "R", HostID: hid, HostName: "hosta", Kind: "cloudflare", Status: "approved", CreatedAt: now, ExpiresAt: now,
		Scope: "cf.pages", ScopeParams: "project=blog", Mode: "token", IPCondition: "203.0.113.7/32"})
	if _, err := q.InsertGrant(ctx, &Grant{ID: "G", RequestID: "R", HostID: hid, HostName: "hosta", Kind: "cloudflare", NotBefore: now,
		NotAfter: now.Add(time.Hour), Scope: "cf.pages", ScopeParams: "project=blog", Mode: "token", IPCondition: "203.0.113.7/32", PeerAddress: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := q.MarkTokenDelivering(ctx, "G", now); !ok {
		t.Fatal("first claim lost")
	}
	if ok, _ := q.MarkTokenDelivering(ctx, "G", now); ok {
		t.Fatal("second claim won")
	}
	q.UnmarkTokenDelivered(ctx, "G")
	if ok, _ := q.MarkTokenDelivering(ctx, "G", now); !ok {
		t.Fatal("claim after unmark lost")
	}
	if err := q.SetTokenID(ctx, "G", "T1"); err != nil {
		t.Fatal(err)
	}
	q.UnmarkTokenDelivered(ctx, "G") // no effect once the id is recorded
	g, _ := q.GetGrant(ctx, "G")
	if !g.TokenDelivered || g.TokenID != "T1" || g.IPCondition != "203.0.113.7/32" || g.PeerAddress != "127.0.0.1" {
		t.Fatalf("grant %+v", g)
	}
	if gs, _ := q.TokenGrantsToDelete(ctx, now); len(gs) != 0 {
		t.Fatal("live token listed for deletion")
	}
	if gs, _ := q.TokenGrantsToDelete(ctx, now.Add(time.Hour)); len(gs) != 1 {
		t.Fatal("expired token not listed")
	}
	// Revoking the host revokes its Cloudflare grants: the token is then due for deletion.
	if err := q.RevokeHost(ctx, hid, now); err != nil {
		t.Fatal(err)
	}
	if gs, _ := q.TokenGrantsToDelete(ctx, now); len(gs) != 1 {
		t.Fatal("revoked host's token not listed")
	}
	if r, _ := q.GetRequest(ctx, "R"); r.Status != "revoked" {
		t.Fatalf("request %s", r.Status)
	}
	q.MarkTokenDeleted(ctx, "G", now)
	if gs, _ := q.TokenGrantsToDelete(ctx, now.Add(time.Hour)); len(gs) != 0 {
		t.Fatal("deleted token still listed")
	}
}
