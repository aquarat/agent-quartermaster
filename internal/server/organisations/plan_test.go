package organisations_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

var instant = time.UnixMilli(2000).UTC()

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) (*store.Store, *config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir = dir
	cfg.PublicBaseURL = "https://approvals.example.com"
	cfg.Ntfy.TopicURL = "https://example.com/SECRET-topic"
	cfg.Targets = []config.Target{{Name: "build", Address: "192.0.2.10", Users: []string{"alice"}, HighRisk: true}}
	cfg.Cloudflare = config.Cloudflare{Enabled: true, AccountID: strings.Repeat("a", 32), ProxyTokenFile: filepath.Join(dir, "parent"), TokenIPCondition: []string{"192.0.2.1/32"}, ProtectedDNSNames: []string{"safe.example.com"}, Scopes: map[string]config.CFScopeOverride{"cf.read": {NoAutoApprove: true}, "cf.email": {Disabled: true}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Cloudflare.ProxyTokenFile, []byte("SECRET-parent"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "aqmas.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	db := s.DB()
	mustExec(t, db, `INSERT INTO meta VALUES('owner_webauthn_id',zeroblob(32));INSERT INTO passkeys(credential_id,credential_json,created_at) VALUES(x'01','SECRET-json',1);
INSERT INTO enrollments(id,hostname,csr_pem,key_fingerprint,peer_address,status,created_at,expires_at) VALUES ('a','builder','SECRET-csr','fp','192.0.2.20','approved',1,20),('b','other','','fp','192.0.2.21','approved',1,20),('c','expired','','fp','192.0.2.22','approved',1,20);
INSERT INTO hosts VALUES(11,'builder','a','a',1,9000,NULL),(12,'other','b','b',1,9000,111),(13,'expired','c','c',1,1999,NULL);
INSERT INTO requests(id,host_id,host_name,peer_address,kind,target_host,login_user,public_key,key_fingerprint,reason,requester_json,ttl_requested,status,created_at,expires_at) VALUES
 ('r1',11,'builder','','ssh','build','alice','','','SECRET-reason','{}',30,'approved',1,3000),('r2',11,'builder','','cloudflare','','','','','','{}',30,'approved',1,3000),('r3',11,'builder','','ssh','build','alice','','','','{}',30,'pending',1,3000);
INSERT INTO grants(serial,id,request_id,host_id,host_name,kind,target_host,login_user,principals,certificate,not_before,not_after,revoked_at,mode,token_id,token_delivered) VALUES
 (10,'g1','r1',11,'builder','ssh','build','alice','[]','SECRET-cert',1,4000,100,'','',0),
 (11,'g2','r2',11,'builder','cloudflare','','','[]','',1,4000,NULL,'token','upstream-id',1);
UPDATE sqlite_sequence SET seq=108 WHERE name='grants';INSERT INTO audit(at,actor,action,object) VALUES(1,'owner','old','grant:g1')`)
	backup := filepath.Join(dir, "personal #1?.sqlite")
	mustExec(t, db, "VACUUM INTO ?", backup)
	return s, cfg, backup
}

func TestReadOnlyPersonalInventory(t *testing.T) {
	_, cfg, bak := fixture(t)
	ctx := t.Context()
	before, err := os.ReadFile(bak)
	if err != nil {
		t.Fatal(err)
	}
	read := func() *organisations.Plan {
		t.Helper()
		p, err := organisations.InspectBackup(ctx, bak, cfg, "ssh-pin", "tls-pin", instant)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read()
	text, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(read())
	if !bytes.Equal(text, again) {
		t.Fatal("unstable plan")
	}
	if bytes.Contains(text, []byte("SECRET")) {
		t.Fatal("private data appeared in plan")
	}
	if len(p.Admissions) != 1 || p.Admissions[0].HostID != 11 || p.Admissions[0].Fingerprint != "a" || p.Admissions[0].Class != "agent" || len(p.Services) != 2 || len(p.Services[1].Sets) != 1 {
		t.Fatal("incorrect admissions or disabled minter enabled")
	}
	if fmt.Sprint(p.Retire.PendingRequests) != "[r3]" || fmt.Sprint(p.Retire.ActiveGrants) != "[g2]" || len(p.Retire.Outstanding) != 2 || p.Retire.GrantSerial != 108 {
		t.Fatal("legacy authority not fully reported")
	}
	for _, sc := range p.Scopes {
		if sc.Name == "cf.email" || sc.Name == "cf.read" && sc.AutoApprove || len(sc.Modes) != 1 {
			t.Fatal("CF narrowing lost")
		}
	}
	cfg.Cloudflare.AccountID = strings.Repeat("b", 32)
	if read().ConfigHash == p.ConfigHash {
		t.Fatal("account drift ignored")
	}
	after, err := os.ReadFile(bak)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inventory changed backup")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(bak + suffix); !os.IsNotExist(err) {
			t.Fatal("inventory made SQLite sidecars")
		}
	}
	if _, err := organisations.InspectBackup(ctx, filepath.Join(cfg.DataDir, "aqmas.db"), cfg, "ssh-pin", "tls-pin", instant); err == nil {
		t.Fatal("accepted live database")
	}
}

func TestBackfillDriftRollbackAndHistory(t *testing.T) {
	s, cfg, bak := fixture(t)
	ctx := t.Context()
	p, err := organisations.InspectBackup(ctx, bak, cfg, "ssh-pin", "tls-pin", instant)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := json.Marshal(p)
	apply := func(want string, commit bool) error {
		tx, err := s.DB().BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := organisations.Backfill(ctx, tx, cfg, "ssh-pin", "tls-pin", instant, want); err != nil {
			return err
		}
		if commit {
			return tx.Commit()
		}
		return nil
	}
	mustExec(t, s.DB(), `UPDATE hosts SET revoked_at=100 WHERE id=11`)
	if err := apply(string(text), true); err == nil {
		t.Fatal("accepted stale plan")
	}
	mustExec(t, s.DB(), `UPDATE hosts SET revoked_at=NULL WHERE id=11`)
	check := func(query string, want int) {
		t.Helper()
		var got int
		if err := s.DB().QueryRow(query).Scan(&got); err != nil || got != want {
			t.Fatalf("%s = %d, %v; want %d", query, got, err, want)
		}
	}
	if err := apply(string(text), false); err != nil {
		t.Fatal(err)
	}
	check(`PRAGMA user_version`, 5)
	check(`SELECT count(*) FROM sqlite_schema WHERE name='organisations'`, 0)
	if err := apply(string(text), true); err != nil {
		t.Fatal(err)
	}
	check(`PRAGMA user_version`, 6)
	check(`SELECT count(*) FROM org_hosts WHERE active=1 AND host_id=11`, 1)
	check(`SELECT count(*) FROM passkey_people`, 1)
	check(`SELECT count(*) FROM requests WHERE status='pending'`, 0)
	check(`SELECT count(*) FROM grants WHERE revoked_at IS NULL`, 0)
	check(`SELECT count(*) FROM request_bindings`, 0)
	check(`SELECT count(*) FROM grants WHERE token_id='upstream-id' AND token_deleted_at IS NULL`, 1)
	check(`SELECT count(*) FROM audit WHERE object='grant:g1'`, 1)
	check(`SELECT seq FROM sqlite_sequence WHERE name='grants'`, 108)
	check(`SELECT count(*) FROM pragma_foreign_key_check`, 0)
	// A dual-admitted host can have two equally named targets. V1 may only
	// resolve the signed personal alias; shared names confer no status access.
	db := s.DB()
	mustExec(t, db, `INSERT INTO organisations VALUES('other','club','club',1,0);
INSERT INTO services VALUES('club-fleet','other','fleet','fleet','fleet',1,0);
INSERT INTO credential_sets VALUES('other-build','club-fleet','fleet','build','build','ssh-ca',1,0);
INSERT INTO org_hosts VALUES('other',11,1,1);
INSERT INTO request_bindings VALUES('r1','other-build',1,1,1,1);`)
	resource, err := organisations.PersonalAlias(ctx, db, 11, "ssh-ca", "build", instant)
	if err != nil || resource.OrgID != p.Organisation.ID {
		t.Fatalf("personal alias = %+v, %v", resource, err)
	}
	if _, err := organisations.PersonalRequest(ctx, db, 11, "r1", instant); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("v1 exposed club request")
	}
	mustExec(t, db, `INSERT INTO request_bindings VALUES('r3',?,1,1,1,1)`, resource.SetID)
	if _, err := organisations.PersonalRequest(ctx, db, 11, "r3", instant); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `UPDATE org_hosts SET active=0,generation=2 WHERE org_id=?`, resource.OrgID)
	if _, err := organisations.PersonalAlias(ctx, db, 11, "ssh-ca", "build", instant); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("club admission conferred personal access")
	}
	mustExec(t, db, `UPDATE org_hosts SET active=1,generation=3 WHERE org_id=?`, resource.OrgID)
	if _, err := organisations.PersonalRequest(ctx, db, 11, "r3", instant); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("re-admission revived a request")
	}
}

func TestInventoryLimit(t *testing.T) {
	s, cfg, _ := fixture(t)
	mustExec(t, s.DB(), `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<512) INSERT INTO passkeys(credential_id,credential_json,created_at) SELECT CAST('new'||i AS BLOB),'{}',1 FROM n`)
	tx, err := s.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = organisations.Inventory(context.Background(), tx, cfg, "ssh", "tls", instant)
	if !errors.Is(err, organisations.ErrTooLarge) {
		t.Fatalf("oversize inventory: %v", err)
	}
}
