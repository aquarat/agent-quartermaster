package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestMigration3NamesExistingPasskeys builds a database at schema version 2 (as deployed for
// milestone 1, passkeys registered by the UI without a name) and opens it with this binary.
func TestMigration3NamesExistingPasskeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "aqmas.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.ExecContext(ctx, migrations[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, "PRAGMA user_version = 2"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	for i, name := range []string{"", "Laptop", " ", ""} {
		if _, err := db.ExecContext(ctx, "INSERT INTO passkeys(credential_id, credential_json, name, created_at) VALUES (?, '{}', ?, ?)",
			[]byte(fmt.Sprint("cred", i)), name, now+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	// A session referencing a passkey survives the migration.
	if _, err := db.ExecContext(ctx, "INSERT INTO web_sessions(hash, passkey_id, created_at, expires_at) VALUES ('h', 1, ?, ?)", now, now+1000); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pks, err := s.Q().Passkeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range pks {
		names = append(names, p.Name)
	}
	if fmt.Sprint(names) != "[Passkey 1 Laptop Passkey 3 Passkey 4]" {
		t.Fatalf("names after migration: %q", names)
	}
	if id, err := s.Q().SessionPasskeyID(ctx, "h"); err != nil || id != 1 {
		t.Fatalf("session: %d %v", id, err)
	}
	var v int
	s.DB().QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	if v != len(migrations) {
		t.Fatalf("user_version %d", v)
	}
	// Removing a passkey ends its sessions (foreign key) and is reported.
	n, err := s.Q().DeletePasskey(ctx, 1)
	if err != nil || n != 1 {
		t.Fatalf("delete: %d %v", n, err)
	}
	if _, err := s.Q().DeletePasskey(ctx, 1); err != ErrNotFound {
		t.Fatalf("delete twice: %v", err)
	}
	if err := s.Q().RenamePasskey(ctx, 2, "not-its-name", "x"); err != ErrConflict {
		t.Fatalf("rename CAS: %v", err)
	}
}
