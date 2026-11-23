//go:build linux

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/server/pki"
)

func TestUnknownFormatNeverCreatesCA(t *testing.T) {
	e := newEnv(t)
	if _, err := e.s.store.DB().Exec(`PRAGMA user_version=99`); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(CADir(e.cfg.DataDir), pki.SSHCAKeyFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if s, err := New(Options{Config: e.cfg}); err == nil {
		s.Close()
		t.Fatal("opened unknown format")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("generated CA before checking database format")
	}
}
