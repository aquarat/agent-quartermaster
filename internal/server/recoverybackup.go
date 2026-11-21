package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"io"
	"os"
)

// Verify a standalone backup against the owner inventory BEFORE SQLite opens
// it: missing sets or earlier valid revisions cannot pass a full-file digest.
func verifyRecoverySource(c *config.Config) error {
	if c.Seal.RecoverySerial == nil || *c.Seal.RecoverySerial < 0 || *c.Seal.RecoverySerial >= 1<<62 || len(c.Seal.RecoveryBackupSHA256) != 64 {
		return errors.New("recovery needs an authenticated backup SHA-256 and independent SSH serial high-water mark")
	}
	path := DBPath(c.DataDir)
	for _, ext := range []string{"-wal", "-journal", "-shm"} {
		if _, err := os.Lstat(path + ext); !os.IsNotExist(err) {
			return errors.New("restore a standalone online backup without sidecars into a private directory")
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("invalid recovery database")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != c.Seal.RecoveryBackupSHA256 {
		return errors.New("recovery database differs from authenticated backup inventory")
	}
	return nil
}
