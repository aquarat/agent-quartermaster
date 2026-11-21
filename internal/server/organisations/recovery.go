package organisations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// RecoveryPoint creates a new closed, fsynced SQLite snapshot in a private
// directory on the data volume. Never copy aqmas.db independently of its WAL.
// The directory is not reused, even after a failed/interrupted rehearsal.
func RecoveryPoint(ctx context.Context, db *sql.DB, dir string) (path, digest string, err error) {
	root, err := os.MkdirTemp(dir, "pre-organisations-")
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(root, "aqmas.db")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	if _, err = db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return "", "", err
	}
	if err = f.Sync(); err != nil {
		return "", "", err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "", errors.New("empty SQLite recovery point")
	}
	for _, d := range []string{root, dir} {
		fd, err := os.Open(d)
		if err != nil {
			return "", "", err
		}
		err = fd.Sync()
		closeErr := fd.Close()
		if err != nil {
			return "", "", err
		}
		if closeErr != nil {
			return "", "", closeErr
		}
	}
	return path, hex.EncodeToString(h.Sum(nil)), nil
}
