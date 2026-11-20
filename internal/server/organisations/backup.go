package organisations

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
	_ "modernc.org/sqlite"
)

// InspectBackup deliberately has no store.Open path (that would create a DB
// or migrate old tables). immutable is only valid for a closed standalone
// online backup. In particular, never ignore a WAL to make a plan succeed.
func InspectBackup(ctx context.Context, path string, cfg *config.Config, sshPin, clientPin string, now time.Time) (*Plan, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("expected a standalone SQLite backup file")
	}
	live, err := os.Stat(filepath.Join(cfg.DataDir, "aqmas.db"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if live != nil && os.SameFile(st, live) {
		return nil, errors.New("use an online backup, not the configured live database")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			return nil, errors.New("use a standalone SQLite backup without journal files")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	u := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return Inventory(ctx, tx, cfg, sshPin, clientPin, now)
}
