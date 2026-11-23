package store

import (
	"context"
	"database/sql"
	"net/url"
)

// OpenReadOnly opens a standalone backup (no WAL or journal beside it) for
// reading only: no migration, no journal mode change, nothing is written.
func OpenReadOnly(path string) (*Store, error) {
	v := url.Values{}
	v.Add("mode", "ro")
	v.Add("immutable", "1")
	v.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+v.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var ver int
	if err = db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&ver); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, scoped: ver >= 6}, nil
}
