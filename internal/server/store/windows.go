package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Only optional delegation policy is durable. No token, proposal or open
// window is restored by an older binary. Fence every authority transition,
// even a remove/re-admit that ends up with the same visible set of grants.
func (s *Store) InitWindows(ctx context.Context) error {
	return s.Tx(ctx, func(q *Q) error {
		if _, err := q.q.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS window_config(org_id TEXT PRIMARY KEY REFERENCES organisations(id),rev INTEGER NOT NULL CHECK(rev>0),policy TEXT NOT NULL) STRICT;CREATE TABLE IF NOT EXISTS authority_epoch(id INTEGER PRIMARY KEY CHECK(id=1),n INTEGER NOT NULL) STRICT;INSERT OR IGNORE INTO authority_epoch VALUES(1,1)`); err != nil {
			return err
		}
		for _, table := range []string{"org_hosts", "org_approvers", "organisations", "credential_sets", "services", "window_config"} {
			for _, verb := range []string{"INSERT", "UPDATE", "DELETE"} {
				if _, err := q.q.ExecContext(ctx, fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS window_fence_%s_%s AFTER %s ON %s BEGIN UPDATE authority_epoch SET n=n+1 WHERE id=1;END`, table, verb, verb, table)); err != nil {
					return err
				}
			}
		}
		_, err := q.q.ExecContext(ctx, `CREATE TRIGGER IF NOT EXISTS window_fence_key AFTER DELETE ON passkeys BEGIN UPDATE authority_epoch SET n=n+1 WHERE id=1;END`)
		return err
	})
}
func (q *Q) WindowEpoch(ctx context.Context) (int64, error) {
	var n int64
	err := q.q.QueryRowContext(ctx, `SELECT n FROM authority_epoch WHERE id=1`).Scan(&n)
	return n, err
}
func (q *Q) WindowConfig(ctx context.Context, org string) (rev int, personal bool, policy string, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT COALESCE(w.rev,0),o.id=c.org_id,COALESCE(w.policy,'') FROM organisations o JOIN personal_cutover c LEFT JOIN window_config w ON w.org_id=o.id WHERE o.id=? AND NOT o.archived`, org).Scan(&rev, &personal, &policy)
	return
}
func (q *Q) SetWindowConfig(ctx context.Context, org string, rev int, p string) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO window_config(org_id,rev,policy) VALUES(?,?,?) ON CONFLICT(org_id) DO UPDATE SET rev=excluded.rev,policy=excluded.policy WHERE window_config.rev=excluded.rev-1`, org, rev+1, p))
}
func (q *Q) SessionExpiry(ctx context.Context, sess string) (time.Time, error) {
	var v int64
	err := q.q.QueryRowContext(ctx, `SELECT expires_at FROM web_sessions WHERE hash=?`, sess).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return fromMS(v), err
}
