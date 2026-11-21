package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (q *Q) TestedWrap(ctx context.Context, row int64, version uint64) (*time.Time, error) {
	var v int64
	err := q.q.QueryRowContext(ctx, `SELECT tested_at FROM seal_wraps WHERE passkey=? AND generation=?`, row, version).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t := fromMS(v)
	return &t, nil
}
func (q *Q) SameSigner(ctx context.Context, row int64, raw []byte) error {
	var n int
	return q.q.QueryRowContext(ctx, `SELECT 1 FROM passkeys WHERE id=? AND credential_id=?`, row, raw).Scan(&n)
}
func (q *Q) CanRemoveWrap(ctx context.Context, row int64, version uint64) (bool, error) {
	var ok bool
	err := q.q.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM seal_wraps WHERE generation=?1 AND passkey=?2) OR EXISTS(SELECT 1 FROM seal_wraps WHERE generation=?1 AND passkey!=?2)`, version, row).Scan(&ok)
	return ok, err
}
func (q *Q) DeleteWrap(ctx context.Context, row int64, v uint64) error {
	return one(q.q.ExecContext(ctx, `DELETE FROM seal_wraps WHERE passkey=? AND generation=? AND EXISTS(SELECT 1 FROM seal_wraps WHERE passkey!=? AND generation=?)`, row, v, row, v))
}
func (q *Q) InsertWrap(ctx context.Context, row int64, v uint64, salt, wrap []byte, now time.Time) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO seal_wraps(passkey,salt,wrap,generation,tested_at) VALUES(?,?,?,?,?)`, row, salt, wrap, v, ms(now)))
}
