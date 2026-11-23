package store

import "context"

// SameSigner checks that passkey row still holds exactly this credential ID.
func (q *Q) SameSigner(ctx context.Context, row int64, raw []byte) error {
	var n int
	return q.q.QueryRowContext(ctx, `SELECT 1 FROM passkeys WHERE id=? AND credential_id=?`, row, raw).Scan(&n)
}
