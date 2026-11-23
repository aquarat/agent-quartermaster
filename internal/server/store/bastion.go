package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// Bastion access (docs/BASTION-ACCESS.md §11). These tables sit beside the numbered schema
// ladder, like the env and window tables: created idempotently at start, in every mode.

// InitBastion creates the bastion tables.
func (s *Store) InitBastion(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS bastion_grants(grant_id TEXT PRIMARY KEY,level TEXT NOT NULL CHECK(level IN ('inspect','root')),close_buckets INTEGER NOT NULL CHECK(close_buckets IN (0,1)),closed_count INTEGER NOT NULL DEFAULT 0,alert TEXT NOT NULL DEFAULT '' CHECK(alert IN ('','sent','failed','off')),alert_at INTEGER,approved_at INTEGER NOT NULL,delivered_at INTEGER) STRICT;
CREATE TABLE IF NOT EXISTS setup_requests(id TEXT PRIMARY KEY,host_id INTEGER NOT NULL REFERENCES hosts(id),host_name TEXT NOT NULL,peer_address TEXT NOT NULL,task TEXT NOT NULL,params TEXT NOT NULL,reason TEXT NOT NULL,requester_json TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired','cancelled')),created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,decided_at INTEGER,decision_note TEXT NOT NULL DEFAULT '',digest TEXT NOT NULL DEFAULT '') STRICT;
CREATE INDEX IF NOT EXISTS setup_requests_status ON setup_requests(status,host_id);`)
	return err
}

// ---- grants ----

// BastionGrant is the bastion record of a grant with kind "bastion".
type BastionGrant struct {
	GrantID      string
	Level        string
	CloseBuckets bool
	Closed       int
	Alert        string // "", sent, failed, off
	ApprovedAt   time.Time
	DeliveredAt  *time.Time
}

// InsertBastionGrant records a bastion grant in the approving transaction.
func (q *Q) InsertBastionGrant(ctx context.Context, g *BastionGrant) error {
	_, err := q.q.ExecContext(ctx, `INSERT INTO bastion_grants(grant_id,level,close_buckets,closed_count,alert,approved_at) VALUES(?,?,?,?,?,?)`,
		g.GrantID, g.Level, g.CloseBuckets, g.Closed, g.Alert, ms(g.ApprovedAt))
	return err
}

// GetBastionGrant loads a bastion record.
func (q *Q) GetBastionGrant(ctx context.Context, grant string) (*BastionGrant, error) {
	var g BastionGrant
	var approved int64
	var delivered sql.NullInt64
	err := q.q.QueryRowContext(ctx, `SELECT grant_id,level,close_buckets,closed_count,alert,approved_at,delivered_at FROM bastion_grants WHERE grant_id=?`, grant).
		Scan(&g.GrantID, &g.Level, &g.CloseBuckets, &g.Closed, &g.Alert, &approved, &delivered)
	if err != nil {
		return nil, notFound(err)
	}
	g.ApprovedAt, g.DeliveredAt = fromMS(approved), fromNullMS(delivered)
	return &g, nil
}

// SetBastionAlert records the outcome of the alert attempt, once.
func (q *Q) SetBastionAlert(ctx context.Context, grant, outcome string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE bastion_grants SET alert=?,alert_at=? WHERE grant_id=? AND alert=''`, outcome, ms(now), grant))
}

// MarkBastionDelivered marks a root certificate handed out. It succeeds exactly once, only
// after the alert attempt was recorded, and only while the grant is unrevoked and unexpired.
func (q *Q) MarkBastionDelivered(ctx context.Context, grant string, now, notBefore time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE bastion_grants SET delivered_at=?1 WHERE grant_id=?2 AND delivered_at IS NULL AND alert!='' AND approved_at>=?3
		AND EXISTS(SELECT 1 FROM grants g WHERE g.id=?2 AND g.revoked_at IS NULL AND g.not_after>?1)`, ms(now), grant, ms(notBefore)))
}

// BastionSessions lists bastion grants, newest first.
func (q *Q) BastionSessions(ctx context.Context, limit int) ([]*Grant, error) {
	return q.grants(ctx, "kind = 'bastion' ORDER BY serial DESC LIMIT ?", limit)
}

// ActiveBastionRoot returns the latest expiry among unrevoked, unexpired root certificates.
func (q *Q) ActiveBastionRoot(ctx context.Context, now time.Time) (*time.Time, error) {
	var until sql.NullInt64
	err := q.q.QueryRowContext(ctx, `SELECT max(g.not_after) FROM grants g JOIN bastion_grants b ON b.grant_id=g.id WHERE g.kind='bastion' AND b.level='root' AND g.revoked_at IS NULL AND g.not_after>?`, ms(now)).Scan(&until)
	return fromNullMS(until), err
}

// ---- maintenance tasks queued by agents ----

// SetupRequest is a routine maintenance task an agent asked the owner to run.
type SetupRequest struct {
	ID           string
	HostID       int64
	HostName     string
	PeerAddress  string
	Task         string
	Params       string // canonical parameter text
	Reason       string
	Requester    api.Requester
	Status       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	DecidedAt    *time.Time
	DecisionNote string
	Digest       string // first 16 hex of SHA-256 of the signed text, once approved
}

const setupCols = `id,host_id,host_name,peer_address,task,params,reason,requester_json,status,created_at,expires_at,decided_at,decision_note,digest`

func scanSetup(sc interface{ Scan(...any) error }) (*SetupRequest, error) {
	var r SetupRequest
	var rj string
	var created, expires int64
	var decided sql.NullInt64
	if err := sc.Scan(&r.ID, &r.HostID, &r.HostName, &r.PeerAddress, &r.Task, &r.Params, &r.Reason, &rj, &r.Status, &created, &expires, &decided, &r.DecisionNote, &r.Digest); err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(rj), &r.Requester)
	r.CreatedAt, r.ExpiresAt, r.DecidedAt = fromMS(created), fromMS(expires), fromNullMS(decided)
	return &r, nil
}

// ExpireSetupRequests moves undecided requests past their deadline to expired.
func (q *Q) ExpireSetupRequests(ctx context.Context, now time.Time) error {
	_, err := q.q.ExecContext(ctx, `UPDATE setup_requests SET status='expired',decided_at=?1 WHERE status='pending' AND expires_at<=?1`, ms(now))
	return err
}

// InsertSetupRequest stores a pending request.
func (q *Q) InsertSetupRequest(ctx context.Context, r *SetupRequest) error {
	rj, _ := json.Marshal(r.Requester)
	_, err := q.q.ExecContext(ctx, `INSERT INTO setup_requests(`+setupCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.HostID, r.HostName, r.PeerAddress, r.Task, r.Params, r.Reason, string(rj), r.Status, ms(r.CreatedAt), ms(r.ExpiresAt), nullMS(r.DecidedAt), r.DecisionNote, r.Digest)
	return err
}

// GetSetupRequest loads one request.
func (q *Q) GetSetupRequest(ctx context.Context, id string) (*SetupRequest, error) {
	return scanSetup(q.q.QueryRowContext(ctx, `SELECT `+setupCols+` FROM setup_requests WHERE id=?`, id))
}

// PendingSetupRequests lists undecided, unexpired requests, oldest first.
func (q *Q) PendingSetupRequests(ctx context.Context, now time.Time) ([]*SetupRequest, error) {
	rows, err := q.q.QueryContext(ctx, `SELECT `+setupCols+` FROM setup_requests WHERE status='pending' AND expires_at>? ORDER BY created_at`, ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SetupRequest
	for rows.Next() {
		r, err := scanSetup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountPendingSetup counts a host's undecided maintenance requests.
func (q *Q) CountPendingSetup(ctx context.Context, host int64, now time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM setup_requests WHERE host_id=? AND status='pending' AND expires_at>?`, host, ms(now)).Scan(&n)
	return n, err
}

// DecideSetupRequest moves a pending, unexpired request to another status. host 0 matches
// any host (the owner); otherwise only that host's request (cancel).
func (q *Q) DecideSetupRequest(ctx context.Context, id string, host int64, status, note, digest string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE setup_requests SET status=?,decision_note=?,digest=?,decided_at=?4 WHERE id=?5 AND status='pending' AND expires_at>?4 AND (?6=0 OR host_id=?6)`,
		status, note, digest, ms(now), id, host))
}

// CountRecentSetup counts a host's maintenance requests created since t, decided or not.
func (q *Q) CountRecentSetup(ctx context.Context, host int64, since time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM setup_requests WHERE host_id=? AND created_at>?`, host, ms(since)).Scan(&n)
	return n, err
}

// CountAllPendingSetup counts every undecided maintenance request.
func (q *Q) CountAllPendingSetup(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM setup_requests WHERE status='pending' AND expires_at>?`, ms(now)).Scan(&n)
	return n, err
}
