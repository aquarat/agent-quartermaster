// Package store is aqmasd's SQLite persistence (pure-Go modernc.org/sqlite, WAL, foreign keys,
// numbered migrations). It stores no private keys and no bearer secrets: web sessions and enroll
// codes are kept as SHA-256 hashes only.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a state transition is not possible (already decided, used, ...).
var ErrConflict = errors.New("conflict")

// Store wraps the database.
type Store struct {
	db *sql.DB
}

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Q runs queries against either the database or a transaction.
type Q struct{ q querier }

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	v := url.Values{}
	v.Add("_pragma", "foreign_keys(1)")
	v.Add("_pragma", "journal_mode(WAL)")
	v.Add("_pragma", "busy_timeout(10000)")
	v.Add("_pragma", "synchronous(NORMAL)")
	v.Add("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+v.Encode())
	if err != nil {
		return nil, err
	}
	// One connection: serialises writers, avoids SQLITE_BUSY between our own goroutines.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the underlying database (tests and diagnostics).
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var fk int
	if err := s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		return err
	}
	if fk != 1 {
		return errors.New("store: foreign keys not enabled")
	}
	var ver int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&ver); err != nil {
		return err
	}
	if ver > len(migrations) {
		return fmt.Errorf("store: database schema version %d is newer than this binary (%d)", ver, len(migrations))
	}
	for i := ver; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Q returns a querier on the database (do not use inside Tx callbacks).
func (s *Store) Q() *Q { return &Q{s.db} }

// Tx runs fn in an IMMEDIATE transaction. Inside fn, use only the given *Q.
func (s *Store) Tx(ctx context.Context, fn func(q *Q) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Q{tx}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func fromNullMS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

func nullMS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ms(*t)
}

func one(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ---- meta ----

// Meta returns a meta value or ErrNotFound.
func (q *Q) Meta(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := q.q.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&v)
	return v, notFound(err)
}

// SetMetaIfAbsent stores value unless key exists, and returns the stored value.
func (q *Q) SetMetaIfAbsent(ctx context.Context, key string, value []byte) ([]byte, error) {
	if _, err := q.q.ExecContext(ctx, "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING", key, value); err != nil {
		return nil, err
	}
	return q.Meta(ctx, key)
}

// ---- audit ----

// Audit appends an audit entry. Never pass secrets in detail.
func (q *Q) Audit(ctx context.Context, at time.Time, actor, action, object, detail string) error {
	_, err := q.q.ExecContext(ctx, "INSERT INTO audit(at, actor, action, object, detail) VALUES (?, ?, ?, ?, ?)",
		ms(at), actor, action, object, detail)
	return err
}

// RecentAudit returns the newest n audit entries, newest first.
func (q *Q) RecentAudit(ctx context.Context, n int) ([]api.AuditEntry, error) {
	rows, err := q.q.QueryContext(ctx, "SELECT at, actor, action, object, detail FROM audit ORDER BY id DESC LIMIT ?", n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []api.AuditEntry{}
	for rows.Next() {
		var e api.AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Action, &e.Object, &e.Detail); err != nil {
			return nil, err
		}
		e.At = fromMS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- expiry ----

// ExpireStale marks undecided requests/enrollments past their expiry as expired and deletes
// spent challenges and sessions. It returns how many requests+enrollments it expired.
func (q *Q) ExpireStale(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	for _, stmt := range []string{
		"UPDATE requests SET status = 'expired', decided_at = ? WHERE status = 'pending' AND expires_at <= ?",
		"UPDATE enrollments SET status = 'expired', decided_at = ? WHERE status = 'pending' AND expires_at <= ?",
	} {
		res, err := q.q.ExecContext(ctx, stmt, ms(now), ms(now))
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	cut := ms(now.Add(-time.Hour))
	if _, err := q.q.ExecContext(ctx, "DELETE FROM challenges WHERE expires_at < ?", cut); err != nil {
		return total, err
	}
	if _, err := q.q.ExecContext(ctx, "DELETE FROM web_sessions WHERE expires_at < ?", ms(now)); err != nil {
		return total, err
	}
	return total, nil
}

// ---- enrollments ----

// Enrollment is a host enrollment request.
type Enrollment struct {
	ID             string
	Hostname       string
	CSRPEM         string
	KeyFingerprint string
	SSHHostKeyFPs  []string
	Note           string
	PeerAddress    string
	Status         string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	DecidedAt      *time.Time
	DecisionNote   string
	CertPEM        string
	CertDelivered  bool
}

const enrollCols = "id, hostname, csr_pem, key_fingerprint, ssh_host_key_fps, note, peer_address, status, created_at, expires_at, decided_at, decision_note, cert_pem, cert_delivered"

func scanEnrollment(sc interface{ Scan(...any) error }) (*Enrollment, error) {
	var e Enrollment
	var fps string
	var created, expires int64
	var decided sql.NullInt64
	var delivered int
	if err := sc.Scan(&e.ID, &e.Hostname, &e.CSRPEM, &e.KeyFingerprint, &fps, &e.Note, &e.PeerAddress, &e.Status,
		&created, &expires, &decided, &e.DecisionNote, &e.CertPEM, &delivered); err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(fps), &e.SSHHostKeyFPs)
	e.CreatedAt, e.ExpiresAt, e.DecidedAt = fromMS(created), fromMS(expires), fromNullMS(decided)
	e.CertDelivered = delivered != 0
	return &e, nil
}

// InsertEnrollment stores a new pending enrollment.
func (q *Q) InsertEnrollment(ctx context.Context, e *Enrollment) error {
	fps, _ := json.Marshal(e.SSHHostKeyFPs)
	if e.SSHHostKeyFPs == nil {
		fps = []byte("[]")
	}
	_, err := q.q.ExecContext(ctx, `INSERT INTO enrollments(id, hostname, csr_pem, key_fingerprint, ssh_host_key_fps, note, peer_address, status, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
		e.ID, e.Hostname, e.CSRPEM, e.KeyFingerprint, string(fps), e.Note, e.PeerAddress, ms(e.CreatedAt), ms(e.ExpiresAt))
	return err
}

// GetEnrollment loads one enrollment.
func (q *Q) GetEnrollment(ctx context.Context, id string) (*Enrollment, error) {
	return scanEnrollment(q.q.QueryRowContext(ctx, "SELECT "+enrollCols+" FROM enrollments WHERE id = ?", id))
}

// PendingEnrollments lists undecided, unexpired enrollments, oldest first.
func (q *Q) PendingEnrollments(ctx context.Context, now time.Time) ([]*Enrollment, error) {
	rows, err := q.q.QueryContext(ctx, "SELECT "+enrollCols+" FROM enrollments WHERE status = 'pending' AND expires_at > ? ORDER BY created_at", ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Enrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountPendingEnrollments counts undecided, unexpired enrollments.
func (q *Q) CountPendingEnrollments(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, "SELECT count(*) FROM enrollments WHERE status = 'pending' AND expires_at > ?", ms(now)).Scan(&n)
	return n, err
}

// DecideEnrollment moves a pending, unexpired enrollment to approved/denied.
func (q *Q) DecideEnrollment(ctx context.Context, id, status, note, certPEM string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE enrollments SET status = ?, decision_note = ?, cert_pem = ?, decided_at = ?
		WHERE id = ? AND status = 'pending' AND expires_at > ?`, status, note, certPEM, ms(now), id, ms(now)))
}

// MarkCertDelivered records that the client certificate was handed out (returned once).
func (q *Q) MarkCertDelivered(ctx context.Context, id string) (bool, error) {
	res, err := q.q.ExecContext(ctx, "UPDATE enrollments SET cert_delivered = 1 WHERE id = ? AND status = 'approved' AND cert_delivered = 0", id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ---- hosts ----

// Host is an enrolled host identity (one client certificate).
type Host struct {
	ID           int64
	Name         string
	CertSHA256   string
	EnrollmentID string
	CreatedAt    time.Time
	NotAfter     time.Time
	RevokedAt    *time.Time
}

const hostCols = "id, name, cert_sha256, enrollment_id, created_at, not_after, revoked_at"

func scanHost(sc interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	var created, notAfter int64
	var revoked sql.NullInt64
	if err := sc.Scan(&h.ID, &h.Name, &h.CertSHA256, &h.EnrollmentID, &created, &notAfter, &revoked); err != nil {
		return nil, notFound(err)
	}
	h.CreatedAt, h.NotAfter, h.RevokedAt = fromMS(created), fromMS(notAfter), fromNullMS(revoked)
	return &h, nil
}

// HostByCert finds the host whose client certificate has this DER SHA-256.
func (q *Q) HostByCert(ctx context.Context, certSHA256 string) (*Host, error) {
	return scanHost(q.q.QueryRowContext(ctx, "SELECT "+hostCols+" FROM hosts WHERE cert_sha256 = ?", certSHA256))
}

// ActiveHostByName finds the non-revoked host with this name.
func (q *Q) ActiveHostByName(ctx context.Context, name string) (*Host, error) {
	return scanHost(q.q.QueryRowContext(ctx, "SELECT "+hostCols+" FROM hosts WHERE name = ? AND revoked_at IS NULL", name))
}

// GetHost loads a host by id.
func (q *Q) GetHost(ctx context.Context, id int64) (*Host, error) {
	return scanHost(q.q.QueryRowContext(ctx, "SELECT "+hostCols+" FROM hosts WHERE id = ?", id))
}

// InsertHost records a new host identity.
func (q *Q) InsertHost(ctx context.Context, h *Host) (int64, error) {
	res, err := q.q.ExecContext(ctx, "INSERT INTO hosts(name, cert_sha256, enrollment_id, created_at, not_after) VALUES (?, ?, ?, ?, ?)",
		h.Name, h.CertSHA256, h.EnrollmentID, ms(h.CreatedAt), ms(h.NotAfter))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RevokeHost marks a host identity revoked and revokes its standing approvals.
func (q *Q) RevokeHost(ctx context.Context, id int64, now time.Time) error {
	if err := one(q.q.ExecContext(ctx, "UPDATE hosts SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", ms(now), id)); err != nil {
		return err
	}
	_, err := q.q.ExecContext(ctx, "UPDATE standing SET revoked_at = ? WHERE host_id = ? AND revoked_at IS NULL", ms(now), id)
	return err
}

// ---- requests ----

// Request is an access request.
type Request struct {
	ID             string
	HostID         int64
	HostName       string
	PeerAddress    string
	Kind           string
	TargetHost     string
	LoginUser      string
	PublicKey      string
	KeyFingerprint string
	Reason         string
	Requester      api.Requester
	TTLRequested   int
	Status         string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	DecidedAt      *time.Time
	DecisionNote   string
	StandingID     string
}

const reqCols = "id, host_id, host_name, peer_address, kind, target_host, login_user, public_key, key_fingerprint, reason, requester_json, ttl_requested, status, created_at, expires_at, decided_at, decision_note, standing_id"

func scanRequest(sc interface{ Scan(...any) error }) (*Request, error) {
	var r Request
	var reqJSON string
	var created, expires int64
	var decided sql.NullInt64
	var standing sql.NullString
	if err := sc.Scan(&r.ID, &r.HostID, &r.HostName, &r.PeerAddress, &r.Kind, &r.TargetHost, &r.LoginUser, &r.PublicKey,
		&r.KeyFingerprint, &r.Reason, &reqJSON, &r.TTLRequested, &r.Status, &created, &expires, &decided, &r.DecisionNote, &standing); err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(reqJSON), &r.Requester)
	r.CreatedAt, r.ExpiresAt, r.DecidedAt = fromMS(created), fromMS(expires), fromNullMS(decided)
	r.StandingID = standing.String
	return &r, nil
}

// InsertRequest stores a new request with the given status.
func (q *Q) InsertRequest(ctx context.Context, r *Request) error {
	rj, _ := json.Marshal(r.Requester)
	var standing any
	if r.StandingID != "" {
		standing = r.StandingID
	}
	_, err := q.q.ExecContext(ctx, `INSERT INTO requests(`+reqCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.HostID, r.HostName, r.PeerAddress, r.Kind, r.TargetHost, r.LoginUser, r.PublicKey, r.KeyFingerprint, r.Reason,
		string(rj), r.TTLRequested, r.Status, ms(r.CreatedAt), ms(r.ExpiresAt), nullMS(r.DecidedAt), r.DecisionNote, standing)
	return err
}

// GetRequest loads one request.
func (q *Q) GetRequest(ctx context.Context, id string) (*Request, error) {
	return scanRequest(q.q.QueryRowContext(ctx, "SELECT "+reqCols+" FROM requests WHERE id = ?", id))
}

// PendingRequests lists undecided, unexpired requests, oldest first.
func (q *Q) PendingRequests(ctx context.Context, now time.Time) ([]*Request, error) {
	rows, err := q.q.QueryContext(ctx, "SELECT "+reqCols+" FROM requests WHERE status = 'pending' AND expires_at > ? ORDER BY created_at", ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DecideRequest moves a pending, unexpired request to approved or denied.
func (q *Q) DecideRequest(ctx context.Context, id, status, note string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE requests SET status = ?, decision_note = ?, decided_at = ?
		WHERE id = ? AND status = 'pending' AND expires_at > ?`, status, note, ms(now), id, ms(now)))
}

// MarkRequestRevoked marks an approved request revoked (its grant was revoked).
func (q *Q) MarkRequestRevoked(ctx context.Context, id string) error {
	_, err := q.q.ExecContext(ctx, "UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'", id)
	return err
}

// CountSimilar counts approved requests from the same host for the same target and user since t.
func (q *Q) CountSimilar(ctx context.Context, hostID int64, target, user string, since time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM requests WHERE host_id = ? AND target_host = ? AND login_user = ?
		AND status IN ('approved','revoked') AND created_at >= ?`, hostID, target, user, ms(since)).Scan(&n)
	return n, err
}

// ---- grants ----

// Grant is an issued credential.
type Grant struct {
	Serial      int64
	ID          string
	RequestID   string
	HostID      int64
	HostName    string
	Kind        string
	TargetHost  string
	LoginUser   string
	Principals  []string
	Certificate string
	NotBefore   time.Time
	NotAfter    time.Time
	RevokedAt   *time.Time
}

// Status derives the grant status at now.
func (g *Grant) Status(now time.Time) string {
	switch {
	case g.RevokedAt != nil:
		return api.StatusRevoked
	case !now.Before(g.NotAfter):
		return api.StatusExpired
	}
	return api.StatusApproved
}

const grantCols = "serial, id, request_id, host_id, host_name, kind, target_host, login_user, principals, certificate, not_before, not_after, revoked_at"

func scanGrant(sc interface{ Scan(...any) error }) (*Grant, error) {
	var g Grant
	var principals string
	var nb, na int64
	var revoked sql.NullInt64
	if err := sc.Scan(&g.Serial, &g.ID, &g.RequestID, &g.HostID, &g.HostName, &g.Kind, &g.TargetHost, &g.LoginUser,
		&principals, &g.Certificate, &nb, &na, &revoked); err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(principals), &g.Principals)
	g.NotBefore, g.NotAfter, g.RevokedAt = fromMS(nb), fromMS(na), fromNullMS(revoked)
	return &g, nil
}

// InsertGrant reserves a grant row and returns its serial; fill the certificate with SetGrantCert.
func (q *Q) InsertGrant(ctx context.Context, g *Grant) (int64, error) {
	pj, _ := json.Marshal(g.Principals)
	res, err := q.q.ExecContext(ctx, `INSERT INTO grants(id, request_id, host_id, host_name, kind, target_host, login_user, principals, certificate, not_before, not_after)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.RequestID, g.HostID, g.HostName, g.Kind, g.TargetHost, g.LoginUser, string(pj), g.Certificate, ms(g.NotBefore), ms(g.NotAfter))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetGrantCert stores the signed certificate (public data) for a grant.
func (q *Q) SetGrantCert(ctx context.Context, serial int64, cert string) error {
	return one(q.q.ExecContext(ctx, "UPDATE grants SET certificate = ? WHERE serial = ?", cert, serial))
}

// GrantByRequest loads the grant issued for a request.
func (q *Q) GrantByRequest(ctx context.Context, requestID string) (*Grant, error) {
	return scanGrant(q.q.QueryRowContext(ctx, "SELECT "+grantCols+" FROM grants WHERE request_id = ?", requestID))
}

// GetGrant loads a grant by id.
func (q *Q) GetGrant(ctx context.Context, id string) (*Grant, error) {
	return scanGrant(q.q.QueryRowContext(ctx, "SELECT "+grantCols+" FROM grants WHERE id = ?", id))
}

// HostGrants lists a host's grants, newest first; activeOnly limits to unexpired, unrevoked ones.
func (q *Q) HostGrants(ctx context.Context, hostID int64, activeOnly bool, now time.Time) ([]*Grant, error) {
	query := "SELECT " + grantCols + " FROM grants WHERE host_id = ?"
	args := []any{hostID}
	if activeOnly {
		query += " AND revoked_at IS NULL AND not_after > ?"
		args = append(args, ms(now))
	}
	query += " ORDER BY serial DESC LIMIT 200"
	rows, err := q.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrant marks a grant revoked (it cannot recall an issued certificate in M1).
func (q *Q) RevokeGrant(ctx context.Context, id string, now time.Time) error {
	return one(q.q.ExecContext(ctx, "UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", ms(now), id))
}

// ---- standing approvals ----

// Standing is a standing approval ("approve similar requests for N hours").
type Standing struct {
	ID              string
	HostID          int64
	HostName        string
	Kind            string
	TargetHost      string
	LoginUser       string
	MaxTTL          int
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
	Uses            int
	SourceRequestID string
}

const standingCols = "id, host_id, host_name, kind, target_host, login_user, max_ttl, created_at, expires_at, revoked_at, uses, source_request_id"

func scanStanding(sc interface{ Scan(...any) error }) (*Standing, error) {
	var s Standing
	var created, expires int64
	var revoked sql.NullInt64
	if err := sc.Scan(&s.ID, &s.HostID, &s.HostName, &s.Kind, &s.TargetHost, &s.LoginUser, &s.MaxTTL, &created, &expires, &revoked, &s.Uses, &s.SourceRequestID); err != nil {
		return nil, notFound(err)
	}
	s.CreatedAt, s.ExpiresAt, s.RevokedAt = fromMS(created), fromMS(expires), fromNullMS(revoked)
	return &s, nil
}

// InsertStanding stores a standing approval.
func (q *Q) InsertStanding(ctx context.Context, s *Standing) error {
	_, err := q.q.ExecContext(ctx, `INSERT INTO standing(id, host_id, host_name, kind, target_host, login_user, max_ttl, created_at, expires_at, source_request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.HostID, s.HostName, s.Kind, s.TargetHost, s.LoginUser, s.MaxTTL, ms(s.CreatedAt), ms(s.ExpiresAt), s.SourceRequestID)
	return err
}

// GetStanding loads one standing approval.
func (q *Q) GetStanding(ctx context.Context, id string) (*Standing, error) {
	return scanStanding(q.q.QueryRowContext(ctx, "SELECT "+standingCols+" FROM standing WHERE id = ?", id))
}

// ActiveStanding lists unexpired, unrevoked standing approvals; hostID 0 means all hosts.
func (q *Q) ActiveStanding(ctx context.Context, hostID int64, now time.Time) ([]*Standing, error) {
	query := "SELECT " + standingCols + " FROM standing WHERE revoked_at IS NULL AND expires_at > ?"
	args := []any{ms(now)}
	if hostID != 0 {
		query += " AND host_id = ?"
		args = append(args, hostID)
	}
	rows, err := q.q.QueryContext(ctx, query+" ORDER BY created_at", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Standing
	for rows.Next() {
		s, err := scanStanding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UseStanding increments the use counter of an active standing approval.
func (q *Q) UseStanding(ctx context.Context, id string, now time.Time) error {
	return one(q.q.ExecContext(ctx, "UPDATE standing SET uses = uses + 1 WHERE id = ? AND revoked_at IS NULL AND expires_at > ?", id, ms(now)))
}

// RevokeStanding revokes a standing approval.
func (q *Q) RevokeStanding(ctx context.Context, id string, now time.Time) error {
	return one(q.q.ExecContext(ctx, "UPDATE standing SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", ms(now), id))
}

// ---- passkeys ----

// Passkey is a stored WebAuthn credential (public data only).
type Passkey struct {
	ID             int64
	CredentialID   []byte
	CredentialJSON string
	Name           string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// Passkeys lists all passkeys.
func (q *Q) Passkeys(ctx context.Context) ([]*Passkey, error) {
	rows, err := q.q.QueryContext(ctx, "SELECT id, credential_id, credential_json, name, created_at, last_used_at FROM passkeys ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		var p Passkey
		var created int64
		var used sql.NullInt64
		if err := rows.Scan(&p.ID, &p.CredentialID, &p.CredentialJSON, &p.Name, &created, &used); err != nil {
			return nil, err
		}
		p.CreatedAt, p.LastUsedAt = fromMS(created), fromNullMS(used)
		out = append(out, &p)
	}
	return out, rows.Err()
}

// CountPasskeys counts registered passkeys.
func (q *Q) CountPasskeys(ctx context.Context) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, "SELECT count(*) FROM passkeys").Scan(&n)
	return n, err
}

// InsertPasskey stores a new passkey.
func (q *Q) InsertPasskey(ctx context.Context, p *Passkey) (int64, error) {
	res, err := q.q.ExecContext(ctx, "INSERT INTO passkeys(credential_id, credential_json, name, created_at) VALUES (?, ?, ?, ?)",
		p.CredentialID, p.CredentialJSON, p.Name, ms(p.CreatedAt))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdatePasskeyAfterUse stores the updated credential (sign count, flags) after an assertion.
// It only succeeds if the stored credential is unchanged since it was read (oldJSON), so two
// concurrent assertions cannot both pass with the same counter.
func (q *Q) UpdatePasskeyAfterUse(ctx context.Context, credID []byte, oldJSON, newJSON string, now time.Time) (int64, error) {
	var id int64
	err := q.q.QueryRowContext(ctx, "UPDATE passkeys SET credential_json = ?, last_used_at = ? WHERE credential_id = ? AND credential_json = ? RETURNING id",
		newJSON, ms(now), credID, oldJSON).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrConflict
	}
	return id, err
}

// ---- challenges ----

// Challenge is a stored WebAuthn ceremony (per-action approval, login or registration).
type Challenge struct {
	ID          string
	Purpose     string // action, login, register
	ObjectType  string
	ObjectID    string
	Canonical   string
	SessionData string // webauthn.SessionData JSON (login/register)
	SessionHash string // web session the challenge was issued to ("" for unauthenticated ceremonies)
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// InsertChallenge stores a challenge.
func (q *Q) InsertChallenge(ctx context.Context, c *Challenge) error {
	_, err := q.q.ExecContext(ctx, `INSERT INTO challenges(id, purpose, object_type, object_id, canonical, session_data, session_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Purpose, c.ObjectType, c.ObjectID, c.Canonical, c.SessionData, c.SessionHash, ms(c.CreatedAt), ms(c.ExpiresAt))
	return err
}

// ErrExpired is returned for a challenge or code past its expiry.
var ErrExpired = errors.New("expired")

// ConsumeChallenge atomically marks a challenge used and returns it. A challenge can be consumed
// once; an expired one is consumed and ErrExpired returned. Unknown or used: ErrNotFound.
func (q *Q) ConsumeChallenge(ctx context.Context, id, purpose string, now time.Time) (*Challenge, error) {
	var c Challenge
	var created, expires int64
	err := q.q.QueryRowContext(ctx, `UPDATE challenges SET used = 1 WHERE id = ? AND purpose = ? AND used = 0
		RETURNING id, purpose, object_type, object_id, canonical, session_data, session_hash, created_at, expires_at`, id, purpose).
		Scan(&c.ID, &c.Purpose, &c.ObjectType, &c.ObjectID, &c.Canonical, &c.SessionData, &c.SessionHash, &created, &expires)
	if err != nil {
		return nil, notFound(err)
	}
	c.CreatedAt, c.ExpiresAt = fromMS(created), fromMS(expires)
	if !now.Before(c.ExpiresAt) {
		return nil, ErrExpired
	}
	return &c, nil
}

// ---- enroll codes ----

// InsertEnrollCode stores the hash of a one-time passkey enroll code.
func (q *Q) InsertEnrollCode(ctx context.Context, hash string, now, expires time.Time) error {
	_, err := q.q.ExecContext(ctx, "INSERT INTO enroll_codes(hash, created_at, expires_at) VALUES (?, ?, ?)", hash, ms(now), ms(expires))
	return err
}

// EnrollCodeValid reports whether an unused, unexpired code with this hash exists.
func (q *Q) EnrollCodeValid(ctx context.Context, hash string, now time.Time) (bool, error) {
	var n int
	err := q.q.QueryRowContext(ctx, "SELECT count(*) FROM enroll_codes WHERE hash = ? AND used_at IS NULL AND expires_at > ?", hash, ms(now)).Scan(&n)
	return n == 1, err
}

// ConsumeEnrollCode marks a valid code used; ErrConflict if it is not valid.
func (q *Q) ConsumeEnrollCode(ctx context.Context, hash string, now time.Time) error {
	return one(q.q.ExecContext(ctx, "UPDATE enroll_codes SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ?", ms(now), hash, ms(now)))
}

// ---- web sessions ----

// InsertSession stores a session by the hash of its cookie value.
func (q *Q) InsertSession(ctx context.Context, hash string, passkeyID int64, now, expires time.Time) error {
	_, err := q.q.ExecContext(ctx, "INSERT INTO web_sessions(hash, passkey_id, created_at, expires_at) VALUES (?, ?, ?, ?)", hash, passkeyID, ms(now), ms(expires))
	return err
}

// SessionValid reports whether the session hash exists and is unexpired.
func (q *Q) SessionValid(ctx context.Context, hash string, now time.Time) (bool, error) {
	var n int
	err := q.q.QueryRowContext(ctx, "SELECT count(*) FROM web_sessions WHERE hash = ? AND expires_at > ?", hash, ms(now)).Scan(&n)
	return n == 1, err
}

// DeleteSession removes a session.
func (q *Q) DeleteSession(ctx context.Context, hash string) error {
	_, err := q.q.ExecContext(ctx, "DELETE FROM web_sessions WHERE hash = ?", hash)
	return err
}
