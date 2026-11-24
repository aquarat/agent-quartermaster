package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
)

// Scoped is latched at open. A daemon may not keep serving during cutover.
func (q *Q) Scoped() bool { return q.scoped }

func (q *Q) PersonalAdmission(ctx context.Context, hostID int64, now time.Time) error {
	if !q.scoped {
		return nil
	}
	var one int
	err := q.q.QueryRowContext(ctx, `SELECT 1 FROM personal_cutover c JOIN organisations o ON o.id=c.org_id JOIN org_hosts a ON a.org_id=o.id JOIN hosts h ON h.id=a.host_id WHERE a.active=1 AND o.archived=0 AND h.revoked_at IS NULL AND h.id=? AND h.not_after>?`, hostID, ms(now)).Scan(&one)
	return notFound(err)
}

// Admitted reports whether the host holds an active admission to any organisation that is
// not archived. It says nothing about what that organisation contains.
func (q *Q) Admitted(ctx context.Context, hostID int64) (bool, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM org_hosts a JOIN organisations o ON o.id=a.org_id WHERE a.host_id=? AND a.active=1 AND o.archived=0`, hostID).Scan(&n)
	return n > 0, err
}

func (q *Q) PersonalResource(ctx context.Context, host int64, kind, alias string, now time.Time) (organisations.Resource, error) {
	r, err := organisations.PersonalAlias(ctx, q.q, host, kind, alias, now)
	return r, notFound(err)
}

func (q *Q) CountBoundSimilar(ctx context.Context, id string, since time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM requests r JOIN request_bindings b ON b.request_id=r.id JOIN request_bindings source ON source.set_id=b.set_id JOIN requests s ON s.id=source.request_id WHERE s.id=? AND r.host_id=s.host_id AND r.kind=s.kind AND r.login_user=s.login_user AND r.scope=s.scope AND r.created_at>=? AND r.status IN ('approved','revoked')`, id, ms(since)).Scan(&n)
	return n, err
}

func (q *Q) BoundResource(ctx context.Context, host int64, id string, now time.Time) (organisations.Resource, error) {
	r, err := organisations.PersonalRequest(ctx, q.q, host, id, now)
	return r, notFound(err)
}

func (q *Q) RecordedResource(ctx context.Context, id string) (organisations.Resource, error) {
	r, err := organisations.RecordedResource(ctx, q.q, id)
	return r, notFound(err)
}

// Called in an immediate transaction after resolving the authenticated host
// and personal alias. Scoped writes on future /v2 routes use their own binding.
func (q *Q) InsertPersonalRequest(ctx context.Context, r *Request) error {
	if !q.scoped {
		return q.InsertRequest(ctx, r)
	}
	kind, alias := "ssh-ca", r.TargetHost
	switch {
	case r.Kind == "ssh":
	case r.Kind == "cloudflare" && r.Mode == "proxy":
		kind, alias = "cloudflare-proxy", "proxy"
	case r.Kind == "cloudflare" && r.Mode == "token":
		kind, alias = "cloudflare-mint", "mint"
	default:
		return ErrNotFound
	}
	b, err := q.PersonalResource(ctx, r.HostID, kind, alias, r.CreatedAt)
	if err != nil {
		return err
	}
	if err := q.InsertRequest(ctx, r); err != nil {
		return err
	}
	_, err = q.q.ExecContext(ctx, `INSERT INTO request_bindings VALUES(?,?,?,?,?,?)`, r.ID, b.SetID, b.SetRevision, b.ServiceRevision, b.PolicyRevision, b.Generation)
	return err
}

func (q *Q) PersonalStatus(ctx context.Context, id string, host int64, now time.Time) (*Request, error) {
	// The generic agent paths (status, cancel) serve SSH and Cloudflare requests only; every
	// other kind has endpoints of its own and is "not found" here, in every mode.
	query := `SELECT ` + reqCols + ` FROM requests WHERE id=? AND host_id=? AND kind IN ('ssh','cloudflare')`
	args := []any{id, host}
	query, args = q.personalOnly(query, args, "id", host, now)
	return scanRequest(q.q.QueryRowContext(ctx, query, args...))
}

// Use in host-facing reads only. Owner recovery/revocation may also need
// archived objects. Do not scope the host-wide pending limit this way.
func (q *Q) personalOnly(query string, args []any, source string, host int64, now time.Time) (string, []any) {
	if !q.scoped {
		return query, args
	}
	return query + ` AND ` + source + ` IN (SELECT request_id FROM personal_requests WHERE host_id=? AND host_not_after>?)`, append(args, host, ms(now))
}

func (q *Q) IsOrgOwner(ctx context.Context, org, session string, signer int64, now time.Time) error {
	var one int
	err := q.q.QueryRowContext(ctx, `SELECT 1 FROM people p JOIN org_approvers a ON a.person_id=p.id JOIN passkey_people login ON login.person_id=p.id JOIN web_sessions w ON w.passkey_id=login.passkey_id JOIN passkey_people signing ON signing.person_id=p.id WHERE p.owner=1 AND a.org_id=? AND w.hash=? AND w.expires_at>? AND signing.passkey_id=?`, org, session, ms(now), signer).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	return err
}
