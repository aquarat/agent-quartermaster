package organisations

import (
	"context"
	"database/sql"
	"time"
)

// Lookup must run before constructing an agent response. Resolve the route
// namespace in SQL; admission alone doesn't establish an object's namespace.
type lookup interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Resource struct {
	OrgID, OrgSlug, OrgTitle                                 string
	ServiceID, ServiceSlug, ServiceTitle                     string
	SetID, SetSlug, SetTitle                                 string
	Kind                                                     string
	SetRevision, ServiceRevision, PolicyRevision, Generation int
	Enrollment, Class                                        string
}

const resourceColumns = `org_id,org_slug,org_title,service_id,service_slug,service_title,set_id,set_slug,set_title,kind,set_revision,service_revision,policy_revision,generation,enrollment_id,class`

func readResource(row *sql.Row) (Resource, error) {
	var r Resource
	err := row.Scan(&r.OrgID, &r.OrgSlug, &r.OrgTitle, &r.ServiceID, &r.ServiceSlug, &r.ServiceTitle, &r.SetID, &r.SetSlug, &r.SetTitle, &r.Kind, &r.SetRevision, &r.ServiceRevision, &r.PolicyRevision, &r.Generation, &r.Enrollment, &r.Class)
	return r, err
}

// PersonalAlias accepts the canonical migrated selector only. Config's SSH
// alias resolution is safe only after the caller has checked the config pin.
func PersonalAlias(ctx context.Context, db lookup, hostID int64, kind, alias string, now time.Time) (Resource, error) {
	return readResource(db.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM personal_resources WHERE host_id=? AND kind=? AND alias=? AND host_not_after>?`, hostID, kind, alias, now.UnixMilli()))
}

func PersonalRequest(ctx context.Context, db lookup, hostID int64, id string, now time.Time) (Resource, error) {
	return readResource(db.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM personal_requests WHERE host_id=? AND request_id=? AND host_not_after>?`, hostID, id, now.UnixMilli()))
}

// RecordedResource is owner-only: a revoked enrollment, expired admission or
// archived set must not strand a grant that still needs upstream cleanup.
func RecordedResource(ctx context.Context, db lookup, id string) (Resource, error) {
	return readResource(db.QueryRowContext(ctx, `SELECT o.id,o.slug,o.title,v.id,v.slug,v.title,s.id,s.slug,s.title,s.kind,b.set_revision,b.service_revision,b.policy_revision,b.generation,e.id,e.class FROM request_bindings b JOIN requests r ON r.id=b.request_id JOIN hosts h ON h.id=r.host_id JOIN enrollments e ON e.id=h.enrollment_id JOIN credential_sets s ON s.id=b.set_id JOIN services v ON v.id=s.service_id JOIN organisations o ON o.id=v.org_id WHERE b.request_id=?`, id))
}
