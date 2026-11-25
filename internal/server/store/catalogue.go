package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func (q *Q) MarkPolicySchema(ctx context.Context) error {
	var version int
	if err := q.q.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= 7 {
		return nil
	}
	_, err := q.q.ExecContext(ctx, `PRAGMA user_version=7`)
	return err
}

func (q *Q) rows(ctx context.Context, query string, visit func(*sql.Rows) error, args ...any) error {
	rs, err := q.q.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rs.Close()
	for rs.Next() {
		if err := visit(rs); err != nil {
			return err
		}
	}
	return rs.Err()
}

func (q *Q) GlobalOwner(ctx context.Context, sess string, signer int64, now time.Time) (string, error) {
	var id string
	err := q.q.QueryRowContext(ctx, `SELECT p.id FROM people p JOIN passkey_people l ON l.person_id=p.id JOIN web_sessions w ON w.passkey_id=l.passkey_id JOIN passkey_people s ON s.person_id=p.id WHERE p.owner=1 AND w.hash=? AND w.expires_at>? AND s.passkey_id=?`, sess, ms(now), signer).Scan(&id)
	return id, notFound(err)
}

func (q *Q) OrgPolicy(ctx context.Context, org string, rev int) (api.DurationPolicy, error) {
	var p api.DurationPolicy
	err := q.q.QueryRowContext(ctx, `SELECT default_seconds,soft_cap,indefinite,standing_default,standing_soft_cap,standing_indefinite FROM org_policies WHERE org_id=? AND revision=?`, org, rev).Scan(&p.Default, &p.Soft, &p.Indefinite, &p.StandingDefault, &p.StandingSoft, &p.StandingIndefinite)
	if err != nil {
		return p, notFound(err)
	}
	p.Discovery, p.DenyGet, err = q.OrgFlags(ctx, org, rev)
	return p, err
}

// orgFlagsDDL holds the per-revision policy switches added after schema 6
// (0.10.0). It is a table of its own, not new org_policies columns: a previous
// binary keeps writing its eight-column policy rows and simply never reads
// this, so a policy it replaces has every switch off again.
const orgFlagsDDL = `CREATE TABLE IF NOT EXISTS org_flags(org_id TEXT NOT NULL REFERENCES organisations(id),revision INTEGER NOT NULL CHECK(revision>0),discovery INTEGER NOT NULL CHECK(discovery IN (0,1)),deny_get INTEGER NOT NULL CHECK(deny_get IN (0,1)),PRIMARY KEY(org_id,revision)) STRICT`

// OrgFlags reads an organisation's switches at one policy revision. No row
// (or no table yet) means every switch is off.
func (q *Q) OrgFlags(ctx context.Context, org string, rev int) (discovery, denyGet bool, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT discovery,deny_get FROM org_flags WHERE org_id=? AND revision=?`, org, rev).Scan(&discovery, &denyGet)
	if errors.Is(err, sql.ErrNoRows) || err != nil && strings.Contains(err.Error(), "no such table") {
		return false, false, nil
	}
	return discovery, denyGet, err
}

func (q *Q) ScopeRule(ctx context.Context, set, scope string, rev int) (api.CatalogueRule, error) {
	r := api.CatalogueRule{Set: set, Scope: scope}
	err := q.q.QueryRowContext(ctx, `SELECT p.auto,p.standing,EXISTS(SELECT 1 FROM relaxed_proxy_scopes x WHERE x.set_id=p.set_id AND x.scope=p.scope AND x.revision=p.revision) FROM set_policies p WHERE set_id=? AND scope=? AND revision<=? ORDER BY revision DESC LIMIT 1`, set, scope, rev).Scan(&r.Auto, &r.Standing, &r.Relax)
	return r, notFound(err)
}

func (q *Q) Catalogue(ctx context.Context, owner string, now time.Time) (api.Catalogue, error) {
	out := api.Catalogue{OwnerID: owner, Orgs: []api.CatalogueOrg{}}
	err := q.rows(ctx, `SELECT id,slug,title,revision FROM organisations WHERE archived=0 ORDER BY slug`, func(rs *sql.Rows) error {
		var o api.CatalogueOrg
		err := rs.Scan(&o.ID, &o.Slug, &o.Title, &o.Revision)
		out.Orgs = append(out.Orgs, o)
		return err
	})
	if err != nil {
		return out, err
	}
	for i := range out.Orgs {
		o := &out.Orgs[i]
		o.Policy, err = q.OrgPolicy(ctx, o.ID, o.Revision)
		if err != nil {
			return out, err
		}
		o.Services = []api.CatalogueService{}
		o.Rules = []api.CatalogueRule{}
		o.Hosts = []api.CatalogueHost{}
		o.Auto = []api.AutoAccess{}
		if err = q.rows(ctx, `SELECT id,slug,title,revision,provider FROM services WHERE org_id=? AND archived=0 ORDER BY slug`, func(rs *sql.Rows) error {
			var v api.CatalogueService
			err := rs.Scan(&v.ID, &v.Slug, &v.Title, &v.Revision, &v.Provider)
			o.Services = append(o.Services, v)
			return err
		}, o.ID); err != nil {
			return out, err
		}
		for j := range o.Services {
			v := &o.Services[j]
			v.Sets = []api.CatalogueSet{}
			if err = q.rows(ctx, `SELECT id,slug,title,revision,kind,archived FROM credential_sets WHERE service_id=? ORDER BY slug`, func(rs *sql.Rows) error {
				var s api.CatalogueSet
				err := rs.Scan(&s.ID, &s.Slug, &s.Title, &s.Revision, &s.Kind, &s.Archived)
				v.Sets = append(v.Sets, s)
				return err
			}, v.ID); err != nil {
				return out, err
			}
		}
		if err = q.rows(ctx, `SELECT p.set_id,p.scope,p.auto,p.standing,EXISTS(SELECT 1 FROM relaxed_proxy_scopes x WHERE x.set_id=p.set_id AND x.scope=p.scope AND x.revision=p.revision) FROM set_policies p JOIN credential_sets s ON s.id=p.set_id JOIN services v ON v.id=s.service_id WHERE v.org_id=? AND v.archived=0 AND s.archived=0 AND p.revision=(SELECT max(revision) FROM set_policies WHERE set_id=p.set_id AND scope=p.scope AND revision<=?) ORDER BY p.set_id,p.scope`, func(rs *sql.Rows) error {
			var r api.CatalogueRule
			err := rs.Scan(&r.Set, &r.Scope, &r.Auto, &r.Standing, &r.Relax)
			o.Rules = append(o.Rules, r)
			return err
		}, o.ID, o.Revision); err != nil {
			return out, err
		}
		if err = q.rows(ctx, `SELECT h.id,e.id,h.name,h.cert_sha256,e.class,coalesce(a.active,0),coalesce(a.generation,0) FROM hosts h JOIN enrollments e ON e.id=h.enrollment_id LEFT JOIN org_hosts a ON a.host_id=h.id AND a.org_id=? WHERE h.revoked_at IS NULL AND h.not_after>? ORDER BY h.name,h.id`, func(rs *sql.Rows) error {
			var h api.CatalogueHost
			err := rs.Scan(&h.ID, &h.Enrollment, &h.Name, &h.Fingerprint, &h.Class, &h.Active, &h.Generation)
			o.Hosts = append(o.Hosts, h)
			return err
		}, o.ID, ms(now)); err != nil {
			return out, err
		}
	}
	return out, nil
}

// Transport and membership rechecks happen in the caller's immediate transaction.
func (q *Q) WriteCatalogue(ctx context.Context, object, action string, c api.CatalogueChange, now time.Time) error {
	exec := func(sql string, args ...any) error { _, err := q.q.ExecContext(ctx, sql, args...); return err }
	putPolicy := func(rev int, p api.DurationPolicy) error {
		if err := exec(`INSERT INTO org_policies VALUES(?,?,?,?,?,?,?,?)`, c.Org.ID, rev, p.Default, p.Soft, p.Indefinite, p.StandingDefault, p.StandingSoft, p.StandingIndefinite); err != nil {
			return err
		}
		if !p.Discovery && !p.DenyGet {
			return nil
		}
		if err := exec(orgFlagsDDL); err != nil {
			return err
		}
		return exec(`INSERT INTO org_flags VALUES(?,?,?,?)`, c.Org.ID, rev, p.Discovery, p.DenyGet)
	}
	switch object {
	case "organisation":
		if err := exec(`INSERT INTO organisations(id,slug,title,revision) VALUES(?,?,?,1)`, c.Org.ID, c.Org.Slug, c.Org.Title); err != nil {
			return err
		}
		if err := exec(`INSERT INTO org_approvers VALUES(?,?,'approver',1)`, c.Org.ID, c.Owner); err != nil {
			return err
		}
		return putPolicy(1, *c.Policy)
	case "service":
		return exec(`INSERT INTO services(id,org_id,slug,title,provider,revision) VALUES(?,?,?,?,'application',1)`, c.Service.ID, c.Org.ID, c.Service.Slug, c.Service.Title)
	case "credential_set":
		return exec(`INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES(?,?,'application',?,?,'env-set',0)`, c.Set.ID, c.Service.ID, c.Set.Slug, c.Set.Title)
	case "org_host":
		return exec(`INSERT INTO org_hosts VALUES(?,?,?,?) ON CONFLICT(org_id,host_id) DO UPDATE SET active=excluded.active,generation=excluded.generation`, c.Org.ID, c.Host.ID, action == "admit", c.ResultRevision)
	case "org_policy":
		rev := c.ResultRevision
		if err := putPolicy(rev, *c.Policy); err != nil {
			return err
		}
		for _, r := range *c.Rules {
			if err := exec(`INSERT INTO set_policies VALUES(?,?,?,?,?,?,?,?)`, r.Set, rev, r.Scope, c.Policy.Default, c.Policy.Soft, c.Policy.Indefinite, r.Auto, r.Standing); err != nil {
				return err
			}
			if r.Relax {
				if err := exec(`INSERT INTO relaxed_proxy_scopes VALUES(?,?,?)`, r.Set, r.Scope, rev); err != nil {
					return err
				}
			}
		}
		if err := exec(`UPDATE organisations SET revision=? WHERE id=?`, rev, c.Org.ID); err != nil {
			return err
		}
		const affected = `(SELECT b.request_id FROM request_bindings b JOIN credential_sets s ON s.id=b.set_id JOIN services v ON v.id=s.service_id WHERE v.org_id=?)`
		if err := exec(`UPDATE requests SET status=CASE status WHEN 'approved' THEN 'revoked' ELSE 'expired' END,decision_note='organisation policy replaced' WHERE status IN ('approved','pending') AND id IN `+affected, c.Org.ID); err != nil {
			return err
		}
		if err := exec(`UPDATE grants SET revoked_at=? WHERE revoked_at IS NULL AND request_id IN `+affected, ms(now), c.Org.ID); err != nil {
			return err
		}
		return exec(`UPDATE standing SET revoked_at=? WHERE revoked_at IS NULL AND source_request_id IN `+affected, ms(now), c.Org.ID)
	}
	return ErrConflict
}
