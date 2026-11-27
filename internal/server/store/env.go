package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"reflect"
	"strings"
	"time"
)

// Store only public reviewed metadata or already-encrypted records. No SQL
// statement takes an env value, a draft salt, an upload ticket or a DEK.
type CipherRecord struct{ Blob, Payload, Wrap []byte }

func (s *Store) InitEnv(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS env_revisions(set_id TEXT NOT NULL REFERENCES credential_sets(id),revision INTEGER NOT NULL,names TEXT NOT NULL,blob BLOB NOT NULL UNIQUE,payload BLOB,wrap BLOB,PRIMARY KEY(set_id,revision)) STRICT;
CREATE TABLE IF NOT EXISTS env_drafts(id TEXT PRIMARY KEY,session TEXT NOT NULL REFERENCES web_sessions(hash) ON DELETE CASCADE,host INTEGER NOT NULL REFERENCES hosts(id),set_id TEXT NOT NULL REFERENCES credential_sets(id),expires INTEGER NOT NULL,ticket_hash TEXT UNIQUE,metadata TEXT NOT NULL,blob BLOB UNIQUE,payload BLOB,wrap BLOB) STRICT;
CREATE TABLE IF NOT EXISTS env_releases(id TEXT PRIMARY KEY,grant_id TEXT UNIQUE,host INTEGER NOT NULL REFERENCES hosts(id),set_id TEXT NOT NULL REFERENCES credential_sets(id),binding TEXT NOT NULL,mode TEXT NOT NULL CHECK(mode IN ('process','file','shell')),peer TEXT NOT NULL,reason TEXT NOT NULL,ttl INTEGER NOT NULL,deadline INTEGER NOT NULL,until_ms INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL CHECK(status IN ('pending','approved','expired','cancelled','denied','revoked')),consumed INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE INDEX IF NOT EXISTS env_by_host_status ON env_releases(host,status);
CREATE TRIGGER IF NOT EXISTS env_end_admission AFTER UPDATE ON org_hosts BEGIN DELETE FROM env_drafts WHERE host=NEW.host_id AND set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.org_id); UPDATE env_releases SET status=CASE status WHEN 'pending' THEN 'expired' ELSE 'revoked' END WHERE status IN ('approved','pending') AND host=NEW.host_id AND set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.org_id);END;
CREATE TRIGGER IF NOT EXISTS env_end_policy AFTER UPDATE ON organisations BEGIN DELETE FROM env_drafts WHERE set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.id);UPDATE env_releases SET status=CASE status WHEN 'pending' THEN 'expired' ELSE 'revoked' END WHERE status IN ('approved','pending') AND set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.id);END;
CREATE TRIGGER IF NOT EXISTS env_end_revision AFTER UPDATE ON credential_sets BEGIN DELETE FROM env_drafts WHERE set_id=NEW.id;UPDATE env_releases SET status=CASE status WHEN 'pending' THEN 'expired' ELSE 'revoked' END WHERE status IN ('approved','pending') AND set_id=NEW.id;END;`)
	if err != nil {
		return err
	}
	// 0.10.0: the delivery "get" (a secret printed by `aqmas get`). The mode
	// column's CHECK predates it and cannot be altered in place, so such a row
	// stores mode 'process' and its real delivery here; NULL means the mode.
	if _, err = s.db.ExecContext(ctx, envStandingDDL); err != nil {
		return err
	}
	if _, err = s.db.ExecContext(ctx, envProposalDDL); err != nil {
		return err
	}
	// standing: the "don't ask again" rule that approved a release without a tap, if any.
	for col, ddl := range map[string]string{"delivery": `TEXT CHECK(delivery IS NULL OR delivery='get')`, "standing": `TEXT`} {
		var has int
		if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('env_releases') WHERE name=?`, col).Scan(&has); err != nil {
			return err
		}
		if has == 0 {
			if _, err = s.db.ExecContext(ctx, `ALTER TABLE env_releases ADD COLUMN `+col+` `+ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// envStandingDDL: "don't ask again" rules for env sets and secrets, and each
// set's ceiling for them. A rule ends with the admission, the organisation's
// policy revision or the set's revision it was made under, exactly like the
// releases it approves. A previous binary ignores both tables: it asks for a
// tap every time.
const envStandingDDL = `CREATE TABLE IF NOT EXISTS env_standing(id TEXT PRIMARY KEY,host INTEGER NOT NULL REFERENCES hosts(id),set_id TEXT NOT NULL REFERENCES credential_sets(id),binding TEXT NOT NULL,mode TEXT NOT NULL,peer TEXT NOT NULL,max_ttl INTEGER NOT NULL CHECK(max_ttl>0),created INTEGER NOT NULL,expires INTEGER NOT NULL,revoked_at INTEGER,uses INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE INDEX IF NOT EXISTS env_standing_by_host ON env_standing(host,set_id);
CREATE TABLE IF NOT EXISTS set_standing(set_id TEXT PRIMARY KEY REFERENCES credential_sets(id),cap_seconds INTEGER NOT NULL CHECK(cap_seconds BETWEEN 0 AND 86400)) STRICT;
CREATE TRIGGER IF NOT EXISTS env_standing_end_admission AFTER UPDATE ON org_hosts BEGIN UPDATE env_standing SET revoked_at=CAST(unixepoch('subsec')*1000 AS INTEGER) WHERE revoked_at IS NULL AND host=NEW.host_id AND set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.org_id);END;
CREATE TRIGGER IF NOT EXISTS env_standing_end_policy AFTER UPDATE ON organisations BEGIN UPDATE env_standing SET revoked_at=CAST(unixepoch('subsec')*1000 AS INTEGER) WHERE revoked_at IS NULL AND set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.id);END;
CREATE TRIGGER IF NOT EXISTS env_standing_end_revision AFTER UPDATE ON credential_sets BEGIN UPDATE env_standing SET revoked_at=CAST(unixepoch('subsec')*1000 AS INTEGER) WHERE revoked_at IS NULL AND set_id=NEW.id;END;`

// envProposalDDL (0.11.0): a host's request to store values, waiting for the
// owner. A proposal is not bound to a web session (unlike a draft) and may
// name a set or service that does not exist yet, so set_id and service_id are
// not foreign keys. payload holds the sealed records; bucket holds, for a set
// that has no bucket yet, the public material of the bucket it will get (the
// bucket row itself is inserted at commit). Both are gone as soon as the
// proposal is no longer pending, whatever ended it: the CHECK says so. The
// triggers end a proposal on the events that delete drafts. A previous binary
// ignores the table.
const envProposalDDL = `CREATE TABLE IF NOT EXISTS env_proposals(id TEXT PRIMARY KEY,host INTEGER NOT NULL REFERENCES hosts(id),org_id TEXT NOT NULL REFERENCES organisations(id),service_id TEXT NOT NULL,set_id TEXT NOT NULL,service_slug TEXT NOT NULL,set_slug TEXT NOT NULL,new_service INTEGER NOT NULL CHECK(new_service IN (0,1)),new_set INTEGER NOT NULL CHECK(new_set IN (0,1)),expires INTEGER NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','committed','discarded','cancelled','expired','superseded')),result_revision INTEGER NOT NULL DEFAULT 0,metadata TEXT NOT NULL,payload BLOB,wrap BLOB,bucket TEXT,CHECK(status='pending' OR (payload IS NULL AND bucket IS NULL))) STRICT;
CREATE INDEX IF NOT EXISTS env_proposals_by_host ON env_proposals(host,status);
CREATE TRIGGER IF NOT EXISTS env_proposal_end_admission AFTER UPDATE ON org_hosts BEGIN UPDATE env_proposals SET status='superseded',payload=NULL,bucket=NULL WHERE status='pending' AND host=NEW.host_id AND org_id=NEW.org_id;END;
CREATE TRIGGER IF NOT EXISTS env_proposal_end_policy AFTER UPDATE ON organisations BEGIN UPDATE env_proposals SET status='superseded',payload=NULL,bucket=NULL WHERE status='pending' AND org_id=NEW.id;END;
CREATE TRIGGER IF NOT EXISTS env_proposal_end_revision AFTER UPDATE ON credential_sets BEGIN UPDATE env_proposals SET status='superseded',payload=NULL,bucket=NULL WHERE status='pending' AND set_id=NEW.id;END;`

// StagedProposal is a proposal with what only the broker reads: the sealed
// records, the bucket they are sealed to and, for a set without a bucket yet,
// the bucket to insert at commit.
type StagedProposal struct {
	P                      envset.Proposal
	Host                   int64
	ServiceSlug, SetSlug   string
	ServiceTitle, SetTitle string
	Record                 CipherRecord
	Bucket                 string
}

// proposalMeta is the metadata column: the proposal as the host made it, and
// the titles a new service and set get (they are also in P.Title, joined).
type proposalMeta struct {
	P            envset.Proposal `json:"proposal"`
	ServiceTitle string          `json:"service_title"`
	SetTitle     string          `json:"set_title"`
}

func (q *Q) NewEnvProposal(ctx context.Context, x StagedProposal) error {
	raw, err := json.Marshal(proposalMeta{x.P, x.ServiceTitle, x.SetTitle})
	if err != nil {
		return err
	}
	var bucket any
	if x.Bucket != "" {
		bucket = x.Bucket
	}
	return one(q.q.ExecContext(ctx, `INSERT INTO env_proposals(id,host,org_id,service_id,set_id,service_slug,set_slug,new_service,new_set,expires,status,metadata,payload,wrap,bucket) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,?)`, x.P.ID, x.Host, x.P.Org, x.P.Service, x.P.Set, x.ServiceSlug, x.SetSlug, x.P.NewService, x.P.NewSet, x.P.Expires, string(raw), x.Record.Payload, x.Record.Wrap, bucket))
}

const envProposalCols = `metadata,host,service_slug,set_slug,status,result_revision,payload,wrap,coalesce(bucket,'') FROM env_proposals`

func scanEnvProposal(row interface{ Scan(...any) error }) (x StagedProposal, err error) {
	var raw, status string
	var result int
	if err = row.Scan(&raw, &x.Host, &x.ServiceSlug, &x.SetSlug, &status, &result, &x.Record.Payload, &x.Record.Wrap, &x.Bucket); err != nil {
		return x, err
	}
	var m proposalMeta
	if err = json.Unmarshal([]byte(raw), &m); err != nil {
		return x, err
	}
	x.P, x.ServiceTitle, x.SetTitle = m.P, m.ServiceTitle, m.SetTitle
	// The columns are what the triggers and decisions change.
	x.P.Status, x.P.Result = status, result
	return x, nil
}

// EnvProposal loads one proposal in any state.
func (q *Q) EnvProposal(ctx context.Context, id string) (StagedProposal, error) {
	x, err := scanEnvProposal(q.q.QueryRowContext(ctx, `SELECT `+envProposalCols+` WHERE id=?`, id))
	return x, notFound(err)
}

// PendingEnvProposals lists what waits for the owner, oldest first.
func (q *Q) PendingEnvProposals(ctx context.Context, now time.Time) ([]envset.Proposal, error) {
	out := []envset.Proposal{}
	err := q.rows(ctx, `SELECT `+envProposalCols+` WHERE status='pending' AND expires>? ORDER BY id`, func(rs *sql.Rows) error {
		x, err := scanEnvProposal(rs)
		out = append(out, x.P)
		return err
	}, ms(now))
	return out, err
}

// EndEnvProposal moves a pending proposal to its final state and drops its
// sealed records and bucket material in the same statement.
func (q *Q) EndEnvProposal(ctx context.Context, id, status string, result int) error {
	return one(q.q.ExecContext(ctx, `UPDATE env_proposals SET status=?,result_revision=?,payload=NULL,bucket=NULL WHERE id=? AND status='pending'`, status, result, id))
}

// EnvProposalsPending counts a host's proposals that wait for the owner.
func (q *Q) EnvProposalsPending(ctx context.Context, host int64, now time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM env_proposals WHERE host=? AND status='pending' AND expires>?`, host, ms(now)).Scan(&n)
	return n, err
}

// sweepEnvProposals expires proposals (audited: nobody else records that the
// owner never decided), supersedes those that would create a path or use an
// ID somebody took since, and forgets ended ones after a day.
func (q *Q) sweepEnvProposals(ctx context.Context, now time.Time) error {
	type gone struct{ id, detail string }
	var expired []gone
	if err := q.rows(ctx, `UPDATE env_proposals SET status='expired',payload=NULL,bucket=NULL WHERE status='pending' AND expires<=? RETURNING id,json_extract(metadata,'$.proposal.path')||' host='||json_extract(metadata,'$.proposal.host')`, func(rs *sql.Rows) error {
		var g gone
		err := rs.Scan(&g.id, &g.detail)
		expired = append(expired, g)
		return err
	}, ms(now)); err != nil {
		return err
	}
	for _, g := range expired {
		if err := q.Audit(ctx, now, "system", "env_proposal_expire", "proposal:"+g.id, g.detail); err != nil {
			return err
		}
	}
	if _, err := q.q.ExecContext(ctx, `UPDATE env_proposals SET status='superseded',payload=NULL,bucket=NULL WHERE status='pending' AND ((new_set AND EXISTS(SELECT 1 FROM credential_sets s WHERE s.id=env_proposals.set_id OR (s.service_id=env_proposals.service_id AND s.slug=env_proposals.set_slug))) OR (new_service AND EXISTS(SELECT 1 FROM services v WHERE v.id=env_proposals.service_id OR (v.org_id=env_proposals.org_id AND v.slug=env_proposals.service_slug))))`); err != nil {
		return err
	}
	_, err := q.q.ExecContext(ctx, `DELETE FROM env_proposals WHERE status!='pending' AND expires<=?`, ms(now.Add(-24*time.Hour)))
	return err
}

// SupersedeScopeProposals ends the pending proposals of an organisation whose
// scope key is replaced: their records and bucket wraps are to the old keys.
func (q *Q) SupersedeScopeProposals(ctx context.Context, scope string) error {
	_, err := q.q.ExecContext(ctx, `UPDATE env_proposals SET status='superseded',payload=NULL,bucket=NULL WHERE status='pending' AND (org_id=?1 OR wrap IN (SELECT id FROM buckets WHERE scope=?1))`, scope)
	return err
}

// EnvBase is what a set that does not exist yet would be bound to: the
// host's admission to the organisation and, when the service exists, the
// service. Set, Revision and Names are empty.
type EnvBase struct {
	envset.Binding
	OrgTitle, ServiceTitle string
	// ServiceBlocked: a service has the slug but cannot take an env set (it
	// is archived or belongs to another provider).
	ServiceBlocked bool
}

// EnvBase resolves org/service for a host admitted to the organisation;
// ErrNotFound exactly where EnvBinding would hide the organisation.
func (q *Q) EnvBase(ctx context.Context, host int64, org, service string, now time.Time) (EnvBase, error) {
	var b EnvBase
	err := q.q.QueryRowContext(ctx, `SELECT o.id,o.title,o.revision,a.generation,h.enrollment_id,h.name,e.class,p.default_seconds,p.soft_cap,p.indefinite,coalesce(v.id,''),coalesce(v.title,''),coalesce(v.revision,0),coalesce(v.archived OR v.provider!='application',0) FROM org_hosts a JOIN hosts h ON h.id=a.host_id JOIN enrollments e ON e.id=h.enrollment_id JOIN organisations o ON o.id=a.org_id JOIN org_policies p ON p.org_id=o.id AND p.revision=o.revision LEFT JOIN services v ON v.org_id=o.id AND v.slug=?1 WHERE h.id=?2 AND o.slug=?3 AND a.active AND NOT o.archived AND h.revoked_at IS NULL AND h.not_after>?4`, service, host, org, ms(now)).Scan(&b.Org, &b.OrgTitle, &b.PolicyRevision, &b.Generation, &b.Enrollment, &b.Host, &b.Class, &b.Default, &b.Soft, &b.Forever, &b.Service, &b.ServiceTitle, &b.ServiceRevision, &b.ServiceBlocked)
	b.Names = []string{}
	return b, notFound(err)
}

// ServiceIDFree reports whether no service has this ID.
func (q *Q) ServiceIDFree(ctx context.Context, id string) (bool, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM services WHERE id=?`, id).Scan(&n)
	return n == 0, err
}

// CreateEnvService and CreateEnvSet insert what a committed proposal asked
// for, as the catalogue does (WriteCatalogue): an application service at
// revision 1, an env set at revision 0.
func (q *Q) CreateEnvService(ctx context.Context, id, org, slug, title string) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO services(id,org_id,slug,title,provider,revision) VALUES(?,?,?,?,'application',1)`, id, org, slug, title))
}
func (q *Q) CreateEnvSet(ctx context.Context, id, service, slug, title string) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES(?,?,'application',?,?,'env-set',0)`, id, service, slug, title))
}

const envStandingCols = `id,binding,mode,peer,max_ttl,created,expires,uses FROM env_standing`

func scanEnvStanding(row interface{ Scan(...any) error }) (st envset.Standing, err error) {
	var b string
	if err = row.Scan(&st.ID, &b, &st.Mode, &st.Peer, &st.MaxTTL, &st.Created, &st.Expires, &st.Uses); err == nil {
		err = json.Unmarshal([]byte(b), &st.Binding)
	}
	return st, err
}

// NewEnvStanding records a rule under the ID of the release whose approval made it.
func (q *Q) NewEnvStanding(ctx context.Context, host int64, st envset.Standing) error {
	b, err := json.Marshal(st.Binding)
	if err != nil {
		return err
	}
	return one(q.q.ExecContext(ctx, `INSERT INTO env_standing(id,host,set_id,binding,mode,peer,max_ttl,created,expires) VALUES(?,?,?,?,?,?,?,?,?)`, st.ID, host, st.Set, string(b), st.Mode, st.Peer, st.MaxTTL, st.Created, st.Expires))
}

// EnvStanding loads one live rule (not revoked, not expired).
func (q *Q) EnvStanding(ctx context.Context, id string, now time.Time) (envset.Standing, error) {
	st, err := scanEnvStanding(q.q.QueryRowContext(ctx, `SELECT `+envStandingCols+` WHERE id=? AND revoked_at IS NULL AND expires>?`, id, ms(now)))
	return st, notFound(err)
}

// ActiveEnvStanding lists live rules: of one host and set (a request looking
// for a match) or, with host 0, of every host (set "" for every set).
func (q *Q) ActiveEnvStanding(ctx context.Context, host int64, set string, now time.Time) ([]envset.Standing, error) {
	out := []envset.Standing{}
	err := q.rows(ctx, `SELECT `+envStandingCols+` WHERE revoked_at IS NULL AND expires>?1 AND (?2=0 OR host=?2) AND (?3='' OR set_id=?3) ORDER BY id`, func(rs *sql.Rows) error {
		st, err := scanEnvStanding(rs)
		out = append(out, st)
		return err
	}, ms(now), host, set)
	return out, err
}
func (q *Q) UseEnvStanding(ctx context.Context, id string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE env_standing SET uses=uses+1 WHERE id=? AND revoked_at IS NULL AND expires>?`, id, ms(now)))
}

// RevokeEnvStanding ends rules by ID; it reports how many were live.
func (q *Q) RevokeEnvStanding(ctx context.Context, now time.Time, ids ...string) (int, error) {
	n := 0
	for _, id := range ids {
		if id == "" {
			continue
		}
		res, err := q.q.ExecContext(ctx, `UPDATE env_standing SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, ms(now), id)
		if err != nil {
			return n, err
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	return n, nil
}

// RevokeEnvUnder revokes the releases these rules approved that are not
// collected yet, and returns their IDs (their holds go with them): ending a
// rule also ends what it has issued and nobody has picked up.
func (q *Q) RevokeEnvUnder(ctx context.Context, rules ...string) ([]string, error) {
	var out []string
	for _, rule := range rules {
		if rule == "" {
			continue
		}
		if err := q.rows(ctx, `UPDATE env_releases SET status='revoked' WHERE status='approved' AND consumed=0 AND standing=? RETURNING id`, func(rs *sql.Rows) error {
			var id string
			err := rs.Scan(&id)
			out = append(out, id)
			return err
		}, rule); err != nil {
			return out, err
		}
	}
	return out, nil
}

// EnvStandingLoad counts what a rule has issued: releases still waiting to be
// collected, and approvals since a point in time (a release's deadline is its
// creation time plus the pending expiry, which the caller accounts for).
func (q *Q) EnvStandingLoad(ctx context.Context, rule string, now, deadlineAfter time.Time) (uncollected, recent int, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT coalesce(sum(status='approved' AND consumed=0 AND until_ms>?1),0),coalesce(sum(deadline>?2),0) FROM env_releases WHERE standing=?3`, ms(now), ms(deadlineAfter), rule).Scan(&uncollected, &recent)
	return
}

// HostListing reports whether any organisation that admits the host lets
// hosts list (org_flags.discovery at its current policy revision).
func (q *Q) HostListing(ctx context.Context, host int64, now time.Time) (bool, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM org_hosts a JOIN hosts h ON h.id=a.host_id JOIN organisations o ON o.id=a.org_id JOIN org_flags f ON f.org_id=o.id AND f.revision=o.revision AND f.discovery=1 WHERE h.id=? AND a.active=1 AND o.archived=0 AND h.revoked_at IS NULL AND h.not_after>?`, host, ms(now)).Scan(&n)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return false, nil
	}
	return n > 0, err
}

// RevokeSetStanding ends every rule of a set (its ceiling changed).
func (q *Q) RevokeSetStanding(ctx context.Context, set string, now time.Time) error {
	_, err := q.q.ExecContext(ctx, `UPDATE env_standing SET revoked_at=? WHERE set_id=? AND revoked_at IS NULL`, ms(now), set)
	return err
}

// StandingCap is a set's "longest don't-ask-again" in seconds (0: off).
func (q *Q) StandingCap(ctx context.Context, set string) (int, error) {
	n := envset.StandingCapDefault
	err := q.q.QueryRowContext(ctx, `SELECT cap_seconds FROM set_standing WHERE set_id=?`, set).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return envset.StandingCapDefault, nil
	}
	return n, err
}
func (q *Q) SetStandingCap(ctx context.Context, set string, seconds int) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO set_standing(set_id,cap_seconds) VALUES(?,?) ON CONFLICT(set_id) DO UPDATE SET cap_seconds=excluded.cap_seconds`, set, seconds))
}

// StandingCaps is every set's explicit ceiling (sets without a row have the default).
func (q *Q) StandingCaps(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	err := q.rows(ctx, `SELECT set_id,cap_seconds FROM set_standing`, func(rs *sql.Rows) error {
		var id string
		var n int
		err := rs.Scan(&id, &n)
		out[id] = n
		return err
	})
	return out, err
}

// ApproveEnvBy approves a pending release under a standing rule.
func (q *Q) ApproveEnvBy(ctx context.Context, id, grant, standing string, ttl int, until int64) error {
	return one(q.q.ExecContext(ctx, `UPDATE env_releases SET status='approved',grant_id=?,ttl=?,until_ms=?,standing=? WHERE id=? AND status='pending'`, grant, ttl, until, standing, id))
}

// EnvReleaseStanding is the rule that approved a release ("" for a tap).
func (q *Q) EnvReleaseStanding(ctx context.Context, id string) (string, error) {
	var st sql.NullString
	err := q.q.QueryRowContext(ctx, `SELECT standing FROM env_releases WHERE id=?`, id).Scan(&st)
	return st.String, notFound(err)
}
func (q *Q) SweepEnv(ctx context.Context, now time.Time) error {
	if _, err := q.q.ExecContext(ctx, `DELETE FROM env_drafts WHERE expires<=?`, ms(now)); err != nil {
		return err
	}
	if _, err := q.q.ExecContext(ctx, `UPDATE env_releases SET status='expired' WHERE (status='pending' AND deadline<=?1) OR (status='approved' AND until_ms<=?1)`, ms(now)); err != nil {
		return err
	}
	return q.sweepEnvProposals(ctx, now)
}
func (q *Q) EnvBinding(ctx context.Context, host int64, path string, now time.Time) (envset.Binding, error) {
	var b envset.Binding
	var names string
	err := q.q.QueryRowContext(ctx, `SELECT o.slug||'/'||v.slug||'/'||s.slug,o.title||' / '||v.title||' / '||s.title,o.id,v.id,s.id,s.revision,v.revision,o.revision,a.generation,h.enrollment_id,h.name,e.class,coalesce(r.names,'[]'),p.default_seconds,p.soft_cap,p.indefinite FROM org_hosts a JOIN hosts h ON h.id=a.host_id JOIN enrollments e ON e.id=h.enrollment_id JOIN organisations o ON o.id=a.org_id JOIN services v ON v.org_id=o.id JOIN credential_sets s ON s.service_id=v.id JOIN org_policies p ON p.org_id=o.id AND p.revision=o.revision LEFT JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision WHERE h.id=? AND o.slug||'/'||v.slug||'/'||s.slug=? AND a.active AND NOT o.archived AND NOT s.archived AND NOT v.archived AND s.kind='env-set' AND v.provider='application' AND h.revoked_at IS NULL AND h.not_after>? AND (s.revision=0 OR r.wrap IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM signer_keys k WHERE k.set_id=s.id)`, host, path, ms(now)).Scan(&b.Path, &b.Title, &b.Org, &b.Service, &b.Set, &b.Revision, &b.ServiceRevision, &b.PolicyRevision, &b.Generation, &b.Enrollment, &b.Host, &b.Class, &names, &b.Default, &b.Soft, &b.Forever)
	if err == nil {
		err = json.Unmarshal([]byte(names), &b.Names)
	}
	return b, notFound(err)
}
func (q *Q) NewEnvTicket(ctx context.Context, sess string, host int64, d envset.Draft, hash string) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return one(q.q.ExecContext(ctx, `INSERT INTO env_drafts(id,session,host,set_id,expires,ticket_hash,metadata) SELECT ?,?,?,?,?,?,? WHERE (SELECT count(*) FROM env_drafts WHERE session=?)<16`, d.ID, sess, host, d.Set, d.Expires, hash, string(raw), sess))
}

type StagedEnv struct {
	D       envset.Draft
	Session string
	Host    int64
	Record  CipherRecord
}

func (q *Q) envDraft(ctx context.Context, filter string, args ...any) (x StagedEnv, err error) {
	var raw string
	err = q.q.QueryRowContext(ctx, `SELECT metadata,host,session,blob,payload,wrap FROM env_drafts WHERE `+filter, args...).Scan(&raw, &x.Host, &x.Session, &x.Record.Blob, &x.Record.Payload, &x.Record.Wrap)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &x.D)
	}
	return x, notFound(err)
}
func (q *Q) EnvTicket(ctx context.Context, host int64, hash string, now time.Time) (StagedEnv, error) {
	return q.envDraft(ctx, `ticket_hash=? AND host=? AND expires>? AND payload IS NULL`, hash, host, ms(now))
}
func (q *Q) EnvDraft(ctx context.Context, sess, id string, now time.Time) (StagedEnv, error) {
	return q.envDraft(ctx, `session=? AND id=? AND expires>? AND payload IS NOT NULL`, sess, id, ms(now))
}
func (q *Q) UploadEnv(ctx context.Context, d envset.Draft, hash string, b CipherRecord) error {
	m, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return one(q.q.ExecContext(ctx, `UPDATE env_drafts SET ticket_hash=NULL,blob=?,payload=?,wrap=?,metadata=? WHERE id=? AND ticket_hash=? AND payload IS NULL`, b.Blob, b.Payload, b.Wrap, string(m), d.ID, hash))
}
func (q *Q) DeleteEnvDraft(ctx context.Context, id, sess string) error {
	return one(q.q.ExecContext(ctx, `DELETE FROM env_drafts WHERE id=? AND session=?`, id, sess))
}
func (q *Q) Drafts(ctx context.Context, sess string, now time.Time) ([]envset.Draft, error) {
	out := []envset.Draft{}
	err := q.rows(ctx, `SELECT metadata FROM env_drafts WHERE session=? AND expires>? AND payload IS NOT NULL ORDER BY id`, func(rows *sql.Rows) error {
		var m string
		var d envset.Draft
		if err := rows.Scan(&m); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(m), &d); err != nil {
			return err
		}
		out = append(out, d)
		return nil
	}, sess, ms(now))
	return out, err
}
func (q *Q) EnvCipher(ctx context.Context, set string, revision int) (rec CipherRecord, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT blob,payload,wrap FROM env_revisions WHERE set_id=? AND revision=? AND wrap IS NOT NULL`, set, revision).Scan(&rec.Blob, &rec.Payload, &rec.Wrap)
	return rec, notFound(err)
}
func (q *Q) ReplaceEnv(ctx context.Context, b envset.Binding, names []string, r CipherRecord) error {
	m, err := json.Marshal(names)
	if err != nil {
		return err
	}
	if err = one(q.q.ExecContext(ctx, `UPDATE credential_sets SET revision=revision+1 WHERE id=? AND revision=? AND kind='env-set'`, b.Set, b.Revision)); err != nil {
		return err
	}
	if _, err = q.q.ExecContext(ctx, `UPDATE env_revisions SET wrap=NULL,payload=NULL WHERE set_id=?`, b.Set); err != nil {
		return err
	}
	return one(q.q.ExecContext(ctx, `INSERT INTO env_revisions VALUES(?,?,?,?,?,?)`, b.Set, b.Revision+1, string(m), r.Blob, r.Payload, r.Wrap))
}
func (q *Q) NewEnvRelease(ctx context.Context, host int64, r envset.Release) error {
	b, err := json.Marshal(r.Binding)
	if err != nil {
		return err
	}
	mode, delivery := r.Mode, sql.NullString{}
	if mode == "get" {
		mode, delivery = "process", sql.NullString{String: "get", Valid: true}
	}
	return one(q.q.ExecContext(ctx, `INSERT INTO env_releases(id,host,set_id,binding,mode,delivery,peer,reason,ttl,deadline,status) VALUES(?,?,?,?,?,?,?,?,?,?,'pending')`, r.ID, host, r.Set, string(b), mode, delivery, r.Peer, r.Reason, r.TTL, r.Deadline))
}
func (q *Q) EnvRelease(ctx context.Context, id string, grant bool) (r envset.Release, host int64, err error) {
	col := "id"
	if grant {
		col = "grant_id"
	}
	var b string
	err = q.q.QueryRowContext(ctx, `SELECT id,coalesce(grant_id,''),host,binding,coalesce(delivery,mode),peer,reason,ttl,deadline,until_ms,status,consumed FROM env_releases WHERE `+col+`=?`, id).Scan(&r.ID, &r.Grant, &host, &b, &r.Mode, &r.Peer, &r.Reason, &r.TTL, &r.Deadline, &r.Until, &r.Status, &r.Consumed)
	if err == nil {
		err = json.Unmarshal([]byte(b), &r.Binding)
	}
	return r, host, notFound(err)
}
func (q *Q) VisibleEnvRelease(ctx context.Context, host int64, peer, id string, grant bool, now time.Time) (envset.Release, error) {
	r, h, err := q.EnvRelease(ctx, id, grant)
	if err != nil || h != host || r.Peer != peer {
		return r, ErrNotFound
	}
	b, err := q.EnvBinding(ctx, h, r.Path, now)
	if err != nil || b.Set != r.Set || b.Generation != r.Generation {
		return r, ErrNotFound
	}
	if !reflect.DeepEqual(b, r.Binding) && (r.Status == "approved" || r.Status == "pending") {
		return r, ErrNotFound
	}
	return r, nil
}
func (q *Q) OwnerEnvReleases(ctx context.Context) ([]envset.Release, error) {
	var ids []string
	err := q.rows(ctx, `SELECT id FROM env_releases WHERE status IN ('pending','approved') ORDER BY id`, func(rows *sql.Rows) error { var id string; err := rows.Scan(&id); ids = append(ids, id); return err })
	if err != nil {
		return nil, err
	}
	out := []envset.Release{}
	for _, id := range ids {
		r, _, err := q.EnvRelease(ctx, id, false)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
func (q *Q) DecideEnv(ctx context.Context, id, status, grant string, ttl int, until int64) error {
	if status == "approved" {
		return one(q.q.ExecContext(ctx, `UPDATE env_releases SET status=?,grant_id=?,ttl=?,until_ms=? WHERE id=? AND status='pending'`, status, grant, ttl, until, id))
	}
	from := "pending"
	if status == "revoked" {
		from = "approved"
	}
	return one(q.q.ExecContext(ctx, `UPDATE env_releases SET status=? WHERE id=? AND status=?`, status, id, from))
}
func (q *Q) ConsumeEnv(ctx context.Context, id string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE env_releases SET consumed=1 WHERE grant_id=? AND status='approved' AND NOT consumed AND until_ms>?`, id, ms(now)))
}
func (q *Q) EnvPending(ctx context.Context, host int64, now time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM env_releases WHERE host=? AND status='pending' AND deadline>?`, host, ms(now)).Scan(&n)
	return n, err
}

func (q *Q) EnvHost(ctx context.Context, enrollment string) (int64, error) {
	var host int64
	err := q.q.QueryRowContext(ctx, `SELECT id FROM hosts WHERE enrollment_id=? AND revoked_at IS NULL`, enrollment).Scan(&host)
	return host, notFound(err)
}
