package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"reflect"
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
	return err
}
func (q *Q) SweepEnv(ctx context.Context, now time.Time) error {
	if _, err := q.q.ExecContext(ctx, `DELETE FROM env_drafts WHERE expires<=?`, ms(now)); err != nil {
		return err
	}
	_, err := q.q.ExecContext(ctx, `UPDATE env_releases SET status='expired' WHERE (status='pending' AND deadline<=?1) OR (status='approved' AND until_ms<=?1)`, ms(now))
	return err
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
	return one(q.q.ExecContext(ctx, `INSERT INTO env_releases(id,host,set_id,binding,mode,peer,reason,ttl,deadline,status) VALUES(?,?,?,?,?,?,?,?,?,'pending')`, r.ID, host, r.Set, string(b), r.Mode, r.Peer, r.Reason, r.TTL, r.Deadline))
}
func (q *Q) EnvRelease(ctx context.Context, id string, grant bool) (r envset.Release, host int64, err error) {
	col := "id"
	if grant {
		col = "grant_id"
	}
	var b string
	err = q.q.QueryRowContext(ctx, `SELECT id,coalesce(grant_id,''),host,binding,mode,peer,reason,ttl,deadline,until_ms,status,consumed FROM env_releases WHERE `+col+`=?`, id).Scan(&r.ID, &r.Grant, &host, &b, &r.Mode, &r.Peer, &r.Reason, &r.TTL, &r.Deadline, &r.Until, &r.Status, &r.Consumed)
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
