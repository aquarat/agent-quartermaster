package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Seal format 2 (docs/BUCKETS.md §11). Public keys, salts, wraps and records
// only: no statement here takes a bucket key, a scope key or a KEK.
const BucketDDL = `CREATE TABLE IF NOT EXISTS bucket_scopes(scope TEXT PRIMARY KEY,public_key BLOB NOT NULL CHECK(length(public_key)=65),recovery BLOB NOT NULL,created INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS scope_wraps(id INTEGER PRIMARY KEY,passkey INTEGER NOT NULL REFERENCES passkeys(id) ON DELETE CASCADE,scope TEXT NOT NULL REFERENCES bucket_scopes(scope) ON DELETE CASCADE,salt BLOB NOT NULL UNIQUE CHECK(length(salt)=32),wrap BLOB NOT NULL CHECK(length(wrap)=73),created INTEGER NOT NULL,tested_at INTEGER,UNIQUE(passkey,scope)) STRICT;
CREATE TABLE IF NOT EXISTS buckets(id BLOB PRIMARY KEY CHECK(length(id)=32),scope TEXT NOT NULL REFERENCES bucket_scopes(scope),kind TEXT NOT NULL CHECK(kind IN ('ssh-ca','internal-ca','cf-proxy','env-set','signer')),ref TEXT NOT NULL,public_key BLOB NOT NULL CHECK(length(public_key)=65),wrap BLOB NOT NULL CHECK(length(wrap)=113),payload BLOB,created INTEGER NOT NULL,UNIQUE(kind,ref)) STRICT;
CREATE TABLE IF NOT EXISTS notice_channel(singleton INTEGER PRIMARY KEY CHECK(singleton=1),topic_url TEXT NOT NULL) STRICT;
CREATE TRIGGER IF NOT EXISTS keep_one_scope_passkey BEFORE DELETE ON passkeys WHEN EXISTS(SELECT 1 FROM scope_wraps WHERE passkey=OLD.id) AND NOT EXISTS(SELECT 1 FROM scope_wraps WHERE passkey!=OLD.id) BEGIN SELECT RAISE(ABORT,'last passkey that can open buckets'); END;`

// SchemaBuckets is PRAGMA user_version of a format-2 store.
const SchemaBuckets = 9

// BucketRow is a bucket's public description. Label is derived, never stored.
type BucketRow struct {
	ID        []byte
	Scope     string
	Kind      string
	Ref       string
	Public    []byte
	Wrap      []byte
	Payload   []byte
	Created   time.Time
	Label     string
	OrgTitle  string
	OrgID     string
	ServiceID string
}

// ScopeRow is a scope key's public half and its recovery wrap.
type ScopeRow struct {
	Scope    string
	Public   []byte
	Recovery []byte
	Created  time.Time
}

// ScopeWrapRow is one passkey's KEK wrap of a scope key.
type ScopeWrapRow struct {
	ID      int64
	Passkey int64
	RawID   []byte
	Scope   string
	Salt    []byte
	Wrap    []byte
	Created time.Time
	Tested  *time.Time
}

const bucketCols = `b.id,b.scope,b.kind,b.ref,b.public_key,b.wrap,b.payload,b.created,
 CASE b.kind WHEN 'ssh-ca' THEN 'SSH user CA' WHEN 'internal-ca' THEN 'Internal agent CA' ELSE coalesce(o.slug||'/'||v.slug||'/'||s.slug,'(deleted set '||b.ref||')') END,
 coalesce(o.title,''),coalesce(o.id,''),coalesce(v.id,'')
 FROM buckets b LEFT JOIN credential_sets s ON s.id=b.ref AND b.kind NOT IN ('ssh-ca','internal-ca') LEFT JOIN services v ON v.id=s.service_id LEFT JOIN organisations o ON o.id=v.org_id`

func scanBucket(sc interface{ Scan(...any) error }) (BucketRow, error) {
	var b BucketRow
	var created int64
	err := sc.Scan(&b.ID, &b.Scope, &b.Kind, &b.Ref, &b.Public, &b.Wrap, &b.Payload, &created, &b.Label, &b.OrgTitle, &b.OrgID, &b.ServiceID)
	b.Created = fromMS(created)
	return b, err
}

// Buckets lists every bucket, installation-wide first, then by label.
func (q *Q) Buckets(ctx context.Context) ([]BucketRow, error) {
	var out []BucketRow
	err := q.rows(ctx, `SELECT `+bucketCols+` ORDER BY b.scope!='installation', 9`, func(r *sql.Rows) error {
		b, err := scanBucket(r)
		out = append(out, b)
		return err
	})
	return out, err
}
func (q *Q) Bucket(ctx context.Context, id []byte) (BucketRow, error) {
	b, err := scanBucket(q.q.QueryRowContext(ctx, `SELECT `+bucketCols+` WHERE b.id=?`, id))
	return b, notFound(err)
}
func (q *Q) BucketByRef(ctx context.Context, kind, ref string) (BucketRow, error) {
	b, err := scanBucket(q.q.QueryRowContext(ctx, `SELECT `+bucketCols+` WHERE b.kind=? AND b.ref=?`, kind, ref))
	return b, notFound(err)
}
func (q *Q) InsertBucket(ctx context.Context, b BucketRow) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO buckets(id,scope,kind,ref,public_key,wrap,payload,created) VALUES(?,?,?,?,?,?,?,?)`, b.ID, b.Scope, b.Kind, b.Ref, b.Public, b.Wrap, b.Payload, ms(b.Created)))
}

func (q *Q) Scopes(ctx context.Context) ([]ScopeRow, error) {
	var out []ScopeRow
	err := q.rows(ctx, `SELECT scope,public_key,recovery,created FROM bucket_scopes ORDER BY scope!='installation',scope`, func(r *sql.Rows) error {
		var x ScopeRow
		var c int64
		err := r.Scan(&x.Scope, &x.Public, &x.Recovery, &c)
		x.Created = fromMS(c)
		out = append(out, x)
		return err
	})
	return out, err
}
func (q *Q) Scope(ctx context.Context, scope string) (ScopeRow, error) {
	var x ScopeRow
	var c int64
	err := q.q.QueryRowContext(ctx, `SELECT scope,public_key,recovery,created FROM bucket_scopes WHERE scope=?`, scope).Scan(&x.Scope, &x.Public, &x.Recovery, &c)
	x.Created = fromMS(c)
	return x, notFound(err)
}
func (q *Q) InsertScope(ctx context.Context, x ScopeRow) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO bucket_scopes(scope,public_key,recovery,created) VALUES(?,?,?,?)`, x.Scope, x.Public, x.Recovery, ms(x.Created)))
}

const scopeWrapCols = `w.id,w.passkey,p.credential_id,w.scope,w.salt,w.wrap,w.created,w.tested_at FROM scope_wraps w JOIN passkeys p ON p.id=w.passkey`

func scanScopeWrap(sc interface{ Scan(...any) error }) (ScopeWrapRow, error) {
	var o ScopeWrapRow
	var created int64
	var tested sql.NullInt64
	err := sc.Scan(&o.ID, &o.Passkey, &o.RawID, &o.Scope, &o.Salt, &o.Wrap, &created, &tested)
	o.Created = fromMS(created)
	if tested.Valid {
		t := fromMS(tested.Int64)
		o.Tested = &t
	}
	return o, err
}

// ScopeWraps lists passkey wraps of scope keys, optionally of one passkey (0: all).
func (q *Q) ScopeWraps(ctx context.Context, passkey int64) ([]ScopeWrapRow, error) {
	var out []ScopeWrapRow
	err := q.rows(ctx, `SELECT `+scopeWrapCols+` WHERE ?1=0 OR w.passkey=?1 ORDER BY w.passkey,w.scope!='installation',w.scope`, func(r *sql.Rows) error {
		o, err := scanScopeWrap(r)
		out = append(out, o)
		return err
	}, passkey)
	return out, err
}
func (q *Q) ScopeWrap(ctx context.Context, passkey int64, scope string) (ScopeWrapRow, error) {
	o, err := scanScopeWrap(q.q.QueryRowContext(ctx, `SELECT `+scopeWrapCols+` WHERE w.passkey=? AND w.scope=?`, passkey, scope))
	return o, notFound(err)
}

// PutScopeWrap inserts or replaces one passkey's wrap of a scope key (untested).
func (q *Q) PutScopeWrap(ctx context.Context, o ScopeWrapRow) error {
	_, err := q.q.ExecContext(ctx, `INSERT INTO scope_wraps(passkey,scope,salt,wrap,created) VALUES(?,?,?,?,?) ON CONFLICT(passkey,scope) DO UPDATE SET salt=excluded.salt,wrap=excluded.wrap,created=excluded.created,tested_at=NULL`, o.Passkey, o.Scope, o.Salt, o.Wrap, ms(o.Created))
	return err
}
func (q *Q) MarkScopeWrapTested(ctx context.Context, id int64, now time.Time) error {
	_, err := q.q.ExecContext(ctx, `UPDATE scope_wraps SET tested_at=? WHERE id=? AND tested_at IS NULL`, ms(now), id)
	return err
}

// DeleteScopeWraps removes passkey wraps of a scope except one passkey's (rekey).
func (q *Q) DeleteScopeWraps(ctx context.Context, scope string, keep int64) error {
	_, err := q.q.ExecContext(ctx, `DELETE FROM scope_wraps WHERE scope=? AND passkey!=?`, scope, keep)
	return err
}

// ScopeCoverage counts, per passkey, the buckets in scopes it can open.
func (q *Q) ScopeCoverage(ctx context.Context) (map[int64]int, error) {
	out := map[int64]int{}
	err := q.rows(ctx, `SELECT w.passkey,count(b.id) FROM scope_wraps w LEFT JOIN buckets b ON b.scope=w.scope GROUP BY w.passkey`, func(r *sql.Rows) error {
		var p int64
		var n int
		err := r.Scan(&p, &n)
		out[p] = n
		return err
	})
	return out, err
}

// NoticeTopic is the approval-notice ntfy URL, readable with every bucket closed (§9).
func (q *Q) NoticeTopic(ctx context.Context) (string, error) {
	var t string
	err := q.q.QueryRowContext(ctx, `SELECT topic_url FROM notice_channel WHERE singleton=1`).Scan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return t, err
}
func (q *Q) SetNoticeTopic(ctx context.Context, topic string) error {
	if topic == "" {
		_, err := q.q.ExecContext(ctx, `DELETE FROM notice_channel`)
		return err
	}
	_, err := q.q.ExecContext(ctx, `INSERT INTO notice_channel VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET topic_url=excluded.topic_url`, topic)
	return err
}
