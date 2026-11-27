package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Seal format 2 (docs/BUCKETS.md §11). Public keys, salts, wraps and records
// only: no statement here takes a bucket key, a scope key or a KEK.
//
// browser_keys, browser_wraps and the view scope_openers (remembered browsers,
// §13) were added after schema 9 shipped. BucketDDL runs at every boot with IF
// NOT EXISTS, so an existing store gains them empty and nothing else changes;
// the schema version stays 9.
//
// passkey_prf is the sticky mark "this passkey has had a PRF wrap": the trigger
// mark_passkey_prf sets it in the transaction that writes a passkey's first
// PRF wrap (enable, recovery enrol, activation, seal-recover), and the INSERT
// below marks, at boot, every passkey of an existing store that has one now.
// Nothing clears it but removing the passkey. While it is set the passkey is
// refused the remembered-browser path (§13.4), also after its wraps are gone.
const BucketDDL = `CREATE TABLE IF NOT EXISTS bucket_scopes(scope TEXT PRIMARY KEY,public_key BLOB NOT NULL CHECK(length(public_key)=65),recovery BLOB NOT NULL,created INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS scope_wraps(id INTEGER PRIMARY KEY,passkey INTEGER NOT NULL REFERENCES passkeys(id) ON DELETE CASCADE,scope TEXT NOT NULL REFERENCES bucket_scopes(scope) ON DELETE CASCADE,salt BLOB NOT NULL UNIQUE CHECK(length(salt)=32),wrap BLOB NOT NULL CHECK(length(wrap)=73),created INTEGER NOT NULL,tested_at INTEGER,UNIQUE(passkey,scope)) STRICT;
CREATE TABLE IF NOT EXISTS buckets(id BLOB PRIMARY KEY CHECK(length(id)=32),scope TEXT NOT NULL REFERENCES bucket_scopes(scope),kind TEXT NOT NULL CHECK(kind IN ('ssh-ca','internal-ca','cf-proxy','env-set','signer')),ref TEXT NOT NULL,public_key BLOB NOT NULL CHECK(length(public_key)=65),wrap BLOB NOT NULL CHECK(length(wrap)=113),payload BLOB,created INTEGER NOT NULL,UNIQUE(kind,ref)) STRICT;
CREATE TABLE IF NOT EXISTS browser_keys(id INTEGER PRIMARY KEY,passkey INTEGER NOT NULL REFERENCES passkeys(id) ON DELETE CASCADE,public_key BLOB NOT NULL CHECK(length(public_key)=65),label TEXT NOT NULL,created INTEGER NOT NULL,last_used INTEGER,UNIQUE(passkey,public_key)) STRICT;
CREATE TABLE IF NOT EXISTS browser_wraps(id BLOB PRIMARY KEY CHECK(length(id)=32),browser_key INTEGER NOT NULL REFERENCES browser_keys(id) ON DELETE CASCADE,scope TEXT NOT NULL REFERENCES bucket_scopes(scope) ON DELETE CASCADE,wrap BLOB NOT NULL CHECK(length(wrap)=73),sealed_kek BLOB NOT NULL CHECK(length(sealed_kek)=113),created INTEGER NOT NULL,tested_at INTEGER,UNIQUE(browser_key,scope)) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS browser_keys_label ON browser_keys(passkey,label);
CREATE TABLE IF NOT EXISTS passkey_prf(passkey INTEGER PRIMARY KEY REFERENCES passkeys(id) ON DELETE CASCADE,since INTEGER NOT NULL) STRICT;
CREATE TRIGGER IF NOT EXISTS mark_passkey_prf AFTER INSERT ON scope_wraps BEGIN INSERT OR IGNORE INTO passkey_prf(passkey,since) VALUES(NEW.passkey,NEW.created); END;
INSERT OR IGNORE INTO passkey_prf(passkey,since) SELECT passkey,min(created) FROM scope_wraps GROUP BY passkey;
CREATE VIEW IF NOT EXISTS scope_openers AS SELECT passkey,scope,tested_at FROM scope_wraps UNION ALL SELECT k.passkey,w.scope,w.tested_at FROM browser_wraps w JOIN browser_keys k ON k.id=w.browser_key;
CREATE TABLE IF NOT EXISTS notice_channel(singleton INTEGER PRIMARY KEY CHECK(singleton=1),topic_url TEXT NOT NULL) STRICT;
CREATE TRIGGER IF NOT EXISTS keep_one_scope_passkey BEFORE DELETE ON passkeys WHEN EXISTS(` + orphanedWhere + `) BEGIN SELECT RAISE(ABORT,'last passkey that can open buckets'); END;`

// orphanedWhere selects the scopes this passkey (OLD.id) has a wrap of while no
// other passkey has a tested one: removing it would leave only the recovery key.
// The trigger and OrphanedScopes share it, so both are per scope and count only
// tested wraps (docs/BUCKETS.md §7).
// scope_openers lists both kinds of wrap (PRF and remembered browser).
const orphanedWhere = `SELECT DISTINCT w.scope FROM scope_openers w WHERE w.passkey=OLD.id AND NOT EXISTS(SELECT 1 FROM scope_openers x WHERE x.scope=w.scope AND x.passkey!=w.passkey AND x.tested_at IS NOT NULL)`

// BucketTriggers recreates the guard triggers of a format-2 store at boot, so
// a store made by an earlier build of schema 9 gets the current guard.
const BucketTriggers = `DROP TRIGGER IF EXISTS keep_one_scope_passkey;DROP TRIGGER IF EXISTS mark_passkey_prf;`

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
 CASE b.kind WHEN 'ssh-ca' THEN 'SSH user CA' WHEN 'internal-ca' THEN 'Internal agent CA' WHEN s.archived AND s.slug LIKE 'zz-deleted-%' THEN '(deleted) '||o.slug||'/'||v.slug||'/'||substr(s.slug,45) ELSE coalesce(o.slug||'/'||v.slug||'/'||s.slug,'(deleted set '||b.ref||')') END,
 coalesce(o.title,''),coalesce(o.id,''),coalesce(v.id,'')
 FROM buckets b LEFT JOIN credential_sets s ON s.id=b.ref AND b.kind NOT IN ('ssh-ca','internal-ca') LEFT JOIN services v ON v.id=s.service_id LEFT JOIN organisations o ON o.id=v.org_id`

// The label of a bucket whose set is in the Vault's bin (vault.go TombstoneSlug:
// "zz-deleted-" + the 32-character ID + "-" + the start of the slug) reads
// "(deleted) org/service/slug" until the set is restored or purged.
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

// ErrTestedWrap: a passkey's tested wrap of a scope is never replaced by an
// untested one (a page-supplied KEK could make it unopenable).
var ErrTestedWrap = errors.New("this passkey already opens that scope (tested)")

// PutScopeWrap inserts one passkey's wrap of a scope key (untested), or
// replaces an untested one. A tested wrap is kept and ErrTestedWrap returned.
func (q *Q) PutScopeWrap(ctx context.Context, o ScopeWrapRow) error {
	res, err := q.q.ExecContext(ctx, `INSERT INTO scope_wraps(passkey,scope,salt,wrap,created) VALUES(?,?,?,?,?) ON CONFLICT(passkey,scope) DO UPDATE SET salt=excluded.salt,wrap=excluded.wrap,created=excluded.created,tested_at=NULL WHERE scope_wraps.tested_at IS NULL`, o.Passkey, o.Scope, o.Salt, o.Wrap, ms(o.Created))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrTestedWrap
	}
	return nil
}

// RekeyScopeWrap replaces the rekeying passkey's wrap with its wrap of the new
// scope key under a fresh salt (untested until it opens once). Only rekey calls
// it: the old wrap holds a scope key that no longer exists.
func (q *Q) RekeyScopeWrap(ctx context.Context, o ScopeWrapRow) error {
	return one(q.q.ExecContext(ctx, `UPDATE scope_wraps SET salt=?,wrap=?,created=?,tested_at=NULL WHERE passkey=? AND scope=?`, o.Salt, o.Wrap, ms(o.Created), o.Passkey, o.Scope))
}

// ScopeTested reports whether any passkey has a tested wrap of the scope
// (of either kind: PRF or remembered browser).
func (q *Q) ScopeTested(ctx context.Context, scope string) (bool, error) {
	var ok bool
	err := q.q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scope_openers WHERE scope=? AND tested_at IS NOT NULL)`, scope).Scan(&ok)
	return ok, err
}
func (q *Q) MarkScopeWrapTested(ctx context.Context, id int64, now time.Time) error {
	_, err := q.q.ExecContext(ctx, `UPDATE scope_wraps SET tested_at=? WHERE id=? AND tested_at IS NULL`, ms(now), id)
	return err
}

// DeleteScopeWraps removes PRF wraps of a scope except one passkey's (rekey).
func (q *Q) DeleteScopeWraps(ctx context.Context, scope string, keep int64) error {
	_, err := q.q.ExecContext(ctx, `DELETE FROM scope_wraps WHERE scope=? AND passkey!=?`, scope, keep)
	return err
}

// ---- remembered browsers (§13) ----

// BrowserKeyRow is the public half of one browser profile's key, registered
// for exactly one passkey.
type BrowserKeyRow struct {
	ID       int64
	Passkey  int64
	RawID    []byte
	Public   []byte
	Label    string
	Created  time.Time
	LastUsed *time.Time
}

// BrowserWrapRow is one remembered browser's wrap of a scope key: the scope
// scalar under a KEK (Wrap) and that KEK sealed to the browser key (SealedKEK).
// Both are ciphertext the broker cannot open.
type BrowserWrapRow struct {
	ID        []byte // 32 random bytes, bound into both ciphertexts
	Key       int64
	Passkey   int64
	RawID     []byte
	Public    []byte
	Scope     string
	Wrap      []byte
	SealedKEK []byte
	Created   time.Time
	Tested    *time.Time
}

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

const browserKeyCols = `k.id,k.passkey,p.credential_id,k.public_key,k.label,k.created,k.last_used FROM browser_keys k JOIN passkeys p ON p.id=k.passkey`

func scanBrowserKey(sc interface{ Scan(...any) error }) (BrowserKeyRow, error) {
	var o BrowserKeyRow
	var created int64
	var used sql.NullInt64
	err := sc.Scan(&o.ID, &o.Passkey, &o.RawID, &o.Public, &o.Label, &created, &used)
	o.Created, o.LastUsed = fromMS(created), nullTime(used)
	return o, err
}

// BrowserKeys lists remembered browsers, optionally of one passkey (0: all).
func (q *Q) BrowserKeys(ctx context.Context, passkey int64) ([]BrowserKeyRow, error) {
	var out []BrowserKeyRow
	err := q.rows(ctx, `SELECT `+browserKeyCols+` WHERE ?1=0 OR k.passkey=?1 ORDER BY k.passkey,k.created,k.id`, func(r *sql.Rows) error {
		o, err := scanBrowserKey(r)
		out = append(out, o)
		return err
	}, passkey)
	return out, err
}

// BrowserKey is one passkey's remembered browser with this public key.
func (q *Q) BrowserKey(ctx context.Context, passkey int64, public []byte) (BrowserKeyRow, error) {
	o, err := scanBrowserKey(q.q.QueryRowContext(ctx, `SELECT `+browserKeyCols+` WHERE k.passkey=? AND k.public_key=?`, passkey, public))
	return o, notFound(err)
}

// PutBrowserKey registers a browser key for a passkey, or returns the row it
// already has, with the label of this (signed) action.
func (q *Q) PutBrowserKey(ctx context.Context, o BrowserKeyRow) (int64, error) {
	if _, err := q.q.ExecContext(ctx, `INSERT INTO browser_keys(passkey,public_key,label,created) VALUES(?,?,?,?) ON CONFLICT(passkey,public_key) DO UPDATE SET label=excluded.label`, o.Passkey, o.Public, o.Label, ms(o.Created)); err != nil {
		return 0, err
	}
	var id int64
	err := q.q.QueryRowContext(ctx, `SELECT id FROM browser_keys WHERE passkey=? AND public_key=?`, o.Passkey, o.Public).Scan(&id)
	return id, err
}

// PasskeyHadPRF reports the sticky mark: the passkey has, or once had, a PRF wrap.
func (q *Q) PasskeyHadPRF(ctx context.Context, passkey int64) (bool, error) {
	var ok bool
	err := q.q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM passkey_prf WHERE passkey=?)`, passkey).Scan(&ok)
	return ok, err
}

// PasskeysWithPRF lists the passkeys carrying the sticky mark.
func (q *Q) PasskeysWithPRF(ctx context.Context) (map[int64]bool, error) {
	out := map[int64]bool{}
	err := q.rows(ctx, `SELECT passkey FROM passkey_prf`, func(r *sql.Rows) error {
		var p int64
		err := r.Scan(&p)
		out[p] = true
		return err
	})
	return out, err
}

// DeleteBrowserKey forgets a remembered browser; its wraps go with it (cascade).
func (q *Q) DeleteBrowserKey(ctx context.Context, id int64) error {
	return one(q.q.ExecContext(ctx, `DELETE FROM browser_keys WHERE id=?`, id))
}

// TouchBrowserKey records that a remembered browser opened something.
func (q *Q) TouchBrowserKey(ctx context.Context, id int64, now time.Time) error {
	_, err := q.q.ExecContext(ctx, `UPDATE browser_keys SET last_used=? WHERE id=?`, ms(now), id)
	return err
}

const browserWrapCols = `w.id,w.browser_key,k.passkey,p.credential_id,k.public_key,w.scope,w.wrap,w.sealed_kek,w.created,w.tested_at FROM browser_wraps w JOIN browser_keys k ON k.id=w.browser_key JOIN passkeys p ON p.id=k.passkey`

func scanBrowserWrap(sc interface{ Scan(...any) error }) (BrowserWrapRow, error) {
	var o BrowserWrapRow
	var created int64
	var tested sql.NullInt64
	err := sc.Scan(&o.ID, &o.Key, &o.Passkey, &o.RawID, &o.Public, &o.Scope, &o.Wrap, &o.SealedKEK, &created, &tested)
	o.Created, o.Tested = fromMS(created), nullTime(tested)
	return o, err
}

// BrowserWraps lists remembered-browser wraps, optionally of one browser key (0: all).
func (q *Q) BrowserWraps(ctx context.Context, key int64) ([]BrowserWrapRow, error) {
	var out []BrowserWrapRow
	err := q.rows(ctx, `SELECT `+browserWrapCols+` WHERE ?1=0 OR w.browser_key=?1 ORDER BY k.passkey,w.browser_key,w.scope!='installation',w.scope`, func(r *sql.Rows) error {
		o, err := scanBrowserWrap(r)
		out = append(out, o)
		return err
	}, key)
	return out, err
}
func (q *Q) BrowserWrap(ctx context.Context, key int64, scope string) (BrowserWrapRow, error) {
	o, err := scanBrowserWrap(q.q.QueryRowContext(ctx, `SELECT `+browserWrapCols+` WHERE w.browser_key=? AND w.scope=?`, key, scope))
	return o, notFound(err)
}

// PutBrowserWrap inserts a remembered browser's wrap of a scope key (untested),
// or replaces an untested one. A tested wrap is kept and ErrTestedWrap returned.
func (q *Q) PutBrowserWrap(ctx context.Context, o BrowserWrapRow) error {
	res, err := q.q.ExecContext(ctx, `INSERT INTO browser_wraps(id,browser_key,scope,wrap,sealed_kek,created) VALUES(?,?,?,?,?,?) ON CONFLICT(browser_key,scope) DO UPDATE SET id=excluded.id,wrap=excluded.wrap,sealed_kek=excluded.sealed_kek,created=excluded.created,tested_at=NULL WHERE browser_wraps.tested_at IS NULL`, o.ID, o.Key, o.Scope, o.Wrap, o.SealedKEK, ms(o.Created))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrTestedWrap
	}
	return nil
}

// RekeyBrowserWrap replaces the rekeying browser's wrap with its wrap of the
// new scope key under a fresh KEK (untested until it opens once).
func (q *Q) RekeyBrowserWrap(ctx context.Context, o BrowserWrapRow) error {
	return one(q.q.ExecContext(ctx, `UPDATE browser_wraps SET id=?,wrap=?,sealed_kek=?,created=?,tested_at=NULL WHERE browser_key=? AND scope=?`, o.ID, o.Wrap, o.SealedKEK, ms(o.Created), o.Key, o.Scope))
}
func (q *Q) MarkBrowserWrapTested(ctx context.Context, id []byte, now time.Time) error {
	_, err := q.q.ExecContext(ctx, `UPDATE browser_wraps SET tested_at=? WHERE id=? AND tested_at IS NULL`, ms(now), id)
	return err
}

// DeleteBrowserWraps removes remembered-browser wraps of a scope except one
// browser key's (rekey; 0 keeps none).
func (q *Q) DeleteBrowserWraps(ctx context.Context, scope string, keep int64) error {
	_, err := q.q.ExecContext(ctx, `DELETE FROM browser_wraps WHERE scope=? AND browser_key!=?`, scope, keep)
	return err
}

// BrowserOrphanedScopes lists the scopes this remembered browser has a wrap of
// while nothing else has a tested one (no PRF wrap, no other browser's wrap):
// forgetting it would leave only the recovery key.
func (q *Q) BrowserOrphanedScopes(ctx context.Context, key int64) ([]string, error) {
	var out []string
	err := q.rows(ctx, `SELECT w.scope FROM browser_wraps w WHERE w.browser_key=?1 AND NOT EXISTS(SELECT 1 FROM scope_wraps x WHERE x.scope=w.scope AND x.tested_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM browser_wraps y WHERE y.scope=w.scope AND y.browser_key!=w.browser_key AND y.tested_at IS NOT NULL) ORDER BY 1`, func(r *sql.Rows) error {
		var s string
		err := r.Scan(&s)
		out = append(out, s)
		return err
	}, key)
	return out, err
}

// ScopeCoverage counts, per passkey, the buckets in scopes it can open.
func (q *Q) ScopeCoverage(ctx context.Context) (map[int64]int, error) {
	out := map[int64]int{}
	err := q.rows(ctx, `SELECT w.passkey,count(b.id) FROM (SELECT DISTINCT passkey,scope FROM scope_openers) w LEFT JOIN buckets b ON b.scope=w.scope GROUP BY w.passkey`, func(r *sql.Rows) error {
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

// CFProxySet is the personal organisation's Cloudflare proxy set (the ref of its cf-proxy bucket).
func (q *Q) CFProxySet(ctx context.Context) (string, error) {
	var id string
	err := q.q.QueryRowContext(ctx, `SELECT t.id FROM personal_cutover c JOIN services v ON v.org_id=c.org_id JOIN credential_sets t ON t.service_id=v.id WHERE t.kind='cloudflare-proxy' AND v.slug='dns-cdn'`).Scan(&id)
	return id, notFound(err)
}

// UpdateBucket replaces a bucket's key pair, wrap and record (rekey).
func (q *Q) UpdateBucket(ctx context.Context, id, public, wrap, payload []byte) error {
	return one(q.q.ExecContext(ctx, `UPDATE buckets SET public_key=?,wrap=?,payload=? WHERE id=?`, public, wrap, payload, id))
}

// ReplaceScope replaces a scope's key pair and recovery wrap (rekey).
func (q *Q) ReplaceScope(ctx context.Context, x ScopeRow) error {
	return one(q.q.ExecContext(ctx, `UPDATE bucket_scopes SET public_key=?,recovery=? WHERE scope=?`, x.Public, x.Recovery, x.Scope))
}

// ScopeBuckets lists the buckets of one scope.
func (q *Q) ScopeBuckets(ctx context.Context, scope string) ([]BucketRow, error) {
	var out []BucketRow
	err := q.rows(ctx, `SELECT `+bucketCols+` WHERE b.scope=? ORDER BY b.id`, func(r *sql.Rows) error {
		b, err := scanBucket(r)
		out = append(out, b)
		return err
	}, scope)
	return out, err
}

// RekeyEnv re-encrypts the current revision of a set (older revisions hold no values).
func (q *Q) RekeyEnv(ctx context.Context, set string, revision int, payload, wrap []byte) error {
	return one(q.q.ExecContext(ctx, `UPDATE env_revisions SET payload=?,wrap=? WHERE set_id=? AND revision=? AND wrap IS NOT NULL`, payload, wrap, set, revision))
}

// RekeySigner re-encrypts a signer key record.
func (q *Q) RekeySigner(ctx context.Context, set string, payload, wrap []byte) error {
	return one(q.q.ExecContext(ctx, `UPDATE signer_keys SET payload=?,wrap=? WHERE set_id=?`, payload, wrap, set))
}

// DropScopeDrafts deletes every env draft of the sets in a scope (rekey).
func (q *Q) DropScopeDrafts(ctx context.Context, scope string) error {
	_, err := q.q.ExecContext(ctx, `DELETE FROM env_drafts WHERE set_id IN (SELECT ref FROM buckets WHERE scope=? AND kind='env-set') OR wrap IN (SELECT id FROM buckets WHERE scope=?)`, scope, scope)
	return err
}

// DeletePasskeyScopeWraps removes one passkey's wraps of these scopes, or all (disable).
func (q *Q) DeletePasskeyScopeWraps(ctx context.Context, passkey int64, scopes []string) error {
	if len(scopes) == 0 {
		_, err := q.q.ExecContext(ctx, `DELETE FROM scope_wraps WHERE passkey=?`, passkey)
		return err
	}
	for _, sc := range scopes {
		if _, err := q.q.ExecContext(ctx, `DELETE FROM scope_wraps WHERE passkey=? AND scope=?`, passkey, sc); err != nil {
			return err
		}
	}
	return nil
}

// OrphanedScopes lists the scopes this passkey has a wrap of while no other
// passkey has a tested wrap (the same rule as trigger keep_one_scope_passkey).
func (q *Q) OrphanedScopes(ctx context.Context, passkey int64) ([]string, error) {
	var out []string
	err := q.rows(ctx, `SELECT * FROM (`+strings.Replace(orphanedWhere, "OLD.id", "?1", 1)+`) ORDER BY 1`, func(r *sql.Rows) error {
		var s string
		err := r.Scan(&s)
		out = append(out, s)
		return err
	}, passkey)
	return out, err
}

// CheckpointWAL truncates the WAL after removals so freed pages do not keep old wraps (§7).
func (s *Store) CheckpointWAL(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// SetRevision is a credential set's current revision (archived or not).
func (q *Q) SetRevision(ctx context.Context, set string) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT revision FROM credential_sets WHERE id=?`, set).Scan(&n)
	return n, notFound(err)
}

// SignerKey is a signer's public description and sealed record (archived or not).
func (q *Q) SignerKey(ctx context.Context, set string) (scheme string, public []byte, rec CipherRecord, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT scheme,public_key,blob,payload,wrap FROM signer_keys WHERE set_id=?`, set).Scan(&scheme, &public, &rec.Blob, &rec.Payload, &rec.Wrap)
	return scheme, public, rec, notFound(err)
}

// Raw is the underlying querier (the activation transaction's own statements).
func (q *Q) Raw() querier { return q.q }

// AutoScopes lists the scopes of a set whose current policy (its organisation's
// revision) turns auto-approval on; empty when the set, service or organisation
// is archived. The "auto" hold of a cf-proxy bucket lives only while it is not empty.
func (q *Q) AutoScopes(ctx context.Context, set string) ([]string, error) {
	var out []string
	err := q.rows(ctx, `SELECT p.scope FROM set_policies p JOIN credential_sets s ON s.id=p.set_id JOIN services v ON v.id=s.service_id JOIN organisations o ON o.id=v.org_id WHERE p.set_id=? AND NOT s.archived AND NOT v.archived AND NOT o.archived AND p.revision=(SELECT max(revision) FROM set_policies WHERE set_id=p.set_id AND scope=p.scope AND revision<=o.revision) AND p.auto ORDER BY p.scope`, func(r *sql.Rows) error {
		var sc string
		err := r.Scan(&sc)
		out = append(out, sc)
		return err
	}, set)
	return out, err
}
