package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// Vault tables are additive and created on a sealed start, like the env
// tables: a previous binary ignores them. A signer set is a credential_sets
// row (the shipped CHECK admits only 'env-set' for application services) at
// revision 0 with a signer_keys row. A previous binary therefore sees an
// empty env set: nothing to request, deliver or check in its recovery
// inventory. This binary refuses env use of any set that has a signer row.
// A secret (0.10.0) is the same trick with a secret_sets row: an env set that
// holds exactly one key, the secret's environment variable name. A previous
// binary sees a one-key env set, which `aqmas run` delivers just the same.
// An SSH key (0.11.0) is a signer whose scheme is one of the SSH ones, with an
// ssh_keys row for its comment and its "may be handed out" switch. A previous
// binary sees a signer with a scheme it does not know and signs nothing with it.
// A deleted item (0.11.0) stays a credential_sets row, archived and under a
// tombstone slug so its path is free, with a deleted_sets row that keeps the
// original slug until it is restored or purged. Every query that resolves a
// path or lists sets already skips archived rows, in this binary and in
// earlier ones.
// No statement here takes a value, a private key or a DEK: only public
// metadata and sealed records.
func (s *Store) InitVault(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS signer_keys(set_id TEXT PRIMARY KEY REFERENCES credential_sets(id),scheme TEXT NOT NULL,public_key BLOB NOT NULL,origin TEXT NOT NULL CHECK(origin IN ('generated','imported')),created INTEGER NOT NULL,signatures INTEGER NOT NULL DEFAULT 0,blob BLOB NOT NULL UNIQUE,payload BLOB,wrap BLOB) STRICT;
CREATE TABLE IF NOT EXISTS secret_sets(set_id TEXT PRIMARY KEY REFERENCES credential_sets(id),note TEXT NOT NULL,url TEXT NOT NULL,created INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS org_vault(org_id TEXT PRIMARY KEY REFERENCES organisations(id),allow_reveal INTEGER NOT NULL CHECK(allow_reveal IN (0,1))) STRICT;
CREATE TABLE IF NOT EXISTS sign_requests(id TEXT PRIMARY KEY,grant_id TEXT UNIQUE,host INTEGER NOT NULL REFERENCES hosts(id),set_id TEXT NOT NULL REFERENCES credential_sets(id),binding TEXT NOT NULL,items TEXT NOT NULL,peer TEXT NOT NULL,reason TEXT NOT NULL,ttl INTEGER NOT NULL CHECK(ttl>=0),max INTEGER NOT NULL CHECK(max>0),deadline INTEGER NOT NULL,until_ms INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL CHECK(status IN ('pending','approved','used','expired','cancelled','denied','revoked')),used INTEGER NOT NULL DEFAULT 0 CHECK(used>=0 AND used<=max)) STRICT;
CREATE INDEX IF NOT EXISTS sign_by_host_status ON sign_requests(host,status);
CREATE TRIGGER IF NOT EXISTS sign_end_admission AFTER UPDATE ON org_hosts BEGIN UPDATE sign_requests SET status=CASE status WHEN 'pending' THEN 'expired' ELSE 'revoked' END WHERE status IN ('approved','pending') AND host=NEW.host_id AND set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.org_id);END;
CREATE TRIGGER IF NOT EXISTS sign_end_policy AFTER UPDATE ON organisations BEGIN UPDATE sign_requests SET status=CASE status WHEN 'pending' THEN 'expired' ELSE 'revoked' END WHERE status IN ('approved','pending') AND set_id IN(SELECT s.id FROM credential_sets s JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.id);END;
CREATE TRIGGER IF NOT EXISTS sign_end_set AFTER UPDATE ON credential_sets BEGIN UPDATE sign_requests SET status=CASE status WHEN 'pending' THEN 'expired' ELSE 'revoked' END WHERE status IN ('approved','pending') AND set_id=NEW.id;END;
CREATE TRIGGER IF NOT EXISTS signer_key_immutable BEFORE UPDATE OF set_id,scheme,public_key,origin,blob ON signer_keys BEGIN SELECT RAISE(ABORT,'immutable signer key'); END;
CREATE TABLE IF NOT EXISTS ssh_keys(set_id TEXT PRIMARY KEY REFERENCES credential_sets(id),comment TEXT NOT NULL,handout INTEGER NOT NULL CHECK(handout IN (0,1)),created INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS deleted_sets(set_id TEXT PRIMARY KEY REFERENCES credential_sets(id),slug TEXT NOT NULL,kind TEXT NOT NULL,deleted_at INTEGER NOT NULL,purge_at INTEGER NOT NULL,passkey INTEGER NOT NULL,deleted_by TEXT NOT NULL,digest TEXT NOT NULL) STRICT;`)
	if err != nil {
		return err
	}
	// 0.11.0: what an SSH key's request is for ('ssh-agent' or 'ssh-handout');
	// NULL is ordinary signing, which is all an earlier binary ever wrote.
	var has int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('sign_requests') WHERE name='use'`).Scan(&has); err != nil {
		return err
	}
	if has == 0 {
		_, err = s.db.ExecContext(ctx, `ALTER TABLE sign_requests ADD COLUMN use TEXT CHECK(use IS NULL OR use IN ('ssh-agent','ssh-handout'))`)
	}
	return err
}

// VaultTarget is the owner's view of one application set. Its JSON names are
// the signed metadata fields (docs/API.md "Vault").
type VaultTarget struct {
	OrgID           string   `json:"org_id"`
	OrgSlug         string   `json:"org_slug"`
	OrgTitle        string   `json:"org_title"`
	ServiceID       string   `json:"service_id"`
	ServiceSlug     string   `json:"service_slug"`
	ServiceTitle    string   `json:"service_title"`
	SetID           string   `json:"set_id"`
	SetSlug         string   `json:"set_slug"`
	SetTitle        string   `json:"set_title"`
	Kind            string   `json:"kind"`
	Revision        int      `json:"revision"`
	ServiceRevision int      `json:"-"`
	PolicyRevision  int      `json:"-"`
	Names           []string `json:"names"`
	AllowReveal     bool     `json:"allow_reveal"`
	Scheme          string   `json:"scheme,omitempty"`
	PublicKey       []byte   `json:"-"`
	Origin          string   `json:"origin,omitempty"`
	Created         int64    `json:"created_at,omitempty"`
	Signatures      int      `json:"signatures"`
	// A secret's optional note and URL (public metadata, signed at creation).
	Note string `json:"note,omitempty"`
	URL  string `json:"url,omitempty"`
	// StandingCap is the set's "longest don't-ask-again" in seconds (0: off).
	StandingCap int `json:"standing_cap_seconds"`
	// An SSH key's comment and whether its private key may be handed out.
	Comment string `json:"comment,omitempty"`
	Handout bool   `json:"handout,omitempty"`
}

// Path is the item's organisation/service/set path.
func (t VaultTarget) Path() string { return t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug }

// vaultCols selects one application set. A binned set is read with the slug it
// had (deleted_sets keeps it; the row itself carries a tombstone slug).
const vaultCols = `o.id,o.slug,o.title,v.id,v.slug,v.title,s.id,coalesce(d.slug,s.slug),s.title,s.revision,v.revision,o.revision,coalesce(r.names,'[]'),coalesce((SELECT allow_reveal FROM org_vault x WHERE x.org_id=o.id),1),coalesce(k.scheme,''),k.public_key,coalesce(k.origin,''),coalesce(k.created,0),coalesce(k.signatures,0),z.set_id IS NOT NULL,coalesce(z.note,''),coalesce(z.url,''),coalesce((SELECT cap_seconds FROM set_standing c WHERE c.set_id=s.id),3600),y.set_id IS NOT NULL,coalesce(y.comment,''),coalesce(y.handout,0) FROM organisations o JOIN services v ON v.org_id=o.id JOIN credential_sets s ON s.service_id=v.id LEFT JOIN signer_keys k ON k.set_id=s.id LEFT JOIN secret_sets z ON z.set_id=s.id LEFT JOIN ssh_keys y ON y.set_id=s.id LEFT JOIN deleted_sets d ON d.set_id=s.id LEFT JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision AND r.wrap IS NOT NULL WHERE NOT o.archived AND NOT v.archived AND v.provider='application' AND s.kind='env-set'`

// vaultLive and vaultBinned complete vaultCols: the sets in use, and the bin.
const (
	vaultLive   = vaultCols + ` AND NOT s.archived`
	vaultBinned = vaultCols + ` AND s.archived AND d.set_id IS NOT NULL`
)

func scanVault(row interface{ Scan(...any) error }) (t VaultTarget, err error) {
	var names string
	var secret, sshKey bool
	if err = row.Scan(&t.OrgID, &t.OrgSlug, &t.OrgTitle, &t.ServiceID, &t.ServiceSlug, &t.ServiceTitle, &t.SetID, &t.SetSlug, &t.SetTitle, &t.Revision, &t.ServiceRevision, &t.PolicyRevision, &names, &t.AllowReveal, &t.Scheme, &t.PublicKey, &t.Origin, &t.Created, &t.Signatures, &secret, &t.Note, &t.URL, &t.StandingCap, &sshKey, &t.Comment, &t.Handout); err != nil {
		return t, err
	}
	t.Kind = "env-set"
	if t.Scheme != "" {
		t.Kind, t.StandingCap = "signer", 0
		if sshKey {
			t.Kind = "ssh-key"
		}
	} else if secret {
		t.Kind = "secret"
	}
	return t, json.Unmarshal([]byte(names), &t.Names)
}
func (q *Q) VaultSets(ctx context.Context) ([]VaultTarget, error) {
	out := []VaultTarget{}
	err := q.rows(ctx, `SELECT `+vaultLive+` ORDER BY o.slug,v.slug,s.slug`, func(rs *sql.Rows) error {
		t, err := scanVault(rs)
		out = append(out, t)
		return err
	})
	return out, err
}
func (q *Q) VaultSet(ctx context.Context, set string) (VaultTarget, error) {
	t, err := scanVault(q.q.QueryRowContext(ctx, `SELECT `+vaultLive+` AND s.id=?`, set))
	return t, notFound(err)
}

// SignerSets names the sets the catalogue must show as kind "signer".
func (q *Q) SignerSets(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	err := q.rows(ctx, `SELECT set_id FROM signer_keys`, func(rs *sql.Rows) error {
		var id string
		err := rs.Scan(&id)
		out[id] = true
		return err
	})
	return out, err
}

// SecretSets names the sets the catalogue must show as kind "secret".
func (q *Q) SecretSets(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	err := q.rows(ctx, `SELECT set_id FROM secret_sets`, func(rs *sql.Rows) error {
		var id string
		err := rs.Scan(&id)
		out[id] = true
		return err
	})
	return out, err
}

// IsSecret reports whether a set is a single-value secret.
func (q *Q) IsSecret(ctx context.Context, set string) (bool, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM secret_sets WHERE set_id=?`, set).Scan(&n)
	return n > 0, err
}

// CreateSecret inserts a secret's set row and its marker; the caller writes
// revision 1 (the one sealed value) in the same transaction.
func (q *Q) CreateSecret(ctx context.Context, t VaultTarget, now time.Time) error {
	if err := one(q.q.ExecContext(ctx, `INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES(?,?,'application',?,?,'env-set',0)`, t.SetID, t.ServiceID, t.SetSlug, t.SetTitle)); err != nil {
		return err
	}
	return q.MarkSecret(ctx, t.SetID, t.Note, t.URL, now)
}

// MarkSecret turns an existing one-key env set into a secret.
func (q *Q) MarkSecret(ctx context.Context, set, note, url string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO secret_sets(set_id,note,url,created) SELECT s.id,?,?,? FROM credential_sets s WHERE s.id=? AND s.kind='env-set' AND s.provider='application' AND NOT EXISTS(SELECT 1 FROM signer_keys k WHERE k.set_id=s.id)`, note, url, ms(now), set))
}

type VaultOrg struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	AllowReveal bool   `json:"allow_reveal"`
}

func (q *Q) VaultOrgs(ctx context.Context) ([]VaultOrg, error) {
	out := []VaultOrg{}
	err := q.rows(ctx, `SELECT o.id,o.slug,o.title,coalesce((SELECT allow_reveal FROM org_vault x WHERE x.org_id=o.id),1) FROM organisations o WHERE NOT o.archived ORDER BY o.slug`, func(rs *sql.Rows) error {
		var o VaultOrg
		err := rs.Scan(&o.ID, &o.Slug, &o.Title, &o.AllowReveal)
		out = append(out, o)
		return err
	})
	return out, err
}
func (q *Q) VaultOrg(ctx context.Context, id string) (o VaultOrg, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT o.id,o.slug,o.title,coalesce((SELECT allow_reveal FROM org_vault x WHERE x.org_id=o.id),1) FROM organisations o WHERE NOT o.archived AND o.id=?`, id).Scan(&o.ID, &o.Slug, &o.Title, &o.AllowReveal)
	return o, notFound(err)
}
func (q *Q) SetOrgVault(ctx context.Context, org string, reveal bool) error {
	return one(q.q.ExecContext(ctx, `INSERT INTO org_vault(org_id,allow_reveal) VALUES(?,?) ON CONFLICT(org_id) DO UPDATE SET allow_reveal=excluded.allow_reveal`, org, reveal))
}

// VaultService resolves the parent of a new signer set.
func (q *Q) VaultService(ctx context.Context, service string) (t VaultTarget, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT o.id,o.slug,o.title,v.id,v.slug,v.title,v.revision,o.revision FROM organisations o JOIN services v ON v.org_id=o.id WHERE NOT o.archived AND NOT v.archived AND v.provider='application' AND v.id=?`, service).Scan(&t.OrgID, &t.OrgSlug, &t.OrgTitle, &t.ServiceID, &t.ServiceSlug, &t.ServiceTitle, &t.ServiceRevision, &t.PolicyRevision)
	return t, notFound(err)
}
func (q *Q) SetSlugFree(ctx context.Context, service, id, slug string) (bool, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM credential_sets WHERE id=? OR (service_id=? AND slug=?)`, id, service, slug).Scan(&n)
	return n == 0, err
}
func (q *Q) CreateSigner(ctx context.Context, t VaultTarget, r CipherRecord, now time.Time) error {
	if err := one(q.q.ExecContext(ctx, `INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES(?,?,'application',?,?,'env-set',0)`, t.SetID, t.ServiceID, t.SetSlug, t.SetTitle)); err != nil {
		return err
	}
	return one(q.q.ExecContext(ctx, `INSERT INTO signer_keys(set_id,scheme,public_key,origin,created,blob,payload,wrap) VALUES(?,?,?,?,?,?,?,?)`, t.SetID, t.Scheme, t.PublicKey, t.Origin, ms(now), r.Blob, r.Payload, r.Wrap))
}
func (q *Q) SignerCipher(ctx context.Context, set string) (rec CipherRecord, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT blob,payload,wrap FROM signer_keys WHERE set_id=? AND wrap IS NOT NULL`, set).Scan(&rec.Blob, &rec.Payload, &rec.Wrap)
	return rec, notFound(err)
}

// SSHKeySets names the sets the catalogue must show as kind "ssh-key".
func (q *Q) SSHKeySets(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	err := q.rows(ctx, `SELECT set_id FROM ssh_keys`, func(rs *sql.Rows) error {
		var id string
		err := rs.Scan(&id)
		out[id] = true
		return err
	})
	return out, err
}

// CreateSSHKey inserts an SSH key: a signer row and its marker.
func (q *Q) CreateSSHKey(ctx context.Context, t VaultTarget, r CipherRecord, now time.Time) error {
	if err := q.CreateSigner(ctx, t, r, now); err != nil {
		return err
	}
	return one(q.q.ExecContext(ctx, `INSERT INTO ssh_keys(set_id,comment,handout,created) VALUES(?,?,?,?)`, t.SetID, t.Comment, t.Handout, ms(now)))
}

// SSHKeyMeta is an SSH key's comment and hand-out switch; ok is false for a
// set that is not an SSH key.
func (q *Q) SSHKeyMeta(ctx context.Context, set string) (comment string, handout, ok bool, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT comment,handout FROM ssh_keys WHERE set_id=?`, set).Scan(&comment, &handout)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, false, nil
	}
	return comment, handout, err == nil, err
}

// SetSSHHandout changes whether the key may be handed out. Turning it off
// also ends hand-out requests that are waiting or approved but not collected.
func (q *Q) SetSSHHandout(ctx context.Context, set string, handout bool) error {
	if err := one(q.q.ExecContext(ctx, `UPDATE ssh_keys SET handout=? WHERE set_id=? AND handout!=?`, handout, set, handout)); err != nil {
		return err
	}
	if handout {
		return nil
	}
	_, err := q.q.ExecContext(ctx, `UPDATE sign_requests SET status=CASE status WHEN 'pending' THEN 'expired' ELSE 'revoked' END WHERE status IN ('approved','pending') AND set_id=? AND use='ssh-handout'`, set)
	return err
}

// UseHandout spends a hand-out grant: the private key is delivered once.
func (q *Q) UseHandout(ctx context.Context, grant string, now time.Time) error {
	return one(q.q.ExecContext(ctx, `UPDATE sign_requests SET used=1,status='used' WHERE grant_id=? AND status='approved' AND used=0 AND use='ssh-handout' AND until_ms>?`, grant, ms(now)))
}

// ---- the bin (deleted items) ----

// BinTTL is how long a deleted item can be restored before it is purged.
const BinTTL = 7 * 24 * time.Hour

// DeletedSet is one item in the bin: the set as it was, and who deleted it when.
type DeletedSet struct {
	VaultTarget
	DeletedAt int64  `json:"deleted_at"`
	PurgeAt   int64  `json:"purge_at"`
	DeletedBy string `json:"deleted_by"`
	Digest    string `json:"digest"`
	// PathTaken: a live item has the path now, so Restore is refused.
	PathTaken bool `json:"path_taken"`
}

// Ended counts what a delete ended.
type Ended struct {
	Grants   int `json:"grants"`
	Standing int `json:"standing"`
	Releases int `json:"releases"`
	Pending  int `json:"pending"`
}

// TombstoneSlug is the slug a binned set's row carries so that its path is
// free: valid under the slug CHECK, unique by the set's own random ID.
func TombstoneSlug(id, slug string) string {
	return "zz-deleted-" + id[:min(len(id), 12)] + "-" + slug[:min(len(slug), 39)]
}

// BinSet moves a live application set to the bin. The UPDATE fires the
// triggers that end everything that could still use the set: drafts, pending
// requests and approved releases (env_end_revision), signing requests and
// grants (sign_end_set) and don't-ask-again rules (env_standing_end_revision).
// A set whose revision moved since the owner reviewed it is ErrConflict.
func (q *Q) BinSet(ctx context.Context, t VaultTarget, passkey int64, digest string, now time.Time) (Ended, error) {
	var e Ended
	at := ms(now)
	for _, c := range []struct {
		n     *int
		query string
	}{
		{&e.Grants, `SELECT count(*) FROM sign_requests WHERE set_id=?1 AND status='approved' AND until_ms>?2`},
		{&e.Standing, `SELECT count(*) FROM env_standing WHERE set_id=?1 AND revoked_at IS NULL AND expires>?2`},
		{&e.Releases, `SELECT count(*) FROM env_releases WHERE set_id=?1 AND status='approved' AND NOT consumed AND until_ms>?2`},
		{&e.Pending, `SELECT (SELECT count(*) FROM sign_requests WHERE set_id=?1 AND status='pending' AND deadline>?2)+(SELECT count(*) FROM env_releases WHERE set_id=?1 AND status='pending' AND deadline>?2)`},
	} {
		if err := q.q.QueryRowContext(ctx, c.query, t.SetID, at).Scan(c.n); err != nil {
			return e, err
		}
	}
	if err := one(q.q.ExecContext(ctx, `UPDATE credential_sets SET archived=1,slug=? WHERE id=? AND NOT archived AND revision=? AND provider='application'`, TombstoneSlug(t.SetID, t.SetSlug), t.SetID, t.Revision)); err != nil {
		return e, err
	}
	return e, one(q.q.ExecContext(ctx, `INSERT INTO deleted_sets(set_id,slug,kind,deleted_at,purge_at,passkey,deleted_by,digest) VALUES(?1,?2,?3,?4,?5,?6,coalesce((SELECT name FROM passkeys WHERE id=?6),''),?7)`, t.SetID, t.SetSlug, t.Kind, at, ms(now.Add(BinTTL)), passkey, digest))
}

const deletedCols = `,d.deleted_at,d.purge_at,d.deleted_by,d.digest,EXISTS(SELECT 1 FROM credential_sets x WHERE x.service_id=s.service_id AND x.slug=d.slug AND x.id!=s.id)`

func scanDeleted(row interface{ Scan(...any) error }) (DeletedSet, error) {
	var d DeletedSet
	t, err := scanVault(scanTail{row, []any{&d.DeletedAt, &d.PurgeAt, &d.DeletedBy, &d.Digest, &d.PathTaken}})
	d.VaultTarget = t
	return d, err
}

// scanTail lets scanVault read its own columns while the caller's follow.
type scanTail struct {
	row  interface{ Scan(...any) error }
	tail []any
}

func (s scanTail) Scan(dst ...any) error { return s.row.Scan(append(dst, s.tail...)...) }

func deletedQuery(where string) string {
	i := strings.Index(vaultBinned, " FROM organisations")
	return `SELECT ` + vaultBinned[:i] + deletedCols + vaultBinned[i:] + where
}

// DeletedSets lists the bin, soonest purge first.
func (q *Q) DeletedSets(ctx context.Context) ([]DeletedSet, error) {
	out := []DeletedSet{}
	err := q.rows(ctx, deletedQuery(` ORDER BY d.purge_at,s.id`), func(rs *sql.Rows) error {
		d, err := scanDeleted(rs)
		out = append(out, d)
		return err
	})
	return out, err
}
func (q *Q) DeletedSet(ctx context.Context, set string) (DeletedSet, error) {
	d, err := scanDeleted(q.q.QueryRowContext(ctx, deletedQuery(` AND s.id=?`), set))
	return d, notFound(err)
}

// RestoreSet takes a set out of the bin under its original slug. A live set
// with that slug in the service (the UNIQUE constraint) is ErrConflict. The
// UPDATE fires the same triggers as BinSet did; nothing of the set was live.
func (q *Q) RestoreSet(ctx context.Context, set string) error {
	if _, err := q.q.ExecContext(ctx, `UPDATE credential_sets SET archived=0,slug=(SELECT slug FROM deleted_sets WHERE set_id=?1) WHERE id=?1 AND archived AND EXISTS(SELECT 1 FROM deleted_sets WHERE set_id=?1)`, set); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return err
	}
	return one(q.q.ExecContext(ctx, `DELETE FROM deleted_sets WHERE set_id=?`, set))
}

// DuePurges are the binned sets whose seven days are over.
func (q *Q) DuePurges(ctx context.Context, now time.Time) ([]string, error) {
	var ids []string
	err := q.rows(ctx, `SELECT set_id FROM deleted_sets WHERE purge_at<=? ORDER BY purge_at`, func(rs *sql.Rows) error {
		var id string
		err := rs.Scan(&id)
		ids = append(ids, id)
		return err
	}, ms(now))
	return ids, err
}

// PurgeInfo is what the audit log keeps of a purged set: never a value.
type PurgeInfo struct {
	Path, Kind, Digest, DeletedBy string
	DeletedAt                     int64
	Buckets                       [][]byte
}

// PurgeSet destroys a binned set for good: every sealed record of it (all env
// revisions and drafts, the signer or SSH key record), its bucket (the wrap
// of the bucket key to the scope key included) and every row that refers to
// it, then the set row itself. The store runs with secure_delete, so the
// freed pages are overwritten. It needs no open bucket and no key. A set that
// is not in the bin is ErrNotFound.
func (q *Q) PurgeSet(ctx context.Context, set string) (PurgeInfo, error) {
	var p PurgeInfo
	err := q.q.QueryRowContext(ctx, `SELECT coalesce(o.slug,'?')||'/'||coalesce(v.slug,'?')||'/'||d.slug,d.kind,d.digest,d.deleted_by,d.deleted_at FROM deleted_sets d JOIN credential_sets s ON s.id=d.set_id AND s.archived LEFT JOIN services v ON v.id=s.service_id LEFT JOIN organisations o ON o.id=v.org_id WHERE d.set_id=?`, set).Scan(&p.Path, &p.Kind, &p.Digest, &p.DeletedBy, &p.DeletedAt)
	if err != nil {
		return p, notFound(err)
	}
	if err = q.rows(ctx, `SELECT id FROM buckets WHERE ref=? AND kind IN ('env-set','signer')`, func(rs *sql.Rows) error {
		var id []byte
		err := rs.Scan(&id)
		p.Buckets = append(p.Buckets, id)
		return err
	}, set); err != nil {
		return p, err
	}
	for _, stmt := range []string{
		`DELETE FROM env_drafts WHERE set_id=?`,
		`DELETE FROM env_revisions WHERE set_id=?`,
		`DELETE FROM env_releases WHERE set_id=?`,
		`DELETE FROM env_standing WHERE set_id=?`,
		`DELETE FROM set_standing WHERE set_id=?`,
		`DELETE FROM sign_requests WHERE set_id=?`,
		`DELETE FROM signer_keys WHERE set_id=?`,
		`DELETE FROM ssh_keys WHERE set_id=?`,
		`DELETE FROM secret_sets WHERE set_id=?`,
		`DELETE FROM buckets WHERE ref=? AND kind IN ('env-set','signer')`,
		`DELETE FROM deleted_sets WHERE set_id=?`,
	} {
		if _, err = q.q.ExecContext(ctx, stmt, set); err != nil {
			return p, err
		}
	}
	err = one(q.q.ExecContext(ctx, `DELETE FROM credential_sets WHERE id=? AND archived AND provider='application'`, set))
	if err != nil && strings.Contains(err.Error(), "FOREIGN KEY") {
		// A row of a table this function does not know still names the set:
		// the archived, emptied row stays as a tombstone. Nothing sealed is left.
		err = nil
	}
	return p, err
}

// VaultBinding is the host-less binding used to seal a web-form revision.
func (t VaultTarget) Binding() envset.Binding {
	return envset.Binding{Org: t.OrgID, Service: t.ServiceID, Set: t.SetID, Revision: t.Revision, Names: t.Names}
}

func (q *Q) SignBinding(ctx context.Context, host int64, path string, now time.Time) (b signer.Binding, err error) {
	err = q.q.QueryRowContext(ctx, `SELECT o.slug||'/'||v.slug||'/'||s.slug,o.title||' / '||v.title||' / '||s.title,o.id,v.id,s.id,s.revision,v.revision,o.revision,a.generation,h.enrollment_id,h.name,e.class,k.scheme,k.public_key,p.default_seconds,p.soft_cap FROM org_hosts a JOIN hosts h ON h.id=a.host_id JOIN enrollments e ON e.id=h.enrollment_id JOIN organisations o ON o.id=a.org_id JOIN services v ON v.org_id=o.id JOIN credential_sets s ON s.service_id=v.id JOIN signer_keys k ON k.set_id=s.id JOIN org_policies p ON p.org_id=o.id AND p.revision=o.revision WHERE h.id=? AND o.slug||'/'||v.slug||'/'||s.slug=? AND a.active AND NOT o.archived AND NOT s.archived AND NOT v.archived AND v.provider='application' AND h.revoked_at IS NULL AND h.not_after>? AND k.wrap IS NOT NULL`, host, path, ms(now)).Scan(&b.Path, &b.Title, &b.Org, &b.Service, &b.Set, &b.Revision, &b.ServiceRevision, &b.PolicyRevision, &b.Generation, &b.Enrollment, &b.Host, &b.Class, &b.Scheme, &b.PublicKey, &b.Default, &b.Soft)
	return b, notFound(err)
}

// SweepSign expires what is overdue and forgets requests that ended more than
// thirty days ago (the audit log keeps their history).
func (q *Q) SweepSign(ctx context.Context, now time.Time) error {
	if _, err := q.q.ExecContext(ctx, `UPDATE sign_requests SET status='expired' WHERE (status='pending' AND deadline<=?1) OR (status='approved' AND until_ms<=?1)`, ms(now)); err != nil {
		return err
	}
	_, err := q.q.ExecContext(ctx, `DELETE FROM sign_requests WHERE status NOT IN ('pending','approved') AND max(deadline,until_ms)<?`, ms(now.Add(-30*24*time.Hour)))
	return err
}

// SignRecent counts a host's requests whose pending deadline is after t.
func (q *Q) SignRecent(ctx context.Context, host int64, t time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM sign_requests WHERE host=? AND deadline>?`, host, ms(t)).Scan(&n)
	return n, err
}

func (q *Q) NewSignRequest(ctx context.Context, host int64, r signer.Request) error {
	b, err := json.Marshal(r.Binding)
	if err != nil {
		return err
	}
	items, err := json.Marshal(r.Items)
	if err != nil {
		return err
	}
	use := sql.NullString{String: r.Use, Valid: r.Use != ""}
	return one(q.q.ExecContext(ctx, `INSERT INTO sign_requests(id,host,set_id,binding,items,peer,reason,ttl,max,deadline,status,use) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?)`, r.ID, host, r.Set, string(b), string(items), r.Peer, r.Reason, r.TTL, r.Max, r.Deadline, use))
}
func (q *Q) SignRequest(ctx context.Context, id string, grant bool) (r signer.Request, host int64, err error) {
	col := "id"
	if grant {
		col = "grant_id"
	}
	var b, items string
	err = q.q.QueryRowContext(ctx, `SELECT id,coalesce(grant_id,''),host,binding,items,peer,reason,ttl,max,deadline,until_ms,status,used,coalesce(use,'') FROM sign_requests WHERE `+col+`=?`, id).Scan(&r.ID, &r.Grant, &host, &b, &items, &r.Peer, &r.Reason, &r.TTL, &r.Max, &r.Deadline, &r.Until, &r.Status, &r.Used, &r.Use)
	if err == nil {
		err = json.Unmarshal([]byte(b), &r.Binding)
	}
	if err == nil {
		err = json.Unmarshal([]byte(items), &r.Items)
	}
	return r, host, notFound(err)
}

// VisibleSignRequest hides a request from every other host and address, and
// hides a live one whose signed-over binding no longer matches the catalogue.
func (q *Q) VisibleSignRequest(ctx context.Context, host int64, peer, id string, grant bool, now time.Time) (signer.Request, error) {
	r, h, err := q.SignRequest(ctx, id, grant)
	if err != nil || h != host || r.Peer != peer {
		return r, ErrNotFound
	}
	b, err := q.SignBinding(ctx, h, r.Path, now)
	if err != nil || b.Set != r.Set || b.Generation != r.Generation {
		return r, ErrNotFound
	}
	if !reflect.DeepEqual(b, r.Binding) && (r.Status == "approved" || r.Status == "pending") {
		return r, ErrNotFound
	}
	return r, nil
}
func (q *Q) OwnerSignRequests(ctx context.Context) ([]signer.Request, error) {
	var ids []string
	err := q.rows(ctx, `SELECT id FROM sign_requests WHERE status IN ('pending','approved') ORDER BY id`, func(rows *sql.Rows) error { var id string; err := rows.Scan(&id); ids = append(ids, id); return err })
	if err != nil {
		return nil, err
	}
	out := []signer.Request{}
	for _, id := range ids {
		r, _, err := q.SignRequest(ctx, id, false)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
func (q *Q) DecideSign(ctx context.Context, id, status, grant string, ttl, max int, until int64) error {
	if status == "approved" {
		return one(q.q.ExecContext(ctx, `UPDATE sign_requests SET status=?,grant_id=?,ttl=?,max=?,until_ms=? WHERE id=? AND status='pending'`, status, grant, ttl, max, until, id))
	}
	from := "pending"
	if status == "revoked" {
		from = "approved"
	}
	return one(q.q.ExecContext(ctx, `UPDATE sign_requests SET status=? WHERE id=? AND status=?`, status, id, from))
}

// UseSign spends n signatures of a live grant, or none at all; a grant with
// none left becomes 'used' and leaves the owner's list.
func (q *Q) UseSign(ctx context.Context, grant, set string, n int, now time.Time) error {
	if err := one(q.q.ExecContext(ctx, `UPDATE sign_requests SET used=used+?1,status=CASE WHEN used+?1>=max THEN 'used' ELSE status END WHERE grant_id=?2 AND status='approved' AND used+?1<=max AND until_ms>?3`, n, grant, ms(now))); err != nil {
		return err
	}
	return one(q.q.ExecContext(ctx, `UPDATE signer_keys SET signatures=signatures+? WHERE set_id=?`, n, set))
}
func (q *Q) SignPending(ctx context.Context, host int64, now time.Time) (int, error) {
	var n int
	err := q.q.QueryRowContext(ctx, `SELECT count(*) FROM sign_requests WHERE host=? AND status='pending' AND deadline>?`, host, ms(now)).Scan(&n)
	return n, err
}

// SetHistory is the newest n audit rows about one application set, newest
// first, for the owner's item view: owner actions on the set itself (object
// set:ID), what admitted hosts asked for and collected (their detail starts
// with the set's path, which the broker wrote from its own rows) and the
// owner's decisions on those (a signing decision names " PATH host="; an env
// decision carries the signed metadata, which names the set by ID). It is a display aid read from the append-only
// log; nothing is decided from it.
func (q *Q) SetHistory(ctx context.Context, set, path string, n int) ([]api.AuditEntry, error) {
	out := []api.AuditEntry{}
	err := q.rows(ctx, `SELECT at,actor,action,object,detail FROM audit WHERE object='set:'||?1
 OR (actor LIKE 'host:%' AND (action LIKE 'env~_%' ESCAPE '~' OR action='sign' OR action LIKE 'sign~_%' ESCAPE '~' OR action LIKE 'ssh~_%' ESCAPE '~') AND (detail=?2 OR substr(detail,1,length(?2)+1)=?2||' '))
 OR (actor='owner' AND action LIKE 'vault~_sign~_%' ESCAPE '~' AND instr(detail,' '||?2||' host=')>0)
 OR (actor='owner' AND action LIKE 'env~_%' ESCAPE '~' AND instr(detail,'\"set\":\"'||?1||'\"')>0)
 ORDER BY id DESC LIMIT ?3`, func(rs *sql.Rows) error {
		var e api.AuditEntry
		var at int64
		if err := rs.Scan(&at, &e.Actor, &e.Action, &e.Object, &e.Detail); err != nil {
			return err
		}
		e.At = fromMS(at)
		out = append(out, e)
		return nil
	}, set, path, n)
	return out, err
}

// HostSet is one row of the host's own catalogue (GET /v2/catalogue).
type HostSet struct {
	OrgSlug, OrgTitle, ServiceSlug, ServiceTitle, Provider string
	SetID, SetSlug, SetTitle, Kind                         string
	Revision                                               int
}

// HostSets lists the sets of every organisation that admits the host AND lets
// hosts list (org_flags.discovery at the organisation's current policy
// revision). An organisation without the switch contributes nothing, exactly
// as if the host were not admitted to it.
func (q *Q) HostSets(ctx context.Context, host int64, now time.Time) ([]HostSet, error) {
	out := []HostSet{}
	err := q.rows(ctx, `SELECT o.slug,o.title,v.slug,v.title,v.provider,s.id,s.slug,s.title,s.kind,s.revision FROM org_hosts a JOIN hosts h ON h.id=a.host_id JOIN organisations o ON o.id=a.org_id JOIN org_flags f ON f.org_id=o.id AND f.revision=o.revision AND f.discovery=1 JOIN services v ON v.org_id=o.id JOIN credential_sets s ON s.service_id=v.id WHERE h.id=? AND a.active=1 AND o.archived=0 AND v.archived=0 AND s.archived=0 AND h.revoked_at IS NULL AND h.not_after>? ORDER BY o.slug,v.slug,s.slug`, func(rs *sql.Rows) error {
		var x HostSet
		err := rs.Scan(&x.OrgSlug, &x.OrgTitle, &x.ServiceSlug, &x.ServiceTitle, &x.Provider, &x.SetID, &x.SetSlug, &x.SetTitle, &x.Kind, &x.Revision)
		out = append(out, x)
		return err
	}, host, ms(now))
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return []HostSet{}, nil // no policy has ever turned listing on
	}
	return out, err
}

// HostSetDetail is what the listing says about one application set: its kind
// and names (an SSH key: its scheme, public key, comment and hand-out switch).
// OK is false for a set with nothing to ask for yet.
type HostSetDetail struct {
	Kind      string
	Names     []string
	Scheme    string
	PublicKey []byte
	Note, URL string
	Comment   string
	Handout   bool
	OK        bool
}

func (q *Q) HostSetDetail(ctx context.Context, set string) (d HostSetDetail, err error) {
	var raw string
	var secret, sshKey bool
	err = q.q.QueryRowContext(ctx, `SELECT coalesce(r.names,'[]'),coalesce(k.scheme,''),k.public_key,k.wrap IS NOT NULL,z.set_id IS NOT NULL,coalesce(z.note,''),coalesce(z.url,''),y.set_id IS NOT NULL,coalesce(y.comment,''),coalesce(y.handout,0) FROM credential_sets s LEFT JOIN signer_keys k ON k.set_id=s.id LEFT JOIN secret_sets z ON z.set_id=s.id LEFT JOIN ssh_keys y ON y.set_id=s.id LEFT JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision AND r.wrap IS NOT NULL WHERE s.id=?`, set).Scan(&raw, &d.Scheme, &d.PublicKey, &d.OK, &secret, &d.Note, &d.URL, &sshKey, &d.Comment, &d.Handout)
	if err != nil {
		return HostSetDetail{}, notFound(err)
	}
	if d.Scheme != "" {
		d.Kind, d.Note, d.URL = "signer", "", ""
		if sshKey {
			d.Kind = "ssh-key"
		}
		return d, nil
	}
	if err = json.Unmarshal([]byte(raw), &d.Names); err != nil {
		return HostSetDetail{}, err
	}
	d.Kind, d.PublicKey = "env-set", nil
	if secret {
		d.Kind = "secret"
	}
	d.OK = len(d.Names) > 0
	return d, nil
}
