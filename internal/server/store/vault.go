package store

import (
	"context"
	"database/sql"
	"encoding/json"
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
CREATE TRIGGER IF NOT EXISTS signer_key_immutable BEFORE UPDATE OF set_id,scheme,public_key,origin,blob ON signer_keys BEGIN SELECT RAISE(ABORT,'immutable signer key'); END;`)
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
}

const vaultCols = `o.id,o.slug,o.title,v.id,v.slug,v.title,s.id,s.slug,s.title,s.revision,v.revision,o.revision,coalesce(r.names,'[]'),coalesce((SELECT allow_reveal FROM org_vault x WHERE x.org_id=o.id),1),coalesce(k.scheme,''),k.public_key,coalesce(k.origin,''),coalesce(k.created,0),coalesce(k.signatures,0),z.set_id IS NOT NULL,coalesce(z.note,''),coalesce(z.url,'') FROM organisations o JOIN services v ON v.org_id=o.id JOIN credential_sets s ON s.service_id=v.id LEFT JOIN signer_keys k ON k.set_id=s.id LEFT JOIN secret_sets z ON z.set_id=s.id LEFT JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision AND r.wrap IS NOT NULL WHERE NOT o.archived AND NOT v.archived AND NOT s.archived AND v.provider='application' AND s.kind='env-set'`

func scanVault(row interface{ Scan(...any) error }) (t VaultTarget, err error) {
	var names string
	var secret bool
	if err = row.Scan(&t.OrgID, &t.OrgSlug, &t.OrgTitle, &t.ServiceID, &t.ServiceSlug, &t.ServiceTitle, &t.SetID, &t.SetSlug, &t.SetTitle, &t.Revision, &t.ServiceRevision, &t.PolicyRevision, &names, &t.AllowReveal, &t.Scheme, &t.PublicKey, &t.Origin, &t.Created, &t.Signatures, &secret, &t.Note, &t.URL); err != nil {
		return t, err
	}
	t.Kind = "env-set"
	if t.Scheme != "" {
		t.Kind = "signer"
	} else if secret {
		t.Kind = "secret"
	}
	return t, json.Unmarshal([]byte(names), &t.Names)
}
func (q *Q) VaultSets(ctx context.Context) ([]VaultTarget, error) {
	out := []VaultTarget{}
	err := q.rows(ctx, `SELECT `+vaultCols+` ORDER BY o.slug,v.slug,s.slug`, func(rs *sql.Rows) error {
		t, err := scanVault(rs)
		out = append(out, t)
		return err
	})
	return out, err
}
func (q *Q) VaultSet(ctx context.Context, set string) (VaultTarget, error) {
	t, err := scanVault(q.q.QueryRowContext(ctx, `SELECT `+vaultCols+` AND s.id=?`, set))
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
	return one(q.q.ExecContext(ctx, `INSERT INTO sign_requests(id,host,set_id,binding,items,peer,reason,ttl,max,deadline,status) VALUES(?,?,?,?,?,?,?,?,?,?,'pending')`, r.ID, host, r.Set, string(b), string(items), r.Peer, r.Reason, r.TTL, r.Max, r.Deadline))
}
func (q *Q) SignRequest(ctx context.Context, id string, grant bool) (r signer.Request, host int64, err error) {
	col := "id"
	if grant {
		col = "grant_id"
	}
	var b, items string
	err = q.q.QueryRowContext(ctx, `SELECT id,coalesce(grant_id,''),host,binding,items,peer,reason,ttl,max,deadline,until_ms,status,used FROM sign_requests WHERE `+col+`=?`, id).Scan(&r.ID, &r.Grant, &host, &b, &items, &r.Peer, &r.Reason, &r.TTL, &r.Max, &r.Deadline, &r.Until, &r.Status, &r.Used)
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
 OR (actor LIKE 'host:%' AND (action LIKE 'env~_%' ESCAPE '~' OR action='sign' OR action LIKE 'sign~_%' ESCAPE '~') AND (detail=?2 OR substr(detail,1,length(?2)+1)=?2||' '))
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
// and names. ok is false for a set with nothing to ask for yet.
func (q *Q) HostSetDetail(ctx context.Context, set string) (kind string, names []string, scheme, note, url string, ok bool, err error) {
	var raw string
	var secret bool
	err = q.q.QueryRowContext(ctx, `SELECT coalesce(r.names,'[]'),coalesce(k.scheme,''),k.wrap IS NOT NULL,z.set_id IS NOT NULL,coalesce(z.note,''),coalesce(z.url,'') FROM credential_sets s LEFT JOIN signer_keys k ON k.set_id=s.id LEFT JOIN secret_sets z ON z.set_id=s.id LEFT JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision AND r.wrap IS NOT NULL WHERE s.id=?`, set).Scan(&raw, &scheme, &ok, &secret, &note, &url)
	if err != nil {
		return "", nil, "", "", "", false, notFound(err)
	}
	if scheme != "" {
		return "signer", nil, scheme, "", "", ok, nil
	}
	if err = json.Unmarshal([]byte(raw), &names); err != nil {
		return "", nil, "", "", "", false, err
	}
	kind = "env-set"
	if secret {
		kind = "secret"
	}
	return kind, names, "", note, url, len(names) > 0, nil
}
