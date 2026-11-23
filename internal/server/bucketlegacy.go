package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"

	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// Reading a format-1 (v0.4.1) sealed store for the one-way move to buckets
// (docs/BUCKETS.md §8). Only the bucket-migrate stage uses this: the MK is
// opened once, by the first staging tap, every record is decrypted and sealed
// again to its bucket, and the MK is wiped before the tap returns.

// legacyStore is the public half of a format-1 store: its inventory and the
// unlock wraps of its passkeys (passkey row → salt and wrap).
type legacyStore struct {
	inv   seal.Inventory
	wraps map[int64]legacyWrap
}
type legacyWrap struct {
	salt seal.ID
	wrap []byte
}

// loadLegacy checks the format-1 store against the root pin and the public
// trust anchors before anything is staged.
func (s *Server) loadLegacy(ctx context.Context) (*legacyStore, error) {
	if err := s.retiredSources(); err != nil {
		return nil, err
	}
	db := s.store.DB()
	var text string
	var blob []byte
	if err := db.QueryRowContext(ctx, `SELECT manifest, inventory FROM seal_active WHERE singleton=1 AND length(manifest)<=1048576 AND length(inventory)<=524288`).Scan(&text, &blob); err != nil {
		return nil, err
	}
	var m seal.Manifest
	var inv seal.Inventory
	bad := errors.New("seal: public activation pin mismatch")
	if seal.Digest([]byte(text)) != s.cfg.Seal.Manifest || json.Unmarshal([]byte(text), &m) != nil || m.Format != 1 || m.InventoryDigest != seal.Digest(blob) || json.Unmarshal(blob, &inv) != nil {
		return nil, bad
	}
	if m.Generation != inv.Generation || m.Recipient != s.cfg.Seal.Recipient || inv.Recipient != m.Recipient || inv.SSHCA != s.sshPin() || inv.InternalCA != s.pki.CAPin() || inv.ConfigHash != s.profileRevision || inv.Installation == (seal.ID{}) {
		return nil, bad
	}
	l := &legacyStore{inv: inv, wraps: map[int64]legacyWrap{}}
	rows, err := db.QueryContext(ctx, `SELECT passkey,salt,wrap,generation FROM seal_wraps`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var row int64
		var salt, wrap []byte
		var gen uint64
		if err = rows.Scan(&row, &salt, &wrap, &gen); err != nil {
			return nil, err
		}
		if gen != inv.Version || len(salt) != 32 || len(wrap) != 73 {
			continue
		}
		var w legacyWrap
		copy(w.salt[:], salt)
		w.wrap = wrap
		l.wraps[row] = w
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(l.wraps) == 0 {
		return nil, errors.New("seal: no format-1 unlock wrap")
	}
	return l, nil
}

func tableExists(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string) bool {
	var n int
	return db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, name).Scan(&n) == nil && n == 1
}

// legacyEnvRow is one live env revision of a format-1 store.
type legacyEnvRow struct {
	org, service, set string
	revision          int
	names             string
	blob, payload     []byte
	wrap              []byte
}

// legacySignerRow is one format-1 signer key.
type legacySignerRow struct {
	org, service, set, scheme string
	public, blob              []byte
	payload, wrap             []byte
}

func (s *Server) legacyEnvRows(ctx context.Context) ([]legacyEnvRow, error) {
	db := s.store.DB()
	if !tableExists(ctx, db, "env_revisions") {
		return nil, nil
	}
	signers := ""
	if tableExists(ctx, db, "signer_keys") {
		signers = ` AND NOT EXISTS(SELECT 1 FROM signer_keys k WHERE k.set_id=s.id)`
	}
	rows, err := db.QueryContext(ctx, `SELECT v.org_id,v.id,s.id,s.revision,r.names,r.blob,r.payload,r.wrap FROM credential_sets s JOIN services v ON v.id=s.service_id JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision WHERE s.kind='env-set' AND s.revision>0 AND r.wrap IS NOT NULL`+signers+` ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []legacyEnvRow
	for rows.Next() {
		var r legacyEnvRow
		if err = rows.Scan(&r.org, &r.service, &r.set, &r.revision, &r.names, &r.blob, &r.payload, &r.wrap); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Server) legacySignerRows(ctx context.Context) ([]legacySignerRow, error) {
	db := s.store.DB()
	if !tableExists(ctx, db, "signer_keys") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT v.org_id,v.id,s.id,k.scheme,k.public_key,k.blob,k.payload,k.wrap FROM signer_keys k JOIN credential_sets s ON s.id=k.set_id JOIN services v ON v.id=s.service_id WHERE k.wrap IS NOT NULL ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []legacySignerRow
	for rows.Next() {
		var r legacySignerRow
		if err = rows.Scan(&r.org, &r.service, &r.set, &r.scheme, &r.public, &r.blob, &r.payload, &r.wrap); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// cfProxyBinding is the organisation, service and set of the Cloudflare proxy parent.
func (s *Server) cfProxyBinding(ctx context.Context) (org, service, set string, err error) {
	err = s.store.DB().QueryRowContext(ctx, `SELECT c.org_id,v.id,t.id FROM personal_cutover c JOIN services v ON v.org_id=c.org_id JOIN credential_sets t ON t.service_id=v.id WHERE t.kind='cloudflare-proxy' AND v.slug='dns-cdn'`).Scan(&org, &service, &set)
	return
}

// legacyPlan lists the scopes and the number of buckets per scope that the
// migration will create, from public data only (before the MK is opened).
func (s *Server) legacyPlan(ctx context.Context, l *legacyStore) (map[string]int, error) {
	counts := map[string]int{seal.ScopeInstallation: 0}
	for _, r := range l.inv.Records {
		switch r.Role {
		case seal.RoleSSHCA, seal.RoleInternalCA:
			counts[seal.ScopeInstallation]++
		case seal.RoleCFProxy:
			counts[r.Org]++
		}
	}
	envs, err := s.legacyEnvRows(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range envs {
		counts[r.org]++
	}
	signers, err := s.legacySignerRows(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range signers {
		counts[r.org]++
	}
	return counts, nil
}

// buildLegacy decrypts every format-1 record with mk and stages it in its
// bucket. Plaintext is cleared as soon as it is sealed again.
func (s *Server) buildLegacy(ctx context.Context, st *sealStage, mk *seal.Key) error {
	inv := st.legacy.inv
	inst := s.seal.installation
	roles := map[string]bool{}
	for _, r := range inv.Records {
		if roles[r.Role] {
			return errors.New("format-1 inventory names a role twice")
		}
		roles[r.Role] = true
		p, err := r.Decrypt(inv.Generation, mk, r.Envelope)
		if err != nil {
			return errors.New("a format-1 record failed authentication; nothing was staged")
		}
		err = s.stageLegacyRecord(ctx, st, inst, r, p)
		clear(p)
		if err != nil {
			return err
		}
	}
	if !roles[seal.RoleSSHCA] || !roles[seal.RoleInternalCA] {
		return errors.New("format-1 inventory lacks a CA")
	}
	envs, err := s.legacyEnvRows(ctx)
	if err != nil {
		return err
	}
	for _, r := range envs {
		if len(r.blob) != 32 {
			return errors.New("damaged format-1 env revision")
		}
		o := seal.Object{Org: r.org, Service: r.service, Set: r.set, Role: "env-revision", Revision: uint64(r.revision)}
		copy(o.Blob[:], r.blob)
		p, err := o.Decrypt(inv.Generation, mk, seal.Envelope{Payload: r.payload, WrappedDEK: r.wrap})
		if err != nil {
			return errors.New("a format-1 env revision failed authentication; nothing was staged")
		}
		var entries []envset.Entry
		var names []string
		err = json.Unmarshal(p, &entries)
		clear(p)
		if err != nil || json.Unmarshal([]byte(r.names), &names) != nil || envset.Validate(entries) != nil || !slices.Equal(envset.Names(entries), names) {
			wipeEntries(entries)
			return errors.New("damaged format-1 env revision")
		}
		err = st.stageEnv(inst, r.org, r.set, r.revision, entries)
		wipeEntries(entries)
		if err != nil {
			return err
		}
	}
	signers, err := s.legacySignerRows(ctx)
	if err != nil {
		return err
	}
	for _, r := range signers {
		if len(r.blob) != 32 {
			return errors.New("damaged format-1 signer key")
		}
		o := seal.Object{Org: r.org, Service: r.service, Set: r.set, Role: "signer-key", Revision: 1}
		copy(o.Blob[:], r.blob)
		p, err := o.Decrypt(inv.Generation, mk, seal.Envelope{Payload: r.payload, WrappedDEK: r.wrap})
		if err != nil {
			return errors.New("a format-1 signer key failed authentication; nothing was staged")
		}
		var key signerSecret
		ok := json.Unmarshal(p, &key) == nil
		if sc, found := signer.Lookup(r.scheme); ok && found && key.Scheme == r.scheme && len(key.Private) == 32 {
			pub, err := sc.Public(key.Private)
			ok = err == nil && bytes.Equal(pub, r.public)
		} else {
			ok = false
		}
		clear(key.Private)
		if !ok {
			clear(p)
			return errors.New("damaged format-1 signer key")
		}
		// The format-2 plaintext is the same {"scheme","private"} JSON.
		err = st.stageSigner(inst, r.org, r.set, r.scheme, r.public, p)
		clear(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func wipeEntries(entries []envset.Entry) {
	for i := range entries {
		entries[i].Value = ""
	}
}

// stageLegacyRecord stages one inventory record (its plaintext is p).
func (s *Server) stageLegacyRecord(ctx context.Context, st *sealStage, inst seal.ID, r seal.Record, p []byte) error {
	switch r.Role {
	case seal.RoleSSHCA, seal.RoleInternalCA:
		if err := s.pki.CheckPrivate(r.Role, p); err != nil {
			return errors.New("a format-1 CA key does not match the public CA")
		}
		return st.stageSingle(inst, seal.ScopeInstallation, r.Role, caBucketRef, nil, p)
	case seal.RoleCFProxy:
		org, service, set, err := s.cfProxyBinding(ctx)
		if err != nil || org != r.Org || service != r.Service || set != r.Set {
			return errors.New("the Cloudflare proxy parent's binding changed")
		}
		fields := s.cfFields(org, service, set)
		if string(fields[3]) != r.Issuer || string(fields[4]) != r.Account {
			return errors.New("the Cloudflare issuer or account changed since sealing")
		}
		return st.stageSingle(inst, org, seal.RoleCFProxy, set, fields, p)
	case "cf-minter":
		st.dropped = append(st.dropped, "cf-minter")
		return nil
	case "ntfy-topic":
		st.notice = string(p)
		return nil
	}
	return errors.New("unknown format-1 record role")
}
