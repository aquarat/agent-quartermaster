package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// DrillBackup is `aqmasd seal-drill BACKUP.db RECIPIENT <identity.txt`
// (docs/BUCKETS.md §10): it opens a standalone format-2 backup read-only,
// recovers every scope key from its recovery wrap, opens every bucket and
// authenticates every record, and reports only counts and the manifest
// digest. It never writes. cf may be nil: the Cloudflare parent's record is
// bound to the configured issuer and account, so without them its bucket is
// opened but its record is reported unchecked.
func DrillBackup(path, recipient string, identity []byte, cf *config.Cloudflare) (string, error) {
	for _, ext := range []string{"-wal", "-journal"} {
		if _, err := os.Lstat(path + ext); !os.IsNotExist(err) {
			return "", errors.New("use a standalone online backup without a WAL or journal beside it")
		}
	}
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return "", errors.New("invalid backup")
	}
	st, err := store.OpenReadOnly(path)
	if err != nil {
		return "", err
	}
	defer st.Close()
	ctx := context.Background()
	var v int
	var text string
	if err = st.DB().QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != store.SchemaBuckets {
		return "", errors.New("not a per-credential bucket store (schema 9)")
	}
	if err = st.DB().QueryRow(`SELECT manifest FROM seal_active WHERE singleton=1 AND length(manifest)<=1048576`).Scan(&text); err != nil {
		return "", errors.New("no activation record")
	}
	var m BucketManifest
	if json.Unmarshal([]byte(text), &m) != nil || m.Format != 2 || m.Installation == (seal.ID{}) || m.Recipient != recipient {
		return "", errors.New("the backup is not sealed to that recipient")
	}
	id, err := seal.ParseIdentity(identity)
	if err != nil {
		return "", errors.New("invalid recovery identity")
	}
	cfg := &config.Config{}
	if cf != nil {
		cfg.Cloudflare = *cf
	}
	s := &Server{cfg: cfg, store: st, seal: &sealRuntime{installation: m.Installation, recipient: recipient}}
	q := st.Q()
	scopes, err := q.Scopes(ctx)
	if err != nil {
		return "", err
	}
	nBuckets, nUnchecked := 0, 0
	for _, x := range scopes {
		k, err := seal.Scope{Installation: m.Installation, Name: x.Scope, Public: x.Public}.Recover(id, recipient, x.Recovery)
		if err != nil {
			return "", fmt.Errorf("scope %s did not open from this identity", x.Scope)
		}
		rows, err := q.ScopeBuckets(ctx, x.Scope)
		if err != nil {
			k.Destroy()
			return "", err
		}
		for _, row := range rows {
			b := s.sealBucket(row)
			bk, err := b.UnwrapWith(k, x.Public, row.Wrap)
			if err != nil {
				k.Destroy()
				return "", fmt.Errorf("%s did not open", row.Label)
			}
			if row.Kind == seal.RoleCFProxy && cf == nil {
				nUnchecked++
			} else {
				err = s.checkRecords(ctx, q, row, b, bk)
			}
			bk.Destroy()
			if err != nil {
				k.Destroy()
				return "", err
			}
			nBuckets++
		}
		k.Destroy()
	}
	out := fmt.Sprintf("recovery drill passed: scopes=%d buckets=%d manifest_sha256=%s", len(scopes), nBuckets, seal.Digest([]byte(text)))
	if nUnchecked > 0 {
		out += fmt.Sprintf(" (unchecked without the configuration: %d Cloudflare record)", nUnchecked)
	}
	return out, nil
}
