package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// Deleting a Vault item (docs/API.md "Delete, restore and purge"): one tap
// moves it to the bin, where it is unusable by every host from that moment
// and everything that could still use it has ended. For seven days it can be
// restored exactly as it was; then, or on an earlier "Purge now", its sealed
// records and its bucket are destroyed. The audit log keeps path, kind, who,
// when and a digest of what was sealed: never a value.

// deletedView is one row of Vault → Deleted.
type deletedView struct {
	store.DeletedSet
	Fingerprint   string `json:"fingerprint,omitempty"`
	AuthorizedKey string `json:"authorized_key,omitempty"`
}

func newDeletedView(d store.DeletedSet) deletedView {
	v := setView(d.VaultTarget)
	return deletedView{DeletedSet: d, Fingerprint: v.Fingerprint, AuthorizedKey: v.AuthorizedKey}
}

// setFingerprint identifies a key item on cards and in signed text: the
// SHA-256 of the raw public key for a signer, the OpenSSH fingerprint
// ("SHA256:...") for an SSH key, nothing for an env set or a secret.
func setFingerprint(t store.VaultTarget) string {
	switch t.Kind {
	case "signer":
		return signer.Fingerprint(t.PublicKey)
	case "ssh-key":
		fp, _ := signer.SSHFingerprint(t.Scheme, t.PublicKey)
		return fp
	}
	return ""
}

// setBucketKind is the bucket kind an application set's records live in.
func setBucketKind(kind string) string {
	if kind == "signer" || kind == "ssh-key" {
		return "signer"
	}
	return "env-set"
}

// binDigest names what a purge will destroy without revealing it: SHA-256
// over the set's identity and its current sealed record (ciphertext).
func (s *Server) binDigest(ctx context.Context, q *store.Q, t store.VaultTarget) (string, error) {
	var rec store.CipherRecord
	var err error
	if setBucketKind(t.Kind) == "signer" {
		rec, err = q.SignerCipher(ctx, t.SetID)
	} else if t.Revision > 0 {
		rec, err = q.EnvCipher(ctx, t.SetID, t.Revision)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	sum := sha256.Sum256(seal.Tuple("aqmas-bin", []byte(t.SetID), []byte(t.Kind), []byte(strconv.Itoa(t.Revision)), rec.Payload))
	return hex.EncodeToString(sum[:]), nil
}

func sealIDs(raw [][]byte) []seal.ID {
	var out []seal.ID
	for _, b := range raw {
		if len(b) == len(seal.ID{}) {
			var id seal.ID
			copy(id[:], b)
			out = append(out, id)
		}
	}
	return out
}

func purgeDetail(p store.PurgeInfo) string {
	return fmt.Sprintf("%s kind=%s digest=%s deleted_at=%d deleted_by=%q", p.Path, p.Kind, p.Digest, p.DeletedAt, p.DeletedBy)
}

// applyDelete bins a set inside the finish transaction. The store's triggers
// end its grants, releases, pending requests and don't-ask-again rules.
func (s *Server) applyDelete(ctx context.Context, q *store.Q, pk int64, id string, now time.Time) (out any, object, detail, note string, evict []seal.ID, err error) {
	t, err := q.VaultSet(ctx, id)
	if err != nil {
		return nil, "", "", "", nil, err
	}
	digest, err := s.binDigest(ctx, q, t)
	if err != nil {
		return nil, "", "", "", nil, err
	}
	if row, err := q.BucketByRef(ctx, setBucketKind(t.Kind), t.SetID); err == nil {
		evict = sealIDs([][]byte{row.ID})
	}
	ended, err := q.BinSet(ctx, t, pk, digest, now)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			err = errConflict("the item changed since you opened it; reload and review again")
		}
		return nil, "", "", "", nil, err
	}
	purge := now.Add(store.BinTTL)
	out = map[string]any{"ok": true, "purge_at": purge.UnixMilli(), "ended": ended}
	detail = fmt.Sprintf("%s kind=%s revision=%d digest=%s purge_at=%d ended=grants:%d,standing:%d,releases:%d,pending:%d", t.Path(), t.Kind, t.Revision, digest, purge.UnixMilli(), ended.Grants, ended.Standing, ended.Releases, ended.Pending)
	if fp := setFingerprint(t); fp != "" {
		detail += " fingerprint=" + fp
	}
	return out, "set:" + t.SetID, detail, fmt.Sprintf("Deleted %s (restorable for 7 days)", t.Path()), evict, nil
}

// purgeDue destroys every binned item whose seven days are over. It needs no
// owner, no open bucket and no key: it deletes sealed records and bucket rows.
// The sweeper calls it; so does the Vault before it lists the bin.
func (s *Server) purgeDue(ctx context.Context) {
	if !s.sealServing() {
		return
	}
	now := s.now()
	var evict []seal.ID
	ids, err := s.store.Q().DuePurges(ctx, now)
	if err != nil {
		s.log.Warn("vault: purging the bin failed", "error", err)
		return
	}
	n := 0
	// One transaction an item: a row that cannot be purged does not hold up the rest.
	for _, id := range ids {
		var buckets []seal.ID
		err := s.store.Tx(ctx, func(q *store.Q) error {
			p, err := q.PurgeSet(ctx, id)
			if err != nil {
				return err
			}
			buckets = sealIDs(p.Buckets)
			return q.Audit(ctx, now, "system", "vault_purge", "set:"+id, "auto "+purgeDetail(p))
		})
		if err != nil {
			s.log.Warn("vault: could not purge a binned item", "set", id, "error", err)
			continue
		}
		evict = append(evict, buckets...)
		n++
	}
	if n == 0 {
		return
	}
	s.seal.pool.evict(evict...)
	if err := s.store.CheckpointWAL(ctx); err != nil {
		s.log.Warn("vault: could not truncate the WAL after a purge", "error", err)
	}
	s.bcast.notify()
}
