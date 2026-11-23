package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/policy"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Consumers of open buckets (docs/BUCKETS.md §3.2, §5): every secret is
// decrypted per operation from a bucket the pool holds open, and holds are
// derived from stored state, never from the page.

const envHoldMax = 10 * time.Minute

// ---- holds ----

func untilOf(t time.Time) time.Time {
	if t.IsZero() || t.Equal(untilRevoked) {
		return time.Time{}
	}
	return t
}
func standingHold(st *store.Standing) bucketHold {
	return bucketHold{Kind: "standing", Ref: "standing:" + st.ID, Reason: "standing rule " + st.ID, Until: untilOf(st.ExpiresAt)}
}
func standingFromHold(request string, until time.Time) bucketHold {
	return bucketHold{Kind: "standing", Ref: "standing-from:" + request, Reason: "new standing rule", Until: untilOf(until)}
}
func rearmHold(st *store.Standing) bucketHold {
	h := standingHold(st)
	h.Reason = "re-arms standing rule " + st.ID
	if !h.Until.IsZero() {
		h.Reason += " until " + h.Until.UTC().Format(time.RFC3339)
	}
	return h
}
func (s *Server) cfGrantHold(request string, notAfter time.Time) bucketHold {
	return bucketHold{Kind: "grant", Ref: "request:" + request, Reason: "Cloudflare grant", Until: untilOf(notAfter)}
}
func (s *Server) envHold(release string, until int64) bucketHold {
	u := s.now().Add(envHoldMax)
	if until > 0 && time.UnixMilli(until).Before(u) {
		u = time.UnixMilli(until)
	}
	return bucketHold{Kind: "env", Ref: "env:" + release, Reason: "env release until collected (10 minutes at most)", Until: u.UTC()}
}
func signHold(request string, until time.Time) bucketHold {
	return bucketHold{Kind: "sign", Ref: "sign:" + request, Reason: "signing grant until used up", Until: untilOf(until)}
}
func windowHold(id string, until time.Time) bucketHold {
	return bucketHold{Kind: "window", Ref: "window:" + id, Reason: "approval window", Until: untilOf(until)}
}
func instantHold() bucketHold {
	return bucketHold{Kind: "instant", Ref: "instant", Reason: "instant (this approval only)"}
}

// ---- the CAs ----

func (s *Server) caRow(ctx context.Context, q *store.Q, role string) (store.BucketRow, error) {
	row, err := q.BucketByRef(ctx, role, caBucketRef)
	if err != nil {
		return row, errConflict("the " + role + " bucket is missing; restore from backup")
	}
	return row, nil
}

// withCA lends a PKI holding the CA's private key for one operation. The PEM
// record is decrypted from the open bucket and cleared afterwards.
func (s *Server) withCA(ctx context.Context, q *store.Q, role string, fn func(*pki.PKI) error) error {
	if s.seal == nil {
		return fn(s.pki)
	}
	if err := s.bucketsReady(); err != nil {
		return err
	}
	row, err := s.caRow(ctx, q, role)
	if err != nil {
		return err
	}
	return s.withBucket(row, func(b seal.Bucket, k *seal.Key) error {
		pemBytes, err := b.Open(k, role, nil, row.Payload)
		if err != nil {
			return errConflict(row.Label + ": sealed record failed authentication")
		}
		defer clear(pemBytes)
		p, err := s.pki.WithPrivate(role, pemBytes)
		if err != nil {
			return errConflict(row.Label + ": record does not match the pinned public key")
		}
		return fn(p)
	})
}

func (s *Server) caOpen(ctx context.Context, q *store.Q, role string) bool {
	if s.seal == nil {
		return true
	}
	if !s.sealServing() {
		return false
	}
	row, err := s.caRow(ctx, q, role)
	return err == nil && s.seal.pool.isOpen(bucketSealID(row))
}
func (s *Server) holdCA(ctx context.Context, role string, holds ...bucketHold) {
	if !s.sealServing() {
		return
	}
	if row, err := s.caRow(ctx, s.store.Q(), role); err == nil {
		s.seal.pool.hold(bucketSealID(row), holds...)
	}
}

// ---- the Cloudflare proxy parent ----

func cfProxySet(ctx context.Context, q *store.Q) (string, error) { return q.CFProxySet(ctx) }
func (s *Server) cfRow(ctx context.Context, q *store.Q) (store.BucketRow, error) {
	set, err := cfProxySet(ctx, q)
	if err != nil {
		return store.BucketRow{}, errConflict("no Cloudflare proxy set")
	}
	row, err := q.BucketByRef(ctx, seal.RoleCFProxy, set)
	if err != nil {
		return row, errConflict("the Cloudflare proxy parent has no bucket")
	}
	return row, nil
}

// CFRecordFields are the context fields of a cf-proxy record (§3.2).
func (s *Server) cfRecordFields(row store.BucketRow) [][]byte {
	return s.cfFields(row.OrgID, row.ServiceID, row.Ref)
}
func (s *Server) cfFields(org, service, set string) [][]byte {
	issuer := s.cfg.Cloudflare.APIBase
	if issuer == "" {
		issuer = "https://api.cloudflare.com/client/v4"
	}
	return [][]byte{[]byte(org), []byte(service), []byte(set), []byte(issuer), []byte(s.cfg.Cloudflare.AccountID)}
}

// cfParentToken decrypts the proxy parent for one upstream call. The Go
// string copy is the documented heap exception (§1).
func (s *Server) cfParentToken(ctx context.Context) (string, error) {
	if err := s.bucketsReady(); err != nil {
		return "", err
	}
	row, err := s.cfRow(ctx, s.store.Q())
	if err != nil {
		return "", err
	}
	var tok string
	err = s.withBucket(row, func(b seal.Bucket, k *seal.Key) error {
		p, err := b.Open(k, seal.RoleCFProxy, s.cfRecordFields(row), row.Payload)
		if err != nil {
			return errConflict(row.Label + ": sealed record failed authentication")
		}
		tok = string(p)
		clear(p)
		return nil
	})
	return tok, err
}
func (s *Server) cfParentReady(ctx context.Context) error {
	if err := s.bucketsReady(); err != nil {
		return err
	}
	row, err := s.cfRow(ctx, s.store.Q())
	if err != nil {
		return err
	}
	if !s.seal.pool.isOpen(bucketSealID(row)) {
		return closedErr(row)
	}
	return nil
}
func (s *Server) cfBucketOpen(ctx context.Context, q *store.Q) bool {
	if s.seal == nil {
		return true
	}
	if !s.sealServing() {
		return false
	}
	row, err := s.cfRow(ctx, q)
	return err == nil && s.seal.pool.isOpen(bucketSealID(row))
}
func (s *Server) cfAutoHold(ctx context.Context, q *store.Q) bucketHold {
	set, _ := cfProxySet(ctx, q)
	return bucketHold{Kind: "auto", Ref: "auto:" + set, Reason: "Cloudflare auto-approval until restart"}
}

// cfAutoOn reports whether the set's current policy still auto-approves some
// scope the catalogue allows: the "auto" hold lives only while it does (§5).
func (s *Server) cfAutoOn(ctx context.Context, q *store.Q, set string) (bool, error) {
	if s.cf.cat == nil {
		return false, nil
	}
	scopes, err := q.AutoScopes(ctx, set)
	if err != nil {
		return false, err
	}
	for _, name := range scopes {
		if sc, ok := s.cf.cat.Lookup(name); ok && sc.AutoApprove {
			return true, nil
		}
	}
	return false, nil
}
func (s *Server) holdCF(ctx context.Context, holds ...bucketHold) {
	if !s.sealServing() {
		return
	}
	if row, err := s.cfRow(ctx, s.store.Q()); err == nil {
		s.seal.pool.hold(bucketSealID(row), holds...)
	}
}

// ---- set buckets (env sets and signers) ----

func (s *Server) setRow(ctx context.Context, q *store.Q, kind, set string) (store.BucketRow, error) {
	row, err := q.BucketByRef(ctx, kind, set)
	if errors.Is(err, store.ErrNotFound) {
		return row, errConflict("this set has no stored values yet")
	}
	return row, err
}

// ensureSetBucket returns the set's bucket, creating it at the first write:
// a fresh key pair wrapped to the scope's public key, the private half wiped
// at once. No bucket or scope key is opened.
func (s *Server) ensureSetBucket(ctx context.Context, q *store.Q, kind, set, org string) (store.BucketRow, error) {
	row, err := q.BucketByRef(ctx, kind, set)
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return row, err
	}
	sc, err := q.Scope(ctx, org)
	if errors.Is(err, store.ErrNotFound) {
		return row, errConflict("this organisation has no scope key yet: create the scope first (Admin → Buckets)")
	}
	if err != nil {
		return row, err
	}
	// A new scope's only wrap was made with a page-supplied KEK: nothing is
	// written into it until a passkey has opened it once (§7).
	if ok, err := q.ScopeTested(ctx, org); err != nil {
		return row, err
	} else if !ok {
		return row, errConflict("test the new scope first: no passkey has opened " + scopeName(ctx, q, org) + " yet (Admin → Passkeys → Test)")
	}
	if err = s.insertBucket(ctx, q, sc, kind, set, nil); err != nil {
		return row, err
	}
	return q.BucketByRef(ctx, kind, set)
}

// insertBucket creates a bucket in scope sc. With seal non-nil the caller
// receives the new private key (rekey); otherwise it is wiped here.
func (s *Server) insertBucket(ctx context.Context, q *store.Q, sc store.ScopeRow, kind, ref string, keep **seal.Key) error {
	sk, pub, err := seal.NewKeyPair()
	if err != nil {
		return err
	}
	id := seal.RandomID()
	b := seal.Bucket{Installation: s.seal.installation, ID: id, Scope: sc.Scope, Kind: kind, Public: pub}
	wrap, err := b.WrapTo(sc.Public, sk)
	if keep != nil && err == nil {
		*keep = sk
	} else {
		sk.Destroy()
	}
	if err != nil {
		return err
	}
	return q.InsertBucket(ctx, store.BucketRow{ID: id[:], Scope: sc.Scope, Kind: kind, Ref: ref, Public: pub, Wrap: wrap, Created: s.now()})
}

// ---- env entry records (§3.2, §11) ----

// envRecord is one entry of an env revision or draft: name, random entry ID
// and the record sealed to the set's bucket (unset drafts carry names only).
type envRecord struct {
	N string `json:"n"`
	I string `json:"i,omitempty"`
	C string `json:"c,omitempty"`
}

func entryFields(set string, id []byte, name string) [][]byte {
	return [][]byte{[]byte(set), id, []byte(name)}
}

// sealEntries encrypts values to the bucket's public key: no secret needed.
func (s *Server) sealEntries(b seal.Bucket, set string, entries []envset.Entry) ([]envRecord, error) {
	out := make([]envRecord, 0, len(entries))
	for _, e := range entries {
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			return nil, err
		}
		c, err := b.Seal(seal.RoleEnvEntry, entryFields(set, id, e.Name), []byte(e.Value))
		if err != nil {
			return nil, err
		}
		out = append(out, envRecord{N: e.Name, I: encodeID(id), C: encodeID(c)})
	}
	return out, nil
}

// openEntries decrypts records with the open bucket key. The caller clears values.
func openEntries(b seal.Bucket, k *seal.Key, set string, recs []envRecord) ([]envset.Entry, error) {
	out := make([]envset.Entry, 0, len(recs))
	for _, r := range recs {
		id, err1 := strictB64(r.I, 32)
		c, err2 := strictB64(r.C, 8192+81+16)
		if err1 != nil || err2 != nil || len(id) != 32 {
			return nil, errConflict("damaged env record")
		}
		p, err := b.Open(k, seal.RoleEnvEntry, entryFields(set, id, r.N), c)
		if err != nil {
			return nil, errConflict("env record failed authentication")
		}
		out = append(out, envset.Entry{Name: r.N, Value: string(p)})
		clear(p)
	}
	return out, nil
}

func parseRecords(payload []byte, values bool) ([]envRecord, error) {
	var recs []envRecord
	if json.Unmarshal(payload, &recs) != nil || recs == nil && string(payload) != "[]" {
		return nil, errConflict("damaged env record list")
	}
	for i, r := range recs {
		if i > 0 && recs[i-1].N >= r.N || (r.C != "") != values || values && r.I == "" {
			return nil, errConflict("damaged env record list")
		}
	}
	return recs, nil
}
func recordsJSON(recs []envRecord) ([]byte, error) {
	slices.SortFunc(recs, func(a, b envRecord) int { return strings.Compare(a.N, b.N) })
	if recs == nil {
		recs = []envRecord{}
	}
	return json.Marshal(recs)
}
func recordNames(recs []envRecord) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.N
	}
	slices.Sort(out)
	return out
}

// checkRecordLimits applies envset.Validate's limits from record lengths:
// a value is len(record) − 81 bytes (enc 65 + tag 16).
func checkRecordLimits(recs []envRecord) error {
	if len(recs) > 64 {
		return errBad("result exceeds env-set limits: too many keys")
	}
	size := 0
	seen := map[string]bool{}
	for _, r := range recs {
		c, err := strictB64(r.C, 8192+81+16)
		if err != nil || len(c) < 81 || len(c)-81 > 8192 || !envset.SafeName(r.N) || seen[r.N] {
			return errBad("result exceeds env-set limits")
		}
		seen[r.N] = true
		size += len(r.N) + len(c) - 81
	}
	if size > envset.MaxBytes {
		return errBad("result exceeds env-set limits: environment too large")
	}
	return nil
}

// revisionRecords reads the current revision's records (no decryption) and
// checks they belong to the set's current bucket.
func (s *Server) revisionRecords(ctx context.Context, q *store.Q, b envset.Binding) ([]envRecord, *store.BucketRow, error) {
	if b.Revision == 0 {
		return []envRecord{}, nil, nil
	}
	r, err := q.EnvCipher(ctx, b.Set, b.Revision)
	if err != nil {
		return nil, nil, err
	}
	row, err := s.setRow(ctx, q, "env-set", b.Set)
	if err != nil {
		return nil, nil, err
	}
	if string(r.Wrap) != string(row.ID) {
		return nil, nil, errConflict("env revision is not sealed to the set's bucket")
	}
	recs, err := parseRecords(r.Payload, true)
	if err != nil {
		return nil, nil, err
	}
	if !slices.Equal(recordNames(recs), b.Names) {
		return nil, nil, errConflict("damaged env revision")
	}
	return recs, &row, nil
}

// values decrypts the current revision from the open set bucket.
func (s *Server) values(ctx context.Context, q *store.Q, b envset.Binding) ([]envset.Entry, error) {
	recs, row, err := s.revisionRecords(ctx, q, b)
	if err != nil || row == nil {
		return []envset.Entry{}, err
	}
	var out []envset.Entry
	err = s.withBucket(*row, func(bk seal.Bucket, k *seal.Key) error {
		var err error
		out, err = openEntries(bk, k, b.Set, recs)
		return err
	})
	if err != nil {
		return nil, err
	}
	if envset.Validate(out) != nil {
		return nil, errConflict("damaged env revision")
	}
	return out, nil
}

// writeRevision stores the next revision of an env set from records.
func (s *Server) writeRevision(ctx context.Context, q *store.Q, b envset.Binding, row store.BucketRow, recs []envRecord) error {
	if err := checkRecordLimits(recs); err != nil {
		return err
	}
	payload, err := recordsJSON(recs)
	if err != nil {
		return err
	}
	blob := seal.RandomID()
	return q.ReplaceEnv(ctx, b, recordNames(recs), store.CipherRecord{Blob: blob[:], Payload: payload, Wrap: row.ID})
}

// mergeRecords applies an edit to records: new values come sealed already,
// unchanged entries keep their ciphertext.
func mergeRecords(old []envRecord, op string, sealed []envRecord, remove []string) []envRecord {
	m := map[string]envRecord{}
	if op != "import" {
		for _, r := range old {
			m[r.N] = r
		}
	}
	for _, r := range sealed {
		if op == "unset" {
			delete(m, r.N)
		} else {
			m[r.N] = r
		}
	}
	for _, n := range remove {
		delete(m, n)
	}
	out := make([]envRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b envRecord) int { return strings.Compare(a.N, b.N) })
	return out
}

// ---- signer records ----

func signerFields(t store.VaultTarget) [][]byte {
	return [][]byte{[]byte(t.SetID), []byte(t.Scheme), t.PublicKey}
}

// ---- what an approval needs (§4.1) ----

func (s *Server) need(row store.BucketRow, holds ...bucketHold) bucketNeed {
	return bucketNeed{Bucket: row, Holds: append([]bucketHold{instantHold()}, holds...)}
}

// matchingStanding lists active standing rules that would approve r.
func (s *Server) matchingStanding(ctx context.Context, q *store.Q, r *store.Request) ([]*store.Standing, error) {
	now := s.now()
	rules, err := q.ActiveStanding(ctx, r.HostID, now)
	if err != nil {
		return nil, err
	}
	cand := policy.Candidate{HostID: r.HostID, PeerAddress: r.PeerAddress, Kind: r.Kind, Target: r.TargetHost, LoginUser: r.LoginUser, TTL: r.TTLRequested, Scope: r.Scope, ScopeParams: r.ScopeParams, Mode: r.Mode}
	var out []*store.Standing
	for _, st := range rules {
		rule := policy.Rule{HostID: st.HostID, PeerAddress: st.PeerAddress, Kind: st.Kind, Target: st.TargetHost, LoginUser: st.LoginUser,
			MaxTTL: st.MaxTTL, ExpiresAt: st.ExpiresAt, Revoked: st.RevokedAt != nil, Scope: st.Scope, ScopeParams: st.ScopeParams, Mode: st.Mode}
		if !policy.Matches(rule, cand, now) {
			continue
		}
		if r.Kind == api.KindSSH {
			source, err := q.GetRequest(ctx, st.SourceRequestID)
			if err != nil || source.Principal != r.Principal || source.TargetAddress != r.TargetAddress || source.TargetPort != r.TargetPort || s.highRisk(r) {
				continue
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// cfAutoFor reports whether r would have been auto-approved with the bucket open.
func (s *Server) cfAutoFor(ctx context.Context, q *store.Q, r *store.Request) bool {
	if r.Mode != api.CFModeProxy || !q.Scoped() {
		return false
	}
	b, err := q.BoundResource(ctx, r.HostID, r.ID, s.now())
	if err != nil {
		return false
	}
	l, err := s.limits(ctx, q, b, r.Scope)
	return err == nil && l.Auto && r.TTLRequested > 0 && r.TTLRequested <= l.Soft
}

// decisionNeeds derives the buckets of a request or enrollment decision from
// stored state and the signed choice.
func (s *Server) decisionNeeds(ctx context.Context, q *store.Q, a canon.Action) ([]bucketNeed, error) {
	if s.seal == nil || a.Action != canon.ActionApprove || a.Object != canon.ObjectRequest && a.Object != canon.ObjectEnrollment {
		return nil, nil
	}
	if err := s.bucketsReady(); err != nil {
		return nil, err
	}
	if a.Object == canon.ObjectEnrollment {
		row, err := s.caRow(ctx, q, seal.RoleInternalCA)
		if err != nil {
			return nil, err
		}
		return []bucketNeed{s.need(row)}, nil
	}
	r, err := q.GetRequest(ctx, a.ID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	now := s.now()
	standingUntil := time.Time{}
	switch {
	case a.StandingIndefinite:
		standingUntil = untilRevoked
	case a.StandingSeconds > 0:
		standingUntil = now.Add(secs(a.StandingSeconds))
	case a.StandingHours > 0:
		standingUntil = now.Add(time.Duration(a.StandingHours) * time.Hour)
	}
	var holds []bucketHold
	if a.StandingHours > 0 || a.StandingSeconds > 0 || a.StandingIndefinite {
		holds = append(holds, standingFromHold(r.ID, standingUntil))
	}
	rules, err := s.matchingStanding(ctx, q, r)
	if err != nil {
		return nil, err
	}
	for _, st := range rules {
		holds = append(holds, rearmHold(st))
	}
	if r.Kind == api.KindCloudflare {
		if r.Mode != api.CFModeProxy {
			return nil, nil
		}
		row, err := s.cfRow(ctx, q)
		if err != nil {
			return nil, err
		}
		grantUntil := now.Add(secs(a.TTLSeconds))
		if a.Indefinite {
			grantUntil = untilRevoked
		}
		holds = append(holds, s.cfGrantHold(r.ID, grantUntil))
		if s.cfAutoFor(ctx, q, r) {
			h := s.cfAutoHold(ctx, q)
			h.Reason = "re-arms Cloudflare auto-approval until restart"
			holds = append(holds, h)
		}
		return []bucketNeed{s.need(row, holds...)}, nil
	}
	row, err := s.caRow(ctx, q, seal.RoleSSHCA)
	if err != nil {
		return nil, err
	}
	return []bucketNeed{s.need(row, holds...)}, nil
}

// addDecisionHolds keeps the buckets of an applied decision open for what it
// created (window confirm, batch): only buckets already open gain holds.
func (s *Server) addDecisionHolds(ctx context.Context, a canon.Action) {
	if !s.sealServing() || a.Action != canon.ActionApprove {
		return
	}
	needs, err := s.decisionNeeds(ctx, s.store.Q(), a)
	if err != nil {
		return
	}
	for _, n := range needs {
		var keep []bucketHold
		for _, h := range n.Holds {
			if h.Kind != "instant" {
				keep = append(keep, h)
			}
		}
		if len(keep) > 0 {
			s.seal.pool.hold(bucketSealID(n.Bucket), keep...)
		}
	}
}

// ---- reconcile and paused users ----

// reconcileHolds drops holds whose grant, rule, release, signing grant or
// window is no longer live, and turns "standing-from:<request>" into the
// rule's own hold. It runs every 15 s and after every revoke-like event.
func (s *Server) reconcileHolds(ctx context.Context) {
	if !s.sealServing() {
		return
	}
	z := s.seal
	z.pool.expire(s.now())
	z.capabilities.expire(s.now())
	q := s.store.Q()
	dead := map[string]bool{}
	for id, holds := range z.pool.allHolds() {
		for _, h := range holds {
			live, repl := s.holdLive(ctx, q, h)
			if repl != nil {
				z.pool.hold(id, *repl)
				live = false
			}
			if !live {
				dead[h.Ref] = true
			}
		}
	}
	if len(dead) > 0 {
		z.pool.drop(func(_ seal.ID, h bucketHold) bool { return dead[h.Ref] })
	}
}

func (s *Server) holdLive(ctx context.Context, q *store.Q, h bucketHold) (bool, *bucketHold) {
	now := s.now()
	kind, id, _ := strings.Cut(h.Ref, ":")
	gone := func(err error) bool { return errors.Is(err, store.ErrNotFound) }
	switch kind {
	case "tap":
		return true, nil
	case "auto":
		// Until restart, Close all, or the policy no longer auto-approving. Fails
		// closed: a policy that cannot be read drops the hold.
		on, err := s.cfAutoOn(ctx, q, id)
		return on && err == nil, nil
	case "request":
		g, err := q.GrantByRequest(ctx, id)
		if err != nil {
			return !gone(err), nil
		}
		return g.Status(now) == api.StatusApproved, nil
	case "standing":
		st, err := q.GetStanding(ctx, id)
		if err != nil {
			return !gone(err), nil
		}
		return st.RevokedAt == nil && now.Before(st.ExpiresAt), nil
	case "standing-from":
		rules, err := q.ActiveStanding(ctx, 0, now)
		if err != nil {
			return true, nil
		}
		for _, st := range rules {
			if st.SourceRequestID == id {
				h := standingHold(st)
				return true, &h
			}
		}
		return false, nil
	case "env":
		r, _, err := q.EnvRelease(ctx, id, false)
		if err != nil {
			return !gone(err), nil
		}
		return r.Status == "approved" && !r.Consumed && r.Until > now.UnixMilli(), nil
	case "sign":
		r, _, err := q.SignRequest(ctx, id, false)
		if err != nil {
			return !gone(err), nil
		}
		return r.Status == "approved" && r.Until > now.UnixMilli(), nil
	case "window":
		p := &s.seal.windows
		p.Lock()
		defer p.Unlock()
		w := p.active[id]
		return w != nil && w.live(now), nil
	}
	return false, nil
}

// liveUsers are the grants, releases, signing grants and standing rules that
// need this bucket: its holds when open, its paused users when closed.
func (s *Server) liveUsers(ctx context.Context, q *store.Q, row store.BucketRow) ([]bucketHold, error) {
	now := s.now()
	var out []bucketHold
	switch row.Kind {
	case seal.RoleSSHCA, seal.RoleCFProxy:
		rules, err := q.ActiveStanding(ctx, 0, now)
		if err != nil {
			return nil, err
		}
		for _, st := range rules {
			if row.Kind == seal.RoleSSHCA && st.Kind == api.KindSSH || row.Kind == seal.RoleCFProxy && st.Kind == api.KindCloudflare && st.Mode == api.CFModeProxy {
				out = append(out, standingHold(st))
			}
		}
		if row.Kind == seal.RoleCFProxy {
			gs, err := q.ActiveGrants(ctx, now)
			if err != nil {
				return nil, err
			}
			for _, g := range gs {
				if g.Kind == api.KindCloudflare && g.Mode == api.CFModeProxy {
					out = append(out, s.cfGrantHold(g.RequestID, g.NotAfter))
				}
			}
		}
	case "env-set":
		rs, err := q.OwnerEnvReleases(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if r.Set == row.Ref && r.Status == "approved" && !r.Consumed && r.Until > now.UnixMilli() {
				out = append(out, s.envHold(r.ID, r.Until))
			}
		}
	case "signer":
		rs, err := q.OwnerSignRequests(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if r.Set == row.Ref && r.Status == "approved" && r.Until > now.UnixMilli() {
				out = append(out, signHold(r.ID, time.UnixMilli(r.Until)))
			}
		}
	}
	return out, nil
}

func holdPlan(h bucketHold) string {
	if h.Until.IsZero() {
		return h.Reason
	}
	return fmt.Sprintf("%s until %s", h.Reason, h.Until.UTC().Format(time.RFC3339))
}
