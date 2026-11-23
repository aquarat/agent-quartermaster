package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The approval tap that also opens buckets (docs/BUCKETS.md §4). A challenge
// whose action needs buckets carries an open descriptor; the WebAuthn
// challenge is bound to it; the finish carries the browser's sealed KEKs.

// bucketNeed is one bucket an action needs and the holds it keeps afterwards.
// Holds with Kind "instant" are dropped as soon as the action is applied.
type bucketNeed struct {
	Bucket store.BucketRow
	Holds  []bucketHold
}

// tapOpen is the server half of one offered open, keyed by challenge ID.
type tapOpen struct {
	session    string
	attempt    string
	descriptor string
	needs      []bucketNeed
	scopes     []string
	expires    time.Time
	ext        protocol.AuthenticationExtensions
	// scope-enrol descriptors (enrol, test): the one credential and its salts.
	purpose string
	cred    []byte
	salts   []seal.ID
	// rekey: the fresh salt of the PRF's second evaluation; the new scope key
	// is wrapped under the KEK derived from it (descriptor "rekey_salt").
	rekeySalt *seal.ID
}
type tapRegistry struct {
	sync.Mutex
	m map[string]*tapOpen
}

func (r *tapRegistry) put(id string, t *tapOpen, now time.Time) {
	r.Lock()
	defer r.Unlock()
	if r.m == nil {
		r.m = map[string]*tapOpen{}
	}
	for k, v := range r.m {
		if !now.Before(v.expires) {
			delete(r.m, k)
		}
	}
	r.m[id] = t
}
func (r *tapRegistry) take(id string) *tapOpen {
	r.Lock()
	defer r.Unlock()
	t := r.m[id]
	delete(r.m, id)
	return t
}
func (r *tapRegistry) clear() {
	r.Lock()
	defer r.Unlock()
	clear(r.m)
}

// scopeOrder puts the installation scope first, then organisations by ID.
func scopeOrder(needs []bucketNeed) []string {
	var out []string
	for _, n := range needs {
		if !slices.Contains(out, n.Bucket.Scope) {
			out = append(out, n.Bucket.Scope)
		}
	}
	return sortScopes(out)
}
func sortScopes(out []string) []string {
	slices.SortFunc(out, func(a, b string) int {
		if a == b {
			return 0
		}
		if a == seal.ScopeInstallation {
			return -1
		}
		if b == seal.ScopeInstallation {
			return 1
		}
		return strings.Compare(a, b)
	})
	return out
}

// mergeNeeds collapses needs per bucket (a batch may name one bucket twice).
func mergeNeeds(needs []bucketNeed) []bucketNeed {
	var out []bucketNeed
	for _, n := range needs {
		i := slices.IndexFunc(out, func(x bucketNeed) bool { return bytes.Equal(x.Bucket.ID, n.Bucket.ID) })
		if i < 0 {
			out = append(out, bucketNeed{Bucket: n.Bucket, Holds: slices.Clone(n.Holds)})
			continue
		}
		for _, h := range n.Holds {
			if !slices.ContainsFunc(out[i].Holds, func(x bucketHold) bool { return x.Ref == h.Ref }) {
				out[i].Holds = append(out[i].Holds, h)
			}
		}
	}
	slices.SortFunc(out, func(a, b bucketNeed) int { return bytes.Compare(a.Bucket.ID, b.Bucket.ID) })
	return out
}

func bucketSealID(row store.BucketRow) (id seal.ID) {
	copy(id[:], row.ID)
	return
}
func (s *Server) sealBucket(row store.BucketRow) seal.Bucket {
	return seal.Bucket{Installation: s.seal.installation, ID: bucketSealID(row), Scope: row.Scope, Kind: row.Kind, Public: row.Public}
}

// holdText is the card's wording for a hold.
func holdText(h bucketHold) string {
	if h.Reason != "" {
		return h.Reason
	}
	return h.Kind
}

// descriptorBucket fields are in sorted key order: encoding/json writes a
// struct's fields in declaration order, and the descriptor is canonical JSON
// (sorted keys) that the page re-serialises and compares.
type descriptorBucket struct {
	Hold  string `json:"hold"`
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Scope string `json:"scope"`
	Until string `json:"until"`
}

// offerOpen prepares the open part of a challenge for these needs. It returns
// nil when nothing is needed. o.creds is narrowed to the passkeys that can
// open every needed scope unless every needed bucket is already open.
func (s *Server) offerOpen(ctx context.Context, sess, canonical string, needs []bucketNeed, o *owner) (*tapOpen, []byte, error) {
	return s.offerScopes(ctx, sess, canonical, needs, nil, o)
}

// offerScopes is offerOpen with extra scopes whose keys the tap must open
// without any bucket (passkey enable: the stage wraps them for the target).
func (s *Server) offerScopes(ctx context.Context, sess, canonical string, needs []bucketNeed, extra []string, o *owner) (*tapOpen, []byte, error) {
	return s.offerScopesRekey(ctx, sess, canonical, needs, extra, o, nil)
}

// offerScopesRekey is offerScopes for a rekey when rekeySalt is set: exactly
// one scope, and every passkey's second PRF input is the fresh salt.
func (s *Server) offerScopesRekey(ctx context.Context, sess, canonical string, needs []bucketNeed, extra []string, o *owner, rekeySalt *seal.ID) (*tapOpen, []byte, error) {
	if s.seal == nil || len(needs) == 0 && len(extra) == 0 {
		return nil, nil, nil
	}
	if err := s.bucketsReady(); err != nil {
		return nil, nil, err
	}
	needs = mergeNeeds(needs)
	scopes := scopeOrder(needs)
	for _, sc := range extra {
		if !slices.Contains(scopes, sc) {
			scopes = append(scopes, sc)
		}
	}
	scopes = sortScopes(scopes)
	if len(scopes) > 2 {
		return nil, nil, errBad("one approval can open buckets of at most two scopes; split the selection")
	}
	if rekeySalt != nil && len(scopes) != 1 {
		return nil, nil, errBad("a rekey opens exactly one scope")
	}
	attempt, recipient, err := s.seal.opens.Begin(sess, "approve", "")
	if err != nil {
		return nil, nil, &apiErr{429, "rate_limited", err.Error()}
	}
	d := map[string]any{"v": 1, "object": "bucket-open", "purpose": "approve", "attempt_id": attempt, "installation": s.seal.installation, "epoch": s.seal.opens.Epoch(), "recipient": encodeID(recipient), "scopes": scopes}
	if rekeySalt != nil {
		d["rekey_salt"] = encodeID(rekeySalt[:])
	}
	allOpen := len(extra) == 0
	var list []descriptorBucket
	for _, n := range needs {
		var holds, until []string
		for _, h := range n.Holds {
			holds = append(holds, holdText(h))
			if !h.Until.IsZero() {
				until = append(until, h.Until.UTC().Format(time.RFC3339))
			}
		}
		slices.Sort(until)
		u := ""
		if len(until) > 0 {
			u = until[len(until)-1]
		}
		list = append(list, descriptorBucket{Hold: strings.Join(holds, "; "), ID: encodeID(n.Bucket.ID), Kind: n.Bucket.Kind, Label: n.Bucket.Label, Scope: n.Bucket.Scope, Until: u})
		allOpen = allOpen && s.seal.pool.isOpen(bucketSealID(n.Bucket))
	}
	if list == nil {
		list = []descriptorBucket{}
	}
	d["buckets"] = list
	desc, err := reviewJSON(d)
	if err != nil {
		return nil, nil, err
	}
	wraps, err := s.store.Q().ScopeWraps(ctx, 0)
	if err != nil {
		return nil, nil, err
	}
	by := map[string]protocol.PRFValues{}
	var allowed []webauthn.Credential
	for _, c := range o.creds {
		var salts [][]byte
		for _, sc := range scopes {
			for _, w := range wraps {
				if w.Scope == sc && bytes.Equal(w.RawID, c.ID) {
					salts = append(salts, w.Salt)
				}
			}
		}
		if len(salts) != len(scopes) {
			if allOpen {
				allowed = append(allowed, c)
			}
			continue
		}
		v := protocol.PRFValues{First: salts[0]}
		if len(salts) == 2 {
			v.Second = salts[1]
		} else if rekeySalt != nil {
			v.Second = rekeySalt[:]
		}
		by[encodeID(c.ID)] = v
		allowed = append(allowed, c)
	}
	if len(allowed) == 0 {
		what := needLabels(needs)
		if what == "" {
			what = "the keys of " + strings.Join(scopes, ", ")
		}
		return nil, nil, &apiErr{423, "locked", "no passkey can open " + what + " yet: enable one in Security → Passkeys, or use the recovery key"}
	}
	o.creds = allowed
	t := &tapOpen{session: sess, attempt: attempt, descriptor: desc, needs: needs, scopes: scopes, expires: s.now().Add(ChallengeTTL), rekeySalt: rekeySalt}
	if len(by) > 0 {
		t.ext = protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{EvalByCredential: by}}
	}
	return t, seal.OpenChallenge([]byte(canonical), []byte(desc)), nil
}

func needLabels(needs []bucketNeed) string {
	var l []string
	for _, n := range needs {
		l = append(l, n.Bucket.Label)
	}
	return strings.Join(l, ", ")
}

// actionOptions builds the assertion options for a canonical action, with an
// open descriptor when the action needs buckets. selected narrows the allow list.
func (s *Server) actionOptions(ctx context.Context, sess, canonical string, needs []bucketNeed, selected *storedPasskey) (protocol.PublicKeyCredentialRequestOptions, *tapOpen, error) {
	var opts protocol.PublicKeyCredentialRequestOptions
	o, err := s.loadOwner(ctx)
	if err != nil {
		return opts, nil, err
	}
	if selected != nil {
		o.creds = []webauthn.Credential{selected.cred}
	}
	t, challenge, err := s.offerOpen(ctx, sess, canonical, needs, o)
	if err != nil {
		return opts, nil, err
	}
	if t == nil {
		challenge = sha256Bytes(canonical)
	}
	opts, err = s.requestOptions(o, challenge)
	if err != nil {
		return opts, nil, err
	}
	if t != nil && t.ext.PRF != nil {
		opts.Extensions = t.ext
	}
	return opts, t, nil
}

// openOffer is the descriptor the page must verify, show and bind.
func (t *tapOpen) offer() *api.OpenOffer {
	if t == nil {
		return nil
	}
	return &api.OpenOffer{Descriptor: t.descriptor}
}

// verifyTap checks the assertion over the (possibly bound) challenge of c and,
// when the challenge offered an open, opens the needed buckets. settle(true)
// replaces the instant hold by the descriptor's holds; settle(false) releases.
// settle is never nil and must be called once.
func (s *Server) verifyTap(ctx context.Context, sess, challengeID, canonical string, assertion json.RawMessage, pkt *api.OpenPacket) (int64, func(bool), error) {
	noop := func(bool) {}
	var t *tapOpen
	if s.seal != nil {
		t = s.seal.taps.take(challengeID)
	}
	if t == nil {
		if pkt != nil {
			return 0, noop, errBad("this approval opens no bucket")
		}
		row, err := s.verifyAssertion(ctx, sha256Bytes(canonical), assertion)
		return row, noop, err
	}
	if t.session != sess || !s.now().Before(t.expires) {
		return 0, noop, errConflict("stale approval; review again")
	}
	challenge := seal.OpenChallenge([]byte(canonical), []byte(t.descriptor))
	row, err := s.verifySelected(ctx, challenge, assertion, nil, t.ext)
	if err != nil {
		return 0, noop, err
	}
	settle, err := s.openTap(ctx, t, sess, row, challenge, pkt)
	if err != nil {
		return 0, noop, err
	}
	return row, settle, nil
}

func (s *Server) openTap(ctx context.Context, t *tapOpen, sess string, row int64, challenge []byte, pkt *api.OpenPacket) (func(bool), error) {
	z := s.seal
	ref := "tap:" + t.attempt
	instant := bucketHold{Kind: "instant", Ref: ref, Reason: "applying the approval", Until: s.now().Add(time.Minute)}
	settle := func(ok bool) {
		if ok {
			for _, n := range t.needs {
				var keep []bucketHold
				for _, h := range n.Holds {
					if h.Kind != "instant" {
						keep = append(keep, h)
					}
				}
				z.pool.hold(bucketSealID(n.Bucket), keep...)
			}
		}
		z.pool.release(ref)
	}
	fail := func(err error) (func(bool), error) { z.pool.release(ref); return nil, err }
	// Buckets already open only gain the instant hold; the rest need the packet.
	var closed []bucketNeed
	for _, n := range t.needs {
		if !z.pool.hold(bucketSealID(n.Bucket), instant) {
			closed = append(closed, n)
		}
	}
	if len(closed) == 0 {
		if pkt != nil && pkt.AttemptID == t.attempt {
			// The page evaluated PRF although nothing was closed: consume and discard.
			// Only this tap's attempt: another pending tap's attempt is left alone.
			if at, err := z.opens.Take(sess, "approve", pkt.AttemptID); err == nil {
				enc, _ := strictB64(pkt.Enc, 65)
				ct, _ := strictB64(pkt.Ciphertext, 512)
				if keys, err := at.Open(z.installation, z.opens.Epoch(), challenge, nil, enc, ct); err == nil {
					destroyKeys(keys)
				}
			}
		}
		return settle, nil
	}
	if pkt == nil {
		return fail(&apiErr{423, "locked", "this approval must open " + needLabels(closed) + ": use a passkey that can open it"})
	}
	scopeKeys, pk, err := s.tapScopeKeys(ctx, t, sess, row, challenge, pkt)
	if err != nil {
		return fail(err)
	}
	defer destroyKeys(scopeKeys)
	// A rekey replaces bucket keys under scopeMu and evicts them before it
	// unlocks: re-read each bucket under the same lock so a key from before a
	// rekey is never installed after it.
	z.scopeMu.Lock()
	defer z.scopeMu.Unlock()
	q := s.store.Q()
	opened := 0
	for i, scope := range t.scopes {
		skS := scopeKeys[i]
		sc, err := q.Scope(ctx, scope)
		if err != nil {
			return fail(err)
		}
		for _, n := range closed {
			if n.Bucket.Scope != scope {
				continue
			}
			cur, err := q.Bucket(ctx, n.Bucket.ID)
			if err != nil || cur.Scope != scope || !bytes.Equal(cur.Public, n.Bucket.Public) {
				return fail(errConflict(n.Bucket.Label + " changed since the review (rekeyed or removed); review again"))
			}
			k, err := s.sealBucket(cur).UnwrapWith(skS, sc.Public, cur.Wrap)
			if err != nil {
				return fail(errForbidden(n.Bucket.Label + " did not open; nothing was applied"))
			}
			z.pool.install(bucketSealID(cur), k, instant)
			opened++
		}
	}
	s.log.Info("buckets opened by approval", "count", opened, "passkey", passkeyID(pk.CredentialID))
	return settle, nil
}

// tapScopeKeys consumes the tap's attempt, opens the packet into KEKs and
// unwraps the signing passkey's scope keys, in descriptor order. The KEKs are
// wiped here; the caller destroys the scope keys.
func (s *Server) tapScopeKeys(ctx context.Context, t *tapOpen, sess string, row int64, challenge []byte, pkt *api.OpenPacket) ([]*seal.Key, *store.Passkey, error) {
	keks, pk, err := s.tapKEKs(ctx, t, sess, row, challenge, pkt)
	if err != nil {
		return nil, nil, err
	}
	defer destroyKeys(keks)
	out, err := s.unwrapScopes(ctx, row, t.scopes, keks[:len(t.scopes)])
	return out, pk, err
}

// tapKEKs consumes the tap's attempt and opens the packet into one KEK per
// descriptor scope (the caller destroys them).
func (s *Server) tapKEKs(ctx context.Context, t *tapOpen, sess string, row int64, challenge []byte, pkt *api.OpenPacket) ([]*seal.Key, *store.Passkey, error) {
	z := s.seal
	if pkt == nil || pkt.AttemptID != t.attempt {
		return nil, nil, errConflict("stale approval; review again")
	}
	at, err := z.opens.Take(sess, "approve", pkt.AttemptID)
	if err != nil {
		return nil, nil, errConflict("stale approval; review again")
	}
	pk, err := s.passkeyRow(ctx, row)
	if err != nil {
		return nil, nil, err
	}
	enc, err1 := strictB64(pkt.Enc, 65)
	ct, err2 := strictB64(pkt.Ciphertext, 512)
	if err1 != nil || err2 != nil {
		return nil, nil, errBad("invalid open packet")
	}
	keks, err := at.Open(z.installation, z.opens.Epoch(), challenge, pk.CredentialID, enc, ct)
	if err != nil {
		return nil, nil, errForbidden("the passkey's keys could not be read; nothing was opened")
	}
	want := len(t.scopes)
	if t.rekeySalt != nil {
		want++ // the second evaluation, at the fresh salt
	}
	if len(keks) != want {
		destroyKeys(keks)
		return nil, nil, errForbidden("wrong number of keys for this approval; nothing was opened")
	}
	return keks, pk, nil
}

// unwrapScopes opens the passkey's wraps of these scopes with its KEKs.
func (s *Server) unwrapScopes(ctx context.Context, row int64, scopes []string, keks []*seal.Key) ([]*seal.Key, error) {
	q := s.store.Q()
	var out []*seal.Key
	for i, scope := range scopes {
		sw, err := q.ScopeWrap(ctx, row, scope)
		if err != nil {
			destroyKeys(out)
			return nil, &apiErr{423, "locked", "this passkey cannot open " + scopeName(ctx, q, scope) + " buckets: enable it in Security → Passkeys"}
		}
		sc, err := q.Scope(ctx, scope)
		if err != nil {
			destroyKeys(out)
			return nil, err
		}
		skS, err := s.passkeyScope(sw).Unwrap(keks[i], sw.Wrap, sc.Public)
		if err != nil {
			destroyKeys(out)
			return nil, errForbidden("this passkey's key for " + scopeName(ctx, q, scope) + " did not open; nothing was opened")
		}
		out = append(out, skS)
		_ = q.MarkScopeWrapTested(ctx, sw.ID, s.now())
	}
	return out, nil
}

// scopeName is a scope's display name: "installation" or the organisation's title.
func scopeName(ctx context.Context, q *store.Q, scope string) string {
	if scope == seal.ScopeInstallation {
		return "installation"
	}
	if o, err := q.VaultOrg(ctx, scope); err == nil {
		return o.Title
	}
	return scope
}

func destroyKeys(keys []*seal.Key) {
	for _, k := range keys {
		k.Destroy()
	}
}

func (s *Server) passkeyScope(w store.ScopeWrapRow) seal.PasskeyScope {
	o := seal.PasskeyScope{Installation: s.seal.installation, RPID: s.rpID, RawID: w.RawID, Scope: w.Scope}
	copy(o.Salt[:], w.Salt)
	return o
}

func (s *Server) passkeyRow(ctx context.Context, row int64) (*store.Passkey, error) {
	all, err := s.store.Q().Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == row {
			return all[i], nil
		}
	}
	return nil, errForbidden("passkey no longer registered")
}

// withBucket lends the open key of a bucket to fn, or reports it closed in
// the agent-facing 423 shape (the CLI keeps waiting within its deadline).
func (s *Server) withBucket(row store.BucketRow, fn func(seal.Bucket, *seal.Key) error) error {
	if err := s.bucketsReady(); err != nil {
		return err
	}
	b := s.sealBucket(row)
	err := s.seal.pool.use(b.ID, func(k *seal.Key) error { return fn(b, k) })
	if errors.Is(err, errBucketClosed) {
		return closedErr(row)
	}
	return err
}
func closedErr(row store.BucketRow) *apiErr {
	return &apiErr{423, "locked", fmt.Sprintf("%s is closed: waiting for the owner to reopen it", row.Label)}
}

// enrolTap offers a scope-enrol descriptor (purpose "enrol" or "test"): one
// named credential evaluates PRF at explicit salts, one per scope. The page
// derives the KEKs and seals them to the descriptor's recipient as for an
// approval (contract "Enrolment / stage descriptors").
func (s *Server) enrolTap(sess, purpose, canonical string, cred webauthn.Credential, scopes []string, salts []seal.ID) (protocol.PublicKeyCredentialRequestOptions, *tapOpen, error) {
	var opts protocol.PublicKeyCredentialRequestOptions
	if len(scopes) == 0 || len(scopes) > 2 || len(salts) != len(scopes) {
		return opts, nil, errBad("name one or two scopes")
	}
	attempt, recipient, err := s.seal.opens.Begin(sess, purpose, "")
	if err != nil {
		return opts, nil, &apiErr{429, "rate_limited", err.Error()}
	}
	list := make([]string, len(salts))
	for i, x := range salts {
		list[i] = encodeID(x[:])
	}
	d := map[string]any{"v": 1, "object": "scope-enrol", "purpose": purpose, "attempt_id": attempt, "installation": s.seal.installation, "epoch": s.seal.opens.Epoch(),
		"recipient": encodeID(recipient), "scopes": scopes, "salts": list, "credential_id": encodeID(cred.ID), "buckets": []descriptorBucket{}}
	desc, err := reviewJSON(d)
	if err != nil {
		return opts, nil, err
	}
	o := &owner{id: s.ownerID, name: s.cfg.OwnerName, creds: []webauthn.Credential{cred}}
	opts, err = s.requestOptions(o, seal.OpenChallenge([]byte(canonical), []byte(desc)))
	if err != nil {
		return opts, nil, err
	}
	v := protocol.PRFValues{First: salts[0][:]}
	if len(salts) == 2 {
		v.Second = salts[1][:]
	}
	ext := protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: v}}
	opts.Extensions = ext
	t := &tapOpen{session: sess, attempt: attempt, descriptor: desc, scopes: scopes, expires: s.now().Add(ChallengeTTL), ext: ext, purpose: purpose, cred: bytes.Clone(cred.ID), salts: salts}
	return opts, t, nil
}

// enrolKEKs opens the packet of an enrol or test tap: one KEK per scope,
// bound to the tap's credential and bound challenge. The caller destroys them.
func (s *Server) enrolKEKs(t *tapOpen, sess, canonical string, pkt *api.OpenPacket) ([]*seal.Key, error) {
	z := s.seal
	if pkt == nil || pkt.AttemptID != t.attempt {
		return nil, errConflict("stale ceremony; start again")
	}
	at, err := z.opens.Take(sess, t.purpose, pkt.AttemptID)
	if err != nil {
		return nil, errConflict("stale ceremony; start again")
	}
	enc, err1 := strictB64(pkt.Enc, 65)
	ct, err2 := strictB64(pkt.Ciphertext, 512)
	if err1 != nil || err2 != nil {
		return nil, errBad("invalid open packet")
	}
	keks, err := at.Open(z.installation, z.opens.Epoch(), seal.OpenChallenge([]byte(canonical), []byte(t.descriptor)), t.cred, enc, ct)
	if err != nil {
		return nil, errForbidden("the passkey's keys could not be read; nothing was changed")
	}
	if len(keks) != len(t.scopes) {
		destroyKeys(keks)
		return nil, errForbidden("wrong number of keys; nothing was changed")
	}
	return keks, nil
}
