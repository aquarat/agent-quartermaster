package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

func (s *Server) sealRoutes(m *http.ServeMux) {
	s.capabilityRoutes(m)
	s.approvalRoutes(m)
	s.envWebRoutes(m)
	s.vaultRoutes(m)
	s.recoveryRoutes(m)
	m.Handle("GET /api/ui/seal/status", s.requireSession(s.sealStatus))
	m.Handle("POST /api/ui/seal/drill", s.requireSession(s.sealDrill))
	s.stageRoutes(m)
	// Seal control also serves "activate" while a stage waits for it.
	for path, fn := range map[string]capHandler{"challenge": s.sealControlBegin, "finish": s.sealControlFinish} {
		m.Handle("POST /api/ui/seal/control/"+path, s.requireSession(func(w http.ResponseWriter, r *http.Request, sess string) {
			if s.seal == nil || s.seal.mode != modeSetup {
				if err := s.bucketsReady(); err != nil {
					s.writeErr(w, r, err)
					return
				}
			}
			out, err := fn(r.Context(), r, sess)
			if err != nil {
				s.writeErr(w, r, mapNotFound(err))
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, out)
		}))
	}
}
func (s *Server) sealOwner(ctx context.Context, q *store.Q, sess string, pk int64) error {
	if v, _ := ctx.Value(verifiedSignerKey{}).(*verifiedIdentity); v != nil && v.row != 0 {
		if v.row != pk || q.SameSigner(ctx, pk, v.raw) != nil {
			return errForbidden("actual signing credential no longer enrolled")
		}
	}
	if _, err := q.GlobalOwner(ctx, sess, pk, s.now()); err != nil {
		return errForbidden("owner session and credential required")
	}
	ok, err := q.SessionValid(ctx, sess, accessSub(ctx), s.now())
	if err != nil || !ok {
		return errForbidden("session no longer valid")
	}
	return nil
}

// ---- status (contract "GET /api/ui/seal/status") ----

type scopeView struct {
	Scope   string `json:"scope"`
	Title   string `json:"title"`
	Buckets int    `json:"buckets"`
	HasKey  bool   `json:"has_key"`
	// Tested: some passkey has opened the scope key since it was created or
	// rekeyed. A keyed scope that is not tested opens only from the passkey
	// that made it (untested) or the recovery key.
	Tested bool `json:"tested"`
}
type pausedView struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}
type bucketView struct {
	ID         string       `json:"id"`
	Kind       string       `json:"kind"`
	Label      string       `json:"label"`
	Scope      string       `json:"scope"`
	ScopeTitle string       `json:"scope_title"`
	Open       bool         `json:"open"`
	OpenedAt   *time.Time   `json:"opened_at,omitempty"`
	Holds      []bucketHold `json:"holds"`
	Paused     []pausedView `json:"paused"`
}
type coverageScope struct {
	Scope  string `json:"scope"`
	Tested bool   `json:"tested"`
}
type passkeyCoverage struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Current bool            `json:"current"`
	PRF     bool            `json:"prf"`
	Scopes  []coverageScope `json:"scopes"`
	Opens   int             `json:"opens"`
	Of      int             `json:"of"`
	Missing []string        `json:"missing"`
}
type sealView struct {
	Mode           string            `json:"mode"`
	Installation   *seal.ID          `json:"installation,omitempty"`
	Epoch          *seal.ID          `json:"epoch,omitempty"`
	Scopes         []scopeView       `json:"scopes"`
	Buckets        []bucketView      `json:"buckets"`
	Passkeys       []passkeyCoverage `json:"passkeys"`
	Active         []windowInfo      `json:"active_windows,omitempty"`
	Profiles       []windowProfile   `json:"profiles,omitempty"`
	VerifiedAccess bool              `json:"verified_access,omitempty"`
	LeafExpires    string            `json:"leaf_expires,omitempty"`
	LeafRepair     string            `json:"leaf_repair,omitempty"`
	Stage          *stageView        `json:"stage,omitempty"` // setup mode only
}

func (s *Server) sealStatus(w http.ResponseWriter, r *http.Request, sess string) {
	if s.seal == nil {
		writeJSON(w, 200, sealView{Mode: "unsealed", Scopes: []scopeView{}, Buckets: []bucketView{}, Passkeys: []passkeyCoverage{}})
		return
	}
	view, err := s.sealView(r.Context(), sess)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, view)
}

func (s *Server) leafRepair() string {
	text, _ := reviewJSON(map[string]any{"ca_pin": s.pki.CAPin(), "configured_sans": s.cfg.TLSSANs, "effect": "Renew the server-only agent TLS leaf, then restart (every bucket closes)"})
	return text
}

func (s *Server) sealView(ctx context.Context, sess string) (sealView, error) {
	z := s.seal
	epoch := z.opens.Epoch()
	v := sealView{Mode: z.mode, Installation: &z.installation, Epoch: &epoch, Scopes: []scopeView{}, Buckets: []bucketView{}, Passkeys: []passkeyCoverage{}}
	if s.pki.ServerLeaf != nil {
		v.LeafExpires = s.pki.ServerLeaf.NotAfter.UTC().Format(time.RFC3339)
	}
	v.LeafRepair = s.leafRepair()
	if z.stage != nil && z.mode == modeSetup {
		row, err := s.store.Q().SessionPasskeyID(ctx, sess)
		if err == nil && s.sealOwner(ctx, s.store.Q(), sess, row) == nil {
			v.Stage, err = s.stageStatus(ctx, sess)
		}
		return v, err
	}
	if z.mode != modeBuckets {
		return v, nil
	}
	q := s.store.Q()
	row, err := q.SessionPasskeyID(ctx, sess)
	if err != nil {
		return v, err
	}
	if err = s.sealOwner(ctx, q, sess, row); err != nil {
		return v, err
	}
	v.VerifiedAccess = s.access != nil && accessSub(ctx) != ""
	if v.Profiles, err = s.windowProfiles(ctx, q, sess, row); err != nil {
		return v, err
	}
	pool := &z.windows
	pool.Lock()
	gen, err := q.WindowEpoch(ctx)
	if err == nil {
		pool.prune(s.now(), gen)
		for _, w := range pool.active {
			v.Active = append(v.Active, windowInfo{w.terms.ID, w.terms.Title, w.opener, w.opened, w.absolute})
		}
	}
	pool.Unlock()
	if err != nil {
		return v, err
	}
	// Scopes: the installation and every organisation, with or without a key.
	scopes, err := q.Scopes(ctx)
	if err != nil {
		return v, err
	}
	orgs, err := q.VaultOrgs(ctx)
	if err != nil {
		return v, err
	}
	buckets, err := q.Buckets(ctx)
	if err != nil {
		return v, err
	}
	count := map[string]int{}
	for _, b := range buckets {
		count[b.Scope]++
	}
	has := func(sc string) bool {
		return slices.ContainsFunc(scopes, func(x store.ScopeRow) bool { return x.Scope == sc })
	}
	titles := map[string]string{seal.ScopeInstallation: "Installation"}
	v.Scopes = append(v.Scopes, scopeView{Scope: seal.ScopeInstallation, Title: "Installation", Buckets: count[seal.ScopeInstallation], HasKey: has(seal.ScopeInstallation)})
	for _, o := range orgs {
		titles[o.ID] = o.Title
		v.Scopes = append(v.Scopes, scopeView{Scope: o.ID, Title: o.Title, Buckets: count[o.ID], HasKey: has(o.ID)})
	}
	for i := range v.Scopes {
		if v.Scopes[i].HasKey {
			if v.Scopes[i].Tested, err = q.ScopeTested(ctx, v.Scopes[i].Scope); err != nil {
				return v, err
			}
		}
	}
	open := z.pool.snapshot()
	for _, b := range buckets {
		bv := bucketView{ID: encodeID(b.ID), Kind: b.Kind, Label: b.Label, Scope: b.Scope, ScopeTitle: titles[b.Scope], Holds: []bucketHold{}, Paused: []pausedView{}}
		if ob, ok := open[bucketSealID(b)]; ok {
			bv.Open, bv.Holds = true, ob.Holds
			t := ob.Opened
			bv.OpenedAt = &t
			if bv.Holds == nil {
				bv.Holds = []bucketHold{}
			}
		}
		users, err := s.liveUsers(ctx, q, b)
		if err != nil {
			return v, err
		}
		for _, u := range users {
			if !slices.ContainsFunc(bv.Holds, func(h bucketHold) bool { return h.Ref == u.Ref }) {
				bv.Paused = append(bv.Paused, pausedView{u.Kind, u.Ref, u.Reason})
			}
		}
		v.Buckets = append(v.Buckets, bv)
	}
	keys, err := loadPasskeys(ctx, q)
	if err != nil {
		return v, err
	}
	wraps, err := q.ScopeWraps(ctx, 0)
	if err != nil {
		return v, err
	}
	for _, k := range keys {
		c := passkeyCoverage{ID: k.id, Name: k.Name, Current: k.ID == row, Scopes: []coverageScope{}, Of: len(buckets), Missing: []string{}}
		for _, w := range wraps {
			if w.Passkey == k.ID {
				c.Scopes = append(c.Scopes, coverageScope{w.Scope, w.Tested != nil})
				c.Opens += count[w.Scope]
			}
		}
		c.PRF = len(c.Scopes) > 0
		for _, sc := range v.Scopes {
			if !slices.ContainsFunc(c.Scopes, func(x coverageScope) bool { return x.Scope == sc.Scope }) {
				c.Missing = append(c.Missing, sc.Scope)
			}
		}
		v.Passkeys = append(v.Passkeys, c)
	}
	return v, nil
}

// ---- seal control (v3 object "seal-control") ----

type controlChoice struct {
	Action  string   `json:"action"`
	Buckets []string `json:"buckets,omitempty"`
	Scope   string   `json:"scope,omitempty"`
}

type controlBucket struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// controlPlan validates a choice against current state and returns the
// canonical's own fields and the buckets the tap must open.
func (s *Server) controlPlan(ctx context.Context, q *store.Q, c controlChoice, openCount int) (map[string]any, []bucketNeed, error) {
	fields := map[string]any{}
	if s.seal.mode == modeSetup && c.Action != "activate" {
		return nil, nil, errConflict("finish staging first")
	}
	switch c.Action {
	case "close-all":
		if c.Scope != "" || len(c.Buckets) > 0 {
			return nil, nil, errBad("close-all takes no buckets or scope")
		}
		fields["open_buckets"] = openCount
		return fields, nil, nil
	case "renew-leaf":
		if c.Scope != "" || len(c.Buckets) > 0 {
			return nil, nil, errBad("renew-leaf takes no buckets or scope")
		}
		row, err := s.caRow(ctx, q, seal.RoleInternalCA)
		if err != nil {
			return nil, nil, err
		}
		fields["repair"] = s.leafRepair()
		return fields, []bucketNeed{s.need(row)}, nil
	case "reopen":
		if c.Scope != "" || len(c.Buckets) == 0 || len(c.Buckets) > 16 || !slices.IsSorted(c.Buckets) {
			return nil, nil, errBad("name the buckets to reopen, sorted")
		}
		var list []controlBucket
		var needs []bucketNeed
		for i, id := range c.Buckets {
			raw, err := strictB64(id, 32)
			if err != nil || len(raw) != 32 || i > 0 && c.Buckets[i-1] == id {
				return nil, nil, errBad("invalid bucket id")
			}
			row, err := q.Bucket(ctx, raw)
			if err != nil {
				return nil, nil, mapNotFound(err)
			}
			users, err := s.liveUsers(ctx, q, row)
			if err != nil {
				return nil, nil, err
			}
			list = append(list, controlBucket{id, row.Label})
			needs = append(needs, s.need(row, users...))
		}
		fields["buckets"] = list
		return fields, needs, nil
	case "rekey":
		if len(c.Buckets) > 0 || c.Scope == "" {
			return nil, nil, errBad("name the scope to rekey")
		}
		if _, err := q.Scope(ctx, c.Scope); err != nil {
			return nil, nil, errConflict("this scope has no key")
		}
		rows, err := q.ScopeBuckets(ctx, c.Scope)
		if err != nil {
			return nil, nil, err
		}
		fields["scope"], fields["scope_title"], fields["bucket_count"] = c.Scope, scopeName(ctx, q, c.Scope), len(rows)
		var needs []bucketNeed
		for _, row := range rows {
			needs = append(needs, s.need(row))
		}
		return fields, needs, nil
	case "activate":
		// A plain signature over the manifest: the root runner verifies it with its pins.
		st := s.seal.stage
		if s.seal.mode != modeSetup || st == nil {
			return nil, nil, errConflict("nothing is staged to activate")
		}
		if c.Scope != "" || len(c.Buckets) > 0 {
			return nil, nil, errBad("activate takes no buckets or scope")
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		if !st.ready() {
			return nil, nil, errConflict("create and test every scope key and prove the recovery key first")
		}
		text, err := s.stageManifest(st)
		if err != nil {
			return nil, nil, err
		}
		fields["manifest"] = text
		return fields, nil, nil
	}
	return nil, nil, errBad("invalid seal action")
}

func (s *Server) controlCanonical(fields map[string]any, action, nonce, at string) (string, error) {
	m := map[string]any{"v": 3, "object": "seal-control", "action": action, "id": encodeID(s.seal.installation[:]), "epoch": s.seal.opens.Epoch(), "nonce": nonce, "issued_at": at}
	for k, v := range fields {
		m[k] = v
	}
	return reviewJSON(m)
}

func (s *Server) sealControlBegin(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in controlChoice
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	q := s.store.Q()
	fields, needs, err := s.controlPlan(ctx, q, in, s.seal.pool.count())
	if err != nil {
		return nil, err
	}
	text, err := s.controlCanonical(fields, in.Action, canon.NewNonce(), s.now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	if in.Action == "rekey" {
		// The tap opens the scope key (PRF first = the passkey's salt) and, at
		// a fresh salt (second), yields the KEK the new scope key is wrapped
		// under, so a KEK seen before the rekey does not open it (§7).
		o, err := s.loadOwner(ctx)
		if err != nil {
			return nil, err
		}
		salt := seal.RandomID()
		t, challenge, err := s.offerScopesRekey(ctx, sess, text, needs, []string{in.Scope}, o, &salt)
		if err != nil {
			return nil, err
		}
		opts, err := s.requestOptions(o, challenge)
		if err != nil {
			return nil, err
		}
		opts.Extensions = t.ext
		id, err := s.storeChallenge(ctx, sess, "seal-control", in.Action, text, t)
		if err != nil {
			return nil, err
		}
		return api.ChallengeResponse{ChallengeID: id, Canonical: text, PublicKey: opts, Open: t.offer()}, nil
	}
	return s.beginTap(ctx, sess, "seal-control", in.Action, text, needs, nil)
}

func (s *Server) sealControlFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil || c.SessionHash != sess || c.ObjectType != "seal-control" {
		if err == nil && s.seal != nil {
			s.seal.taps.take(c.ID)
		}
		return nil, errConflict("stale seal action")
	}
	var meta struct {
		Action  string
		Nonce   string
		At      string          `json:"issued_at"`
		Count   int             `json:"open_buckets"`
		Buckets []controlBucket `json:"buckets"`
		Scope   string          `json:"scope"`
	}
	if json.Unmarshal([]byte(c.Canonical), &meta) != nil || meta.Action != c.ObjectID {
		s.seal.taps.take(c.ID)
		return nil, errBad("bad seal action")
	}
	choice := controlChoice{Action: meta.Action, Scope: meta.Scope}
	for _, b := range meta.Buckets {
		choice.Buckets = append(choice.Buckets, b.ID)
	}
	q := s.store.Q()
	fields, _, err := s.controlPlan(ctx, q, choice, meta.Count)
	if err == nil {
		var expected string
		expected, err = s.controlCanonical(fields, meta.Action, meta.Nonce, meta.At)
		if err == nil && expected != c.Canonical {
			err = errConflict("seal state changed; review again")
		}
	}
	if err != nil {
		s.seal.taps.take(c.ID)
		return nil, err
	}
	if meta.Action == "rekey" {
		return s.rekey(ctx, sess, c, in)
	}
	if meta.Action == "activate" {
		if in.Open != nil {
			return nil, errBad("activation opens nothing")
		}
		row, err := s.verifyAssertion(ctx, sha256Bytes(c.Canonical), in.Assertion)
		if err != nil {
			return nil, err
		}
		// When the runner drives the stage it verifies this signature against its pins
		// before it finishes: refuse an unpinned passkey while that is only a message.
		if _, installed := s.runnerStatus(); installed {
			if err = s.pinnedFor(ctx, row); err != nil {
				return nil, err
			}
		}
		if err = s.activateStage(ctx, sess, row, c.Canonical, in.Assertion); err != nil {
			return nil, err
		}
		defer s.stopSealed()
		return api.OK{OK: true}, nil
	}
	row, settle, err := s.verifyTap(ctx, sess, c.ID, c.Canonical, in.Assertion, in.Open)
	if err != nil {
		return nil, err
	}
	restart := false
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := s.sealOwner(ctx, q, sess, row); err != nil {
			return err
		}
		switch meta.Action {
		case "renew-leaf":
			if err := s.withCA(ctx, q, seal.RoleInternalCA, func(p *pki.PKI) error { return p.RenewLeaf(s.cfg.TLSSANs) }); err != nil {
				return err
			}
			restart = true
			return q.Audit(ctx, s.now(), "owner", "renew_tls_leaf", "seal", c.Canonical)
		case "reopen":
			return q.Audit(ctx, s.now(), "owner", "seal_reopen", "seal", fmt.Sprintf("passkey=%d canonical=%s", row, c.Canonical))
		case "close-all":
			return q.Audit(ctx, s.now(), "owner", "seal_close_all", "seal", fmt.Sprintf("passkey=%d canonical=%s", row, c.Canonical))
		}
		return errBad("invalid seal action")
	})
	settle(err == nil)
	if err != nil {
		return nil, err
	}
	switch meta.Action {
	case "close-all":
		s.closeAll()
		s.log.Info("every bucket closed by the owner")
	case "reopen":
		s.reconcileHolds(ctx)
	}
	s.bcast.notify()
	if restart {
		defer s.stopSealed()
	}
	return api.OK{OK: true}, nil
}

// closeAll wipes every open bucket and hold and ends every window (§5). It is
// also the hook for the planned bastion-SSH approval.
func (s *Server) closeAll() {
	z := s.seal
	z.windows.Lock()
	clear(z.windows.active)
	z.windows.Unlock()
	z.taps.clear()
	z.opens.Invalidate()
	z.capabilities.wipe()
	z.pool.closeAll()
}

// rekey replaces a scope key and every bucket key of the scope, re-encrypts
// every record, drops drafts, closes the scope's open buckets and keeps only
// the tapping passkey's wrap (§7).
func (s *Server) rekey(ctx context.Context, sess string, c *store.Challenge, in api.DecideRequest) (any, error) {
	z := s.seal
	t := z.taps.take(c.ID)
	if t == nil || t.session != sess || !s.now().Before(t.expires) || len(t.scopes) != 1 || t.rekeySalt == nil {
		return nil, errConflict("stale approval; review again")
	}
	scope := t.scopes[0]
	challenge := seal.OpenChallenge([]byte(c.Canonical), []byte(t.descriptor))
	row, err := s.verifySelected(ctx, challenge, in.Assertion, nil, t.ext)
	if err != nil {
		return nil, err
	}
	if in.Open == nil {
		return nil, &apiErr{423, "locked", "rekey must open the scope: use a passkey that can open it"}
	}
	keks, _, err := s.tapKEKs(ctx, t, sess, row, challenge, in.Open)
	if err != nil {
		return nil, err
	}
	defer destroyKeys(keks)
	olds, err := s.unwrapScopes(ctx, row, t.scopes, keks[:1])
	if err != nil {
		return nil, err
	}
	defer destroyKeys(olds)
	z.scopeMu.Lock()
	defer z.scopeMu.Unlock()
	newScope, pubS, err := seal.NewKeyPair()
	if err != nil {
		return nil, err
	}
	defer newScope.Destroy()
	var ids []seal.ID
	var count int
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := s.sealOwner(ctx, q, sess, row); err != nil {
			return err
		}
		old, err := q.Scope(ctx, scope)
		if err != nil {
			return err
		}
		rows, err := q.ScopeBuckets(ctx, scope)
		if err != nil {
			return err
		}
		for _, b := range rows {
			if err := s.rekeyBucket(ctx, q, b, olds[0], old.Public, pubS); err != nil {
				return err
			}
			ids = append(ids, bucketSealID(b))
		}
		count = len(rows)
		rec, err := seal.Scope{Installation: z.installation, Name: scope, Public: pubS}.RecoveryWrap(z.recipient, newScope)
		if err != nil {
			return err
		}
		if err = q.ReplaceScope(ctx, store.ScopeRow{Scope: scope, Public: pubS, Recovery: rec}); err != nil {
			return err
		}
		sw, err := q.ScopeWrap(ctx, row, scope)
		if err != nil {
			return err
		}
		// The new wrap is under the fresh salt's KEK (the second evaluation of
		// this tap). The broker cannot check that KEK before it is used, so the
		// wrap is untested until it next opens (Admin → Passkeys → Test).
		sw.Salt = bytes.Clone(t.rekeySalt[:])
		w, err := s.passkeyScope(sw).Wrap(keks[1], newScope, pubS)
		if err != nil {
			return err
		}
		if err = q.RekeyScopeWrap(ctx, store.ScopeWrapRow{Passkey: row, Scope: scope, Salt: sw.Salt, Wrap: w, Created: s.now()}); err != nil {
			return err
		}
		if err = q.DeleteScopeWraps(ctx, scope, row); err != nil {
			return err
		}
		if err = q.DropScopeDrafts(ctx, scope); err != nil {
			return err
		}
		return q.Audit(ctx, s.now(), "owner", "seal_rekey", "scope:"+scope, fmt.Sprintf("passkey=%d buckets=%d canonical=%s", row, len(rows), c.Canonical))
	})
	if err != nil {
		return nil, err
	}
	z.pool.evict(ids...)
	_ = s.store.CheckpointWAL(ctx)
	s.bcast.notify()
	s.notify.Send("aqmas: rekey", fmt.Sprintf("Scope %s rekeyed: %d bucket(s); test the rekeying passkey, then enable the other passkeys again", scope, count), s.cfg.PublicBaseURL+"/")
	return map[string]any{"ok": true, "buckets": count}, nil
}

// rekeyBucket gives one bucket a new key pair under the new scope key and
// re-encrypts its records. Old keys are wiped before returning.
func (s *Server) rekeyBucket(ctx context.Context, q *store.Q, row store.BucketRow, oldScope *seal.Key, oldScopePub, newScopePub []byte) error {
	b := s.sealBucket(row)
	oldKey, err := b.UnwrapWith(oldScope, oldScopePub, row.Wrap)
	if err != nil {
		return errForbidden(row.Label + " did not open; nothing was changed")
	}
	defer oldKey.Destroy()
	newKey, pub, err := seal.NewKeyPair()
	if err != nil {
		return err
	}
	defer newKey.Destroy()
	nb := b
	nb.Public = pub
	wrap, err := nb.WrapTo(newScopePub, newKey)
	if err != nil {
		return err
	}
	reseal := func(role string, fields [][]byte, rec []byte) ([]byte, error) {
		p, err := b.Open(oldKey, role, fields, rec)
		if err != nil {
			return nil, errConflict(row.Label + ": a record failed authentication; nothing was changed")
		}
		defer clear(p)
		return nb.Seal(role, fields, p)
	}
	var payload []byte
	switch row.Kind {
	case seal.RoleSSHCA, seal.RoleInternalCA:
		if payload, err = reseal(row.Kind, nil, row.Payload); err != nil {
			return err
		}
	case seal.RoleCFProxy:
		if payload, err = reseal(row.Kind, s.cfRecordFields(row), row.Payload); err != nil {
			return err
		}
	case "env-set":
		rev, err := q.SetRevision(ctx, row.Ref)
		if err != nil {
			return err
		}
		if rev > 0 {
			cur, err := q.EnvCipher(ctx, row.Ref, rev)
			if err != nil {
				return err
			}
			if !bytes.Equal(cur.Wrap, row.ID) {
				return errConflict(row.Label + ": revision is not sealed to its bucket")
			}
			recs, err := parseRecords(cur.Payload, true)
			if err != nil {
				return err
			}
			for i, r := range recs {
				id, err1 := strictB64(r.I, 32)
				c, err2 := strictB64(r.C, 8192+81+16)
				if err1 != nil || err2 != nil {
					return errConflict("damaged env record")
				}
				n, err := reseal(seal.RoleEnvEntry, entryFields(row.Ref, id, r.N), c)
				if err != nil {
					return err
				}
				recs[i].C = encodeID(n)
			}
			body, err := recordsJSON(recs)
			if err != nil {
				return err
			}
			if err = q.RekeyEnv(ctx, row.Ref, rev, body, row.ID); err != nil {
				return err
			}
		}
	case "signer":
		scheme, public, rec, err := q.SignerKey(ctx, row.Ref)
		if err != nil {
			return err
		}
		n, err := reseal(seal.RoleSignerKey, signerFields(store.VaultTarget{SetID: row.Ref, Scheme: scheme, PublicKey: public}), rec.Payload)
		if err != nil {
			return err
		}
		if err = q.RekeySigner(ctx, row.Ref, n, row.ID); err != nil {
			return err
		}
	}
	return q.UpdateBucket(ctx, row.ID, pub, wrap, payload)
}
