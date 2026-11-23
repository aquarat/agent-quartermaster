package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Passkey capabilities in format 2 (docs/BUCKETS.md §7, contract "Passkey
// enable"). An existing passkey signs the capability and, in the same tap,
// opens the keys of at most two scopes; the target passkey then taps once
// with fresh salts and the broker wraps each open scope key under its KEKs.
// A scope without a key yet gets one at that point (fresh skS, recovery wrap).

type capabilityStages struct {
	sync.Mutex
	entries map[string]*capStage
}
type capIntent struct {
	Action     string   `json:"action"`
	Name       string   `json:"nickname"`
	Capability string   `json:"capability"`
	Target     string   `json:"credential_id"`
	Scopes     []string `json:"scopes"`
	// Remembered browsers (§13): the browser key's public half (base64url) for
	// remember, forget and the test of a browser's wraps; its label for remember.
	Browser string `json:"browser_key,omitempty"`
	Label   string `json:"browser_label,omitempty"`
}
type capStage struct {
	session, id string
	signer      int64
	signerRaw   []byte
	intent      capIntent
	canonical   string
	expires     time.Time
	sd          *webauthn.SessionData
	credential  *webauthn.Credential
	target      int64
	keys        map[string]*seal.Key // open scope keys, wiped at finish or expiry
	created     map[string]store.ScopeRow
	timer       *time.Timer // wipes an abandoned stage at its deadline
}

func (st *capStage) wipe() {
	if st.timer != nil {
		st.timer.Stop()
	}
	for k, v := range st.keys {
		v.Destroy()
		delete(st.keys, k)
	}
}

// expire wipes every stage past its deadline. An abandoned enable would
// otherwise keep its opened scope keys until the next authorize; the
// reconcile pass calls this every 15 s, and each stage has its own timer.
func (p *capabilityStages) expire(now time.Time) {
	p.Lock()
	defer p.Unlock()
	for id, st := range p.entries {
		if !now.Before(st.expires) {
			st.wipe()
			delete(p.entries, id)
		}
	}
}

// drop wipes and removes one stage if it is still pending (its timer).
func (p *capabilityStages) drop(st *capStage) {
	p.Lock()
	defer p.Unlock()
	if p.entries[st.id] == st {
		delete(p.entries, st.id)
	}
	st.wipe()
}
func (p *capabilityStages) wipe() {
	p.Lock()
	defer p.Unlock()
	for id, st := range p.entries {
		st.wipe()
		delete(p.entries, id)
	}
}

type capHandler func(context.Context, *http.Request, string) (any, error)

// sealedEndpoint serves a format-2 session route: 404 unsealed, 423 while a
// format-1 store waits for migration.
func (s *Server) sealedEndpoint(m *http.ServeMux, pattern string, fn capHandler) {
	m.Handle(pattern, s.requireSession(func(w http.ResponseWriter, r *http.Request, sess string) {
		if err := s.bucketsReady(); err != nil {
			s.writeErr(w, r, err)
			return
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
func (s *Server) capabilityRoutes(m *http.ServeMux) {
	for path, f := range map[string]capHandler{"challenge": s.capChallenge, "authorize": s.capAuthorize, "create": s.capCreate, "evaluate": s.capEvaluate, "finish": s.capFinish} {
		s.sealedEndpoint(m, "POST /api/ui/seal/passkeys/"+path, f)
	}
}

// validScopes checks a requested scope list: at most two, known, each once,
// returned installation first.
func (s *Server) validScopes(ctx context.Context, q *store.Q, in []string) ([]string, error) {
	if len(in) > 2 {
		return nil, errBad("one tap covers at most two scopes; repeat for the others")
	}
	out := slices.Clone(in)
	for i, sc := range out {
		if slices.Contains(out[:i], sc) {
			return nil, errBad("each scope once")
		}
		if sc == seal.ScopeInstallation {
			continue
		}
		if _, err := q.VaultOrg(ctx, sc); err != nil {
			return nil, errBad("unknown scope")
		}
	}
	return sortScopes(out), nil
}

func (s *Server) checkIntent(ctx context.Context, q *store.Q, in capIntent) (*storedPasskey, error) {
	if in.Capability != "unlock" && in.Capability != "approve-only" {
		return nil, errBad("select an explicit passkey capability")
	}
	name, err := normalizeNickname(in.Name)
	if err != nil || in.Name != name {
		return nil, errBad("invalid nickname")
	}
	scopes, err := s.validScopes(ctx, q, in.Scopes)
	if err != nil || !slices.Equal(scopes, in.Scopes) {
		return nil, errBad("invalid scopes")
	}
	unlock := in.Capability == "unlock"
	if unlock != (len(scopes) > 0) && in.Action != "disable" && in.Action != "forget" {
		return nil, errBad("an unlock capability names one or two scopes; approve-only names none")
	}
	browser, err := intentBrowser(in)
	if err != nil {
		return nil, err
	}
	all, err := loadPasskeys(ctx, q)
	if err != nil {
		return nil, err
	}
	if in.Action == "register" {
		if in.Target != "" || nicknameTaken(all, name, 0) {
			return nil, errConflict("credential name unavailable")
		}
		return nil, nil
	}
	for i, p := range all {
		if encodeID(p.CredentialID) != in.Target || p.Name != name {
			continue
		}
		wraps, err := q.ScopeWraps(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		has := func(sc string) bool {
			return slices.ContainsFunc(wraps, func(w store.ScopeWrapRow) bool { return w.Scope == sc })
		}
		keys, err := q.BrowserKeys(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		// This passkey's remembered browser with the intent's key, and its wraps.
		var key *store.BrowserKeyRow
		var keyWraps []store.BrowserWrapRow
		for j := range keys {
			if browser != nil && bytes.Equal(keys[j].Public, browser) {
				key = &keys[j]
				if keyWraps, err = q.BrowserWraps(ctx, key.ID); err != nil {
					return nil, err
				}
			}
		}
		keyHas := func(sc string) bool {
			return slices.ContainsFunc(keyWraps, func(w store.BrowserWrapRow) bool { return w.Scope == sc })
		}
		switch in.Action {
		case "remember":
			// Only for a passkey without PRF: one that has PRF wraps keeps using
			// its own secret and is never moved to the weaker path (§13.4).
			if len(wraps) > 0 {
				return nil, errConflict("this passkey opens buckets with its own secret (PRF): a remembered browser is only for passkeys without PRF")
			}
			for _, w := range keyWraps {
				if w.Tested != nil && slices.Contains(scopes, w.Scope) {
					return nil, errConflict("this browser is already remembered for " + scopeName(ctx, q, w.Scope) + " (tested): nothing to do")
				}
			}
			return &all[i], nil
		case "forget":
			if key == nil {
				return nil, errConflict("this browser is not remembered for that passkey")
			}
			orphans, err := q.BrowserOrphanedScopes(ctx, key.ID)
			if err != nil {
				return nil, err
			}
			if len(orphans) > 0 {
				var names []string
				for _, sc := range orphans {
					names = append(names, scopeName(ctx, q, sc))
				}
				return nil, errConflict("this remembered browser is the only thing that can open " + strings.Join(names, ", ") + ": remember another browser or enable another passkey for it first, or enrol with the recovery key (Security → Recovery key)")
			}
			return &all[i], nil
		case "enable":
			if unlock {
				if len(keys) > 0 {
					return nil, errConflict("this passkey opens buckets only from remembered browsers: use Remember this browser, or forget its browsers first to enable it with PRF")
				}
				// A tested wrap is never replaced (a page-supplied KEK could break it).
				for _, w := range wraps {
					if w.Tested != nil && slices.Contains(scopes, w.Scope) {
						return nil, errConflict("this passkey already opens " + scopeName(ctx, q, w.Scope) + " (tested): nothing to enable")
					}
				}
				return &all[i], nil
			}
		case "test":
			if browser != nil {
				if unlock && key != nil && !slices.ContainsFunc(scopes, func(sc string) bool { return !keyHas(sc) }) {
					return &all[i], nil
				}
				return nil, errConflict("this browser is not remembered for those scopes")
			}
			if unlock && !slices.ContainsFunc(scopes, func(sc string) bool { return !has(sc) }) {
				return &all[i], nil
			}
		case "disable":
			// In rounds of at most two scopes; no scope named means all of them.
			if len(wraps) == 0 || slices.ContainsFunc(scopes, func(sc string) bool { return !has(sc) }) {
				return nil, errConflict("this passkey does not open that scope")
			}
			if err = s.keepScopes(ctx, q, p.ID, scopes); err != nil {
				return nil, err
			}
			return &all[i], nil
		}
	}
	return nil, errConflict("passkey or capability changed")
}

// keepScopes is keepUnlock for a subset of the passkey's scopes (none: all).
func (s *Server) keepScopes(ctx context.Context, q *store.Q, row int64, scopes []string) error {
	if len(scopes) == 0 {
		return s.keepUnlock(ctx, q, row)
	}
	orphans, err := q.OrphanedScopes(ctx, row)
	if err != nil {
		return err
	}
	var hit []string
	for _, sc := range scopes {
		if slices.Contains(orphans, sc) {
			hit = append(hit, sc)
		}
	}
	return s.orphanErr(ctx, q, row, hit)
}

// keepUnlock refuses to take away the last passkey that can open a scope
// (the trigger keep_one_scope_passkey refuses the last one overall).
func (s *Server) keepUnlock(ctx context.Context, q *store.Q, row int64) error {
	if !s.sealServing() {
		return nil // format 1 awaiting migration: its own trigger guards the wraps
	}
	orphans, err := q.OrphanedScopes(ctx, row)
	if err != nil {
		return err
	}
	return s.orphanErr(ctx, q, row, orphans)
}

// orphanErr says why taking the passkey away would orphan these scopes. When
// another passkey is enabled for one but not tested yet, it says to test that
// passkey rather than to enable one (only tested wraps count).
func (s *Server) orphanErr(ctx context.Context, q *store.Q, row int64, orphans []string) error {
	if len(orphans) == 0 {
		return nil
	}
	wraps, err := q.ScopeWraps(ctx, 0)
	if err != nil {
		return err
	}
	all, err := loadPasskeys(ctx, q)
	if err != nil {
		return err
	}
	nick := func(id int64) string {
		for _, p := range all {
			if p.ID == id {
				return p.Name
			}
		}
		return "the other passkey"
	}
	var names, untested []string
	for _, sc := range orphans {
		names = append(names, scopeName(ctx, q, sc))
		for _, w := range wraps {
			if w.Scope == sc && w.Passkey != row && w.Tested == nil {
				untested = append(untested, "test passkey "+nick(w.Passkey)+" for "+scopeName(ctx, q, sc))
				break
			}
		}
	}
	if len(untested) == len(orphans) {
		return errConflict("no other passkey has opened " + strings.Join(names, ", ") + " yet: " + strings.Join(untested, "; ") + " first (Security → Passkeys → Test)")
	}
	msg := "this is the only passkey that can open " + strings.Join(names, ", ") + ": enable another passkey for it first"
	if len(untested) > 0 {
		msg += " (" + strings.Join(untested, "; ") + ")"
	}
	return errConflict(msg)
}

func (s *Server) capCanonical(action, id string, in capIntent) (string, error) {
	m := s.reviewFields("passkey-capability", action, id)
	m["credential_id"] = in.Target
	m["nickname"] = in.Name
	m["capability"] = in.Capability
	scopes := in.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	m["scopes"] = scopes
	capBrowserFields(m, in)
	return reviewJSON(m)
}

func (s *Server) capChallenge(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in capIntent
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	q := s.store.Q()
	scopes, err := s.validScopes(ctx, q, in.Scopes)
	if err != nil {
		return nil, err
	}
	in.Scopes = scopes
	target, err := s.checkIntent(ctx, q, in)
	if err != nil {
		return nil, err
	}
	text, err := s.capCanonical(in.Action, ids.Secret(32), in)
	if err != nil {
		return nil, err
	}
	switch in.Action {
	case "test":
		// The target taps at its own salts: proof that its wraps open.
		wraps, err := q.ScopeWraps(ctx, target.ID)
		if err != nil {
			return nil, err
		}
		var salts []seal.ID
		for _, sc := range scopes {
			for _, w := range wraps {
				if w.Scope == sc {
					var x seal.ID
					copy(x[:], w.Salt)
					salts = append(salts, x)
				}
			}
		}
		browser, _ := intentBrowser(in)
		if browser != nil {
			// A remembered browser's wraps: the "salts" are its wrap IDs.
			key, err := q.BrowserKey(ctx, target.ID, browser)
			if err != nil {
				return nil, err
			}
			salts = nil
			for _, sc := range scopes {
				bw, err := q.BrowserWrap(ctx, key.ID, sc)
				if err != nil {
					return nil, err
				}
				var x seal.ID
				copy(x[:], bw.ID)
				salts = append(salts, x)
			}
		}
		opts, t, err := s.enrolTap(sess, "test", text, target.cred, scopes, salts, browser)
		if err != nil {
			return nil, err
		}
		id, err := s.storeChallenge(ctx, sess, "passkey-capability", in.Action, text, t)
		if err != nil {
			return nil, err
		}
		return api.ChallengeResponse{ChallengeID: id, Canonical: text, PublicKey: opts, Open: t.offer()}, nil
	case "register", "enable", "remember":
		// The approving tap opens the keys of the listed scopes that have one.
		var extra []string
		for _, sc := range scopes {
			if _, err := q.Scope(ctx, sc); err == nil {
				extra = append(extra, sc)
			} else if !isStoreNotFound(err) {
				return nil, err
			}
		}
		o, err := s.loadOwner(ctx)
		if err != nil {
			return nil, err
		}
		t, challenge, err := s.offerScopes(ctx, sess, text, nil, extra, o)
		if err != nil {
			return nil, err
		}
		if t == nil {
			challenge = sha256Bytes(text)
		}
		opts, err := s.requestOptions(o, challenge)
		if err != nil {
			return nil, err
		}
		if t != nil && t.ext.PRF != nil {
			opts.Extensions = t.ext
		}
		id, err := s.storeChallenge(ctx, sess, "passkey-capability", in.Action, text, t)
		if err != nil {
			return nil, err
		}
		return api.ChallengeResponse{ChallengeID: id, Canonical: text, PublicKey: opts, Open: t.offer()}, nil
	}
	return s.beginReview(ctx, sess, "passkey-capability", in.Action, text, nil)
}

type capPlan struct {
	capIntent
	ID           string
	Epoch        seal.ID
	Installation seal.ID
}

func (s *Server) capAuthorize(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil {
		return nil, err
	}
	t := s.seal.taps.take(c.ID)
	if c.SessionHash != sess || c.ObjectType != "passkey-capability" {
		return nil, errConflict("wrong ceremony")
	}
	var plan capPlan
	if err = json.Unmarshal([]byte(c.Canonical), &plan); err != nil || plan.Epoch != s.seal.opens.Epoch() || plan.Installation != s.seal.installation || plan.Action != c.ObjectID {
		return nil, errConflict("stale capability ceremony")
	}
	if want, err := s.capCanonicalFrom(c.Canonical, plan); err != nil || want != c.Canonical {
		return nil, errConflict("stale capability ceremony")
	}
	if plan.Action == "test" {
		return s.capTest(ctx, sess, c, t, plan, in)
	}
	var row int64
	var keys []*seal.Key
	if t != nil {
		if t.session != sess || !s.now().Before(t.expires) || t.purpose != "" {
			return nil, errConflict("stale approval; review again")
		}
		challenge := seal.OpenChallenge([]byte(c.Canonical), []byte(t.descriptor))
		if row, err = s.verifySelected(ctx, challenge, in.Assertion, nil, t.ext); err != nil {
			return nil, err
		}
		if keys, _, err = s.tapScopeKeys(ctx, t, sess, row, challenge, in.Open); err != nil {
			return nil, err
		}
	} else {
		if in.Open != nil {
			return nil, errBad("this approval opens no scope")
		}
		if row, err = s.verifyAssertion(ctx, sha256Bytes(c.Canonical), in.Assertion); err != nil {
			return nil, err
		}
	}
	st := &capStage{id: plan.ID, session: sess, signer: row, intent: plan.capIntent, canonical: c.Canonical, expires: s.now().Add(RegisterTTL), keys: map[string]*seal.Key{}, created: map[string]store.ScopeRow{}}
	if t != nil {
		for i, sc := range t.scopes {
			st.keys[sc] = keys[i]
		}
	}
	stored := false
	defer func() {
		if !stored {
			st.wipe()
		}
	}()
	signer, err := s.passkeyRow(ctx, row)
	if err != nil {
		return nil, err
	}
	st.signerRaw = signer.CredentialID
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := s.sealOwner(ctx, q, sess, row); err != nil {
			return err
		}
		target, err := s.checkIntent(ctx, q, plan.capIntent)
		if err != nil {
			return err
		}
		if target != nil {
			st.credential = &target.cred
			st.target = target.ID
		}
		if plan.Action == "disable" {
			if err = q.DeletePasskeyScopeWraps(ctx, target.ID, plan.Scopes); err != nil {
				return err
			}
			return q.Audit(ctx, s.now(), "owner", "passkey_disable_unlock", "passkey:"+target.id, c.Canonical)
		}
		if plan.Action == "forget" {
			// The wraps go with the key (cascade): the broker keeps nothing of it.
			pub, _ := intentBrowser(plan.capIntent)
			key, err := q.BrowserKey(ctx, target.ID, pub)
			if err != nil {
				return err
			}
			if err = q.DeleteBrowserKey(ctx, key.ID); err != nil {
				return err
			}
			return q.Audit(ctx, s.now(), "owner", "passkey_forget_browser", "passkey:"+target.id, c.Canonical+" signer="+passkeyID(signer.CredentialID))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if plan.Action == "disable" || plan.Action == "forget" {
		_ = s.store.CheckpointWAL(ctx)
		s.bcast.notify()
		return api.OK{OK: true}, nil
	}
	result := map[string]any{"registration_id": st.id}
	if plan.Action == "register" {
		o, err := s.loadOwner(ctx)
		if err != nil {
			return nil, err
		}
		var excluded []protocol.CredentialDescriptor
		for _, c := range o.creds {
			excluded = append(excluded, c.Descriptor())
		}
		cc, sd, err := s.wa.BeginRegistration(o, webauthn.WithExclusions(excluded), webauthn.WithExtensions(webauthn.WithExtensionCredProps(), webauthn.WithExtensionPRFSupport()))
		if err != nil {
			return nil, err
		}
		st.sd = sd
		result["public_key"] = cc.Response
	}
	pool := &s.seal.capabilities
	pool.Lock()
	defer pool.Unlock()
	if pool.entries == nil {
		pool.entries = map[string]*capStage{}
	}
	for id, p := range pool.entries {
		if !s.now().Before(p.expires) || p.session == sess {
			p.wipe()
			delete(pool.entries, id)
		}
	}
	if len(pool.entries) >= 16 {
		return nil, errConflict("too many pending registrations")
	}
	pool.entries[st.id] = st
	st.timer = time.AfterFunc(RegisterTTL, func() { pool.drop(st) })
	stored = true
	return result, nil
}

// capCanonicalFrom rebuilds the canonical from its own fields (a changed or
// extra field is refused).
func (s *Server) capCanonicalFrom(text string, plan capPlan) (string, error) {
	var meta struct {
		IssuedAt string `json:"issued_at"`
		Nonce    string `json:"nonce"`
	}
	if json.Unmarshal([]byte(text), &meta) != nil {
		return "", errBad("invalid canonical")
	}
	m := map[string]any{"v": 3, "object": "passkey-capability", "action": plan.Action, "id": plan.ID, "installation": plan.Installation, "epoch": plan.Epoch, "issued_at": meta.IssuedAt, "nonce": meta.Nonce,
		"credential_id": plan.Target, "nickname": plan.Name, "capability": plan.Capability, "scopes": plan.Scopes}
	if plan.Scopes == nil {
		m["scopes"] = []string{}
	}
	capBrowserFields(m, plan.capIntent)
	return reviewJSON(m)
}

// capTest: the target passkey opens its own wraps; nothing else changes.
func (s *Server) capTest(ctx context.Context, sess string, c *store.Challenge, t *tapOpen, plan capPlan, in api.DecideRequest) (any, error) {
	if t == nil || t.purpose != "test" || t.session != sess || !s.now().Before(t.expires) {
		return nil, errConflict("stale passkey test; start again")
	}
	challenge := seal.OpenChallenge([]byte(c.Canonical), []byte(t.descriptor))
	row, err := s.verifySelected(ctx, challenge, in.Assertion, [][]byte{t.cred}, t.ext)
	if err != nil {
		return nil, err
	}
	q := s.store.Q()
	if err = s.sealOwner(ctx, q, sess, row); err != nil {
		return nil, err
	}
	pk, err := s.passkeyRow(ctx, row)
	if err != nil || !bytes.Equal(pk.CredentialID, t.cred) {
		return nil, errForbidden("wrong passkey for this test")
	}
	keks, err := s.enrolKEKs(t, sess, c.Canonical, in.Open)
	if err != nil {
		return nil, err
	}
	defer destroyKeys(keks)
	var done []string
	if t.browserPub != nil {
		// A remembered browser's wraps: this tap's assertion must have released
		// the sealed KEKs of exactly that browser key (browserkey.go).
		rel := t.released.Load()
		key, err := q.BrowserKey(ctx, row, t.browserPub)
		if err != nil || rel == nil || rel.row != row || rel.key != key.ID {
			return nil, errConflict("this browser's wraps changed; start again")
		}
		for i, scope := range t.scopes {
			bw, err := q.BrowserWrap(ctx, key.ID, scope)
			if err != nil || !bytes.Equal(bw.ID, t.salts[i][:]) {
				return nil, errConflict("this browser's wraps changed; start again")
			}
			sc, err := q.Scope(ctx, scope)
			if err != nil {
				return nil, err
			}
			k, err := s.browserScope(bw).Unwrap(keks[i], bw.Wrap, sc.Public)
			if err != nil {
				return nil, errForbidden("this browser's key for " + scopeName(ctx, q, scope) + " did not open")
			}
			k.Destroy()
			if err = q.MarkBrowserWrapTested(ctx, bw.ID, s.now()); err != nil {
				return nil, err
			}
			done = append(done, scope)
		}
		_ = q.TouchBrowserKey(ctx, key.ID, s.now())
		_ = q.Audit(ctx, s.now(), "owner", "passkey_test", "passkey:"+passkeyID(pk.CredentialID), "browser="+seal.BrowserKeyID(t.browserPub)+" scopes="+strings.Join(done, ","))
		s.bcast.notify()
		return map[string]any{"ok": true, "scopes": done}, nil
	}
	for i, scope := range t.scopes {
		sw, err := q.ScopeWrap(ctx, row, scope)
		if err != nil || !bytes.Equal(sw.Salt, t.salts[i][:]) {
			return nil, errConflict("this passkey's wraps changed; start again")
		}
		sc, err := q.Scope(ctx, scope)
		if err != nil {
			return nil, err
		}
		k, err := s.passkeyScope(sw).Unwrap(keks[i], sw.Wrap, sc.Public)
		if err != nil {
			return nil, errForbidden("this passkey's key for " + scopeName(ctx, q, scope) + " did not open")
		}
		k.Destroy()
		if err = q.MarkScopeWrapTested(ctx, sw.ID, s.now()); err != nil {
			return nil, err
		}
		done = append(done, scope)
	}
	_ = q.Audit(ctx, s.now(), "owner", "passkey_test", "passkey:"+passkeyID(pk.CredentialID), "scopes="+strings.Join(done, ","))
	s.bcast.notify()
	return map[string]any{"ok": true, "scopes": done}, nil
}

// Re-check the authorizing credential as well as the logged-in one. A
// session may have used a different key to approve the registration.
func (s *Server) checkStage(ctx context.Context, q *store.Q, sess string, st *capStage) error {
	if st == nil || st.session != sess || !s.now().Before(st.expires) {
		return errConflict("registration expired or changed")
	}
	// The PRF evaluation is signed by the target, not the credential that
	// authorized adding it. Check the saved authorizer's exact raw ID below.
	if err := s.sealOwner(context.WithValue(ctx, verifiedSignerKey{}, (*verifiedIdentity)(nil)), q, sess, st.signer); err != nil {
		return err
	}
	list, err := q.Passkeys(ctx)
	if err != nil {
		return err
	}
	for _, pk := range list {
		if pk.ID == st.signer && bytes.Equal(pk.CredentialID, st.signerRaw) {
			_, err = s.checkIntent(ctx, q, st.intent)
			return err
		}
	}
	return errConflict("authorizing passkey was removed")
}

func (s *Server) capCreate(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		ID         string          `json:"registration_id"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	pool := &s.seal.capabilities
	pool.Lock()
	defer pool.Unlock()
	st := pool.entries[in.ID]
	if err := s.checkStage(ctx, s.store.Q(), sess, st); err != nil {
		return nil, err
	}
	sd := st.sd
	st.sd = nil
	if sd == nil || !publicExtensionsOnly(in.Credential, true) {
		return nil, errConflict("invalid or reused registration")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(in.Credential)
	if err != nil {
		return nil, errBad("invalid registration")
	}
	o, err := s.loadOwner(ctx)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.CreateCredential(o, *sd, parsed)
	if err != nil || !cred.Flags.UserVerified {
		return nil, errForbidden("registration rejected")
	}
	for _, old := range o.creds {
		if bytes.Equal(old.ID, cred.ID) {
			return nil, errConflict("already registered")
		}
	}
	st.credential = cred
	if st.intent.Capability == "approve-only" {
		defer func() { st.wipe(); delete(pool.entries, st.id) }()
		return api.OK{OK: true}, s.commitCapability(ctx, st, nil, nil)
	}
	return api.OK{OK: true}, nil
}

// commitCapability inserts a registered passkey and/or its new scope wraps,
// with any scope key created in this stage, in one transaction.
func (s *Server) commitCapability(ctx context.Context, st *capStage, wraps []store.ScopeWrapRow, browser []store.BrowserWrapRow) error {
	return s.store.Tx(ctx, func(q *store.Q) error {
		if err := s.checkStage(ctx, q, st.session, st); err != nil {
			return err
		}
		row := st.target
		now := s.now()
		if row == 0 {
			cj, err := json.Marshal(st.credential)
			if err != nil {
				return err
			}
			row, err = q.InsertPasskey(ctx, &store.Passkey{CredentialID: st.credential.ID, CredentialJSON: string(cj), Name: st.intent.Name, CreatedAt: now})
			if err != nil {
				return err
			}
		}
		for _, sc := range st.intent.Scopes {
			if x, ok := st.created[sc]; ok {
				if err := q.InsertScope(ctx, x); err != nil {
					return errConflict("the scope was created meanwhile; start again")
				}
			}
		}
		for _, w := range wraps {
			w.Passkey = row
			if err := q.PutScopeWrap(ctx, w); errors.Is(err, store.ErrTestedWrap) {
				return errConflict("this passkey already opens " + scopeName(ctx, q, w.Scope) + " (tested): its wrap was kept")
			} else if err != nil {
				return err
			}
		}
		if len(browser) > 0 {
			// The remembered browser's key (public half) and its wraps. The signed
			// canonical in the audit entry names the passkey and the key's fingerprint.
			pub, _ := intentBrowser(st.intent)
			key, err := q.PutBrowserKey(ctx, store.BrowserKeyRow{Passkey: row, Public: pub, Label: st.intent.Label, Created: now})
			if err != nil {
				return err
			}
			for _, w := range browser {
				w.Key = key
				if err := q.PutBrowserWrap(ctx, w); errors.Is(err, store.ErrTestedWrap) {
					return errConflict("this browser is already remembered for " + scopeName(ctx, q, w.Scope) + " (tested): its wrap was kept")
				} else if err != nil {
					return err
				}
			}
			return q.Audit(ctx, now, "owner", "passkey_remember_browser", "passkey:"+passkeyID(st.credential.ID), st.canonical+" signer="+passkeyID(st.signerRaw))
		}
		return q.Audit(ctx, now, "owner", "passkey_capability", "passkey:"+passkeyID(st.credential.ID), st.canonical+" signer="+passkeyID(st.signerRaw))
	})
}

func (s *Server) capEvaluate(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		ID string `json:"registration_id"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	pool := &s.seal.capabilities
	pool.Lock()
	defer pool.Unlock()
	st := pool.entries[in.ID]
	q := s.store.Q()
	if err := s.checkStage(ctx, q, sess, st); err != nil {
		return nil, err
	}
	if st.credential == nil || st.intent.Capability != "unlock" {
		return nil, errConflict("registration incomplete")
	}
	var salts []seal.ID
	for _, sc := range st.intent.Scopes {
		if st.keys[sc] == nil {
			// Only a scope without any key may be created here.
			if _, err := q.Scope(ctx, sc); err == nil {
				return nil, errConflict("the approving tap did not open " + scopeName(ctx, q, sc) + "; start again")
			} else if !isStoreNotFound(err) {
				return nil, err
			}
			k, pub, err := seal.NewKeyPair()
			if err != nil {
				return nil, err
			}
			rec, err := seal.Scope{Installation: s.seal.installation, Name: sc, Public: pub}.RecoveryWrap(s.seal.recipient, k)
			if err != nil {
				k.Destroy()
				return nil, err
			}
			st.keys[sc] = k
			st.created[sc] = store.ScopeRow{Scope: sc, Public: pub, Recovery: rec, Created: s.now()}
		}
		salts = append(salts, seal.RandomID())
	}
	m := s.reviewFields("passkey-enrol", "enrol", st.id)
	m["credential_id"] = encodeID(st.credential.ID)
	m["scopes"] = st.intent.Scopes
	text, err := reviewJSON(m)
	if err != nil {
		return nil, err
	}
	browser, _ := intentBrowser(st.intent)
	if browser != nil {
		m["browser_key"], m["browser_key_id"] = st.intent.Browser, seal.BrowserKeyID(browser)
		if text, err = reviewJSON(m); err != nil {
			return nil, err
		}
	}
	opts, t, err := s.enrolTap(sess, "enrol", text, *st.credential, st.intent.Scopes, salts, browser)
	if err != nil {
		return nil, err
	}
	id, err := s.storeChallenge(ctx, sess, "passkey-enrol", st.id, text, t)
	if err != nil {
		return nil, err
	}
	return api.ChallengeResponse{ChallengeID: id, Canonical: text, PublicKey: opts, Open: t.offer()}, nil
}

func (s *Server) capFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		ID          string          `json:"registration_id"`
		ChallengeID string          `json:"challenge_id"`
		Assertion   json.RawMessage `json:"assertion"`
		Open        *api.OpenPacket `json:"open"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil {
		return nil, err
	}
	t := s.seal.taps.take(c.ID)
	if c.SessionHash != sess || c.ObjectType != "passkey-enrol" || c.ObjectID != in.ID || t == nil || t.purpose != "enrol" || t.session != sess || !s.now().Before(t.expires) {
		return nil, errConflict("stale passkey enrolment; start again")
	}
	pool := &s.seal.capabilities
	pool.Lock()
	defer pool.Unlock()
	st := pool.entries[in.ID]
	if err := s.checkStage(ctx, s.store.Q(), sess, st); err != nil {
		return nil, err
	}
	browser, _ := intentBrowser(st.intent)
	if st.credential == nil || !bytes.Equal(st.credential.ID, t.cred) || !slices.Equal(t.scopes, st.intent.Scopes) || !bytes.Equal(t.browserPub, browser) {
		return nil, errConflict("stale passkey enrolment; start again")
	}
	challenge := seal.OpenChallenge([]byte(c.Canonical), []byte(t.descriptor))
	if st.target != 0 {
		row, err := s.verifySelected(ctx, challenge, in.Assertion, [][]byte{t.cred}, t.ext)
		if err != nil || row != st.target {
			return nil, errForbidden("wrong passkey for this enrolment")
		}
	} else {
		if !publicExtensionsOnly(in.Assertion, false) {
			return nil, errForbidden("unexpected client extension output")
		}
		parsed, err := protocol.ParseCredentialRequestResponseBytes(in.Assertion)
		if err != nil {
			return nil, errForbidden("invalid assertion")
		}
		o := &owner{id: s.ownerID, name: s.cfg.OwnerName, creds: []webauthn.Credential{*st.credential}}
		cred, err := s.wa.ValidateLogin(o, webauthn.SessionData{Challenge: encodeID(challenge), RelyingPartyID: s.rpID, Origin: s.cfg.PublicBaseURL, UserID: s.ownerID, AllowedCredentialIDs: [][]byte{t.cred}, UserVerification: protocol.VerificationRequired, Extensions: t.ext.Session()}, parsed)
		if err != nil || !cred.Flags.UserVerified || !cred.Flags.UserPresent || cred.Authenticator.CloneWarning {
			return nil, errForbidden("credential did not verify")
		}
		st.credential = cred
	}
	keks, err := s.enrolKEKs(t, sess, c.Canonical, in.Open)
	if err != nil {
		return nil, err
	}
	defer destroyKeys(keks)
	var wraps []store.ScopeWrapRow
	var bwraps []store.BrowserWrapRow
	for i, sc := range t.scopes {
		pub := st.created[sc].Public
		if pub == nil {
			row, err := s.store.Q().Scope(ctx, sc)
			if err != nil {
				return nil, err
			}
			pub = row.Public
		}
		if browser != nil {
			// The KEK is random bytes from the browser being remembered: the scope
			// key is wrapped under it and the KEK is sealed to that browser's key.
			bs := seal.BrowserScope{Installation: s.seal.installation, RPID: s.rpID, RawID: t.cred, Scope: sc, WrapID: t.salts[i], Browser: browser}
			w, err := bs.Wrap(keks[i], st.keys[sc], pub)
			if err != nil {
				return nil, errConflict("could not wrap the scope key; start again")
			}
			sealed, err := bs.SealKEK(keks[i])
			if err != nil {
				return nil, errConflict("could not seal to the browser key; start again")
			}
			bwraps = append(bwraps, store.BrowserWrapRow{ID: bytes.Clone(t.salts[i][:]), Scope: sc, Wrap: w, SealedKEK: sealed, Created: s.now()})
			continue
		}
		ps := seal.PasskeyScope{Installation: s.seal.installation, RPID: s.rpID, RawID: t.cred, Scope: sc, Salt: t.salts[i]}
		w, err := ps.Wrap(keks[i], st.keys[sc], pub)
		if err != nil {
			return nil, errConflict("could not wrap the scope key; start again")
		}
		wraps = append(wraps, store.ScopeWrapRow{Scope: sc, Salt: bytes.Clone(t.salts[i][:]), Wrap: w, Created: s.now()})
	}
	defer func() { st.wipe(); delete(pool.entries, st.id) }()
	if err = s.commitCapability(ctx, st, wraps, bwraps); err != nil {
		return nil, err
	}
	s.bcast.notify()
	how := ""
	if browser != nil {
		how = " from a remembered browser (" + st.intent.Label + ")"
	}
	s.notify.Send("aqmas: passkey", "A passkey can now open "+strings.Join(t.scopes, ", ")+how+" [ref "+ref(st.id)+"]", s.cfg.PublicBaseURL+"/")
	return map[string]any{"ok": true, "scopes": t.scopes}, nil
}

func isStoreNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }
