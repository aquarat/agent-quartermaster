package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"net/http"
	"sync"
	"time"
)

type capabilityStages struct {
	sync.Mutex
	entries map[string]*capStage
}
type capIntent struct {
	Action     string `json:"action"`
	Name       string `json:"nickname"`
	Capability string `json:"capability"`
	Target     string `json:"credential_id"`
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
	salt        seal.ID
	wrapped     []byte
}
type capHandler func(context.Context, *http.Request, string) (any, error)

func (s *Server) sealedEndpoint(m *http.ServeMux, pattern string, fn capHandler) {
	m.Handle(pattern, s.requireSession(func(w http.ResponseWriter, r *http.Request, sess string) {
		if s.seal == nil || s.seal.stage != nil {
			s.writeErr(w, r, errNotFound())
			return
		}
		err := s.withLease(r.Context(), func(ctx context.Context) error {
			out, err := fn(ctx, r, sess)
			if err == nil {
				writeJSON(w, 200, out)
			}
			return err
		})
		if err != nil {
			if err == seal.ErrLocked {
				err = lockedErr()
			}
			s.writeErr(w, r, err)
		}
	}))
}
func (s *Server) capabilityRoutes(m *http.ServeMux) {
	for path, f := range map[string]capHandler{"challenge": s.capChallenge, "authorize": s.capAuthorize, "create": s.capCreate, "evaluate": s.capEvaluate, "finish": s.capFinish} {
		s.sealedEndpoint(m, "POST /api/ui/seal/passkeys/"+path, f)
	}
}
func (s *Server) checkIntent(ctx context.Context, q *store.Q, in capIntent) (*storedPasskey, error) {
	if in.Capability != "unlock" && in.Capability != "approve-only" {
		return nil, errBad("select an explicit passkey capability")
	}
	name, err := normalizeNickname(in.Name)
	if err != nil || in.Name != name {
		return nil, errBad("invalid nickname")
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
		tested, err := q.TestedWrap(ctx, p.ID, s.seal.inv.Version)
		if err != nil {
			return nil, err
		}
		switch {
		case in.Action == "enable" && in.Capability == "unlock" && tested == nil:
			return &all[i], nil
		case in.Action == "disable" && in.Capability == "approve-only" && tested != nil:
			if err = s.keepUnlock(ctx, q, p.ID); err != nil {
				return nil, err
			}
			return &all[i], nil
		}
	}
	return nil, errConflict("passkey or capability changed")
}
func (s *Server) keepUnlock(ctx context.Context, q *store.Q, row int64) error {
	if s.seal == nil {
		return nil
	}
	ok, err := q.CanRemoveWrap(ctx, row, s.seal.inv.Version)
	if err == nil && !ok {
		return errConflict("cannot remove the last tested unlock credential")
	}
	return err
}
func (s *Server) capChallenge(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in capIntent
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if _, err := s.checkIntent(ctx, s.store.Q(), in); err != nil {
		return nil, err
	}
	m := s.reviewFields("passkey-capability", in.Action, ids.Secret(32))
	m["credential_id"] = in.Target
	m["nickname"] = in.Name
	m["capability"] = in.Capability
	m["mk_version"] = s.seal.inv.Version
	text, err := reviewJSON(m)
	if err != nil {
		return nil, err
	}
	return s.beginReview(ctx, sess, "passkey-capability", in.Action, text, nil)
}
func (s *Server) capAuthorize(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, row, err := s.takeReview(ctx, sess, "passkey-capability", in)
	if err != nil {
		return nil, err
	}
	var plan struct {
		capIntent
		ID           string
		Epoch        seal.ID
		Installation seal.ID
		Version      uint64 `json:"mk_version"`
	}
	if err = json.Unmarshal([]byte(c.Canonical), &plan); err != nil || plan.Epoch != s.seal.attempts.Epoch() || plan.Installation != s.seal.inv.Installation || plan.Version != s.seal.inv.Version || plan.Action != c.ObjectID {
		return nil, errConflict("stale capability ceremony")
	}
	st := &capStage{id: plan.ID, session: sess, signer: row, intent: plan.capIntent, canonical: c.Canonical, salt: seal.RandomID(), expires: s.now().Add(RegisterTTL)}
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := s.sealOwner(ctx, q, sess, row); err != nil {
			return err
		}
		all, err := q.Passkeys(ctx)
		if err != nil {
			return err
		}
		for _, pk := range all {
			if pk.ID == row {
				st.signerRaw = pk.CredentialID
			}
		}
		pk, err := s.checkIntent(ctx, q, plan.capIntent)
		if err != nil {
			return err
		}
		if pk != nil {
			st.credential = &pk.cred
			st.target = pk.ID
		}
		if plan.Action == "disable" {
			if err = q.DeleteWrap(ctx, pk.ID, plan.Version); err != nil {
				return err
			}
			return q.Audit(ctx, s.now(), "owner", "passkey_disable_unlock", "passkey:"+pk.id, c.Canonical)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if plan.Action == "disable" {
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
	} else {
		result["selection"] = s.capSelection(st)
	}
	pool := &s.seal.capabilities
	pool.Lock()
	defer pool.Unlock()
	if pool.entries == nil {
		pool.entries = map[string]*capStage{}
	}
	for id, p := range pool.entries {
		if !s.now().Before(p.expires) || p.session == sess {
			delete(pool.entries, id)
		}
	}
	if len(pool.entries) >= 16 {
		return nil, errConflict("too many pending registrations")
	}
	pool.entries[st.id] = st
	return result, nil
}
func (s *Server) capSelection(st *capStage) map[string]any {
	step := "-create"
	if st.wrapped != nil {
		step = "-test"
	}
	return map[string]any{"action": "wrap-enroll", "credential_id": encodeID(st.credential.ID), "epoch": s.seal.attempts.Epoch(), "installation": s.seal.inv.Installation, "mk_version": s.seal.inv.Version, "rp_id": s.rpID, "prf_salt": st.salt, "registration_id": st.id + step}
}

// Re-check the authorizing credential as well as the logged-in one. A
// session may have used a different key to approve the registration.
func (s *Server) checkStage(ctx context.Context, q *store.Q, sess string, st *capStage) error {
	if st == nil || st.session != sess || !s.now().Before(st.expires) {
		return errConflict("registration expired or changed")
	}
	// A PRF evaluation may be signed by the target, not the credential
	// that authorized adding it. Check the saved authorizer's exact raw ID
	// below, independently of the current request's verified signer.
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
		defer delete(pool.entries, st.id)
		return api.OK{OK: true}, s.commitCapability(ctx, st)
	}
	return map[string]any{"selection": s.capSelection(st)}, nil
}
func (s *Server) commitCapability(ctx context.Context, st *capStage) error {
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
		if st.intent.Capability == "unlock" {
			if err := q.InsertWrap(ctx, row, s.seal.inv.Version, st.salt[:], st.wrapped, now); err != nil {
				return err
			}
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
	st := pool.entries[in.ID]
	if err := s.checkStage(ctx, s.store.Q(), sess, st); err != nil {
		pool.Unlock()
		return nil, err
	}
	if st.credential == nil {
		pool.Unlock()
		return nil, errConflict("registration incomplete")
	}
	sel := s.capSelection(st)
	cred := *st.credential
	c := seal.Credential{Generation: s.seal.inv.Generation, RPID: s.rpID, RawID: cred.ID, Salt: st.salt}
	pool.Unlock()
	b, err := s.seal.attempts.Begin(sess, "wrap-enroll", sel["registration_id"].(string), c)
	if err != nil {
		return nil, errConflict("retry passkey evaluation later")
	}
	ch, _ := strictB64(b.Challenge, 32)
	o := &owner{id: s.ownerID, name: s.cfg.OwnerName, creds: []webauthn.Credential{cred}}
	opts, err := s.requestOptions(o, ch)
	if err != nil {
		return nil, err
	}
	opts.Extensions = protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: protocol.PRFValues{First: c.Salt[:]}}}
	return map[string]any{"attempt_id": b.ID, "canonical": b.Canonical, "publicKey": opts}, nil
}
func (s *Server) capFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		sealPacket
		Registration string `json:"registration_id"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	enc, _ := strictB64(in.Enc, 65)
	ct, _ := strictB64(in.CT, maxBody)
	var result any = api.OK{OK: true}
	err := s.seal.attempts.FinishBound(sess, "wrap-enroll", in.ID, enc, ct, func(c seal.Credential, reg string, d [32]byte, b []byte, kek *seal.Key) error {
		pool := &s.seal.capabilities
		pool.Lock()
		defer pool.Unlock()
		st := pool.entries[in.Registration]
		if err := s.checkStage(ctx, s.store.Q(), sess, st); err != nil {
			return err
		}
		if st.credential == nil || s.capSelection(st)["registration_id"] != reg || c.Salt != st.salt || !bytes.Equal(c.RawID, st.credential.ID) {
			return errConflict("stale PRF test")
		}
		ext := protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: protocol.PRFValues{First: c.Salt[:]}}}
		if st.target != 0 {
			row, err := s.verifySelected(ctx, d[:], b, [][]byte{c.RawID}, ext)
			if err != nil || row != st.target {
				return errForbidden("wrong test credential")
			}
		} else {
			if !publicExtensionsOnly(b, false) {
				return errForbidden("unexpected extensions")
			}
			parsed, err := protocol.ParseCredentialRequestResponseBytes(b)
			if err != nil {
				return errForbidden("invalid assertion")
			}
			o := &owner{id: s.ownerID, name: s.cfg.OwnerName, creds: []webauthn.Credential{*st.credential}}
			cred, err := s.wa.ValidateLogin(o, webauthn.SessionData{Challenge: encodeID(d[:]), RelyingPartyID: s.rpID, Origin: s.cfg.PublicBaseURL, UserID: s.ownerID, AllowedCredentialIDs: [][]byte{c.RawID}, UserVerification: protocol.VerificationRequired, Extensions: ext.Session()}, parsed)
			if err != nil || !cred.Flags.UserVerified || !cred.Flags.UserPresent || cred.Authenticator.CloneWarning {
				return errForbidden("credential did not verify")
			}
			st.credential = cred
		}
		if st.wrapped == nil {
			mk, _ := ctx.Value(leaseKey{}).(*seal.Key)
			var err error
			st.wrapped, err = c.Wrap(kek, mk)
			if err == nil {
				result = map[string]any{"selection": s.capSelection(st)}
			}
			return err
		}
		k, err := c.Unwrap(kek, st.wrapped, s.seal.inv.Check)
		if err != nil {
			return errForbidden("unstable PRF")
		}
		k.Destroy()
		defer delete(pool.entries, st.id)
		return s.commitCapability(ctx, st)
	})
	if err != nil {
		return nil, errForbidden("passkey wrap test rejected")
	}
	return result, nil
}
