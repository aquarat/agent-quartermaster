package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/go-webauthn/webauthn/protocol"
)

func (s *Server) sealRoutes(m *http.ServeMux) {
	s.capabilityRoutes(m)
	s.approvalRoutes(m)
	s.envWebRoutes(m)
	for path, f := range map[string]func(http.ResponseWriter, *http.Request, string){"GET /api/ui/seal/status": s.sealStatus, "POST /api/ui/seal/unlock/challenge": s.sealBegin, "POST /api/ui/seal/unlock/finish": s.sealFinish, "POST /api/ui/seal/control/challenge": s.sealControlBegin, "POST /api/ui/seal/control/finish": s.sealControlFinish, "POST /api/ui/seal/drill": s.sealDrill} {
		m.Handle(path, s.requireSession(f))
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

type sealChoice struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Selection map[string]any `json:"selection"`
}
type sealView struct {
	LeafExpires    string          `json:"leaf_expires,omitempty"`
	LeafRepair     string          `json:"leaf_repair,omitempty"`
	Profiles       []windowProfile `json:"profiles,omitempty"`
	Active         []windowInfo    `json:"active_windows,omitempty"`
	VerifiedAccess bool            `json:"verified_access,omitempty"`
	Mode           string          `json:"mode"`
	Epoch          seal.ID         `json:"epoch"`
	Installation   seal.ID         `json:"installation"`
	Choices        []sealChoice    `json:"choices"`
	Manifest       string          `json:"manifest,omitempty"`
	// Setup mode: the key the browser seals the recovery identity to for the on-box drill,
	// and whether that drill has passed.
	DrillKey string `json:"drill_key,omitempty"`
	Drilled  bool   `json:"drilled,omitempty"`
}

// DrillInfo is the HPKE info string for the recovery-drill packet of one staged installation.
func DrillInfo(installation seal.ID) []byte {
	return append([]byte("aqmas-seal-drill-v1\x00"), installation[:]...)
}

// sealDrill runs the offline recovery drill on the bastion itself (an owner
// decision, docs/SETUP.md): the browser seals the pasted age identity to this import process, which
// opens the staged recovery packet with it, authenticates every staged payload and leaves
// only the acknowledgement that activation requires. The identity is cleared at once; it is
// never written, logged or kept. This proves the saved key works; it does not prove the
// machine never saw it.
func (s *Server) sealDrill(w http.ResponseWriter, r *http.Request, sess string) {
	z := s.seal
	if z == nil || z.stage == nil {
		s.writeErr(w, r, errConflict("no seal import is staged"))
		return
	}
	var in struct {
		Packet string `json:"packet"`
	}
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	ctx := r.Context()
	row, err := s.store.Q().SessionPasskeyID(ctx, sess)
	if err == nil {
		err = s.sealOwner(ctx, s.store.Q(), sess, row)
	}
	if err != nil {
		s.writeErr(w, r, errForbidden("owner session required"))
		return
	}
	st := z.stage
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.activated {
		s.writeErr(w, r, errConflict("already activated"))
		return
	}
	identity, err := maint.OpenPacket(st.drill, DrillInfo(z.inv.Installation), in.Packet)
	if err != nil {
		s.writeErr(w, r, errBad("the recovery key packet could not be opened; reload the page and try again"))
		return
	}
	proof, err := z.inv.OfflineProof(identity)
	clear(identity)
	sum := sha256.Sum256([]byte(proof))
	if err != nil || subtle.ConstantTimeCompare(sum[:], st.expectedProof[:]) != 1 {
		s.writeErr(w, r, errConflict("this is not the recovery key for the public key you gave: nothing was changed"))
		return
	}
	path := filepath.Join(st.dir, "recovery.proof")
	_ = os.Remove(path)
	if err = writeExclusive(path, []byte(proof+"\n")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	st.drilled = true
	s.log.Info("recovery drill passed on this machine")
	writeJSON(w, 200, api.OK{OK: true})
}

func (s *Server) sealStatus(w http.ResponseWriter, r *http.Request, sess string) {
	if s.seal == nil {
		writeJSON(w, 200, sealView{Mode: "unsealed"})
		return
	}
	view, err := s.sealView(r.Context(), sess)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, view)
}
func (s *Server) sealView(ctx context.Context, sess string) (sealView, error) {
	z := s.seal
	v := sealView{Mode: "locked", Installation: z.inv.Installation, Epoch: z.attempts.Epoch(), Choices: []sealChoice{}}
	if s.pki.ServerLeaf != nil {
		v.LeafExpires = s.pki.ServerLeaf.NotAfter.UTC().Format(time.RFC3339)
	}
	v.LeafRepair, _ = reviewJSON(map[string]any{"ca_pin": s.pki.CAPin(), "configured_sans": s.cfg.TLSSANs, "effect": "Renew the server-only agent TLS leaf, then restart locked"})
	keys, err := loadPasskeys(ctx, s.store.Q())
	if err != nil {
		return v, err
	}
	if !s.isLocked() {
		v.Mode = "unlocked"
	}
	if z.stage == nil {
		q := s.store.Q()
		row, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return v, err
		}
		v.VerifiedAccess = s.access != nil && accessSub(ctx) != ""
		v.Profiles, err = s.windowProfiles(ctx, q, sess, row)
		if err != nil {
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
		if v.Mode == "unlocked" {
			return v, nil
		}
	}
	if st := z.stage; st != nil {
		st.mu.Lock()
		defer st.mu.Unlock()
		v.Mode = "setup"
		v.DrillKey, v.Drilled = maint.PublicKey(st.drill), st.drilled
		if st.activated {
			v.Mode = "activated"
			return v, nil
		}
		if st.wrap.Tested {
			if sess == st.session {
				m, err := z.inv.Manifest([]seal.WrappedCredential{st.wrap})
				if err != nil {
					return v, err
				}
				b, _ := json.Marshal(m)
				v.Manifest = string(b)
			}
			return v, nil
		}
	}
	for _, pk := range keys {
		wrap, reg, err := s.credentialFor(ctx, sess, &pk)
		if errors.Is(err, errStageBusy) || isNotFound(err) {
			continue
		}
		if err != nil {
			return v, err
		}
		c := wrap.Credential
		sel := map[string]any{"action": "unlock", "credential_id": encodeID(c.RawID), "installation": c.Installation, "epoch": v.Epoch, "rp_id": c.RPID, "mk_version": c.Version, "prf_salt": c.Salt}
		if reg != "" {
			sel["action"] = "wrap-enroll"
			sel["registration_id"] = reg
		}
		v.Choices = append(v.Choices, sealChoice{pk.id, pk.Name, sel})
	}
	return v, nil
}
func isNotFound(err error) bool { var e *apiErr; return errors.As(err, &e) && e.status == 404 }

var errStageBusy = errors.New("another credential or session owns this setup; restart maintenance to discard staging")

// Caller holds stage.mu if in setup mode. Salts are random and stable only
// within this maintenance process, then persisted for the tested credential.
func (s *Server) credentialFor(ctx context.Context, sess string, pk *storedPasskey) (seal.WrappedCredential, string, error) {
	st := s.seal.stage
	if st == nil {
		w, err := s.loadWrap(ctx, pk)
		return w, "", err
	}
	if st.wrap.Passkey != 0 {
		if st.wrap.Passkey != pk.ID || st.session != sess || st.wrap.Tested {
			return seal.WrappedCredential{}, "", errStageBusy
		}
		return st.wrap, st.registration + "-test", nil
	}
	if st.salts == nil {
		st.salts = make(map[int64]seal.ID)
		st.registration = ids.Secret(32)
	}
	salt, ok := st.salts[pk.ID]
	if !ok {
		salt = seal.RandomID()
		st.salts[pk.ID] = salt
	}
	return seal.WrappedCredential{Credential: seal.Credential{Generation: s.seal.inv.Generation, RPID: s.rpID, RawID: pk.CredentialID, Salt: salt}, Passkey: pk.ID}, st.registration + "-create", nil
}

type sealRequest struct {
	Window       *windowOpen `json:"window,omitempty"`
	Credential   string      `json:"credential"`
	Registration string      `json:"registration_id"`
}

func (s *Server) sealBegin(w http.ResponseWriter, r *http.Request, sess string) {
	z := s.seal
	if z == nil || !s.isLocked() {
		s.writeErr(w, r, errConflict("not locked or staging"))
		return
	}
	var in sealRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	ctx := r.Context()
	pk, _, err := findPasskey(ctx, s.store.Q(), in.Credential)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err = s.sealOwner(ctx, s.store.Q(), sess, pk.ID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	var wrap seal.WrappedCredential
	var reg string
	func() {
		if st := z.stage; st != nil {
			st.mu.Lock()
			defer st.mu.Unlock()
		}
		wrap, reg, err = s.credentialFor(ctx, sess, pk)
	}()
	if err != nil || reg != in.Registration {
		s.writeErr(w, r, errConflict("credential selection changed"))
		return
	}
	purpose := "unlock"
	if reg != "" {
		purpose = "wrap-enroll"
	}
	if in.Window != nil {
		if reg != "" || in.Window.Credential != encodeID(pk.CredentialID) {
			s.writeErr(w, r, errBad("wrong combined ceremony"))
			return
		}
		terms, err := s.windowTerms(ctx, s.store.Q(), sess, pk.ID, ids.Secret(32), *in.Window)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		purpose = "unlock-window"
		reg, _ = reviewJSON(terms)
	}
	b, err := z.attempts.Begin(sess, purpose, reg, wrap.Credential)
	if err != nil {
		s.writeErr(w, r, errConflict("cannot begin seal ceremony; refresh and retry"))
		return
	}
	ch, _ := strictB64(b.Challenge, 32)
	o, err := s.loadOwner(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	options, err := s.requestOptions(o, ch)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	options.AllowedCredentials = []protocol.CredentialDescriptor{pk.cred.Descriptor()}
	options.Extensions = protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: protocol.PRFValues{First: wrap.Salt[:]}}}
	writeJSON(w, 200, map[string]any{"attempt_id": b.ID, "canonical": b.Canonical, "publicKey": options})
}

type sealPacket struct {
	Combined bool   `json:"combined,omitempty"`
	ID       string `json:"attempt_id"`
	Enc      string `json:"enc"`
	CT       string `json:"ciphertext"`
}

func (s *Server) sealFinish(w http.ResponseWriter, r *http.Request, sess string) {
	z := s.seal
	if z == nil || !s.isLocked() {
		s.writeErr(w, r, errConflict("not locked or staging"))
		return
	}
	var in sealPacket
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	enc, _ := strictB64(in.Enc, 65)
	ct, _ := strictB64(in.CT, maxBody)
	ctx := r.Context()
	purpose := "unlock"
	if z.stage != nil {
		purpose = "wrap-enroll"
	}
	var receipt *windowReceipt
	if in.Combined && z.stage == nil {
		purpose = "unlock-window"
	}
	err := z.attempts.FinishEvidence(sess, purpose, in.ID, enc, ct, func(c seal.Credential, reg string, d [32]byte, assertion []byte, kek *seal.Key, canonical string) error {
		pk, _, err := findPasskey(ctx, s.store.Q(), passkeyID(c.RawID))
		if err != nil {
			return err
		}
		row, err := s.verifySelected(ctx, d[:], assertion, [][]byte{c.RawID}, protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: protocol.PRFValues{First: c.Salt[:]}}})
		if err != nil || row != pk.ID || !bytes.Equal(pk.CredentialID, c.RawID) {
			return errForbidden("seal assertion rejected")
		}
		if st := z.stage; st != nil {
			st.mu.Lock()
			defer st.mu.Unlock()
			wrap, expected, err := s.credentialFor(ctx, sess, pk)
			if err != nil || reg != expected || wrap.Salt != c.Salt {
				return errConflict("stale wrap enrollment")
			}
			if err = s.sealOwner(ctx, s.store.Q(), sess, row); err != nil {
				return err
			}
			if len(wrap.Wrapped) == 0 {
				wrap.Wrapped, err = c.Wrap(kek, st.mk)
				if err != nil {
					return err
				}
				st.wrap = wrap
				st.session = sess
				return nil
			}
			tested, err := c.Unwrap(kek, wrap.Wrapped, z.inv.Check)
			if err != nil {
				return errForbidden("passkey test could not open the wrap")
			}
			tested.Destroy()
			st.wrap.Tested = true
			manifest, err := z.inv.Manifest([]seal.WrappedCredential{st.wrap})
			if err != nil {
				return err
			}
			b, _ := json.Marshal(manifest)
			s.log.Info("tested seal manifest; compare with owner display", "manifest_sha256", seal.Digest(b))
			return writeExclusive(filepath.Join(st.dir, "manifest.json"), b)
		}
		wrap, err := s.loadWrap(ctx, pk)
		if err != nil || wrap.Salt != c.Salt {
			return errConflict("wrap no longer active")
		}
		mk, err := c.Unwrap(kek, wrap.Wrapped, z.inv.Check)
		if err != nil {
			return errForbidden("seal key check failed")
		}
		var t windowTerms
		var pending *window
		if in.Combined {
			if json.Unmarshal([]byte(reg), &t) != nil {
				mk.Destroy()
				return errBad("invalid window terms")
			}
			z.windows.Lock()
			defer z.windows.Unlock()
		}
		err = z.gate.Install(mk, func() error {
			return s.store.Tx(ctx, func(q *store.Q) error {
				if err := s.sealOwner(ctx, q, sess, row); err != nil {
					return err
				}
				if err := q.CheckSealWrap(ctx, row, c.Version, c.Salt[:], wrap.Wrapped); err != nil {
					return err
				}
				if in.Combined {
					var rec windowReceipt
					pending, rec, err = s.stageWindow(ctx, q, sess, row, t, canonical+" evidence="+openingEvidence(assertion))
					if err != nil {
						return err
					}
					receipt = &rec
				}
				return q.Audit(ctx, s.now(), "owner", "seal_unlock", "seal:"+encodeID(c.Installation[:]), fmt.Sprintf("passkey=%s challenge=%s", pk.id, encodeID(d[:])))
			})
		})
		if err != nil {
			mk.Destroy()
		} else if pending != nil {
			z.windows.publish(pending)
		}
		return err
	})
	if err != nil {
		s.writeErr(w, r, errForbidden("invalid, expired or stale seal ceremony"))
		return
	}
	s.bcast.notify()
	if z.stage == nil {
		s.afterUnlock()
	}
	if receipt != nil {
		writeJSON(w, 200, receipt)
	} else {
		writeJSON(w, 200, api.OK{OK: true})
	}
}

func (s *Server) controlCanonical(ctx context.Context, sess, action, nonce, at string) (string, error) {
	if s.seal == nil {
		return "", errNotFound()
	}
	v, err := s.sealView(ctx, sess)
	if err != nil {
		return "", err
	}
	fields := map[string]any{"v": 3, "action": action, "object": "seal-control", "nonce": nonce, "issued_at": at, "id": v.Installation, "epoch": v.Epoch}
	switch action {
	case "activate":
		if v.Mode != "setup" || v.Manifest == "" {
			return "", errConflict("tested wrap required")
		}
		fields["manifest"] = v.Manifest
	case "lock":
		if v.Mode != "unlocked" {
			return "", lockedErr()
		}
	case "renew-leaf":
		if v.Mode != "unlocked" {
			return "", lockedErr()
		}
		fields["repair"] = v.LeafRepair
	default:
		return "", errBad("invalid seal action")
	}
	b, err := json.Marshal(fields)
	return string(b), err
}
func (s *Server) sealControlBegin(w http.ResponseWriter, r *http.Request, sess string) {
	var in struct {
		Action string `json:"action"`
	}
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	ctx := r.Context()
	now := s.now()
	text, err := s.controlCanonical(ctx, sess, in.Action, canon.NewNonce(), now.UTC().Format(time.RFC3339))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	o, err := s.loadOwner(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	opts, err := s.requestOptions(o, canon.Challenge(text))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	c := &store.Challenge{ID: ids.New(), Purpose: "action", ObjectType: "seal-control", ObjectID: in.Action, Canonical: text, SessionHash: sess, CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL)}
	if err = s.store.Q().InsertChallenge(ctx, c); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, api.ChallengeResponse{ChallengeID: c.ID, Canonical: text, PublicKey: opts})
}
func (s *Server) sealControlFinish(w http.ResponseWriter, r *http.Request, sess string) {
	ctx := r.Context()
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil || c.SessionHash != sess || c.ObjectType != "seal-control" {
		s.writeErr(w, r, errConflict("stale seal action"))
		return
	}
	var meta struct {
		Nonce string
		At    string `json:"issued_at"`
	}
	if json.Unmarshal([]byte(c.Canonical), &meta) != nil {
		s.writeErr(w, r, errBad("bad seal action"))
		return
	}
	expected, err := s.controlCanonical(ctx, sess, c.ObjectID, meta.Nonce, meta.At)
	if err != nil || expected != c.Canonical {
		s.writeErr(w, r, errConflict("seal state changed"))
		return
	}
	row, err := s.verifyAssertion(ctx, canon.Challenge(expected), in.Assertion)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if c.ObjectID == "activate" {
		err = s.activateSeal(ctx, sess, row, c.Canonical, in.Assertion)
	} else if c.ObjectID == "renew-leaf" {
		err = s.withLease(ctx, func(ctx context.Context) error {
			return s.store.Tx(ctx, func(q *store.Q) error {
				if err := s.sealOwner(ctx, q, sess, row); err != nil {
					return err
				}
				p, err := s.signer(ctx, "internal-ca")
				if err != nil {
					return err
				}
				if err = p.RenewLeaf(s.cfg.TLSSANs); err != nil {
					return err
				}
				return q.Audit(ctx, s.now(), "owner", "renew_tls_leaf", "seal", expected)
			})
		})
	} else {
		err = s.store.Tx(ctx, func(q *store.Q) error {
			if err := s.sealOwner(ctx, q, sess, row); err != nil {
				return err
			}
			return q.Audit(ctx, s.now(), "owner", "seal_lock", "seal", fmt.Sprintf("passkey=%d canonical=%s", row, expected))
		})
		if err == nil {
			s.seal.gate.Drain()
			s.seal.attempts.Close()
		}
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, api.OK{OK: true})
	s.stopSealed()
}

func (s *Server) activateSeal(ctx context.Context, sess string, row int64, canonical string, assertion []byte) error {
	if s.configPath != "" {
		current, err := config.Load(s.configPath)
		if err != nil || !reflect.DeepEqual(s.cfg, current) {
			return errConflict("configuration changed during seal review")
		}
	}
	z := s.seal
	st := z.stage
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.activated || !st.wrap.Tested || sess != st.session {
		return errConflict("staging no longer available")
	}
	m, err := z.inv.Manifest([]seal.WrappedCredential{st.wrap})
	if err != nil {
		return err
	}
	manifest, _ := json.Marshal(m)
	var fields struct{ Manifest string }
	if json.Unmarshal([]byte(canonical), &fields) != nil || fields.Manifest != string(manifest) {
		return errConflict("manifest changed")
	}
	proof, err := readSecretFile(filepath.Join(st.dir, "recovery.proof"), true)
	h := sha256.Sum256(bytes.TrimSpace(proof))
	if err != nil || subtle.ConstantTimeCompare(h[:], st.expectedProof[:]) != 1 {
		return errConflict("matching offline recovery proof required")
	}
	if err = s.importSources(func(o seal.Object, b []byte) error {
		r, err := z.inv.Record(o.Role)
		if err != nil {
			return err
		}
		o.Blob = r.Blob
		if o != r.Object {
			return errConflict("source binding changed")
		}
		prev, err := o.Decrypt(z.inv.Generation, st.mk, r.Envelope)
		defer clear(prev)
		if err != nil || !bytes.Equal(prev, b) {
			return errConflict("source changed; restart setup")
		}
		return nil
	}); err != nil {
		return err
	}
	blob, _ := json.Marshal(z.inv)
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ok int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM web_sessions w JOIN passkey_people login ON login.passkey_id=w.passkey_id JOIN people p ON p.id=login.person_id AND p.owner=1 JOIN passkey_people signing ON signing.passkey_id=? AND signing.person_id=p.id JOIN passkeys wrap ON wrap.id=? AND wrap.credential_id=? JOIN passkey_people bound ON bound.passkey_id=wrap.id AND bound.person_id=p.id WHERE w.hash=? AND w.access_sub=? AND w.expires_at>?`, row, st.wrap.Passkey, st.wrap.RawID, sess, accessSub(ctx), s.now().UnixMilli()).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return errConflict("owner or tested credential changed")
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, sealDDL); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO seal_active VALUES(1,?,?,?,?)`, string(manifest), blob, canonical, assertion); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO seal_wraps VALUES(?,?,?,?,?)`, st.wrap.Passkey, st.wrap.Salt[:], st.wrap.Wrapped, st.wrap.Version, s.now().UnixMilli()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM challenges; DELETE FROM enroll_codes; PRAGMA user_version=8`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit(at,actor,action,object,detail) VALUES(?,'owner','seal_activate','seal',?)`, s.now().UnixMilli(), fmt.Sprintf("passkey=%d manifest=%s", row, seal.Digest(manifest))); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	st.activated = true
	return nil
}
