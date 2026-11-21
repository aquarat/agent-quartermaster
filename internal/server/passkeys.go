package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/aaguid"
	"github.com/aquarat/agent-quartermaster/internal/server/nickname"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// owner is the single WebAuthn user.
type owner struct {
	id    []byte
	name  string
	creds []webauthn.Credential
	raw   map[string]string // credential ID (raw bytes as string) -> stored JSON, for CAS updates
}
type verifiedSignerKey struct{}
type verifiedIdentity struct {
	row int64
	raw []byte
}

func (o *owner) WebAuthnID() []byte                         { return o.id }
func (o *owner) WebAuthnName() string                       { return o.name }
func (o *owner) WebAuthnDisplayName() string                { return o.name }
func (o *owner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

func (s *Server) loadOwner(ctx context.Context) (*owner, error) {
	pks, err := s.store.Q().Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	o := &owner{id: s.ownerID, name: s.cfg.OwnerName, raw: map[string]string{}}
	for _, p := range pks {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(p.CredentialJSON), &c); err != nil {
			return nil, err
		}
		o.creds = append(o.creds, c)
		o.raw[string(c.ID)] = p.CredentialJSON
	}
	return o, nil
}

// requestOptions returns PublicKeyCredentialRequestOptions for a challenge (UV required).
func (s *Server) requestOptions(o *owner, challenge []byte) (protocol.PublicKeyCredentialRequestOptions, error) {
	var allow []protocol.CredentialDescriptor
	for _, c := range o.creds {
		allow = append(allow, c.Descriptor())
	}
	as, _, err := s.wa.BeginLogin(o, webauthn.WithChallenge(challenge), webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAllowedCredentials(allow))
	if err != nil {
		return protocol.PublicKeyCredentialRequestOptions{}, err
	}
	return as.Response, nil
}

// verifyAssertion checks a WebAuthn assertion against exactly challenge: signature by a
// registered owner passkey, user verification, origin, RP ID, and a non-regressing sign count.
// On success the stored credential is updated and its passkey row id returned.
func (s *Server) verifyAssertion(ctx context.Context, challenge []byte, assertion json.RawMessage) (int64, error) {
	return s.verifySelected(ctx, challenge, assertion, nil, protocol.AuthenticationExtensions{})
}
func (s *Server) verifySelected(ctx context.Context, challenge []byte, assertion json.RawMessage, allowed [][]byte, ext protocol.AuthenticationExtensions) (int64, error) {
	if len(assertion) == 0 || string(assertion) == "null" {
		return 0, errBad("assertion required")
	}
	if !publicExtensionsOnly(assertion, false) {
		return 0, errForbidden("unexpected client extension output")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return 0, errForbidden("assertion could not be parsed")
	}
	o, err := s.loadOwner(ctx)
	if err != nil {
		return 0, err
	}
	if len(o.creds) == 0 {
		return 0, errForbidden("no passkey registered")
	}
	session := webauthn.SessionData{
		AllowedCredentialIDs: allowed, Extensions: ext.Session(),
		Challenge:        base64.RawURLEncoding.EncodeToString(challenge),
		RelyingPartyID:   s.rpID,
		Origin:           s.cfg.PublicBaseURL,
		UserID:           s.ownerID,
		UserVerification: protocol.VerificationRequired,
	}
	cred, err := s.wa.ValidateLogin(o, session, parsed)
	if err != nil {
		s.log.Warn("passkey assertion rejected", "error", err)
		return 0, errForbidden("passkey assertion rejected")
	}
	if !parsed.Response.AuthenticatorData.Flags.UserVerified() || !parsed.Response.AuthenticatorData.Flags.UserPresent() {
		return 0, errForbidden("user verification required")
	}
	if cred.Authenticator.CloneWarning {
		s.log.Warn("passkey sign count did not increase; possible clone", "credential", base64.RawURLEncoding.EncodeToString(cred.ID))
		_ = s.store.Q().Audit(ctx, s.now(), "system", "passkey_clone_warning", "passkey:"+passkeyID(cred.ID), "sign count regressed; assertion refused")
		return 0, errForbidden("passkey sign count regressed")
	}
	newJSON, err := json.Marshal(cred)
	if err != nil {
		return 0, err
	}
	id, err := s.store.Q().UpdatePasskeyAfterUse(ctx, cred.ID, o.raw[string(cred.ID)], string(newJSON), s.now())
	if v, _ := ctx.Value(verifiedSignerKey{}).(*verifiedIdentity); v != nil && err == nil {
		v.row, v.raw = id, cred.ID
	}
	if errors.Is(err, store.ErrConflict) {
		return 0, errConflict("passkey used concurrently; retry")
	}
	return id, err
}

// Never let extension values travel into passkey storage, update proofs or
// activation audit. Signed authenticator data is not decoded or rewritten.
func publicExtensionsOnly(raw []byte, registration bool) bool {
	var c struct {
		Ext map[string]json.RawMessage `json:"clientExtensionResults"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return false
	}
	if len(c.Ext) == 0 {
		return true
	}
	if !registration || len(c.Ext) != 1 {
		return false
	}
	var props map[string]any
	if json.Unmarshal(c.Ext["credProps"], &props) != nil || len(props) != 1 {
		return false
	}
	_, ok := props["rk"].(bool)
	return ok
}

// passkeyID is a passkey's public id: hex of the first 16 bytes of SHA-256(credential ID). It
// names the passkey in /api/ui/passkeys/{id}/..., in the canonical "passkey" object and in
// the audit log ("passkey:<id>").
func passkeyID(credID []byte) string {
	h := sha256.Sum256(credID)
	return hex.EncodeToString(h[:16])
}

// storedPasskey is a passkey row with its parsed credential record.
type storedPasskey struct {
	*store.Passkey
	cred webauthn.Credential
	id   string // passkeyID
}

func loadPasskeys(ctx context.Context, q *store.Q) ([]storedPasskey, error) {
	pks, err := q.Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]storedPasskey, 0, len(pks))
	for _, p := range pks {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(p.CredentialJSON), &c); err != nil {
			return nil, err
		}
		out = append(out, storedPasskey{Passkey: p, cred: c, id: passkeyID(c.ID)})
	}
	return out, nil
}

// findPasskey returns the passkey with public id id, and all passkeys.
func findPasskey(ctx context.Context, q *store.Q, id string) (*storedPasskey, []storedPasskey, error) {
	all, err := loadPasskeys(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	for i := range all {
		if all[i].id == id {
			return &all[i], all, nil
		}
	}
	return nil, all, errNotFound()
}

func (p *storedPasskey) info(currentRowID int64) api.PasskeyInfo {
	u, a := aaguid.Lookup(p.cred.Authenticator.AAGUID)
	tr := cleanTransports(p.cred.Transport)
	return api.PasskeyInfo{
		ID: p.id, Nickname: p.Name, Authenticator: a.Name, Icon: a.Icon, AAGUID: u, Transports: tr,
		BackupEligible: p.cred.Flags.BackupEligible, BackupState: p.cred.Flags.BackupState,
		SignCount: p.cred.Authenticator.SignCount, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt,
		Current: currentRowID != 0 && p.ID == currentRowID,
	}
}

// passkeyRef is the audit object for a passkey row ("passkey:<public id>").
func (s *Server) passkeyRef(ctx context.Context, q *store.Q, rowID int64) string {
	all, err := loadPasskeys(ctx, q)
	if err == nil {
		for _, p := range all {
			if p.ID == rowID {
				return "passkey:" + p.id
			}
		}
	}
	return fmt.Sprintf("passkey:#%d", rowID)
}

// normalizeNickname applies nickname.Normalize (see that package for the rules).
func normalizeNickname(n string) (string, error) {
	out, err := nickname.Normalize(n)
	if err != nil {
		return "", errBad(err.Error())
	}
	return out, nil
}

// nicknameTaken reports whether another passkey (not exceptRowID) has this nickname, ignoring case.
func nicknameTaken(all []storedPasskey, name string, exceptRowID int64) bool {
	for _, p := range all {
		if p.ID != exceptRowID && nickname.Same(p.Name, name) {
			return true
		}
	}
	return false
}

// uniqueNickname returns name, or name plus " 2", " 3", ... when another passkey has it.
func uniqueNickname(all []storedPasskey, name string) string {
	return nickname.Unique(name, func(c string) bool { return nicknameTaken(all, c, 0) })
}

// cleanTransports keeps the browser-reported transports that look like transport names (at
// most 8 of [a-z0-9-]{1,32}); they are self-reported strings, shown in the UI.
func cleanTransports(in []protocol.AuthenticatorTransport) []string {
	out := []string{}
	for _, t := range in {
		v := string(t)
		ok := len(v) >= 1 && len(v) <= 32
		for _, r := range v {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				ok = false
			}
		}
		if ok && len(out) < 8 {
			out = append(out, v)
		}
	}
	return out
}
