package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// owner is the single WebAuthn user.
type owner struct {
	id    []byte
	name  string
	creds []webauthn.Credential
	raw   map[string]string // credential ID (raw bytes as string) -> stored JSON, for CAS updates
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
	if len(assertion) == 0 || string(assertion) == "null" {
		return 0, errBad("assertion required")
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
		_ = s.store.Q().Audit(ctx, s.now(), "system", "passkey_clone_warning", "passkey", "sign count regressed; assertion refused")
		return 0, errForbidden("passkey sign count regressed")
	}
	newJSON, err := json.Marshal(cred)
	if err != nil {
		return 0, err
	}
	id, err := s.store.Q().UpdatePasskeyAfterUse(ctx, cred.ID, o.raw[string(cred.ID)], string(newJSON), s.now())
	if errors.Is(err, store.ErrConflict) {
		return 0, errConflict("passkey used concurrently; retry")
	}
	return id, err
}
