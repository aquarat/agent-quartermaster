package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/aaguid"
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
	tr := make([]string, 0, len(p.cred.Transport))
	for _, t := range p.cred.Transport {
		tr = append(tr, string(t))
	}
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

// normalizeNickname trims a nickname and checks it: 1..api.MaxNicknameBytes UTF-8 bytes, no
// control, format (bidi, zero-width), private-use or line/paragraph separator characters. The
// nickname appears in signed canonical text, so it must read the same everywhere.
func normalizeNickname(n string) (string, error) {
	n = strings.TrimSpace(n)
	if n == "" {
		return "", errBad("nickname is empty")
	}
	if len(n) > api.MaxNicknameBytes {
		return "", errBad(fmt.Sprintf("nickname is longer than %d bytes", api.MaxNicknameBytes))
	}
	if !utf8.ValidString(n) {
		return "", errBad("nickname is not valid UTF-8")
	}
	for _, r := range n {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Co, unicode.Cs, unicode.Zl, unicode.Zp) {
			return "", errBad("nickname contains control or invisible characters")
		}
	}
	return n, nil
}

// nicknameTaken reports whether another passkey (not exceptRowID) has this nickname, ignoring case.
func nicknameTaken(all []storedPasskey, name string, exceptRowID int64) bool {
	for _, p := range all {
		if p.ID != exceptRowID && strings.EqualFold(p.Name, name) {
			return true
		}
	}
	return false
}

// uniqueNickname returns name, or name plus " 2", " 3", ... when another passkey has it.
func uniqueNickname(all []storedPasskey, name string) string {
	if !nicknameTaken(all, name, 0) {
		return name
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf(" %d", i)
		base := name
		for len(base)+len(suffix) > api.MaxNicknameBytes {
			_, size := utf8.DecodeLastRuneInString(base)
			base = base[:len(base)-size]
		}
		if c := strings.TrimSpace(base) + suffix; !nicknameTaken(all, c, 0) {
			return c
		}
	}
}
