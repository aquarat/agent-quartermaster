package maint

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/go-webauthn/webauthn/protocol"
)

// MaxAge bounds how old a signed request may be when the runner picks it up. It is a little
// longer than the broker's own challenge lifetime, so a tap at the last moment still runs.
const MaxAge = 3 * time.Minute

// Request is the spool file. Everything in it is untrusted until Verify returns.
type Request struct {
	Canonical string          `json:"canonical"`
	Assertion json.RawMessage `json:"assertion"`
	Secrets   string          `json:"secrets,omitempty"`
}

// KeyPin is one root-pinned owner passkey (the shape of go-webauthn's credential record).
type KeyPin struct {
	ID        []byte `json:"id"`
	PublicKey []byte `json:"publicKey"`
}

// Verified is a request whose signature, freshness, task and parameters all checked out.
type Verified struct {
	canon.Signed
	Task   string // TaskUpgrade for the "update" object, else the setup task id
	Params any    // typed parameters (nil for upgrade)
}

// Verify checks a spool request against the root pins: a compiled-in task, canonical typed
// parameters, a fresh signed issuance time, user verification, the configured RP origin and
// an assertion by a pinned credential over exactly SHA-256(canonical).
func Verify(req Request, origin string, pins []KeyPin, now time.Time) (Verified, error) {
	var v Verified
	sg, err := canon.Parse(req.Canonical)
	if err != nil {
		return v, err
	}
	v.Signed = sg
	if now.Before(sg.IssuedAt) || now.Sub(sg.IssuedAt) > MaxAge {
		return v, errors.New("approval is not fresh")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(sg.Nonce)
	if err != nil || len(nonce) != 32 {
		return v, errors.New("invalid nonce")
	}
	switch {
	case sg.Object == "update" && sg.Action.Action == canon.ActionApprove:
		v.Task = TaskUpgrade
		if req.Secrets != "" {
			return v, errors.New("an upgrade takes no secrets")
		}
	case sg.Object == canon.ObjectSetup && sg.Action.Action == canon.ActionRun:
		if sg.ID == TaskUpgrade {
			return v, errors.New("upgrades need an update approval")
		}
		if _, ok := Lookup(sg.ID); !ok {
			return v, errors.New("task is not on the allowlist")
		}
		v.Task = sg.ID
		if v.Params, err = Parse(sg.ID, sg.Params); err != nil {
			return v, err
		}
		hash, err := PacketHash(req.Secrets)
		if err != nil || hash != sg.SecretsHash {
			return v, errors.New("secrets do not match the signed request")
		}
		if (len(SecretNames(sg.ID, v.Params)) != 0) != (req.Secrets != "") {
			return v, errors.New("secrets do not match the signed parameters")
		}
	default:
		return v, errors.New("not a maintenance approval")
	}
	return v, verifyAssertion(req.Canonical, req.Assertion, origin, pins)
}

// verifyAssertion checks a WebAuthn assertion by a pinned credential over SHA-256(text):
// user verification, the RP ID and the origin from the root-owned configuration.
func verifyAssertion(text string, assertion json.RawMessage, origin string, pins []KeyPin) error {
	a, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return errors.New("assertion could not be parsed")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("invalid RP origin")
	}
	for _, k := range pins {
		if len(k.ID) != 0 && bytes.Equal(a.RawID, k.ID) {
			err = a.Verify(base64.RawURLEncoding.EncodeToString(canon.Challenge(text)), u.Hostname(), "", []string{origin}, nil, nil, protocol.TopOriginExplicitVerificationMode, false, true, true, k.PublicKey, protocol.SignaturePolicy{ECDSAEncoding: protocol.ECDSASignatureEncodingDER})
			if err != nil {
				return errors.New("assertion rejected")
			}
			return nil
		}
	}
	return errors.New("credential is not pinned for maintenance")
}

// verifyActivation is root's own check that the store was sealed by the owner and for the
// owner: the activation the import process recorded must be signed by a pinned passkey, and
// the manifest it signs must be the one in the database and name the recovery recipient from
// the signed task. Without it nothing is pinned or deleted.
func verifyActivation(f Facts, recipient, origin string, pins []KeyPin) error {
	var c struct {
		V        int    `json:"v"`
		Action   string `json:"action"`
		Object   string `json:"object"`
		Manifest string `json:"manifest"`
	}
	if len(f.Activation) > 64<<10 || json.Unmarshal([]byte(f.Activation), &c) != nil || c.V != 3 || c.Object != "seal-control" || c.Action != "activate" {
		return errors.New("the activation record is missing or malformed")
	}
	sum := sha256.Sum256([]byte(c.Manifest))
	var m struct {
		Recipient string `json:"offline_recipient"`
	}
	if hex.EncodeToString(sum[:]) != f.Manifest || json.Unmarshal([]byte(c.Manifest), &m) != nil || m.Recipient != recipient {
		return errors.New("the signed activation does not match the stored manifest and your recovery key")
	}
	if err := verifyAssertion(f.Activation, f.ActivationProof, origin, pins); err != nil {
		return errors.New("the activation was not signed by a pinned passkey: " + err.Error())
	}
	return nil
}
