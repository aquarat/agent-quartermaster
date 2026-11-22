package maint

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/go-webauthn/webauthn/protocol"
)

// MaxAge bounds how old a signed request may be when the runner picks it up.
const MaxAge = 2 * time.Minute

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
	a, err := protocol.ParseCredentialRequestResponseBytes(req.Assertion)
	if err != nil {
		return v, errors.New("assertion could not be parsed")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return v, errors.New("invalid RP origin")
	}
	for _, k := range pins {
		if len(k.ID) != 0 && bytes.Equal(a.RawID, k.ID) {
			err = a.Verify(base64.RawURLEncoding.EncodeToString(canon.Challenge(req.Canonical)), u.Hostname(), "", []string{origin}, nil, nil, protocol.TopOriginExplicitVerificationMode, false, true, true, k.PublicKey, protocol.SignaturePolicy{ECDSAEncoding: protocol.ECDSASignatureEncodingDER})
			if err != nil {
				return v, errors.New("assertion rejected")
			}
			return v, nil
		}
	}
	return v, errors.New("credential is not pinned for maintenance")
}
