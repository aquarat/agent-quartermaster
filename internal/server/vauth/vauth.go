// Package vauth is a minimal software WebAuthn authenticator (ES256, "none" attestation) for
// tests. It produces the same JSON a browser's PublicKeyCredential.toJSON() would.
package vauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

var b64 = base64.RawURLEncoding

// Flags in authenticator data.
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
)

// Authenticator holds one discoverable credential.
type Authenticator struct {
	Origin     string
	Key        *ecdsa.PrivateKey
	CredID     []byte
	UserHandle []byte
	RPID       string
	Counter    uint32
	// AAGUID reported at registration (zero when nil). Synced sets the backup-eligible and
	// backup-state flags on every ceremony (a synced passkey); otherwise device-bound.
	AAGUID     []byte
	Synced     bool
	Transports []string // reported at registration; default ["internal"]
}

// New creates an authenticator that claims to run at origin.
func New(origin string) *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 32)
	rand.Read(id)
	return &Authenticator{Origin: origin, Key: k, CredID: id}
}

type creationOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

func (a *Authenticator) clientData(typ string, challenge []byte) []byte {
	cd, _ := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   b64.EncodeToString(challenge),
		"origin":      a.Origin,
		"crossOrigin": false,
	})
	return cd
}

func (a *Authenticator) authData(flags byte, withCred bool) []byte {
	h := sha256.Sum256([]byte(a.RPID))
	out := append([]byte{}, h[:]...)
	if a.Synced {
		flags |= FlagBE | FlagBS
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.Counter)
	if withCred {
		aaguid := make([]byte, 16)
		copy(aaguid, a.AAGUID)
		out = append(out, aaguid...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.CredID)))
		out = append(out, a.CredID...)
		x := a.Key.PublicKey.X.FillBytes(make([]byte, 32))
		y := a.Key.PublicKey.Y.FillBytes(make([]byte, 32))
		cose, _ := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
	}
	return out
}

func (a *Authenticator) transports() []string {
	if a.Transports == nil {
		return []string{"internal"}
	}
	return a.Transports
}

// Register answers PublicKeyCredentialCreationOptions JSON with a "none" attestation.
func (a *Authenticator) Register(optionsJSON []byte) (json.RawMessage, error) {
	var o creationOptions
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	ch, err := b64.DecodeString(o.Challenge)
	if err != nil {
		return nil, err
	}
	uh, err := b64.DecodeString(o.User.ID)
	if err != nil {
		return nil, err
	}
	if o.RP.ID == "" {
		return nil, errors.New("vauth: no rp.id")
	}
	a.RPID, a.UserHandle = o.RP.ID, uh
	ad := a.authData(FlagUP|FlagUV|FlagAT, true)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":    b64.EncodeToString(a.CredID),
		"rawId": b64.EncodeToString(a.CredID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", ch)),
			"attestationObject": b64.EncodeToString(att),
			"transports":        a.transports(),
		},
		"clientExtensionResults":  map[string]any{"credProps": map[string]any{"rk": true}},
		"authenticatorAttachment": "platform",
	})
}

// AssertOpts tweaks an assertion for negative tests.
type AssertOpts struct {
	Flags      byte   // default UP|UV
	Origin     string // default a.Origin
	RPID       string // default a.RPID
	KeepCount  bool   // don't increment the counter
	NoUserHand bool
}

// Assert signs a challenge (raw bytes) as navigator.credentials.get would.
func (a *Authenticator) Assert(challenge []byte) json.RawMessage {
	return a.AssertWith(challenge, AssertOpts{})
}

// AssertOptions answers PublicKeyCredentialRequestOptions JSON.
func (a *Authenticator) AssertOptions(optionsJSON []byte) (json.RawMessage, error) {
	var o struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	ch, err := b64.DecodeString(o.Challenge)
	if err != nil {
		return nil, err
	}
	return a.Assert(ch), nil
}

// AssertWith signs a challenge with options.
func (a *Authenticator) AssertWith(challenge []byte, o AssertOpts) json.RawMessage {
	if !o.KeepCount {
		a.Counter++
	}
	flags := o.Flags
	if flags == 0 {
		flags = FlagUP | FlagUV
	}
	saved := a.RPID
	if o.RPID != "" {
		a.RPID = o.RPID
	}
	ad := a.authData(flags, false)
	a.RPID = saved
	origin := a.Origin
	if o.Origin != "" {
		origin = o.Origin
	}
	savedO := a.Origin
	a.Origin = origin
	cd := a.clientData("webauthn.get", challenge)
	a.Origin = savedO
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		panic(err)
	}
	resp := map[string]any{
		"clientDataJSON":    b64.EncodeToString(cd),
		"authenticatorData": b64.EncodeToString(ad),
		"signature":         b64.EncodeToString(sig),
	}
	if !o.NoUserHand {
		resp["userHandle"] = b64.EncodeToString(a.UserHandle)
	}
	out, _ := json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(a.CredID),
		"rawId":                   b64.EncodeToString(a.CredID),
		"type":                    "public-key",
		"response":                resp,
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
	return out
}
