package seal

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

// Inventory is the immutable ciphertext inventory for the one-time import.
// The transition manifest commits to ciphertext digests, not plaintext hashes.
type Inventory struct {
	Generation
	Recipient  string   `json:"recipient"`
	Check      []byte   `json:"check"`
	Recovery   []byte   `json:"recovery"`
	ConfigHash string   `json:"public_config_digest"`
	SSHCA      string   `json:"ssh_ca"`
	InternalCA string   `json:"internal_ca"`
	Records    []Record `json:"records"`
}
type Record struct {
	Object
	Envelope
}

func Digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func (i Inventory) Record(role string) (Record, error) {
	var found Record
	for _, r := range i.Records {
		if r.Role == role {
			if found.Role != "" {
				return Record{}, errRecord
			}
			found = r
		}
	}
	if found.Role == "" {
		return Record{}, errRecord
	}
	return found, nil
}
func (i *Inventory) Add(mk *Key, o Object, data []byte) error {
	if len(i.Records) >= 5 {
		return errRecord
	}
	for _, r := range i.Records {
		if r.Role == o.Role || r.Blob == o.Blob {
			return errRecord
		}
	}
	e, err := o.Encrypt(i.Generation, mk, data)
	if err != nil {
		return err
	}
	round, err := o.Decrypt(i.Generation, mk, e)
	defer clear(round)
	if err != nil || !bytes.Equal(round, data) {
		return errRecord
	}
	i.Records = append(i.Records, Record{o, e})
	return nil
}

// VerifyInventory authenticates EVERY staged record in isolation, no issuer
// traffic. Require the expected public trust and manifest from off-host.
func (i Inventory) VerifyInventory(mk *Key) error {
	if err := i.Verify(mk, i.Check); err != nil {
		return err
	}
	if len(i.Records) < 2 || len(i.Records) > 5 {
		return errRecord
	}
	var roles []string
	for _, r := range i.Records {
		if slices.Contains(roles, r.Role) {
			return errRecord
		}
		roles = append(roles, r.Role)
		b, err := r.Decrypt(i.Generation, mk, r.Envelope)
		clear(b)
		if err != nil {
			return err
		}
	}
	if !slices.Contains(roles, "ssh-ca") || !slices.Contains(roles, "internal-ca") {
		return errRecord
	}
	return nil
}

// DrillProof is a one-way acknowledgement of decrypting this exact, fresh
// staging inventory. It is never an MK, a wrapping key, or login authority.
func (i Inventory) DrillProof(mk *Key) (string, error) {
	if err := i.VerifyInventory(mk); err != nil {
		return "", err
	}
	b, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	k, err := hkdf.Key(sha256.New, mk.page[:32], i.Installation[:], string(tuple("drill-proof-key", i.Installation[:], number(i.Version))), 32)
	if err != nil {
		return "", err
	}
	defer clear(k)
	mac := hmac.New(sha256.New, k)
	mac.Write(tuple("recovery-drill", i.Installation[:], number(i.Version), []byte(Digest(b))))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

type WrappedCredential struct {
	Credential
	Wrapped []byte
	Passkey int64
	Tested  bool
}
type Manifest struct {
	Format int `json:"seal_format"`
	Generation
	Config          string         `json:"public_config_digest"`
	SSHCA           string         `json:"ssh_ca"`
	InternalCA      string         `json:"internal_ca"`
	LeafException   string         `json:"disk_exception"`
	Recipient       string         `json:"offline_recipient"`
	RecoveryDigest  string         `json:"recovery_packet_digest"`
	InventoryDigest string         `json:"inventory_digest"`
	Objects         []ObjectReview `json:"objects"`
	Wraps           []WrapReview   `json:"tested_unlock_credentials"`
}
type ObjectReview struct {
	Object
	CiphertextSHA256 string
	DEKWrapSHA256    string
}
type WrapReview struct {
	RawID      string
	Salt       ID
	WrapSHA256 string
}

func (i Inventory) Manifest(ws []WrappedCredential) (Manifest, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Format: 1, Generation: i.Generation, Config: i.ConfigHash, SSHCA: i.SSHCA, InternalCA: i.InternalCA, LeafException: "server.key (agent TLS leaf only)", Recipient: i.Recipient, RecoveryDigest: Digest(i.Recovery), InventoryDigest: Digest(b)}
	for _, r := range i.Records {
		m.Objects = append(m.Objects, ObjectReview{r.Object, Digest(r.Payload), Digest(r.WrappedDEK)})
	}
	for _, w := range ws {
		if !w.Tested || !w.valid() || w.Generation != i.Generation || w.Passkey < 1 || len(w.Wrapped) != 73 {
			return Manifest{}, errRecord
		}
		m.Wraps = append(m.Wraps, WrapReview{b64(w.RawID), w.Salt, Digest(w.Wrapped)})
	}
	if len(m.Wraps) == 0 {
		return Manifest{}, errors.New("seal: test an unlock credential before activation")
	}
	return m, nil
}
