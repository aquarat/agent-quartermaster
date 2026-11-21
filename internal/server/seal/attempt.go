package seal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"
)

var kem = hpke.DHKEM(ecdh.P256())
var errAttempt = errors.New("seal: unknown, invalid or stale ceremony")

const attemptTTL = 2 * time.Minute
const maxAssertion = 16 << 10

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Attempts belongs to one boot/lock epoch. It contains no reusable KEK or MK.
// A stopped instance cannot be reused. Call Close before draining leases.
type Attempts struct {
	mu      sync.Mutex
	epoch   ID
	now     func() time.Time
	pending map[string]*attempt
	recent  []time.Time
}
type attempt struct {
	canonical        string
	key              hpke.PrivateKey
	id               ID
	session, purpose string
	registration     string
	credential       Credential
	digest           [32]byte
	expires          time.Time
	timer            *time.Timer
}

type Begin struct {
	ID        string `json:"attempt_id"`
	Canonical string `json:"canonical"`
	Challenge string `json:"challenge"`
}

func NewAttempts(now func() time.Time) *Attempts {
	if now == nil {
		now = time.Now
	}
	return &Attempts{epoch: RandomID(), now: now, pending: make(map[string]*attempt)}
}
func (a *Attempts) Epoch() ID { return a.epoch }

// Invalidate outstanding recipients after a credential revocation. Keep the
// rate limit and epoch (other credentials can start fresh ceremonies).
func (a *Attempts) Invalidate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range a.pending {
		v.timer.Stop()
	}
	clear(a.pending)
}
func (a *Attempts) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range a.pending {
		v.timer.Stop()
	}
	a.pending = nil
}

// Begin creates a fresh single-recipient attempt. For wrap enrollment the
// registration ID must identify the approved, session-bound registration.
func (a *Attempts) Begin(session, purpose, registration string, c Credential) (Begin, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.pending == nil || session == "" || !c.valid() || !(purpose == "unlock" && registration == "" || purpose == "unlock-window" && len(registration) <= 16<<10 && json.Valid([]byte(registration)) || purpose == "wrap-enroll" && label(registration)) {
		return Begin{}, errAttempt
	}
	a.recent = slices.DeleteFunc(a.recent, func(t time.Time) bool { return !now.Before(t.Add(time.Minute)) })
	if len(a.recent) >= 12 || len(a.pending) >= 16 {
		return Begin{}, errors.New("seal: attempt limit reached; retry later")
	}
	a.recent = append(a.recent, now)
	k, err := kem.GenerateKey()
	if err != nil {
		return Begin{}, err
	}
	id := RandomID()
	nonce := RandomID()
	s := b64(id[:])
	c.RawID = slices.Clone(c.RawID)
	m := map[string]any{"action": purpose, "credential_id": b64(c.RawID), "epoch": b64(a.epoch[:]), "id": s, "installation": b64(c.Installation[:]), "issued_at": now.UTC().Format(time.RFC3339), "mk_version": c.Version, "nonce": b64(nonce[:]), "object": "seal", "prf_salt": b64(c.Salt[:]), "recipient": b64(k.PublicKey().Bytes()), "rp_id": c.RPID, "suite": 1, "v": 3}
	if purpose == "wrap-enroll" {
		m["registration_id"] = registration
	}
	if purpose == "unlock-window" {
		m["window"] = registration
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return Begin{}, err
	}
	digest := sha256.Sum256(canonical)
	at := &attempt{key: k, id: id, session: session, purpose: purpose, registration: registration, credential: c, digest: digest, expires: now.Add(attemptTTL)}
	at.canonical = string(canonical)
	a.pending[s] = at
	at.timer = time.AfterFunc(attemptTTL, func() { a.mu.Lock(); defer a.mu.Unlock(); delete(a.pending, s) })
	return Begin{s, string(canonical), b64(digest[:])}, nil
}

// FinishBound consumes the attempt before opening the packet. Apply MUST verify
// the assertion over digest with this exact credential and a live session,
// then unwrap/key-check. KEK and assertion are borrowed until apply returns.
// Close is serialized with apply. Never call back into Attempts from apply.
func (a *Attempts) FinishBound(session, purpose, id string, enc, ct []byte, apply func(Credential, string, [32]byte, []byte, *Key) error) error {
	return a.FinishEvidence(session, purpose, id, enc, ct, func(c Credential, r string, d [32]byte, b []byte, k *Key, _ string) error {
		return apply(c, r, d, b, k)
	})
}
func (a *Attempts) FinishEvidence(session, purpose, id string, enc, ct []byte, apply func(Credential, string, [32]byte, []byte, *Key, string) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	at := a.pending[id]
	if at == nil {
		return errAttempt
	}
	delete(a.pending, id)
	at.timer.Stop()
	if !a.now().Before(at.expires) || at.session != session || at.purpose != purpose || len(enc) != 65 || len(ct) > maxAssertion+56 || len(ct) < 57 {
		return errAttempt
	}
	info := tuple("hpke-finish", at.credential.Installation[:], []byte(purpose))
	aad := tuple("hpke-aad", at.id[:], a.epoch[:], at.digest[:])
	r, err := hpke.NewRecipient(enc, at.key, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		return errAttempt
	}
	b, err := r.Open(aad, ct)
	if err != nil {
		return errAttempt
	}
	defer clear(b)
	if len(b) < 41 || binary.BigEndian.Uint32(b) != 32 || int(binary.BigEndian.Uint32(b[36:])) != len(b)-40 {
		return errAttempt
	}
	kek, err := importKey(b[4:36])
	if err != nil {
		return err
	}
	defer kek.Destroy()
	clear(b[4:36])
	return apply(at.credential, at.registration, at.digest, b[40:], kek, at.canonical)
}
