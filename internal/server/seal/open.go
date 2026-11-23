package seal

import (
	"errors"
	"slices"
	"sync"
	"time"
)

// OpenAttempts holds the single-use HPKE recipients of tap ceremonies that
// carry key-encryption keys (docs/BUCKETS.md §4). It belongs to one boot
// epoch and never holds a KEK or a bucket key: only recipient private keys,
// each bound to a session, a purpose and a reference (the challenge ID).
type OpenAttempts struct {
	mu      sync.Mutex
	epoch   ID
	now     func() time.Time
	pending map[string]*OpenAttempt
	recent  []time.Time
}

// OpenAttempt is one taken (consumed) attempt.
type OpenAttempt struct {
	ID               ID
	key              *Recipient
	session, purpose string
	Ref              string
	expires          time.Time
	timer            *time.Timer
}

const openAttemptTTL = 2 * time.Minute

var errOpenAttempt = errors.New("seal: unknown, expired or reused ceremony")

func NewOpenAttempts(now func() time.Time) *OpenAttempts {
	if now == nil {
		now = time.Now
	}
	return &OpenAttempts{epoch: RandomID(), now: now, pending: map[string]*OpenAttempt{}}
}

// Epoch identifies this process: a restart makes every outstanding ceremony stale.
func (a *OpenAttempts) Epoch() ID { return a.epoch }

// Begin creates a fresh recipient for one ceremony and returns its ID and public key.
func (a *OpenAttempts) Begin(session, purpose, ref string) (string, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.pending == nil || session == "" || !label(purpose) || len(ref) > 256 {
		return "", nil, errOpenAttempt
	}
	a.recent = slices.DeleteFunc(a.recent, func(t time.Time) bool { return !now.Before(t.Add(time.Minute)) })
	if len(a.recent) >= 60 || len(a.pending) >= 64 {
		return "", nil, errors.New("seal: too many unfinished ceremonies; retry shortly")
	}
	a.recent = append(a.recent, now)
	k, err := NewRecipient()
	if err != nil {
		return "", nil, err
	}
	at := &OpenAttempt{ID: RandomID(), key: k, session: session, purpose: purpose, Ref: ref, expires: now.Add(openAttemptTTL)}
	s := b64(at.ID[:])
	a.pending[s] = at
	at.timer = time.AfterFunc(openAttemptTTL, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.pending[s] == at {
			delete(a.pending, s)
		}
	})
	return s, k.Public(), nil
}

// Take consumes the attempt whatever happens next.
func (a *OpenAttempts) Take(session, purpose, id string) (*OpenAttempt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	at := a.pending[id]
	if at == nil {
		return nil, errOpenAttempt
	}
	delete(a.pending, id)
	at.timer.Stop()
	if !a.now().Before(at.expires) || at.session != session || at.purpose != purpose {
		return nil, errOpenAttempt
	}
	return at, nil
}

// Peek reports the reference of a live attempt of this session without consuming it.
func (a *OpenAttempts) Peek(session, id string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	at := a.pending[id]
	if at == nil || at.session != session || !a.now().Before(at.expires) {
		return "", false
	}
	return at.Ref, true
}

// Invalidate drops every outstanding recipient (passkey removed, close all).
func (a *OpenAttempts) Invalidate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range a.pending {
		v.timer.Stop()
	}
	if a.pending != nil {
		clear(a.pending)
	}
}

// Close ends the epoch: no attempt can begin again.
func (a *OpenAttempts) Close() {
	a.Invalidate()
	a.mu.Lock()
	a.pending = nil
	a.mu.Unlock()
}

// Open decrypts the browser's packet into one or two KEKs (owned by the caller).
func (at *OpenAttempt) Open(installation, epoch ID, challenge, cred, enc, ct []byte) ([]*Key, error) {
	if at == nil || len(enc) != 65 || len(ct) < 16+8 || len(ct) > 16+8+64+16 {
		return nil, errOpenAttempt
	}
	p, err := at.key.Open(OpenInfo(installation, at.purpose), OpenAAD(at.ID, epoch, challenge, cred), enc, ct)
	if err != nil {
		return nil, errOpenAttempt
	}
	return SplitKEKs(p)
}

// OpenBytes decrypts an arbitrary packet (the recovery identity), bounded in size.
func (at *OpenAttempt) OpenBytes(installation, epoch ID, challenge, enc, ct []byte) ([]byte, error) {
	if at == nil || len(enc) != 65 || len(ct) < 17 || len(ct) > 8192 {
		return nil, errOpenAttempt
	}
	p, err := at.key.Open(OpenInfo(installation, at.purpose), OpenAAD(at.ID, epoch, challenge, nil), enc, ct)
	if err != nil {
		return nil, errOpenAttempt
	}
	return p, nil
}
