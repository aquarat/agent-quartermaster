//go:build linux

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
)

// A format-2 store built directly (what the migration produces): scope keys
// for the installation and every organisation, the two CA buckets with their
// PEM records, wraps of every scope for the owner's passkey under a
// deterministic software PRF, a pinned manifest, schema 9. The broker is then
// restarted on it, so the real boot path runs.

type bucketFix struct {
	inst      seal.ID
	identity  *age.X25519Identity
	recipient string
	prf       map[string][]byte // credential ID (raw, as string) → PRF secret
}

// prfOut is the software authenticator's PRF: HMAC-SHA256(secret, salt).
func prfOut(secret, salt []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(salt)
	return m.Sum(nil)
}

// sealBuckets converts e (organisations already active) to format 2 and
// restarts its broker. The owner's passkey gets wraps for every scope.
func sealBuckets(t *testing.T, e *env, logs *syncBuffer) *bucketFix {
	t.Helper()
	ctx := t.Context()
	s := e.s
	f := &bucketFix{inst: seal.RandomID(), prf: map[string][]byte{string(e.auth.CredID): []byte("owner-prf-secret-0123456789abcdef")}}
	var err error
	f.identity, err = age.GenerateX25519Identity()
	requireNoError(t, err)
	f.recipient = f.identity.Recipient().String()
	db := s.store.DB()
	_, err = db.Exec(store.BucketDDL + sealActiveDDL)
	requireNoError(t, err)
	scopes := []string{seal.ScopeInstallation}
	rows, err := db.Query(`SELECT id FROM organisations ORDER BY id`)
	requireNoError(t, err)
	for rows.Next() {
		var id string
		requireNoError(t, rows.Scan(&id))
		scopes = append(scopes, id)
	}
	rows.Close()
	q := s.store.Q()
	keys := map[string]*seal.Key{}
	pubs := map[string][]byte{}
	m := BucketManifest{Format: 2, Installation: f.inst, Recipient: f.recipient, SSHCA: s.sshPin(), InternalCA: s.pki.CAPin(), Config: s.profileRevision}
	for _, sc := range scopes {
		k, pub, err := seal.NewKeyPair()
		requireNoError(t, err)
		keys[sc], pubs[sc] = k, pub
		rec, err := seal.Scope{Installation: f.inst, Name: sc, Public: pub}.RecoveryWrap(f.recipient, k)
		requireNoError(t, err)
		requireNoError(t, q.InsertScope(ctx, store.ScopeRow{Scope: sc, Public: pub, Recovery: rec, Created: s.now()}))
		m.Scopes = append(m.Scopes, ManifestScope{sc, encodeID(pub)})
	}
	defer func() {
		for _, k := range keys {
			k.Destroy()
		}
	}()
	for _, ca := range []struct{ role, file string }{{seal.RoleSSHCA, pki.SSHCAKeyFile}, {seal.RoleInternalCA, pki.ClientCAKeyFile}} {
		path := filepath.Join(CADir(e.cfg.DataDir), ca.file)
		pem, err := os.ReadFile(path)
		requireNoError(t, err)
		sk, pub, err := seal.NewKeyPair()
		requireNoError(t, err)
		id := seal.RandomID()
		b := seal.Bucket{Installation: f.inst, ID: id, Scope: seal.ScopeInstallation, Kind: ca.role, Public: pub}
		wrap, err := b.WrapTo(pubs[seal.ScopeInstallation], sk)
		requireNoError(t, err)
		sk.Destroy()
		rec, err := b.Seal(ca.role, nil, pem)
		requireNoError(t, err)
		requireNoError(t, q.InsertBucket(ctx, store.BucketRow{ID: id[:], Scope: seal.ScopeInstallation, Kind: ca.role, Ref: caBucketRef, Public: pub, Wrap: wrap, Payload: rec, Created: s.now()}))
		m.Buckets = append(m.Buckets, ManifestBucket{encodeID(id[:]), seal.ScopeInstallation, ca.role, caBucketRef, encodeID(pub)})
		requireNoError(t, os.Remove(path))
	}
	pk, err := q.SessionPasskeyID(ctx, mustSessionHash(e))
	requireNoError(t, err)
	for _, sc := range scopes {
		f.wrapScope(t, e.s, pk, e.auth.CredID, sc, keys[sc], pubs[sc])
	}
	text, _ := json.Marshal(m)
	_, err = db.Exec(`INSERT INTO seal_active VALUES(1,?,CAST('{}' AS BLOB),'',x'');PRAGMA user_version=9`, string(text))
	requireNoError(t, err)
	e.cfg.Seal = config.Seal{Required: true, Recipient: f.recipient, Manifest: seal.Digest(text)}
	e.restart(logs)
	return f
}

// wrapScope stores passkey row's wrap of a scope key under the software PRF.
func (f *bucketFix) wrapScope(t *testing.T, s *Server, row int64, raw []byte, scope string, k *seal.Key, pub []byte) {
	t.Helper()
	salt := seal.RandomID()
	ps := seal.PasskeyScope{Installation: f.inst, RPID: s.rpID, RawID: raw, Scope: scope, Salt: salt}
	kek, err := ps.DeriveKEK(prfOut(f.prf[string(raw)], salt[:]))
	requireNoError(t, err)
	defer kek.Destroy()
	w, err := ps.Wrap(kek, k, pub)
	requireNoError(t, err)
	requireNoError(t, s.store.Q().PutScopeWrap(t.Context(), store.ScopeWrapRow{Passkey: row, Scope: scope, Salt: salt[:], Wrap: w, Created: s.now()}))
}

func mustSessionHash(e *env) string {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", sessionCookie+"="+e.sess)
	h, ok := e.s.sessionHash(r)
	if !ok {
		e.t.Fatal("no session")
	}
	return h
}

// restart closes the broker and starts a new one on the same data directory.
func (e *env) restart(logs *syncBuffer) {
	e.t.Helper()
	e.agent.Close()
	e.web.Close()
	e.s.Close()
	o := Options{Config: e.cfg, Now: e.clock.Now, Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	s, err := New(o)
	if err != nil {
		e.t.Fatal(err)
	}
	e.s = s
	e.agent = httptest.NewUnstartedServer(s.AgentHandler())
	e.agent.TLS = s.PKI().TLSConfig()
	e.agent.StartTLS()
	e.web = httptest.NewServer(s.WebHandler())
	e.t.Cleanup(func() { s.Close() })
}

// ---- the page's half of a tap (contract "Open descriptor") ----

type tapResp struct {
	ChallengeID string          `json:"challenge_id"`
	Canonical   string          `json:"canonical"`
	PublicKey   json.RawMessage `json:"public_key"`
	Open        *api.OpenOffer  `json:"open"`
}

type descriptor struct {
	Attempt      string   `json:"attempt_id"`
	Epoch        string   `json:"epoch"`
	Installation string   `json:"installation"`
	Object       string   `json:"object"`
	Purpose      string   `json:"purpose"`
	Recipient    string   `json:"recipient"`
	Scopes       []string `json:"scopes"`
	Salts        []string `json:"salts"`
	Credential   string   `json:"credential_id"`
	Buckets      []struct {
		ID, Kind, Label, Scope, Hold, Until string
	} `json:"buckets"`
}

// tapWith signs the bound challenge with a and, when a has a PRF and the
// options ask for one, seals its KEKs to the descriptor's recipient.
func (f *bucketFix) tapWith(t *testing.T, s *Server, a *vauth.Authenticator, r tapResp) (json.RawMessage, *api.OpenPacket) {
	t.Helper()
	var opts struct {
		Challenge  string `json:"challenge"`
		Extensions struct {
			PRF *struct {
				Eval *struct {
					First  string `json:"first"`
					Second string `json:"second"`
				} `json:"eval"`
				ByCred map[string]struct {
					First  string `json:"first"`
					Second string `json:"second"`
				} `json:"evalByCredential"`
			} `json:"prf"`
		} `json:"extensions"`
	}
	requireNoError(t, json.Unmarshal(r.PublicKey, &opts))
	challenge := sha256Bytes(r.Canonical)
	if r.Open != nil {
		challenge = seal.OpenChallenge([]byte(r.Canonical), []byte(r.Open.Descriptor))
	}
	if encodeID(challenge) != opts.Challenge {
		t.Fatal("options challenge is not the bound challenge")
	}
	as := a.Assert(challenge)
	secret := f.prf[string(a.CredID)]
	if r.Open == nil || secret == nil || opts.Extensions.PRF == nil {
		return as, nil
	}
	var d descriptor
	requireNoError(t, json.Unmarshal([]byte(r.Open.Descriptor), &d))
	var salts []string
	if e := opts.Extensions.PRF.Eval; e != nil {
		salts = []string{e.First, e.Second}
	} else if e, ok := opts.Extensions.PRF.ByCred[encodeID(a.CredID)]; ok {
		salts = []string{e.First, e.Second}
	} else {
		return as, nil
	}
	var frames [][]byte
	for i, sc := range d.Scopes {
		raw, err := b64url(salts[i])
		requireNoError(t, err)
		var salt seal.ID
		copy(salt[:], raw)
		kek, err := seal.PasskeyScope{Installation: f.inst, RPID: s.rpID, RawID: a.CredID, Scope: sc, Salt: salt}.DeriveKEK(prfOut(secret, raw))
		requireNoError(t, err)
		frames = append(frames, append([]byte(nil), kek.Bytes()...))
		kek.Destroy()
	}
	if len(frames) == 1 {
		frames = append(frames, nil)
	}
	attempt, _ := b64url(d.Attempt)
	epoch, _ := b64url(d.Epoch)
	pub, _ := b64url(d.Recipient)
	var at, ep seal.ID
	copy(at[:], attempt)
	copy(ep[:], epoch)
	enc, ct, err := seal.SealTo(pub, seal.OpenInfo(f.inst, d.Purpose), seal.OpenAAD(at, ep, challenge, a.CredID), seal.Frames(frames...))
	requireNoError(t, err)
	return as, &api.OpenPacket{AttemptID: d.Attempt, Enc: encodeID(enc), Ciphertext: encodeID(ct)}
}

// openBuckets lists the kinds/refs of the buckets the pool holds open.
func openBuckets(t *testing.T, s *Server) map[string]openBucketView {
	t.Helper()
	out := map[string]openBucketView{}
	rows, err := s.store.Q().Buckets(t.Context())
	requireNoError(t, err)
	snap := s.seal.pool.snapshot()
	for _, r := range rows {
		if v, ok := snap[bucketSealID(r)]; ok {
			out[r.Kind+":"+r.Ref] = v
		}
	}
	return out
}
