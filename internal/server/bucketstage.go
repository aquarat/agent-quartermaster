package server

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// The staged store of seal-import and bucket-migrate (docs/BUCKETS.md §8,
// contract "Stage"). Everything lives in memory until the owner activates:
// scope keys, their recovery wraps, the ceremony passkey's wraps, buckets and
// records. Activation writes it all in one transaction; anything before that
// leaves the database's sealed tables as they were, and restarting the mode
// starts a fresh stage.

const modeActivated = "activated" // staging committed, the process is about to exit

// stageRecord is one sealed value with the context it is bound to.
type stageRecord struct {
	role   string
	fields [][]byte
	ct     []byte
}

type stageScope struct {
	name, title string
	key         *seal.Key
	pub         []byte
	recovery    []byte
	salt        seal.ID // the ceremony passkey's PRF input (zero until created)
	wrap        []byte
	tested      bool
}

type stageBucket struct {
	id               seal.ID
	scope, kind, ref string
	pub, wrap        []byte
	records          []stageRecord
	payload          []byte // ssh-ca, internal-ca, cf-proxy: buckets.payload; env-set: the records JSON; signer: the record
	revision         int    // env-set
}

type sealStage struct {
	mu          sync.Mutex
	source      string // "unsealed" | "format-1"
	legacy      *legacyStore
	plan        map[string]int // scope → buckets the stage will hold
	titles      map[string]string
	built       bool
	scopes      []*stageScope
	buckets     []*stageBucket
	notice      string
	dropped     []string
	digests     map[string][32]byte // seal-import: plaintext source digests, checked again at activation
	passkey     int64               // the ceremony passkey, fixed by its first tap
	raw         []byte
	session     string
	drill       hpke.PrivateKey
	drilled     bool
	activated   bool
	approveOnly []string
}

var errStageBusy = errors.New("another passkey or session owns this staging; restart maintenance to discard it")

func (st *sealStage) wipe() {
	for _, sc := range st.scopes {
		sc.key.Destroy()
		sc.key = nil
	}
	st.notice = ""
}

// reset discards a partly built stage (a failed first tap), so it can be tried again.
func (st *sealStage) reset() {
	st.wipe()
	st.scopes, st.buckets, st.dropped, st.built = nil, nil, nil, false
}

func (st *sealStage) scope(name string) *stageScope {
	for _, sc := range st.scopes {
		if sc.name == name {
			return sc
		}
	}
	return nil
}

func (st *sealStage) scopeNames() []string {
	var out []string
	for n := range st.plan {
		out = append(out, n)
	}
	return sortScopes(out)
}

// newScopes creates the scope keys of the plan and their recovery wraps.
func (st *sealStage) newScopes(inst seal.ID, recipient string) error {
	for _, name := range st.scopeNames() {
		k, pub, err := seal.NewKeyPair()
		if err != nil {
			return err
		}
		rec, err := seal.Scope{Installation: inst, Name: name, Public: pub}.RecoveryWrap(recipient, k)
		if err != nil {
			k.Destroy()
			return err
		}
		st.scopes = append(st.scopes, &stageScope{name: name, title: st.titles[name], key: k, pub: pub, recovery: rec})
	}
	return nil
}

// newBucket creates a bucket key pair, wraps it to its scope and wipes it.
func (st *sealStage) newBucket(inst seal.ID, scope, kind, ref string) (*stageBucket, seal.Bucket, error) {
	sc := st.scope(scope)
	if sc == nil {
		return nil, seal.Bucket{}, errors.New("the store changed during staging: restart the task")
	}
	for _, b := range st.buckets {
		if b.kind == kind && b.ref == ref {
			return nil, seal.Bucket{}, errors.New("a credential was staged twice")
		}
	}
	sk, pub, err := seal.NewKeyPair()
	if err != nil {
		return nil, seal.Bucket{}, err
	}
	defer sk.Destroy()
	sb := seal.Bucket{Installation: inst, ID: seal.RandomID(), Scope: scope, Kind: kind, Public: pub}
	wrap, err := sb.WrapTo(sc.pub, sk)
	if err != nil {
		return nil, seal.Bucket{}, err
	}
	b := &stageBucket{id: sb.ID, scope: scope, kind: kind, ref: ref, pub: pub, wrap: wrap}
	st.buckets = append(st.buckets, b)
	return b, sb, nil
}

// stageSingle stages a bucket holding one record (a CA key, the Cloudflare parent).
func (st *sealStage) stageSingle(inst seal.ID, scope, kind, ref string, fields [][]byte, p []byte) error {
	b, sb, err := st.newBucket(inst, scope, kind, ref)
	if err != nil {
		return err
	}
	ct, err := sb.Seal(kind, fields, p)
	if err != nil {
		return err
	}
	b.records = []stageRecord{{kind, fields, ct}}
	b.payload = ct
	return nil
}

// stageEnv stages an env set's current revision: one record per entry.
func (st *sealStage) stageEnv(inst seal.ID, org, set string, revision int, entries []envset.Entry) error {
	b, sb, err := st.newBucket(inst, org, "env-set", set)
	if err != nil {
		return err
	}
	recs := make([]envRecord, 0, len(entries))
	for _, e := range entries {
		id := seal.RandomID()
		fields := entryFields(set, id[:], e.Name)
		p := []byte(e.Value)
		ct, err := sb.Seal(seal.RoleEnvEntry, fields, p)
		clear(p)
		if err != nil {
			return err
		}
		b.records = append(b.records, stageRecord{seal.RoleEnvEntry, fields, ct})
		recs = append(recs, envRecord{N: e.Name, I: encodeID(id[:]), C: encodeID(ct)})
	}
	if b.payload, err = recordsJSON(recs); err != nil {
		return err
	}
	b.revision = revision
	return checkRecordLimits(recs)
}

// stageSigner stages a signer's private key ({"scheme","private"} JSON in p).
func (st *sealStage) stageSigner(inst seal.ID, org, set, scheme string, public, p []byte) error {
	b, sb, err := st.newBucket(inst, org, "signer", set)
	if err != nil {
		return err
	}
	fields := signerFields(store.VaultTarget{SetID: set, Scheme: scheme, PublicKey: public})
	ct, err := sb.Seal(seal.RoleSignerKey, fields, p)
	if err != nil {
		return err
	}
	b.records = []stageRecord{{seal.RoleSignerKey, fields, ct}}
	b.payload = ct
	return nil
}

// checkScope opens every bucket of a scope with its scope key and authenticates
// every record, discarding plaintext. It returns the number of buckets.
func (st *sealStage) checkScope(inst seal.ID, sc *stageScope, key *seal.Key) (int, error) {
	n := 0
	for _, b := range st.buckets {
		if b.scope != sc.name {
			continue
		}
		sb := seal.Bucket{Installation: inst, ID: b.id, Scope: b.scope, Kind: b.kind, Public: b.pub}
		k, err := sb.UnwrapWith(key, sc.pub, b.wrap)
		if err != nil {
			return 0, errors.New("a staged bucket did not open")
		}
		for _, r := range b.records {
			p, err := sb.Open(k, r.role, r.fields, r.ct)
			clear(p)
			if err != nil {
				k.Destroy()
				return 0, errors.New("a staged record failed authentication")
			}
		}
		k.Destroy()
		n++
	}
	return n, nil
}

func (st *sealStage) ready() bool {
	if !st.built || !st.drilled || st.passkey == 0 || st.activated {
		return false
	}
	for _, sc := range st.scopes {
		if sc.wrap == nil || !sc.tested {
			return false
		}
	}
	return true
}

// DrillInfo is the HPKE info of the staging page's recovery-drill packet.
func DrillInfo(installation seal.ID) []byte {
	return append([]byte("aqmas-seal-drill-v1\x00"), installation[:]...)
}

// newStage starts seal-import (sources: the plaintext CA files, the
// Cloudflare proxy parent and the ntfy topic) or bucket-migrate (the format-1
// store, opened by the first tap).
func (s *Server) newStage() error {
	ctx := context.Background()
	drill, err := maint.NewKey()
	if err != nil {
		return err
	}
	st := &sealStage{drill: drill, titles: map[string]string{seal.ScopeInstallation: "Installation"}}
	var inst seal.ID
	if s.bucketMigrate {
		st.source = "format-1"
		if st.legacy, err = s.loadLegacy(ctx); err != nil {
			return err
		}
		inst = st.legacy.inv.Installation
		if st.plan, err = s.legacyPlan(ctx, st.legacy); err != nil {
			return err
		}
	} else {
		if s.cfg.Seal.Manifest != "" || !s.cfg.Seal.Required {
			return errors.New("begin staging with a recovery recipient and an empty manifest pin")
		}
		st.source = "unsealed"
		inst = seal.RandomID()
	}
	s.seal = newSealRuntime(s, modeSetup, inst)
	s.seal.stage = st
	if err = s.stageTitles(ctx, st); err != nil {
		return err
	}
	if !s.bucketMigrate {
		if err = s.importStage(ctx, st); err != nil {
			st.wipe()
			return err
		}
	}
	s.log.Info("seal stage ready; every value stays in memory until you activate", "source", st.source, "installation", encodeID(inst[:]), "scopes", len(st.plan), "recipient", s.cfg.Seal.Recipient)
	return nil
}

func (s *Server) stageTitles(ctx context.Context, st *sealStage) error {
	for name := range st.plan {
		if name == seal.ScopeInstallation {
			continue
		}
		var title string
		if err := s.store.DB().QueryRowContext(ctx, `SELECT title FROM organisations WHERE id=?`, name).Scan(&title); err != nil {
			return errors.New("a credential belongs to an unknown organisation")
		}
		st.titles[name] = title
	}
	return nil
}

// importStage seals the plaintext sources of an unsealed store directly into buckets.
func (s *Server) importStage(ctx context.Context, st *sealStage) error {
	inst := s.seal.installation
	st.plan = map[string]int{seal.ScopeInstallation: 2}
	st.digests = map[string][32]byte{}
	cf := s.cfg.Cloudflare
	var org, service, set string
	proxy := cf.Enabled && (cf.ProxyTokenCredential != "" || cf.ProxyTokenFile != "")
	if proxy {
		var err error
		if org, service, set, err = s.cfProxyBinding(ctx); err != nil {
			return errors.New("the Cloudflare proxy set is missing; switch to organisations first")
		}
		st.plan[org]++
	}
	if cf.Enabled && (cf.MinterTokenCredential != "" || cf.MinterTokenFile != "") {
		// Token mode is off under organisations: the minter parent was never used.
		st.dropped = append(st.dropped, "cf-minter")
		s.log.Warn("the Cloudflare minter parent is not imported: revoke it at Cloudflare")
	}
	if err := s.stageTitles(ctx, st); err != nil {
		return err
	}
	if err := st.newScopes(inst, s.cfg.Seal.Recipient); err != nil {
		return err
	}
	if err := s.visitSources(ctx, func(role string, b []byte) error {
		st.digests[role] = sha256.Sum256(b)
		switch role {
		case seal.RoleCFProxy:
			return st.stageSingle(inst, org, seal.RoleCFProxy, set, s.cfFields(org, service, set), b)
		default:
			return st.stageSingle(inst, seal.ScopeInstallation, role, caBucketRef, nil, b)
		}
	}); err != nil {
		return err
	}
	st.notice = s.cfg.Ntfy.TopicURL
	st.built = true
	return nil
}

// visitSources reads each plaintext source of a seal import once, checks it
// and lends it to visit; the bytes are cleared afterwards.
func (s *Server) visitSources(ctx context.Context, visit func(role string, b []byte) error) error {
	for _, it := range []struct{ role, file string }{{seal.RoleSSHCA, pki.SSHCAKeyFile}, {seal.RoleInternalCA, pki.ClientCAKeyFile}} {
		b, err := readSecretFile(filepath.Join(CADir(s.cfg.DataDir), it.file), true)
		if err != nil {
			return err
		}
		err = s.pki.CheckPrivate(it.role, b)
		if err == nil {
			err = visit(it.role, b)
		}
		clear(b)
		if err != nil {
			return err
		}
	}
	cf := s.cfg.Cloudflare
	if cf.Enabled && (cf.ProxyTokenCredential != "" || cf.ProxyTokenFile != "") {
		tok, err := loadParentToken("proxy", cf.ProxyTokenCredential, cf.ProxyTokenFile)
		if err != nil {
			return err
		}
		b := []byte(tok)
		err = visit(seal.RoleCFProxy, b)
		clear(b)
		return err
	}
	return nil
}

// ---- status (contract: status.stage) ----

type stageScopeView struct {
	Scope   string `json:"scope"`
	Title   string `json:"title"`
	Buckets int    `json:"buckets"`
	Wrapped bool   `json:"wrapped"`
	Tested  bool   `json:"tested"`
}

// legacyView is also the descriptor's "legacy" object: fields in sorted key
// order, as canonical JSON needs (encoding/json keeps declaration order).
type legacyView struct {
	Installation string `json:"installation"`
	MKVersion    uint64 `json:"mk_version"`
	PRFSalt      string `json:"prf_salt"`
}
type stageChoice struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Credential string      `json:"credential_id"`
	Legacy     *legacyView `json:"legacy,omitempty"`
}
type stageView struct {
	Source         string           `json:"source"`
	Scopes         []stageScopeView `json:"scopes"`
	Drilled        bool             `json:"drilled"`
	DrillKey       string           `json:"drill_key"`
	Manifest       string           `json:"manifest,omitempty"`
	LegacyUnlocked bool             `json:"legacy_unlocked"`
	Dropped        []string         `json:"dropped,omitempty"`
	Choices        []stageChoice    `json:"choices"`
}

func (s *Server) legacyChoice(st *sealStage, row int64) *legacyView {
	if st.legacy == nil || st.built {
		return nil
	}
	w, ok := st.legacy.wraps[row]
	if !ok {
		return nil
	}
	inst := st.legacy.inv.Installation
	return &legacyView{MKVersion: st.legacy.inv.Version, PRFSalt: encodeID(w.salt[:]), Installation: encodeID(inst[:])}
}

// stageStatus is status.stage for the owner's session (caller holds no lock).
func (s *Server) stageStatus(ctx context.Context, sess string) (*stageView, error) {
	st := s.seal.stage
	keys, err := loadPasskeys(ctx, s.store.Q())
	if err != nil {
		return nil, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	v := &stageView{Source: st.source, Scopes: []stageScopeView{}, Drilled: st.drilled, DrillKey: maint.PublicKey(st.drill), LegacyUnlocked: st.legacy != nil && st.built, Dropped: st.dropped, Choices: []stageChoice{}}
	for _, name := range st.scopeNames() {
		sv := stageScopeView{Scope: name, Title: st.titles[name], Buckets: st.plan[name]}
		if sc := st.scope(name); sc != nil {
			sv.Wrapped, sv.Tested = sc.wrap != nil, sc.tested
		}
		v.Scopes = append(v.Scopes, sv)
	}
	for _, k := range keys {
		if st.passkey != 0 && (k.ID != st.passkey || sess != st.session) {
			continue
		}
		c := stageChoice{ID: k.id, Name: k.Name, Credential: encodeID(k.CredentialID), Legacy: s.legacyChoice(st, k.ID)}
		if st.legacy != nil && !st.built && c.Legacy == nil {
			continue // only a format-1 unlock passkey can open the old store
		}
		v.Choices = append(v.Choices, c)
	}
	if st.ready() && sess == st.session {
		if v.Manifest, err = s.stageManifest(st); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// stageManifest is the format-2 activation manifest (caller holds st.mu).
func (s *Server) stageManifest(st *sealStage) (string, error) {
	z := s.seal
	m := BucketManifest{Format: 2, Installation: z.installation, Recipient: s.cfg.Seal.Recipient, SSHCA: s.sshPin(), InternalCA: s.pki.CAPin(), Config: s.profileRevision, ApproveOnly: st.approveOnly, Dropped: st.dropped}
	for _, sc := range st.scopes {
		m.Scopes = append(m.Scopes, ManifestScope{sc.name, encodeID(sc.pub)})
		m.Passkeys = append(m.Passkeys, ManifestWrap{Credential: encodeID(st.raw), Scope: sc.name, Salt: encodeID(sc.salt[:]), WrapSHA256: sha256Hex(sc.wrap)})
	}
	for _, b := range st.buckets {
		m.Buckets = append(m.Buckets, ManifestBucket{encodeID(b.id[:]), b.scope, b.kind, b.ref, encodeID(b.pub)})
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// ---- staging taps (contract "Stage") ----

func (s *Server) stageRoutes(m *http.ServeMux) {
	for path, fn := range map[string]capHandler{"challenge": s.stageChallenge, "finish": s.stageFinish} {
		m.Handle("POST /api/ui/seal/stage/"+path, s.requireSession(func(w http.ResponseWriter, r *http.Request, sess string) {
			if s.seal == nil || s.seal.stage == nil || s.seal.mode != modeSetup {
				s.writeErr(w, r, errConflict("nothing is staged"))
				return
			}
			out, err := fn(r.Context(), r, sess)
			if err != nil {
				s.writeErr(w, r, mapNotFound(err))
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, out)
		}))
	}
}

var stagePurpose = map[string]string{"open-legacy": "migrate", "create": "stage", "test": "test"}

type stageChoiceIn struct {
	Step       string   `json:"step"`
	Credential string   `json:"credential"`
	Scopes     []string `json:"scopes"`
}

// stageCheck validates a step against the stage (caller holds st.mu). It
// returns the salts the tap evaluates (create: fresh; test: the staged ones).
func (s *Server) stageCheck(st *sealStage, in stageChoiceIn, pk *storedPasskey, sess string) ([]seal.ID, error) {
	if st.activated {
		return nil, errConflict("already activated")
	}
	if _, ok := stagePurpose[in.Step]; !ok {
		return nil, errBad("step must be open-legacy, create or test")
	}
	if st.passkey != 0 && (pk.ID != st.passkey || sess != st.session) {
		return nil, errConflict(errStageBusy.Error())
	}
	if len(in.Scopes) == 0 || len(in.Scopes) > 2 || !slices.Equal(sortScopes(slices.Clone(in.Scopes)), in.Scopes) || len(in.Scopes) == 2 && in.Scopes[0] == in.Scopes[1] {
		return nil, errBad("name one or two scopes, installation first")
	}
	for _, sc := range in.Scopes {
		if _, ok := st.plan[sc]; !ok {
			return nil, errBad("unknown scope")
		}
	}
	var salts []seal.ID
	switch in.Step {
	case "open-legacy":
		if st.legacy == nil || st.built {
			return nil, errConflict("the old store is already open")
		}
		if len(in.Scopes) != 1 || in.Scopes[0] != seal.ScopeInstallation {
			return nil, errBad("the first tap creates the installation scope")
		}
		if _, ok := st.legacy.wraps[pk.ID]; !ok {
			return nil, errConflict("this passkey cannot open the format-1 store")
		}
		salts = []seal.ID{seal.RandomID()}
	case "create":
		if !st.built {
			return nil, errConflict("open the old store first")
		}
		for _, name := range in.Scopes {
			if st.scope(name).wrap != nil {
				return nil, errConflict("this scope already has a key for this passkey")
			}
			salts = append(salts, seal.RandomID())
		}
	case "test":
		for _, name := range in.Scopes {
			sc := st.scope(name)
			if sc == nil || sc.wrap == nil || sc.tested {
				return nil, errConflict("create this scope's key first")
			}
			salts = append(salts, sc.salt)
		}
	}
	return salts, nil
}

func (s *Server) stageCanonical(step, credential string, scopes []string, nonce, at string) (string, error) {
	return reviewJSON(map[string]any{"v": 3, "object": "seal-stage", "action": step, "credential": credential, "scopes": scopes,
		"id": encodeID(s.seal.installation[:]), "epoch": s.seal.opens.Epoch(), "nonce": nonce, "issued_at": at})
}

// stageTap is enrolTap with an optional format-1 binding (purpose "migrate"):
// then the first PRF input is the passkey's format-1 salt and the packet's
// first slot carries the format-1 KEK.
func (s *Server) stageTap(sess, purpose, canonical string, cred webauthn.Credential, scopes []string, salts []seal.ID, legacy *legacyView, legacySalt seal.ID) (protocol.PublicKeyCredentialRequestOptions, *tapOpen, error) {
	if legacy == nil {
		return s.enrolTap(sess, purpose, canonical, cred, scopes, salts)
	}
	var opts protocol.PublicKeyCredentialRequestOptions
	attempt, recipient, err := s.seal.opens.Begin(sess, purpose, "")
	if err != nil {
		return opts, nil, &apiErr{429, "rate_limited", err.Error()}
	}
	d := map[string]any{"v": 1, "object": "scope-enrol", "purpose": purpose, "attempt_id": attempt, "installation": s.seal.installation, "epoch": s.seal.opens.Epoch(),
		"recipient": encodeID(recipient), "scopes": scopes, "salts": []string{encodeID(salts[0][:])}, "credential_id": encodeID(cred.ID), "buckets": []descriptorBucket{}, "legacy": legacy}
	desc, err := reviewJSON(d)
	if err != nil {
		return opts, nil, err
	}
	o := &owner{id: s.ownerID, name: s.cfg.OwnerName, creds: []webauthn.Credential{cred}}
	if opts, err = s.requestOptions(o, seal.OpenChallenge([]byte(canonical), []byte(desc))); err != nil {
		return opts, nil, err
	}
	ext := protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: protocol.PRFValues{First: legacySalt[:], Second: salts[0][:]}}}
	opts.Extensions = ext
	t := &tapOpen{session: sess, attempt: attempt, descriptor: desc, scopes: scopes, expires: s.now().Add(ChallengeTTL), ext: ext, purpose: purpose, cred: bytes.Clone(cred.ID), salts: salts}
	return opts, t, nil
}

func (s *Server) stageChallenge(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in stageChoiceIn
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	q := s.store.Q()
	pk, _, err := findPasskey(ctx, q, in.Credential)
	if err != nil {
		return nil, err
	}
	if err = s.sealOwner(ctx, q, sess, pk.ID); err != nil {
		return nil, err
	}
	st := s.seal.stage
	st.mu.Lock()
	defer st.mu.Unlock()
	salts, err := s.stageCheck(st, in, pk, sess)
	if err != nil {
		return nil, err
	}
	text, err := s.stageCanonical(in.Step, pk.id, in.Scopes, canon.NewNonce(), s.now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	var legacy *legacyView
	var legacySalt seal.ID
	if in.Step == "open-legacy" {
		legacy, legacySalt = s.legacyChoice(st, pk.ID), st.legacy.wraps[pk.ID].salt
	}
	opts, t, err := s.stageTap(sess, stagePurpose[in.Step], text, pk.cred, in.Scopes, salts, legacy, legacySalt)
	if err != nil {
		return nil, err
	}
	id, err := s.storeChallenge(ctx, sess, "seal-stage", in.Step, text, t)
	if err != nil {
		return nil, err
	}
	return api.ChallengeResponse{ChallengeID: id, Canonical: text, PublicKey: opts, Open: t.offer()}, nil
}

func (s *Server) stageFinish(ctx context.Context, r *http.Request, sess string) (out any, err error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	z := s.seal
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil {
		return nil, err
	}
	t := z.taps.take(c.ID)
	if c.SessionHash != sess || c.ObjectType != "seal-stage" || t == nil || t.session != sess || !s.now().Before(t.expires) || t.purpose != stagePurpose[c.ObjectID] {
		return nil, errConflict("stale staging step; start it again")
	}
	var meta struct {
		Action     string   `json:"action"`
		Credential string   `json:"credential"`
		Scopes     []string `json:"scopes"`
		Nonce      string   `json:"nonce"`
		IssuedAt   string   `json:"issued_at"`
	}
	if json.Unmarshal([]byte(c.Canonical), &meta) != nil || meta.Action != c.ObjectID || !slices.Equal(meta.Scopes, t.scopes) {
		return nil, errBad("invalid staging step")
	}
	if want, err := s.stageCanonical(meta.Action, meta.Credential, meta.Scopes, meta.Nonce, meta.IssuedAt); err != nil || want != c.Canonical {
		return nil, errConflict("stale staging step; start it again")
	}
	challenge := seal.OpenChallenge([]byte(c.Canonical), []byte(t.descriptor))
	row, err := s.verifySelected(ctx, challenge, in.Assertion, [][]byte{t.cred}, t.ext)
	if err != nil {
		return nil, err
	}
	q := s.store.Q()
	if err = s.sealOwner(ctx, q, sess, row); err != nil {
		return nil, err
	}
	pk, _, err := findPasskey(ctx, q, meta.Credential)
	if err != nil || pk.ID != row || !bytes.Equal(pk.CredentialID, t.cred) {
		return nil, errForbidden("wrong passkey for this step")
	}
	st := z.stage
	st.mu.Lock()
	defer st.mu.Unlock()
	salts, err := s.stageCheck(st, stageChoiceIn{Step: meta.Action, Credential: meta.Credential, Scopes: meta.Scopes}, pk, sess)
	if err != nil {
		return nil, err
	}
	if meta.Action == "open-legacy" {
		// Any failure from here on leaves nothing staged from the format-1 key.
		defer func() {
			if err != nil {
				st.reset()
			}
		}()
	}
	if meta.Action == "test" && !slices.Equal(salts, t.salts) {
		return nil, errConflict("stale staging step; start it again")
	}
	want := len(t.scopes)
	if meta.Action == "open-legacy" {
		want++
	}
	keks, err := s.stageKEKs(t, sess, challenge, in.Open, want)
	if err != nil {
		return nil, err
	}
	defer destroyKeys(keks)
	if meta.Action == "open-legacy" {
		if err = s.openLegacy(ctx, st, row, t.cred, keks[0]); err != nil {
			return nil, err
		}
		if stageAfterLegacy != nil {
			if err = stageAfterLegacy(); err != nil {
				return nil, err
			}
		}
		keks = keks[1:]
	}
	ps := func(scope string, salt seal.ID) seal.PasskeyScope {
		return seal.PasskeyScope{Installation: z.installation, RPID: s.rpID, RawID: t.cred, Scope: scope, Salt: salt}
	}
	for i, name := range t.scopes {
		sc := st.scope(name)
		if meta.Action == "test" {
			k, err := ps(name, sc.salt).Unwrap(keks[i], sc.wrap, sc.pub)
			if err != nil {
				return nil, errForbidden("this passkey's key for " + sc.title + " did not open")
			}
			k.Destroy()
			sc.tested = true
			continue
		}
		w, err := ps(name, t.salts[i]).Wrap(keks[i], sc.key, sc.pub)
		if err != nil {
			return nil, errConflict("could not wrap the scope key; start the step again")
		}
		sc.salt, sc.wrap, sc.tested = t.salts[i], w, false
	}
	if st.passkey == 0 {
		st.passkey, st.raw, st.session = row, bytes.Clone(t.cred), sess
		if st.legacy != nil {
			keys, err := loadPasskeys(ctx, q)
			if err != nil {
				return nil, err
			}
			for _, k := range keys {
				if _, ok := st.legacy.wraps[k.ID]; ok && k.ID != row {
					st.approveOnly = append(st.approveOnly, encodeID(k.CredentialID))
				}
			}
		}
	}
	s.log.Info("staging step done", "step", meta.Action, "scopes", strings.Join(t.scopes, ","))
	s.bcast.notify()
	return api.OK{OK: true}, nil
}

// stageAfterLegacy is nil outside tests: a test sets it to fail the
// open-legacy tap after the format-1 key opened, to prove the stage resets.
var stageAfterLegacy func() error

// stageKEKs consumes the tap's attempt and opens its packet into want keys.
func (s *Server) stageKEKs(t *tapOpen, sess string, challenge []byte, pkt *api.OpenPacket, want int) ([]*seal.Key, error) {
	z := s.seal
	if pkt == nil || pkt.AttemptID != t.attempt {
		return nil, errConflict("this passkey returned no PRF result: use a passkey that supports PRF")
	}
	at, err := z.opens.Take(sess, t.purpose, pkt.AttemptID)
	if err != nil {
		return nil, errConflict("stale staging step; start it again")
	}
	enc, err1 := strictB64(pkt.Enc, 65)
	ct, err2 := strictB64(pkt.Ciphertext, 512)
	if err1 != nil || err2 != nil {
		return nil, errBad("invalid open packet")
	}
	keks, err := at.Open(z.installation, z.opens.Epoch(), challenge, t.cred, enc, ct)
	if err != nil {
		return nil, errForbidden("the passkey's keys could not be read; nothing was changed")
	}
	if len(keks) != want {
		destroyKeys(keks)
		return nil, errForbidden("wrong number of keys; nothing was changed")
	}
	return keks, nil
}

// openLegacy opens the format-1 MK with the passkey's format-1 KEK, stages
// every credential and wipes the MK. On failure nothing stays staged.
func (s *Server) openLegacy(ctx context.Context, st *sealStage, row int64, raw []byte, kek *seal.Key) error {
	w, ok := st.legacy.wraps[row]
	if !ok {
		return errConflict("this passkey cannot open the format-1 store")
	}
	c := seal.Credential{Generation: st.legacy.inv.Generation, RPID: s.rpID, RawID: raw, Salt: w.salt}
	mk, err := c.Unwrap(kek, w.wrap, st.legacy.inv.Check)
	if err != nil {
		return errForbidden("the format-1 key did not open: nothing was staged")
	}
	defer mk.Destroy()
	if err = st.newScopes(s.seal.installation, s.cfg.Seal.Recipient); err == nil {
		err = s.buildLegacy(ctx, st, mk)
	}
	if err == nil {
		for name, n := range st.plan {
			if n != countKind(st.buckets, name) {
				err = errors.New("the store changed during staging: restart the task")
			}
		}
	}
	if err != nil {
		st.reset()
		return errConflict(err.Error())
	}
	st.built = true
	s.log.Info("format-1 store opened once and staged in buckets; its key is wiped", "buckets", len(st.buckets))
	return nil
}

func countKind(bs []*stageBucket, scope string) int {
	n := 0
	for _, b := range bs {
		if b.scope == scope {
			n++
		}
	}
	return n
}

// sealDrill is the staging page's recovery drill: the pasted identity,
// HPKE-sealed to this process, opens every staged scope key from its recovery
// wrap, every bucket and every record. The identity is wiped at once.
func (s *Server) sealDrill(w http.ResponseWriter, r *http.Request, sess string) {
	z := s.seal
	if z == nil || z.stage == nil || z.mode != modeSetup {
		s.writeErr(w, r, errConflict("no seal import is staged"))
		return
	}
	var in struct {
		Packet string `json:"packet"`
	}
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	ctx := r.Context()
	row, err := s.store.Q().SessionPasskeyID(ctx, sess)
	if err == nil {
		err = s.sealOwner(ctx, s.store.Q(), sess, row)
	}
	if err != nil {
		s.writeErr(w, r, errForbidden("owner session required"))
		return
	}
	st := z.stage
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.activated || !st.built {
		s.writeErr(w, r, errConflict("open the old store first"))
		return
	}
	text, err := maint.OpenPacket(st.drill, DrillInfo(z.installation), in.Packet)
	if err != nil {
		s.writeErr(w, r, errBad("the recovery key packet could not be opened; reload the page and try again"))
		return
	}
	id, err := seal.ParseIdentity(text)
	clear(text)
	if err != nil {
		s.writeErr(w, r, errBad("that is not an age identity"))
		return
	}
	buckets := 0
	for _, sc := range st.scopes {
		k, err := seal.Scope{Installation: z.installation, Name: sc.name, Public: sc.pub}.Recover(id, z.recipient, sc.recovery)
		if err != nil {
			s.writeErr(w, r, errConflict("this is not the recovery key for the public key you gave: nothing was changed"))
			return
		}
		n, err := st.checkScope(z.installation, sc, k)
		k.Destroy()
		if err != nil {
			s.writeErr(w, r, errConflict(err.Error()))
			return
		}
		buckets += n
	}
	st.drilled = true
	s.log.Info("recovery drill passed on this machine", "scopes", len(st.scopes), "buckets", buckets)
	s.bcast.notify()
	writeJSON(w, 200, map[string]any{"ok": true, "scopes": len(st.scopes), "buckets": buckets})
}

// ---- activation ----

// activateStage writes the whole stage in one transaction (docs/BUCKETS.md §8
// step 5), then VACUUMs and checkpoints so no freed page keeps format-1 data.
func (s *Server) activateStage(ctx context.Context, sess string, row int64, canonical string, assertion []byte) error {
	if s.configPath != "" {
		current, err := config.Load(s.configPath)
		if err != nil || !reflect.DeepEqual(s.cfg, current) {
			return errConflict("configuration changed during staging")
		}
	}
	z := s.seal
	st := z.stage
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.ready() || sess != st.session {
		return errConflict("staging is not complete")
	}
	manifest, err := s.stageManifest(st)
	if err != nil {
		return err
	}
	var fields struct{ Manifest string }
	if json.Unmarshal([]byte(canonical), &fields) != nil || fields.Manifest != manifest {
		return errConflict("manifest changed")
	}
	if st.digests != nil {
		if err = s.visitSources(ctx, func(role string, b []byte) error {
			if sha256.Sum256(b) != st.digests[role] {
				return errConflict("a source changed; restart setup")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	now := s.now()
	err = s.store.Tx(ctx, func(q *store.Q) error {
		var ok int
		if err := q.Raw().QueryRowContext(ctx, `SELECT 1 FROM web_sessions w JOIN passkey_people login ON login.passkey_id=w.passkey_id JOIN people p ON p.id=login.person_id AND p.owner=1 JOIN passkey_people signing ON signing.passkey_id=? AND signing.person_id=p.id JOIN passkeys wrap ON wrap.id=? AND wrap.credential_id=? JOIN passkey_people bound ON bound.passkey_id=wrap.id AND bound.person_id=p.id WHERE w.hash=? AND w.access_sub=? AND w.expires_at>?`,
			row, st.passkey, st.raw, sess, accessSub(ctx), now.UnixMilli()).Scan(&ok); err != nil {
			return errConflict("owner or staging passkey changed")
		}
		return s.writeStage(ctx, q, st, manifest, canonical, assertion, row)
	})
	if err != nil {
		return err
	}
	st.activated = true
	z.mode = modeActivated
	st.wipe()
	db := s.store.DB()
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		s.log.Error("VACUUM after activation failed; run it before the next backup")
	}
	if err := s.store.CheckpointWAL(ctx); err != nil {
		s.log.Error("WAL checkpoint after activation failed")
	}
	dir, err := os.MkdirTemp(s.cfg.DataDir, "seal-stage-")
	if err == nil {
		err = writeExclusive(filepath.Join(dir, "manifest.json"), []byte(manifest))
	}
	if err != nil {
		s.log.Warn("could not write manifest.json for the runner; the database holds it")
	}
	s.log.Info("activated per-credential buckets; compare the manifest digest with the owner display", "manifest_sha256", seal.Digest([]byte(manifest)))
	return nil
}

// writeStage is the activation transaction's body.
func (s *Server) writeStage(ctx context.Context, q *store.Q, st *sealStage, manifest, canonical string, assertion []byte, row int64) error {
	db := q.Raw()
	now := s.now()
	exec := func(query string, args ...any) error { _, err := db.ExecContext(ctx, query, args...); return err }
	if err := exec(store.BucketDDL + sealActiveDDL); err != nil {
		return err
	}
	for _, sc := range st.scopes {
		if err := q.InsertScope(ctx, store.ScopeRow{Scope: sc.name, Public: sc.pub, Recovery: sc.recovery, Created: now}); err != nil {
			return err
		}
		if err := exec(`INSERT INTO scope_wraps(passkey,scope,salt,wrap,created,tested_at) VALUES(?,?,?,?,?,?)`, st.passkey, sc.name, sc.salt[:], sc.wrap, now.UnixMilli(), now.UnixMilli()); err != nil {
			return err
		}
	}
	hasEnv, hasSigners := tableExists(ctx, db, "env_revisions"), tableExists(ctx, db, "signer_keys")
	if hasSigners {
		// Format 1 froze payload and wrap; format 2 re-encrypts them (rekey).
		if err := exec(`DROP TRIGGER IF EXISTS signer_key_immutable`); err != nil {
			return err
		}
	}
	for _, b := range st.buckets {
		row := store.BucketRow{ID: b.id[:], Scope: b.scope, Kind: b.kind, Ref: b.ref, Public: b.pub, Wrap: b.wrap, Created: now}
		switch b.kind {
		case "env-set":
			if !hasEnv {
				return errors.New("env tables missing")
			}
			if err := one(db.ExecContext(ctx, `UPDATE env_revisions SET payload=?,wrap=? WHERE set_id=? AND revision=? AND wrap IS NOT NULL`, b.payload, b.id[:], b.ref, b.revision)); err != nil {
				return errConflict("an env revision changed during staging")
			}
		case "signer":
			if !hasSigners {
				return errors.New("signer table missing")
			}
			if err := one(db.ExecContext(ctx, `UPDATE signer_keys SET payload=?,wrap=? WHERE set_id=? AND wrap IS NOT NULL`, b.payload, b.id[:], b.ref)); err != nil {
				return errConflict("a signer changed during staging")
			}
		default:
			row.Payload = b.payload
		}
		if err := q.InsertBucket(ctx, row); err != nil {
			return err
		}
	}
	if hasEnv {
		// Older revisions held no values (v0.4.1 nulled them); drafts expire in minutes.
		if err := exec(`DELETE FROM env_revisions WHERE revision!=coalesce((SELECT s.revision FROM credential_sets s WHERE s.id=env_revisions.set_id),-1); DELETE FROM env_drafts`); err != nil {
			return err
		}
		var left int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM env_revisions WHERE wrap IS NOT NULL AND (length(wrap)!=32 OR wrap NOT IN (SELECT id FROM buckets WHERE kind='env-set'))`).Scan(&left); err != nil || left != 0 {
			return errConflict("an env revision was not staged; restart the task")
		}
	}
	if hasSigners {
		var left int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM signer_keys WHERE wrap IS NULL OR length(wrap)!=32 OR wrap NOT IN (SELECT id FROM buckets WHERE kind='signer')`).Scan(&left); err != nil || left != 0 {
			return errConflict("a signer key was not staged; restart the task")
		}
		if err := exec(`CREATE TRIGGER signer_key_immutable BEFORE UPDATE OF set_id,scheme,public_key,origin,blob ON signer_keys BEGIN SELECT RAISE(ABORT,'immutable signer key'); END`); err != nil {
			return err
		}
	}
	if err := q.SetNoticeTopic(ctx, st.notice); err != nil {
		return err
	}
	if err := exec(`DROP TRIGGER IF EXISTS seal_keep_unlock; DROP TABLE IF EXISTS seal_wraps; DELETE FROM seal_active`); err != nil {
		return err
	}
	if err := exec(`INSERT INTO seal_active VALUES(1,?,?,?,?)`, manifest, []byte("{}"), canonical, assertion); err != nil {
		return err
	}
	if err := exec(`DELETE FROM challenges; DELETE FROM enroll_codes`); err != nil {
		return err
	}
	if err := q.Audit(ctx, now, "owner", "seal_activate", "seal", fmt.Sprintf("passkey=%d source=%s manifest=%s", row, st.source, seal.Digest([]byte(manifest)))); err != nil {
		return err
	}
	return exec(fmt.Sprintf(`PRAGMA user_version=%d`, store.SchemaBuckets))
}

func one(r interface{ RowsAffected() (int64, error) }, err error) error {
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n != 1 {
		err = errors.New("expected one row")
	}
	return err
}
