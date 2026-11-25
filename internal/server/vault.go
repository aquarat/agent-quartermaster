package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// The vault is the owner's page for credential-set contents (docs/API.md
// "Vault"): a write-only form, a reveal that only the asking browser can
// read, and signer keys that never leave. Every state change and every reveal
// is its own passkey assertion over a v3 canonical whose metadata this file
// rebuilds from current rows at challenge and again at finish. None of these
// routes accepts an approval-window proof, and none works without a fresh
// assertion.

const (
	vaultAttemptTTL = 5 * time.Minute
	vaultMaxPacket  = 48 << 10
)

// vaultPending is a secret in transit, held only in memory for a few minutes:
// the private half of an upload recipient (and, once submitted, the browser's
// ciphertext), or a freshly generated signer key awaiting its signature.
type vaultPending struct {
	session   string
	expires   time.Time
	recipient *seal.Recipient
	purpose   string // "" until submitted, then "edit" or "signer-import"; "signer-generate"
	target    string // set ID the packet was sealed for
	enc, ct   []byte
	commit    string
	scheme    string
	priv, pub []byte
}
type vaultPool struct {
	mu  sync.Mutex
	m   map[string]*vaultPending
	ttl time.Duration // zero: vaultAttemptTTL
}

func (p *vaultPool) life() time.Duration {
	if p.ttl > 0 {
		return p.ttl
	}
	return vaultAttemptTTL
}

func (p *vaultPool) prune(now time.Time) {
	for id, v := range p.m {
		if !now.Before(v.expires) {
			clear(v.priv)
			delete(p.m, id)
		}
	}
}
func (p *vaultPool) add(now time.Time, v *vaultPending) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	n := 0
	for _, x := range p.m {
		if x.session == v.session {
			n++
		}
	}
	if n >= 16 || len(p.m) >= 64 {
		return "", &apiErr{429, "rate_limited", "too many unfinished vault ceremonies; retry shortly"}
	}
	if p.m == nil {
		p.m = map[string]*vaultPending{}
	}
	id := seal.RandomID()
	s := encodeID(id[:])
	v.expires = now.Add(p.life())
	p.m[s] = v
	// Expiry does not wait for the next vault call: the recipient key, packet
	// or generated key is dropped on a timer of its own.
	time.AfterFunc(p.life(), func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.m[s] == v {
			clear(v.priv)
			delete(p.m, s)
		}
	})
	return s, nil
}

// get returns a snapshot of a live entry of this session. The caller owns the
// snapshot's copy of a generated key and clears it; the packet slices are
// written once and never modified. take also removes and wipes the entry.
func (p *vaultPool) get(now time.Time, sess, id string, take bool) *vaultPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	v := p.m[id]
	if v == nil || v.session != sess {
		return nil
	}
	c := *v
	c.priv = slices.Clone(v.priv)
	if take {
		clear(v.priv)
		delete(p.m, id)
	}
	return &c
}

// bind records the one packet an upload attempt will ever accept.
func (p *vaultPool) bind(now time.Time, sess, id, purpose, target, commit, scheme string, enc, ct []byte) (*vaultPending, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	v := p.m[id]
	if v == nil || v.session != sess || v.recipient == nil || v.purpose != "" {
		return nil, errConflict("upload attempt expired or already used; start again")
	}
	v.purpose, v.target, v.enc, v.ct, v.commit, v.scheme = purpose, target, enc, ct, commit, scheme
	c := *v
	return &c, nil
}
func (p *vaultPool) logout(sess string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, v := range p.m {
		if v.session == sess {
			clear(v.priv)
			delete(p.m, id)
		}
	}
}

func (s *Server) vaultInfo(purpose string) []byte {
	return seal.Tuple("hpke-vault", s.seal.installation[:], []byte(purpose))
}
func (s *Server) vaultUploadAAD(attempt, set string) ([]byte, error) {
	raw, err := strictB64(attempt, 32)
	if err != nil || len(raw) != 32 {
		return nil, errBad("invalid attempt id")
	}
	epoch := s.seal.opens.Epoch()
	return seal.Tuple("hpke-vault-aad", raw, epoch[:], []byte(set)), nil
}

func (s *Server) vaultRoutes(m *http.ServeMux) {
	s.sealedEndpoint(m, "POST /api/ui/seal/vault/attempt", s.vaultAttempt)
	for path, fn := range map[string]capHandler{"GET /api/ui/seal/vault/state": s.vaultState, "GET /api/ui/seal/vault/history": s.vaultHistory, "POST /api/ui/seal/vault/challenge": s.vaultChallenge, "POST /api/ui/seal/vault/finish": s.vaultFinish} {
		s.sealedEndpoint(m, path, fn)
	}
}

// vaultOwner is the common gate: the global owner, in a live session.
func (s *Server) vaultOwner(ctx context.Context, q *store.Q, sess string) (int64, error) {
	pk, err := q.SessionPasskeyID(ctx, sess)
	if err != nil {
		return 0, err
	}
	return pk, s.sealOwner(ctx, q, sess, pk)
}

type vaultSetView struct {
	store.VaultTarget
	PublicKey   string `json:"public_key,omitempty"`
	PublicHex   string `json:"public_hex,omitempty"`
	PublicPEM   string `json:"public_pem,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func (s *Server) vaultState(ctx context.Context, r *http.Request, sess string) (any, error) {
	out := struct {
		Schemes  []signer.Scheme  `json:"schemes"`
		Orgs     []store.VaultOrg `json:"organisations"`
		Sets     []vaultSetView   `json:"sets"`
		Requests []signer.Request `json:"requests"`
	}{Schemes: signer.All(), Sets: []vaultSetView{}}
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if _, err := s.vaultOwner(ctx, q, sess); err != nil {
			return err
		}
		if !q.Scoped() {
			return errNotFound()
		}
		if err := q.SweepSign(ctx, s.now()); err != nil {
			return err
		}
		var err error
		if out.Orgs, err = q.VaultOrgs(ctx); err != nil {
			return err
		}
		sets, err := q.VaultSets(ctx)
		if err != nil {
			return err
		}
		for _, t := range sets {
			v := vaultSetView{VaultTarget: t}
			if t.Kind == "signer" {
				sc, _ := signer.Lookup(t.Scheme)
				v.PublicKey, v.PublicHex, v.Fingerprint = encodeID(t.PublicKey), hex.EncodeToString(t.PublicKey), signer.Fingerprint(t.PublicKey)
				v.PublicPEM, _ = sc.PublicPEM(t.PublicKey)
			}
			out.Sets = append(out.Sets, v)
		}
		out.Requests, err = q.OwnerSignRequests(ctx)
		return err
	})
	return out, err
}

// vaultHistory is the owner's read-only view of one set's recent audit rows
// and, from them, when it last changed and was last used (0: not in the rows
// read). Display only: no value, and nothing a decision is taken from.
func (s *Server) vaultHistory(ctx context.Context, r *http.Request, sess string) (any, error) {
	out := struct {
		Entries     []api.AuditEntry `json:"entries"`
		LastChanged int64            `json:"last_changed_at"`
		LastUsed    int64            `json:"last_used_at"`
	}{Entries: []api.AuditEntry{}}
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if _, err := s.vaultOwner(ctx, q, sess); err != nil {
			return err
		}
		if !q.Scoped() {
			return errNotFound()
		}
		t, err := q.VaultSet(ctx, r.URL.Query().Get("set"))
		if err != nil {
			return err
		}
		rows, err := q.SetHistory(ctx, t.SetID, t.OrgSlug+"/"+t.ServiceSlug+"/"+t.SetSlug, 200)
		if err != nil {
			return err
		}
		for _, e := range rows {
			switch {
			case out.LastChanged == 0 && (e.Action == "vault_commit" || e.Action == "vault_signer_create" || e.Action == "vault_secret_create" || e.Action == "env_commit"):
				out.LastChanged = e.At.UnixMilli()
			case out.LastUsed == 0 && (e.Action == "sign" || strings.HasPrefix(e.Action, "env_collect_")):
				out.LastUsed = e.At.UnixMilli()
			}
		}
		out.Entries = rows[:min(len(rows), 20)]
		return nil
	})
	return out, err
}

// vaultAttempt hands the browser a fresh recipient for one upload.
func (s *Server) vaultAttempt(ctx context.Context, r *http.Request, sess string) (any, error) {
	if err := s.store.Tx(ctx, func(q *store.Q) error { _, err := s.vaultOwner(ctx, q, sess); return err }); err != nil {
		return nil, err
	}
	k, err := seal.NewRecipient()
	if err != nil {
		return nil, err
	}
	id, err := s.seal.vault.add(s.now(), &vaultPending{session: sess, recipient: k})
	if err != nil {
		return nil, err
	}
	return map[string]any{"attempt_id": id, "recipient": encodeID(k.Public()), "expires_at": s.now().Add(vaultAttemptTTL).UnixMilli()}, nil
}

type vaultChoice struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	// commit and signer-create (import): the sealed upload.
	Attempt    string `json:"attempt_id,omitempty"`
	Enc        string `json:"enc,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Commitment string `json:"commitment,omitempty"`
	// reveal
	Names     []string `json:"names,omitempty"`
	Recipient string   `json:"recipient,omitempty"`
	// policy
	AllowReveal *bool `json:"allow_reveal,omitempty"`
	// signer-create
	Service string `json:"service_id,omitempty"`
	Slug    string `json:"set_slug,omitempty"`
	Title   string `json:"set_title,omitempty"`
	Scheme  string `json:"scheme,omitempty"`
	Source  string `json:"source,omitempty"`
	// secret-create, secret-convert: optional public note and link
	Note string `json:"note,omitempty"`
	URL  string `json:"url,omitempty"`
	// standing-cap: the set's "longest don't-ask-again" (0 turns it off)
	StandingCap *int `json:"standing_cap_seconds,omitempty"`
	// sign-approve
	TTL int `json:"ttl_seconds,omitempty"`
	Max int `json:"max_signatures,omitempty"`
}

func targetFields(t store.VaultTarget) map[string]any {
	return map[string]any{"org_id": t.OrgID, "org_slug": t.OrgSlug, "org_title": t.OrgTitle, "service_id": t.ServiceID, "service_slug": t.ServiceSlug, "service_title": t.ServiceTitle, "set_id": t.SetID, "set_slug": t.SetSlug, "set_title": t.SetTitle, "kind": t.Kind, "revision": t.Revision}
}

// openEdit decrypts a submitted form packet. The caller clears the values.
func (s *Server) openEdit(p *vaultPending, t store.VaultTarget, attempt string) (envset.Edit, error) {
	var e envset.Edit
	aad, err := s.vaultUploadAAD(attempt, t.SetID)
	if err != nil {
		return e, err
	}
	b, err := p.recipient.Open(s.vaultInfo("edit"), aad, p.enc, p.ct)
	if err != nil {
		return e, errBad("the sealed form could not be opened; start again")
	}
	defer clear(b)
	if json.Unmarshal(b, &e) != nil || e.Op != "merge" && e.Op != "import" {
		return envset.Edit{}, errBad("invalid form edit")
	}
	digest, err := e.Commit(t.Binding())
	if err != nil || digest != p.commit {
		return envset.Edit{}, errBad("invalid edit commitment")
	}
	return e, nil
}
func (s *Server) openSignerKey(p *vaultPending, attempt, set string) (priv, pub []byte, err error) {
	sc, ok := signer.Lookup(p.scheme)
	if !ok {
		return nil, nil, errBad("unknown signing scheme")
	}
	aad, err := s.vaultUploadAAD(attempt, set)
	if err != nil {
		return nil, nil, err
	}
	b, err := p.recipient.Open(s.vaultInfo("signer-import"), aad, p.enc, p.ct)
	if err != nil {
		return nil, nil, errBad("the sealed key could not be opened; start again")
	}
	defer clear(b)
	var in struct {
		Key string `json:"private_key"`
	}
	if json.Unmarshal(b, &in) != nil {
		return nil, nil, errBad("invalid key packet")
	}
	priv, pub, err = sc.ParsePrivate([]byte(in.Key))
	if err != nil {
		return nil, nil, errBad(err.Error())
	}
	return priv, pub, nil
}

// submit binds an uploaded packet to its attempt exactly once.
func (s *Server) submit(sess string, c vaultChoice, purpose, target string) (*vaultPending, error) {
	enc, err1 := strictB64(c.Enc, 65)
	ct, err2 := strictB64(c.Ciphertext, vaultMaxPacket)
	if err1 != nil || err2 != nil || len(enc) != 65 || len(ct) < 17 {
		return nil, errBad("invalid sealed packet")
	}
	return s.seal.vault.bind(s.now(), sess, c.Attempt, purpose, target, c.Commitment, c.Scheme, enc, ct)
}

// vaultReview validates one choice against current rows and returns the exact
// metadata the owner signs. With submitted=false (finish) it only re-derives:
// it never accepts new ciphertext, and uses the attempt named in the signed
// metadata. facts are unsigned conveniences the page checks against the
// canonical.
func (s *Server) vaultReview(ctx context.Context, q *store.Q, sess string, pk int64, c vaultChoice, begin bool) (meta string, facts map[string]any, err error) {
	if err = s.sealOwner(ctx, q, sess, pk); err != nil {
		return
	}
	if !q.Scoped() {
		return "", nil, errNotFound()
	}
	if err = q.SweepSign(ctx, s.now()); err != nil {
		return
	}
	owner := func(org string) error {
		if q.IsOrgOwner(ctx, org, sess, pk, s.now()) != nil {
			return errForbidden("organisation approval required")
		}
		return nil
	}
	var m map[string]any
	facts = map[string]any{}
	switch c.Action {
	case "policy":
		o, err := q.VaultOrg(ctx, c.ID)
		if err != nil {
			return "", nil, err
		}
		if err = owner(o.ID); err != nil {
			return "", nil, err
		}
		if c.AllowReveal == nil || *c.AllowReveal == o.AllowReveal {
			return "", nil, errConflict("policy already has that value; reload")
		}
		m = map[string]any{"org_id": o.ID, "org_slug": o.Slug, "org_title": o.Title, "old_allow_reveal": o.AllowReveal, "allow_reveal": *c.AllowReveal}
	case "commit":
		t, err := q.VaultSet(ctx, c.ID)
		if err != nil {
			return "", nil, err
		}
		if err = owner(t.OrgID); err != nil {
			return "", nil, err
		}
		if t.Kind != "env-set" && t.Kind != "secret" {
			return "", nil, errBad("not an env set")
		}
		if err = s.canWrite(ctx, q, "env-set", t.SetID, t.OrgID); err != nil {
			return "", nil, err
		}
		var p *vaultPending
		if begin {
			p, err = s.submit(sess, c, "edit", t.SetID)
		} else if p = s.seal.vault.get(s.now(), sess, c.Attempt, false); p == nil || p.purpose != "edit" || p.target != t.SetID {
			err = errConflict("upload attempt expired; start again")
		}
		if err != nil {
			return "", nil, err
		}
		edit, err := s.openEdit(p, t, c.Attempt)
		if err != nil {
			if !begin { // it opened at review: the base revision moved since
				err = errConflict("the set changed; review again")
			}
			return "", nil, err
		}
		changes, err := edit.Changes(t.Names)
		for i := range edit.Entries {
			edit.Entries[i].Value = ""
		}
		if err != nil {
			return "", nil, errBad(err.Error())
		}
		if t.Kind == "secret" && len(namesAfter(t.Names, edit)) != 1 {
			return "", nil, errBad("a secret holds exactly one value: replace it, or keep several values in an env set")
		}
		m = targetFields(t)
		m["attempt_id"], m["operation"], m["changes"], m["commitment"], m["result_revision"] = c.Attempt, edit.Op, changes, p.commit, t.Revision+1
		m["recipient"] = encodeID(p.recipient.Public())
	case "reveal":
		t, err := q.VaultSet(ctx, c.ID)
		if err != nil {
			return "", nil, err
		}
		if err = owner(t.OrgID); err != nil {
			return "", nil, err
		}
		if t.Kind != "env-set" && t.Kind != "secret" {
			return "", nil, errForbidden("a signer key is never revealed")
		}
		if !t.AllowReveal {
			return "", nil, errForbidden("this organisation does not allow reveal")
		}
		names := slices.Clone(c.Names)
		slices.Sort(names)
		if len(names) == 0 || !slices.Equal(names, slices.Compact(slices.Clone(names))) || !slices.Equal(names, c.Names) {
			return "", nil, errBad("name the keys to reveal, sorted, each once")
		}
		for _, n := range names {
			if !slices.Contains(t.Names, n) {
				return "", nil, errConflict("the set changed; reload")
			}
		}
		pub, err := strictB64(c.Recipient, 65)
		if err != nil || len(pub) != 65 || pub[0] != 4 {
			return "", nil, errBad("invalid reveal recipient")
		}
		if _, err = ecdh.P256().NewPublicKey(pub); err != nil {
			return "", nil, errBad("invalid reveal recipient")
		}
		m = targetFields(t)
		m["names"], m["recipient"] = names, c.Recipient
	case "signer-create":
		t, err := q.VaultService(ctx, c.Service)
		if err != nil {
			return "", nil, err
		}
		if err = owner(t.OrgID); err != nil {
			return "", nil, err
		}
		sc, ok := signer.Lookup(c.Scheme)
		if !ok || !catalogueID.MatchString(c.ID) || !config.ValidName(c.Slug) || !catalogueTitle.MatchString(c.Title) || strings.TrimSpace(c.Title) != c.Title {
			return "", nil, errBad("invalid signer set")
		}
		if free, err := q.SetSlugFree(ctx, t.ServiceID, c.ID, c.Slug); err != nil || !free {
			return "", nil, errConflict("a set with that name or ID exists; reload")
		}
		if err = s.canWrite(ctx, q, "signer", c.ID, t.OrgID); err != nil {
			return "", nil, err
		}
		t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Revision = c.ID, c.Slug, c.Title, "signer", 0
		var pub []byte
		recipient := "" // the upload recipient of an import; empty for a generated key
		switch {
		case c.Source == "generate" && begin:
			if c.Attempt != "" || c.Enc != "" || c.Ciphertext != "" {
				return "", nil, errBad("unexpected upload")
			}
			priv, p, err := sc.Generate()
			if err != nil {
				return "", nil, err
			}
			if c.Attempt, err = s.seal.vault.add(s.now(), &vaultPending{session: sess, purpose: "signer-generate", target: t.SetID, scheme: sc.ID, priv: priv, pub: p}); err != nil {
				clear(priv)
				return "", nil, err
			}
			pub = p
		case c.Source == "generate":
			p := s.seal.vault.get(s.now(), sess, c.Attempt, false)
			if p == nil || p.purpose != "signer-generate" || p.target != t.SetID || p.scheme != sc.ID {
				return "", nil, errConflict("generated key expired; start again")
			}
			clear(p.priv)
			pub = p.pub
		case c.Source == "import":
			var p *vaultPending
			if begin {
				p, err = s.submit(sess, c, "signer-import", t.SetID)
			} else if p = s.seal.vault.get(s.now(), sess, c.Attempt, false); p == nil || p.purpose != "signer-import" || p.target != t.SetID || p.scheme != sc.ID {
				err = errConflict("upload attempt expired; start again")
			}
			if err != nil {
				return "", nil, err
			}
			var priv []byte
			if priv, pub, err = s.openSignerKey(p, c.Attempt, t.SetID); err != nil {
				return "", nil, err
			}
			clear(priv)
			recipient = encodeID(p.recipient.Public())
		default:
			return "", nil, errBad("choose generate or import")
		}
		m = targetFields(t)
		m["scheme"], m["source"], m["attempt_id"], m["public_key"], m["fingerprint"], m["result_revision"] = sc.ID, c.Source, c.Attempt, encodeID(pub), signer.Fingerprint(pub), 0
		m["recipient"] = recipient
		pemText, _ := sc.PublicPEM(pub)
		facts["public_key"], facts["fingerprint"], facts["public_hex"], facts["public_pem"] = encodeID(pub), signer.Fingerprint(pub), hex.EncodeToString(pub), pemText
	case "secret-create":
		// A secret is created with its value in one tap: the set row, its
		// marker and revision 1 (docs/API.md "Secrets").
		t, err := q.VaultService(ctx, c.Service)
		if err != nil {
			return "", nil, err
		}
		if err = owner(t.OrgID); err != nil {
			return "", nil, err
		}
		if !catalogueID.MatchString(c.ID) || !config.ValidName(c.Slug) || !catalogueTitle.MatchString(c.Title) || strings.TrimSpace(c.Title) != c.Title || !validSecretMeta(c.Note, c.URL) {
			return "", nil, errBad("invalid secret")
		}
		if free, err := q.SetSlugFree(ctx, t.ServiceID, c.ID, c.Slug); err != nil || !free {
			return "", nil, errConflict("a set with that name or ID exists; reload")
		}
		if err = s.canWrite(ctx, q, "env-set", c.ID, t.OrgID); err != nil {
			return "", nil, err
		}
		t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Revision, t.Names = c.ID, c.Slug, c.Title, "secret", 0, []string{}
		var p *vaultPending
		if begin {
			p, err = s.submit(sess, c, "edit", t.SetID)
		} else if p = s.seal.vault.get(s.now(), sess, c.Attempt, false); p == nil || p.purpose != "edit" || p.target != t.SetID {
			err = errConflict("upload attempt expired; start again")
		}
		if err != nil {
			return "", nil, err
		}
		edit, err := s.openEdit(p, t, c.Attempt)
		if err != nil {
			return "", nil, err
		}
		name := ""
		if len(edit.Entries) == 1 {
			name = edit.Entries[0].Name
		}
		for i := range edit.Entries {
			edit.Entries[i].Value = ""
		}
		if edit.Op != "import" || name == "" || len(edit.Remove) != 0 {
			return "", nil, errBad("a secret is one name and one value")
		}
		m = targetFields(t)
		m["attempt_id"], m["env_name"], m["note"], m["url"], m["commitment"], m["result_revision"] = c.Attempt, name, c.Note, c.URL, p.commit, 1
		m["recipient"] = encodeID(p.recipient.Public())
	case "standing-cap":
		t, err := q.VaultSet(ctx, c.ID)
		if err != nil {
			return "", nil, err
		}
		if err = owner(t.OrgID); err != nil {
			return "", nil, err
		}
		if t.Kind != "env-set" && t.Kind != "secret" {
			return "", nil, errBad("only env sets and secrets have a don't-ask-again limit")
		}
		if c.StandingCap == nil || *c.StandingCap < 0 || *c.StandingCap > envset.StandingCapMax || *c.StandingCap%60 != 0 {
			return "", nil, errBad("the limit is between 0 (off) and 24 hours, in whole minutes")
		}
		if *c.StandingCap == t.StandingCap {
			return "", nil, errConflict("the limit already has that value; reload")
		}
		m = targetFields(t)
		m["old_standing_cap_seconds"], m["standing_cap_seconds"] = t.StandingCap, *c.StandingCap
	case "secret-convert":
		t, err := q.VaultSet(ctx, c.ID)
		if err != nil {
			return "", nil, err
		}
		if err = owner(t.OrgID); err != nil {
			return "", nil, err
		}
		if t.Kind != "env-set" || len(t.Names) != 1 {
			return "", nil, errConflict("only an env set with exactly one key becomes a secret; reload")
		}
		if !validSecretMeta(c.Note, c.URL) {
			return "", nil, errBad("invalid secret")
		}
		m = targetFields(t)
		m["env_name"], m["note"], m["url"] = t.Names[0], c.Note, c.URL
	case "sign-approve", "sign-deny", "sign-revoke":
		v, host, err := q.SignRequest(ctx, c.ID, false)
		if err != nil {
			return "", nil, err
		}
		if err = owner(v.Org); err != nil {
			return "", nil, err
		}
		if c.Action == "sign-revoke" && v.Status != "approved" || c.Action != "sign-revoke" && v.Status != "pending" {
			return "", nil, errConflict("decision no longer available")
		}
		t, err := q.VaultSet(ctx, v.Set)
		if err != nil || t.Kind != "signer" {
			return "", nil, errConflict("signer no longer available")
		}
		if c.Action == "sign-approve" {
			b, err := q.SignBinding(ctx, host, v.Path, s.now())
			if err != nil || !signBindingEqual(b, v.Binding) {
				return "", nil, errConflict("admission or signer changed")
			}
			single := c.TTL == 0 && c.Max == len(v.Items)
			timed := v.TTL > 0 && c.TTL > 0 && c.TTL <= v.TTL && c.Max >= 1 && c.Max <= v.Max
			if !single && !timed {
				return "", nil, errBad("duration or count exceeds the request")
			}
		} else if c.TTL != 0 || c.Max != 0 {
			return "", nil, errBad("unexpected duration")
		}
		items := make([]map[string]any, len(v.Items))
		for i, it := range v.Items {
			items[i] = map[string]any{"name": it.Name, "size": it.Size, "sha256": it.SHA256}
			if it.SHA512 != "" {
				items[i]["sha512"] = it.SHA512
			}
		}
		m = targetFields(t)
		m["request_id"], m["host"], m["enrollment"], m["address"], m["scheme"], m["fingerprint"], m["items"] = v.ID, v.Host, v.Enrollment, v.Peer, v.Scheme, signer.Fingerprint(v.PublicKey), items
		m["requested_ttl_seconds"], m["requested_max_signatures"], m["ttl_seconds"], m["max_signatures"] = v.TTL, v.Max, c.TTL, c.Max
		m["admission_generation"], m["policy_revision"], m["service_revision"], m["soft_cap_seconds"], m["beyond_soft_cap"] = v.Generation, v.PolicyRevision, v.ServiceRevision, v.Soft, c.TTL > v.Soft
	default:
		return "", nil, errBad("unknown vault action")
	}
	meta, err = reviewJSON(m)
	if c.Attempt != "" {
		facts["attempt_id"] = c.Attempt
	}
	return meta, facts, err
}

// namesAfter is the key list an edit leaves behind (names only).
func namesAfter(old []string, e envset.Edit) []string {
	m := map[string]bool{}
	if e.Op != "import" {
		for _, n := range old {
			m[n] = true
		}
	}
	for _, x := range e.Entries {
		m[x.Name] = e.Op != "unset"
	}
	for _, n := range e.Remove {
		m[n] = false
	}
	out := []string{}
	for n, ok := range m {
		if ok {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// validSecretMeta bounds a secret's public note and link: one line of plain
// text, and an http(s) URL with a host and nothing a page would reinterpret.
func validSecretMeta(note, link string) bool {
	if len(note) > 200 || !utf8.ValidString(note) || hasControl(note, false) || strings.TrimSpace(note) != note {
		return false
	}
	if link == "" {
		return true
	}
	u, err := url.Parse(link)
	return err == nil && len(link) <= 300 && utf8.ValidString(link) && !hasControl(link, false) && !strings.ContainsAny(link, " \\\"<>`") && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}
func signBindingEqual(a, b signer.Binding) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func (s *Server) vaultChallenge(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in vaultChoice
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	var meta string
	var facts map[string]any
	var needs []bucketNeed
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		if meta, facts, err = s.vaultReview(ctx, q, sess, pk, in, true); err != nil {
			return err
		}
		needs, err = s.vaultNeeds(ctx, q, in)
		return err
	})
	if err != nil {
		// A refused upload is not kept: its recipient key and packet go now.
		if p := s.seal.vault.get(s.now(), sess, in.Attempt, true); p != nil {
			clear(p.priv)
		}
		return nil, err
	}
	m := s.reviewFields("vault", in.Action, in.ID)
	m["metadata"] = meta
	text, _ := reviewJSON(m)
	ch, err := s.beginTap(ctx, sess, "vault", in.Action, text, needs, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"canonical": ch.Canonical, "challenge_id": ch.ChallengeID, "public_key": ch.PublicKey, "facts": facts}
	if ch.Open != nil {
		out["open"] = ch.Open
	}
	return out, nil
}

// vaultNeeds: a reveal opens the set for an instant; approving signing keeps
// the signer open until the grant is used up, expires or is revoked.
func (s *Server) vaultNeeds(ctx context.Context, q *store.Q, c vaultChoice) ([]bucketNeed, error) {
	switch c.Action {
	case "reveal":
		row, err := s.setRow(ctx, q, "env-set", c.ID)
		if err != nil {
			return nil, err
		}
		return []bucketNeed{s.need(row)}, nil
	case "sign-approve":
		v, _, err := q.SignRequest(ctx, c.ID, false)
		if err != nil {
			return nil, err
		}
		row, err := s.setRow(ctx, q, "signer", v.Set)
		if err != nil {
			return nil, err
		}
		until := s.now().Add(signer.CollectSeconds * time.Second)
		if c.TTL > 0 {
			until = s.now().Add(secs(c.TTL))
		}
		return []bucketNeed{s.need(row, signHold(c.ID, until))}, nil
	}
	return nil, nil
}

// canWrite refuses a first write in an organisation without a scope key.
func (s *Server) canWrite(ctx context.Context, q *store.Q, kind, set, org string) error {
	if _, err := q.BucketByRef(ctx, kind, set); err == nil {
		return nil
	}
	if _, err := q.Scope(ctx, org); err != nil {
		return errConflict("this organisation has no scope key yet: create the scope first (Security → Buckets)")
	}
	return nil
}

func (s *Server) vaultFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	// The only way in: a single-use stored challenge and a fresh user-verified
	// assertion over it. Nothing here consults an approval window.
	c, pk, settle, err := s.takeReview(ctx, sess, "vault", in)
	if err != nil {
		return nil, err
	}
	defer func() { settle(err == nil) }()
	var m struct {
		Action       string
		ID           string
		Metadata     string
		Epoch        seal.ID
		Installation seal.ID
	}
	if json.Unmarshal([]byte(c.Canonical), &m) != nil || m.Action != c.ObjectID || m.Epoch != s.seal.opens.Epoch() || m.Installation != s.seal.installation {
		err = errBad("invalid vault decision")
		return nil, err
	}
	// Rebuild the choice from the signed metadata alone.
	var f struct {
		Attempt     string   `json:"attempt_id"`
		Names       []string `json:"names"`
		Recipient   string   `json:"recipient"`
		AllowReveal *bool    `json:"allow_reveal"`
		Service     string   `json:"service_id"`
		Slug        string   `json:"set_slug"`
		Title       string   `json:"set_title"`
		Scheme      string   `json:"scheme"`
		Source      string   `json:"source"`
		TTL         int      `json:"ttl_seconds"`
		Max         int      `json:"max_signatures"`
		Changes     string   `json:"changes"`
		PublicKey   string   `json:"public_key"`
		Note        string   `json:"note"`
		URL         string   `json:"url"`
		EnvName     string   `json:"env_name"`
		StandingCap *int     `json:"standing_cap_seconds"`
	}
	if json.Unmarshal([]byte(m.Metadata), &f) != nil {
		err = errBad("invalid vault decision")
		return nil, err
	}
	choice := vaultChoice{Action: m.Action, ID: m.ID, Attempt: f.Attempt}
	switch m.Action {
	case "policy":
		choice.AllowReveal = f.AllowReveal
	case "reveal":
		choice.Names, choice.Recipient = f.Names, f.Recipient
	case "signer-create":
		choice.Service, choice.Slug, choice.Title, choice.Scheme, choice.Source = f.Service, f.Slug, f.Title, f.Scheme, f.Source
	case "secret-create":
		choice.Service, choice.Slug, choice.Title, choice.Note, choice.URL = f.Service, f.Slug, f.Title, f.Note, f.URL
	case "secret-convert":
		choice.Note, choice.URL = f.Note, f.URL
	case "standing-cap":
		choice.StandingCap = f.StandingCap
	case "sign-approve":
		choice.TTL, choice.Max = f.TTL, f.Max
	}
	var out any = api.OK{OK: true}
	var note, auditObject, detail string
	defer func() {
		if f.Attempt != "" { // spent whether or not the decision applied
			if p := s.seal.vault.get(s.now(), sess, f.Attempt, true); p != nil {
				clear(p.priv)
			}
		}
	}()
	err = s.store.Tx(ctx, func(q *store.Q) error {
		meta, _, err := s.vaultReview(ctx, q, sess, pk, choice, false)
		if err != nil {
			return err
		}
		if meta != m.Metadata {
			return errConflict("the proposal changed; review again")
		}
		now := s.now()
		switch m.Action {
		case "policy":
			o, err := q.VaultOrg(ctx, m.ID)
			if err != nil {
				return err
			}
			if err = q.SetOrgVault(ctx, o.ID, *f.AllowReveal); err != nil {
				return err
			}
			auditObject, detail, note = "org:"+o.ID, fmt.Sprintf("org=%s allow_reveal=%t", o.Slug, *f.AllowReveal), fmt.Sprintf("Reveal policy for %s set to %t", o.Slug, *f.AllowReveal)
		case "commit":
			t, err := q.VaultSet(ctx, m.ID)
			if err != nil {
				return err
			}
			p := s.seal.vault.get(now, sess, f.Attempt, false)
			if p == nil {
				return errConflict("upload attempt expired; start again")
			}
			edit, err := s.openEdit(p, t, f.Attempt)
			if err != nil {
				return err
			}
			defer func() {
				for i := range edit.Entries {
					edit.Entries[i].Value = ""
				}
			}()
			// Tapless: new values are sealed to the set's public key; the
			// entries this edit does not touch keep their ciphertext.
			b := t.Binding()
			row, err := s.ensureSetBucket(ctx, q, "env-set", t.SetID, t.OrgID)
			if err != nil {
				return err
			}
			old, _, err := s.revisionRecords(ctx, q, b)
			if err != nil {
				return err
			}
			sealed, err := s.sealEntries(s.sealBucket(row), t.SetID, edit.Entries)
			if err != nil {
				return err
			}
			if err = s.writeRevision(ctx, q, b, row, mergeRecords(old, edit.Op, sealed, edit.Remove)); err != nil {
				return err
			}
			next := b
			next.Revision++
			path := t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug
			auditObject, detail, note = "set:"+t.SetID, fmt.Sprintf("%s revision=%d operation=%s changes=%s commitment=%s", path, next.Revision, edit.Op, f.Changes, p.commit), fmt.Sprintf("Saved %s revision %d", path, next.Revision)
		case "reveal":
			t, err := q.VaultSet(ctx, m.ID)
			if err != nil {
				return err
			}
			vals, err := s.values(ctx, q, t.Binding())
			if err != nil {
				return err
			}
			var picked struct {
				Entries []envset.Entry `json:"entries"`
			}
			for _, e := range vals {
				if slices.Contains(f.Names, e.Name) {
					picked.Entries = append(picked.Entries, e)
				}
			}
			if len(picked.Entries) != len(f.Names) {
				return errConflict("the set changed; reload")
			}
			plain, err := json.Marshal(picked)
			if err != nil {
				return err
			}
			defer clear(plain)
			pub, _ := strictB64(f.Recipient, 65)
			epoch := s.seal.opens.Epoch()
			enc, ct, err := seal.SealTo(pub, s.vaultInfo("reveal"), seal.Tuple("hpke-vault-aad", canon.Challenge(c.Canonical), epoch[:], []byte(t.SetID)), plain)
			if err != nil {
				return errBad("invalid reveal recipient")
			}
			out = map[string]any{"enc": encodeID(enc), "ciphertext": encodeID(ct)}
			path := t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug
			auditObject, detail, note = "set:"+t.SetID, fmt.Sprintf("%s revision=%d names=%s", path, t.Revision, strings.Join(f.Names, ",")), fmt.Sprintf("Revealed %d value(s) of %s to the approval page", len(f.Names), path)
		case "signer-create":
			sc, _ := signer.Lookup(f.Scheme)
			p := s.seal.vault.get(now, sess, f.Attempt, false)
			if p == nil {
				return errConflict("key expired; start again")
			}
			var priv, pub []byte
			origin := "generated"
			if f.Source == "import" {
				origin = "imported"
				if priv, pub, err = s.openSignerKey(p, f.Attempt, m.ID); err != nil {
					return err
				}
			} else {
				priv, pub = p.priv, p.pub // p is this request's own snapshot
			}
			defer clear(priv)
			// Whatever happened to the pending entry meanwhile, never seal a key
			// that is not the private half of the public key the owner signed for.
			if derived, err := sc.Public(priv); err != nil || !bytes.Equal(derived, pub) || encodeID(pub) != f.PublicKey {
				return errConflict("key expired; start again")
			}
			t, err := q.VaultService(ctx, f.Service)
			if err != nil {
				return err
			}
			t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Scheme, t.PublicKey, t.Origin = m.ID, f.Slug, f.Title, "signer", sc.ID, pub, origin
			// The signer's bucket is created with it; the key is sealed to its public half.
			row, err := s.ensureSetBucket(ctx, q, "signer", t.SetID, t.OrgID)
			if err != nil {
				return err
			}
			plain, err := json.Marshal(signerSecret{Scheme: sc.ID, Private: priv})
			if err != nil {
				return err
			}
			rec, err := s.sealBucket(row).Seal(seal.RoleSignerKey, signerFields(t), plain)
			clear(plain)
			if err != nil {
				return err
			}
			blob := seal.RandomID()
			if err = q.CreateSigner(ctx, t, store.CipherRecord{Blob: blob[:], Payload: rec, Wrap: row.ID}, now); err != nil {
				return errConflict("a set with that name or ID exists; reload")
			}
			path := t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug
			pemText, _ := sc.PublicPEM(pub)
			out = map[string]any{"set_id": t.SetID, "path": path, "scheme": sc.ID, "public_key": encodeID(pub), "public_hex": hex.EncodeToString(pub), "public_pem": pemText, "fingerprint": signer.Fingerprint(pub)}
			auditObject, detail, note = "set:"+t.SetID, fmt.Sprintf("%s scheme=%s origin=%s fingerprint=%s", path, sc.ID, origin, signer.Fingerprint(pub)), fmt.Sprintf("Created signer %s (%s)", path, sc.ID)
		case "secret-create":
			p := s.seal.vault.get(now, sess, f.Attempt, false)
			if p == nil {
				return errConflict("upload attempt expired; start again")
			}
			t, err := q.VaultService(ctx, f.Service)
			if err != nil {
				return err
			}
			t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Note, t.URL, t.Names = m.ID, f.Slug, f.Title, "secret", f.Note, f.URL, []string{}
			edit, err := s.openEdit(p, t, f.Attempt)
			if err != nil {
				return err
			}
			defer func() {
				for i := range edit.Entries {
					edit.Entries[i].Value = ""
				}
			}()
			if len(edit.Entries) != 1 || edit.Entries[0].Name != f.EnvName {
				return errConflict("the proposal changed; review again")
			}
			if err = q.CreateSecret(ctx, t, now); err != nil {
				return errConflict("a set with that name or ID exists; reload")
			}
			// Same storage as an env set: the set's own bucket, the value sealed
			// to its public key (nothing is opened to create a secret).
			row, err := s.ensureSetBucket(ctx, q, "env-set", t.SetID, t.OrgID)
			if err != nil {
				return err
			}
			sealed, err := s.sealEntries(s.sealBucket(row), t.SetID, edit.Entries)
			if err != nil {
				return err
			}
			if err = s.writeRevision(ctx, q, t.Binding(), row, sealed); err != nil {
				return err
			}
			path := t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug
			out = map[string]any{"set_id": t.SetID, "path": path, "env_name": f.EnvName}
			auditObject, detail, note = "set:"+t.SetID, fmt.Sprintf("%s revision=1 env=%s commitment=%s", path, f.EnvName, p.commit), fmt.Sprintf("Created secret %s", path)
		case "standing-cap":
			t, err := q.VaultSet(ctx, m.ID)
			if err != nil {
				return err
			}
			if err = q.SetStandingCap(ctx, t.SetID, *f.StandingCap); err != nil {
				return err
			}
			// The rules made under the old limit end with it.
			rules, err := q.ActiveEnvStanding(ctx, 0, t.SetID, now)
			if err != nil {
				return err
			}
			if err = q.RevokeSetStanding(ctx, t.SetID, now); err != nil {
				return err
			}
			ended := make([]string, len(rules))
			for i, st := range rules {
				ended[i] = st.ID
			}
			if err = s.revokeUnder(ctx, q, ended...); err != nil {
				return err
			}
			path := t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug
			auditObject, detail, note = "set:"+t.SetID, fmt.Sprintf("%s standing_cap=%d was=%d", path, *f.StandingCap, t.StandingCap), fmt.Sprintf("Don't-ask-again limit of %s set to %d s", path, *f.StandingCap)
		case "secret-convert":
			t, err := q.VaultSet(ctx, m.ID)
			if err != nil {
				return err
			}
			if err = q.MarkSecret(ctx, t.SetID, f.Note, f.URL, now); err != nil {
				return errConflict("the set changed; reload")
			}
			path := t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug
			auditObject, detail, note = "set:"+t.SetID, fmt.Sprintf("%s revision=%d env=%s", path, t.Revision, f.EnvName), fmt.Sprintf("%s is now a secret", path)
		case "sign-approve":
			v, _, err := q.SignRequest(ctx, m.ID, false)
			if err != nil {
				return err
			}
			until := now.Add(signer.CollectSeconds * time.Second)
			if f.TTL > 0 {
				until = now.Add(secs(f.TTL))
			}
			if err = q.DecideSign(ctx, m.ID, "approved", ids.New(), f.TTL, f.Max, until.UnixMilli()); err != nil {
				return err
			}
			auditObject, detail, note = "request:"+m.ID, fmt.Sprintf("%s host=%s ttl=%d max=%d items=%s", v.Path, v.Host, f.TTL, f.Max, itemDigests(v.Items)), fmt.Sprintf("Approved signing with %s for %s", v.Path, v.Host)
		case "sign-deny", "sign-revoke":
			v, _, err := q.SignRequest(ctx, m.ID, false)
			if err != nil {
				return err
			}
			status := "denied"
			if m.Action == "sign-revoke" {
				status = "revoked"
			}
			if err = q.DecideSign(ctx, m.ID, status, "", 0, 0, 0); err != nil {
				return err
			}
			s.seal.pool.release("sign:" + m.ID)
			auditObject, detail, note = "request:"+m.ID, v.Path+" host="+v.Host, fmt.Sprintf("Signing with %s for %s: %s", v.Path, v.Host, status)
		}
		return q.Audit(ctx, now, "owner", "vault_"+strings.ReplaceAll(m.Action, "-", "_"), auditObject, fmt.Sprintf("passkey=%d nonce=%s %s", pk, canonNonce(c.Canonical), detail))
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			err = errConflict("the set changed; reload and review again")
		}
		return nil, err
	}
	// A new revision or a changed limit ends "don't ask again" rules: their holds go now.
	s.reconcileHolds(ctx)
	s.bcast.notify()
	s.notify.Send("aqmas: vault", note+" [ref "+ref(m.ID)+"]", s.cfg.PublicBaseURL+"/")
	return out, nil
}

func itemDigests(items []signer.Item) string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.SHA256
	}
	return strings.Join(out, ",")
}
func canonNonce(canonical string) string {
	var m struct{ Nonce string }
	_ = json.Unmarshal([]byte(canonical), &m)
	return m.Nonce
}

type signerSecret struct {
	Scheme  string `json:"scheme"`
	Private []byte `json:"private"`
}
