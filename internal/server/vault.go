package server

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

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
	mu sync.Mutex
	m  map[string]*vaultPending
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
	v.expires = now.Add(vaultAttemptTTL)
	p.m[s] = v
	return s, nil
}

// get returns a snapshot of a live entry of this session (its slices are
// written once and never modified); take also removes the entry.
func (p *vaultPool) get(now time.Time, sess, id string, take bool) *vaultPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	v := p.m[id]
	if v == nil || v.session != sess {
		return nil
	}
	if take {
		delete(p.m, id)
	}
	c := *v
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
	return seal.Tuple("hpke-vault", s.seal.inv.Installation[:], []byte(purpose))
}
func (s *Server) vaultUploadAAD(attempt, set string) ([]byte, error) {
	raw, err := strictB64(attempt, 32)
	if err != nil || len(raw) != 32 {
		return nil, errBad("invalid attempt id")
	}
	epoch := s.seal.attempts.Epoch()
	return seal.Tuple("hpke-vault-aad", raw, epoch[:], []byte(set)), nil
}

func (s *Server) vaultRoutes(m *http.ServeMux) {
	s.sealedEndpoint(m, "POST /api/ui/seal/vault/attempt", s.vaultAttempt)
	for path, fn := range map[string]capHandler{"GET /api/ui/seal/vault/state": s.vaultState, "POST /api/ui/seal/vault/challenge": s.vaultChallenge, "POST /api/ui/seal/vault/finish": s.vaultFinish} {
		m.Handle(path, s.requireSession(func(w http.ResponseWriter, r *http.Request, sess string) {
			if s.seal == nil || s.seal.stage != nil {
				s.writeErr(w, r, errNotFound())
				return
			}
			s.optionalLease(r.Context(), func(ctx context.Context) {
				v, err := fn(ctx, r, sess)
				if err != nil {
					s.writeErr(w, r, mapNotFound(err))
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(s.deliveryWriter(ctx, w), 200, v)
			})
		}))
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
		Unlocked bool             `json:"unlocked"`
		Schemes  []signer.Scheme  `json:"schemes"`
		Orgs     []store.VaultOrg `json:"organisations"`
		Sets     []vaultSetView   `json:"sets"`
		Requests []signer.Request `json:"requests"`
	}{Unlocked: s.authorisedWork(ctx), Schemes: signer.All(), Sets: []vaultSetView{}}
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
	unlocked := s.authorisedWork(ctx)
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
		if !unlocked && *c.AllowReveal {
			return "", nil, lockedErr()
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
		if t.Kind != "env-set" {
			return "", nil, errBad("not an env set")
		}
		if !unlocked {
			return "", nil, lockedErr()
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
		m = targetFields(t)
		m["attempt_id"], m["operation"], m["changes"], m["commitment"], m["result_revision"] = c.Attempt, edit.Op, changes, p.commit, t.Revision+1
	case "reveal":
		t, err := q.VaultSet(ctx, c.ID)
		if err != nil {
			return "", nil, err
		}
		if err = owner(t.OrgID); err != nil {
			return "", nil, err
		}
		if t.Kind != "env-set" {
			return "", nil, errForbidden("a signer key is never revealed")
		}
		if !t.AllowReveal {
			return "", nil, errForbidden("this organisation does not allow reveal")
		}
		if !unlocked {
			return "", nil, lockedErr()
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
		if !unlocked {
			return "", nil, lockedErr()
		}
		t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Revision = c.ID, c.Slug, c.Title, "signer", 0
		var pub []byte
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
		default:
			return "", nil, errBad("choose generate or import")
		}
		m = targetFields(t)
		m["scheme"], m["source"], m["attempt_id"], m["public_key"], m["fingerprint"], m["result_revision"] = sc.ID, c.Source, c.Attempt, encodeID(pub), signer.Fingerprint(pub), 0
		pemText, _ := sc.PublicPEM(pub)
		facts["public_key"], facts["fingerprint"], facts["public_hex"], facts["public_pem"] = encodeID(pub), signer.Fingerprint(pub), hex.EncodeToString(pub), pemText
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
			if !unlocked {
				return "", nil, lockedErr()
			}
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
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		meta, facts, err = s.vaultReview(ctx, q, sess, pk, in, true)
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
	ch, err := s.beginReview(ctx, sess, "vault", in.Action, text, nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{"canonical": ch.Canonical, "challenge_id": ch.ChallengeID, "public_key": ch.PublicKey, "facts": facts}, nil
}

func (s *Server) vaultFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	// The only way in: a single-use stored challenge and a fresh user-verified
	// assertion over it. Nothing here consults an approval window.
	c, pk, err := s.takeReview(ctx, sess, "vault", in)
	if err != nil {
		return nil, err
	}
	var m struct {
		Action       string
		ID           string
		Metadata     string
		Epoch        seal.ID
		Installation seal.ID
	}
	if json.Unmarshal([]byte(c.Canonical), &m) != nil || m.Action != c.ObjectID || m.Epoch != s.seal.attempts.Epoch() || m.Installation != s.seal.inv.Installation {
		return nil, errBad("invalid vault decision")
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
	}
	if json.Unmarshal([]byte(m.Metadata), &f) != nil {
		return nil, errBad("invalid vault decision")
	}
	choice := vaultChoice{Action: m.Action, ID: m.ID, Attempt: f.Attempt}
	switch m.Action {
	case "policy":
		choice.AllowReveal = f.AllowReveal
	case "reveal":
		choice.Names, choice.Recipient = f.Names, f.Recipient
	case "signer-create":
		choice.Service, choice.Slug, choice.Title, choice.Scheme, choice.Source = f.Service, f.Slug, f.Title, f.Scheme, f.Source
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
			b := t.Binding()
			old, err := s.values(ctx, q, b)
			if err != nil {
				return err
			}
			values, err := edit.Apply(old)
			if err != nil {
				return errBad("result exceeds env-set limits")
			}
			next := b
			next.Revision++
			rec, err := s.envCipher(ctx, next, "", store.CipherRecord{}, values, true)
			if err != nil {
				return err
			}
			if err = q.ReplaceEnv(ctx, b, envset.Names(values), rec); err != nil {
				return err
			}
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
			epoch := s.seal.attempts.Epoch()
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
				priv, pub = slices.Clone(p.priv), p.pub
			}
			defer clear(priv)
			t, err := q.VaultService(ctx, f.Service)
			if err != nil {
				return err
			}
			t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Scheme, t.PublicKey, t.Origin = m.ID, f.Slug, f.Title, "signer", sc.ID, pub, origin
			rec, err := s.signerCipher(ctx, t, store.CipherRecord{}, &signerSecret{Scheme: sc.ID, Private: priv}, true)
			if err != nil {
				return err
			}
			if err = q.CreateSigner(ctx, t, rec, now); err != nil {
				return errConflict("a set with that name or ID exists; reload")
			}
			path := t.OrgSlug + "/" + t.ServiceSlug + "/" + t.SetSlug
			pemText, _ := sc.PublicPEM(pub)
			out = map[string]any{"set_id": t.SetID, "path": path, "scheme": sc.ID, "public_key": encodeID(pub), "public_hex": hex.EncodeToString(pub), "public_pem": pemText, "fingerprint": signer.Fingerprint(pub)}
			auditObject, detail, note = "set:"+t.SetID, fmt.Sprintf("%s scheme=%s origin=%s fingerprint=%s", path, sc.ID, origin, signer.Fingerprint(pub)), fmt.Sprintf("Created signer %s (%s)", path, sc.ID)
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

// signerCipher seals or opens a signer's private key. It is opened in exactly
// one place (signWith) and its plaintext is never marshalled anywhere else.
func (s *Server) signerCipher(ctx context.Context, t store.VaultTarget, rec store.CipherRecord, data *signerSecret, encrypt bool) (store.CipherRecord, error) {
	k, _ := ctx.Value(leaseKey{}).(*seal.Key)
	if k == nil || ctx.Err() != nil {
		return rec, lockedErr()
	}
	blob := seal.RandomID()
	if !encrypt {
		if len(rec.Blob) != 32 {
			s.stopSealed()
			return rec, errConflict("damaged sealed record")
		}
		copy(blob[:], rec.Blob)
	}
	o := seal.Object{Org: t.OrgID, Service: t.ServiceID, Set: t.SetID, Role: "signer-key", Revision: 1, Blob: blob}
	if encrypt {
		p, err := json.Marshal(data)
		if err != nil {
			return rec, err
		}
		defer clear(p)
		e, err := o.Encrypt(s.seal.inv.Generation, k, p)
		return store.CipherRecord{Blob: blob[:], Payload: e.Payload, Wrap: e.WrappedDEK}, err
	}
	p, err := o.Decrypt(s.seal.inv.Generation, k, seal.Envelope{Payload: rec.Payload, WrappedDEK: rec.Wrap})
	defer clear(p)
	if err != nil || json.Unmarshal(p, data) != nil || data.Scheme != t.Scheme || len(data.Private) != 32 {
		s.stopSealed()
		return rec, errConflict("sealed record failed authentication; relocking")
	}
	return rec, nil
}
