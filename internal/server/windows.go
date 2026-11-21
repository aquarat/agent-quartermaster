package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"math/big"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

const windowExclusions = "Individual passkey required: root or high-risk SSH; administrative, private or token-mode Cloudflare; env releases; standing, indefinite and beyond-soft-cap grants; enrollment, admission, catalogue, policy, passkey, broker and update actions."

type windowSettings struct {
	Enabled  bool     `json:"enabled"`
	Absolute int      `json:"max_seconds"`
	Idle     int      `json:"idle_seconds"`
	Sets     []string `json:"sets"`
}
type windowRule struct {
	Set     string `json:"set"`
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Scope   string `json:"scope"`
	Ceiling int    `json:"grant_max_seconds"`
}
type windowProfile struct {
	Org        string         `json:"org"`
	Title      string         `json:"title"`
	Personal   bool           `json:"personal"`
	Revision   int            `json:"window_revision"`
	PolicyRev  int            `json:"policy_revision"`
	Generation int64          `json:"generation"`
	Settings   windowSettings `json:"settings"`
	Eligible   []windowRule   `json:"eligible"`
}
type windowTerms struct {
	Org        string       `json:"org"`
	Title      string       `json:"title"`
	Revision   int          `json:"window_revision"`
	PolicyRev  int          `json:"policy_revision"`
	Generation int64        `json:"generation"`
	Rules      []windowRule `json:"rules"`
	Verbs      string       `json:"verbs"`
	Exclusions string       `json:"exclusions"`
	Duration   int          `json:"duration_seconds"`
	Idle       int          `json:"idle_seconds"`
	Tab        string       `json:"tab_key"`
	Credential string       `json:"credential_id"`
	ID         string       `json:"id"`
}
type windowOpen struct {
	Org        string `json:"org"`
	Duration   int    `json:"duration_seconds"`
	Tab        string `json:"tab_key"`
	Credential string `json:"credential_id"`
}
type windowProposal struct {
	id, canonical string
	expires       time.Time
}
type window struct {
	terms                            windowTerms
	session, subject, opener         string
	row                              int64
	tab                              *ecdsa.PublicKey
	token                            [32]byte
	opened, absolute, idle, presence time.Time
	proposal                         *windowProposal
}
type windowPool struct {
	sync.Mutex
	active map[string]*window
}
type windowReceipt struct {
	ID    string    `json:"id"`
	Token string    `json:"token"`
	Ends  time.Time `json:"expires_at"`
}
type windowInfo struct {
	ID       string    `json:"id"`
	Org      string    `json:"org"`
	Opener   string    `json:"opener"`
	Opened   time.Time `json:"opened"`
	Deadline time.Time `json:"expires_at"`
}

func (w *window) live(now time.Time) bool {
	return now.Before(w.absolute) && now.Before(w.idle) && now.Before(w.presence)
}
func (p *windowPool) prune(now time.Time, epoch int64) {
	for id, w := range p.active {
		if !w.live(now) || w.terms.Generation != epoch {
			delete(p.active, id)
		}
	}
}
func (p *windowPool) logout(sess string) {
	p.Lock()
	defer p.Unlock()
	for id, w := range p.active {
		if w.session == sess {
			delete(p.active, id)
		}
	}
}

func (s *Server) windowProfiles(ctx context.Context, q *store.Q, sess string, pk int64) ([]windowProfile, error) {
	person, err := q.GlobalOwner(ctx, sess, pk, s.now())
	if err != nil {
		return nil, errForbidden("owner session required")
	}
	cat, err := q.Catalogue(ctx, person, s.now())
	if err != nil {
		return nil, err
	}
	epoch, err := q.WindowEpoch(ctx)
	if err != nil {
		return nil, err
	}
	out := []windowProfile{}
	for _, o := range cat.Orgs {
		rev, personal, p, err := q.WindowConfig(ctx, o.ID)
		if err != nil {
			return nil, err
		}
		x := windowProfile{Org: o.ID, Title: o.Title, Personal: personal, Revision: rev, Generation: epoch, PolicyRev: o.Revision, Eligible: []windowRule{}, Settings: windowSettings{Enabled: personal, Absolute: 600, Idle: 120, Sets: []string{}}}
		for _, svc := range o.Services {
			for _, set := range svc.Sets {
				if set.Archived {
					continue
				}
				for _, r := range o.Rules {
					if r.Set != set.ID {
						continue
					}
					if set.Kind == "ssh-ca" {
						t, ok := s.cfg.Target(set.Slug)
						if !ok || t.HighRisk || r.Scope != "" {
							continue
						}
					} else if set.Kind != "cloudflare-proxy" || r.Scope != "cf.read" && r.Scope != "cf.cache.purge" {
						continue
					}
					l, err := s.resourceLimits(organisations.Resource{Kind: set.Kind, SetSlug: set.Slug, PolicyRevision: o.Revision, Class: "agent"}, r, o.Policy)
					if err != nil {
						return nil, err
					}
					limit := min(1800, l.Soft, l.Hard)
					if limit < s.cfg.TTL.MinSeconds {
						continue
					}
					x.Eligible = append(x.Eligible, windowRule{set.ID, o.Title + "/" + svc.Title + "/" + set.Title, set.Kind, r.Scope, limit})
					if personal && !slices.Contains(x.Settings.Sets, set.ID) {
						x.Settings.Sets = append(x.Settings.Sets, set.ID)
					}
				}
			}
		}
		slices.Sort(x.Settings.Sets)
		if rev > 0 && json.Unmarshal([]byte(p), &x.Settings) != nil {
			return nil, errConflict("invalid window policy")
		}
		out = append(out, x)
	}
	return out, nil
}
func (s *Server) profile(ctx context.Context, q *store.Q, sess string, pk int64, org string) (windowProfile, error) {
	profiles, err := s.windowProfiles(ctx, q, sess, pk)
	if err == nil {
		for _, p := range profiles {
			if p.Org == org {
				return p, nil
			}
		}
		err = errNotFound()
	}
	return windowProfile{}, err
}
func validSettings(p windowProfile, c windowSettings) bool {
	if c.Absolute < 300 || c.Absolute > 3600 || c.Idle < 15 || c.Idle > c.Absolute || c.Sets == nil || !slices.IsSorted(c.Sets) {
		return false
	}
	for i, id := range c.Sets {
		if i > 0 && id == c.Sets[i-1] || !slices.ContainsFunc(p.Eligible, func(r windowRule) bool { return r.Set == id }) {
			return false
		}
	}
	return true
}
func (s *Server) windowRoutes(m *http.ServeMux) {
	for path, f := range map[string]capHandler{"policy/challenge": s.windowPolicyBegin, "policy/finish": s.windowPolicyFinish, "open/challenge": s.windowOpenBegin, "open/finish": s.windowOpenFinish, "prepare": s.windowPrepare, "confirm": s.windowConfirm, "presence": s.windowPresence, "close": s.windowClose} {
		s.sealedEndpoint(m, "POST /api/ui/seal/windows/"+path, f)
	}
}
func (s *Server) windowPolicyBegin(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		Org      string
		Settings windowSettings
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	q := s.store.Q()
	pk, err := q.SessionPasskeyID(ctx, sess)
	if err != nil {
		return nil, err
	}
	p, err := s.profile(ctx, q, sess, pk, in.Org)
	if err != nil {
		return nil, err
	}
	if !validSettings(p, in.Settings) {
		return nil, errBad("invalid window limits or sets")
	}
	m := s.reviewFields("window-policy", "replace", in.Org)
	m["old"], _ = reviewJSON(p)
	m["new"], _ = reviewJSON(in.Settings)
	text, _ := reviewJSON(m)
	return s.beginReview(ctx, sess, "window-policy", "replace", text, nil)
}
func (s *Server) windowPolicyFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, pk, err := s.takeReview(ctx, sess, "window-policy", in)
	if err != nil {
		return nil, err
	}
	var m struct{ ID, Old, New string }
	if json.Unmarshal([]byte(c.Canonical), &m) != nil {
		return nil, errBad("invalid policy")
	}
	var cfg windowSettings
	err = s.store.Tx(ctx, func(q *store.Q) error {
		p, err := s.profile(ctx, q, sess, pk, m.ID)
		if err != nil {
			return err
		}
		old, _ := reviewJSON(p)
		if old != m.Old || json.Unmarshal([]byte(m.New), &cfg) != nil || !validSettings(p, cfg) {
			return errConflict("window policy changed")
		}
		if err = q.SetWindowConfig(ctx, m.ID, p.Revision, m.New); err != nil {
			return err
		}
		return q.Audit(ctx, s.now(), "owner", "window_policy", "organisation:"+m.ID, c.Canonical)
	})
	return api.OK{OK: true}, err
}
func parseTab(b64 string) (*ecdsa.PublicKey, error) {
	b, err := strictB64(b64, 65)
	if err != nil || len(b) != 65 || b[0] != 4 {
		return nil, errBad("invalid tab key")
	}
	x, y := new(big.Int).SetBytes(b[1:33]), new(big.Int).SetBytes(b[33:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, errBad("invalid tab key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
func (s *Server) windowTerms(ctx context.Context, q *store.Q, sess string, pk int64, id string, in windowOpen) (windowTerms, error) {
	var t windowTerms
	if accessSub(ctx) == "" || s.access == nil {
		return t, errForbidden("windows require verified Access identity")
	}
	if _, err := parseTab(in.Tab); err != nil {
		return t, err
	}
	p, err := s.profile(ctx, q, sess, pk, in.Org)
	if err != nil {
		return t, err
	}
	if !p.Settings.Enabled || !validSettings(p, p.Settings) || in.Duration < 300 || in.Duration > p.Settings.Absolute {
		return t, errBad("window off or duration exceeds policy")
	}
	t = windowTerms{Org: p.Org, Title: p.Title, Revision: p.Revision, PolicyRev: p.PolicyRev, Generation: p.Generation, Rules: []windowRule{}, Verbs: "request approve; request deny", Exclusions: windowExclusions, Duration: in.Duration, Idle: min(p.Settings.Idle, in.Duration), Tab: in.Tab, Credential: in.Credential, ID: id}
	for _, v := range p.Eligible {
		if slices.Contains(p.Settings.Sets, v.Set) {
			t.Rules = append(t.Rules, v)
		}
	}
	if len(t.Rules) == 0 {
		return t, errConflict("no eligible sets")
	}
	return t, nil
}
func (s *Server) windowOpenBegin(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in windowOpen
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	raw, err := strictB64(in.Credential, 1023)
	if err != nil {
		return nil, err
	}
	pk, _, err := findPasskey(ctx, s.store.Q(), passkeyID(raw))
	if err != nil {
		return nil, err
	}
	t, err := s.windowTerms(ctx, s.store.Q(), sess, pk.ID, ids.Secret(32), in)
	if err != nil {
		return nil, err
	}
	m := s.reviewFields("window", "open", t.ID)
	m["terms"], _ = reviewJSON(t)
	text, _ := reviewJSON(m)
	return s.beginReview(ctx, sess, "window", "open", text, pk)
}

// stageWindow runs INSIDE the issuing transaction; publication is under the
// same window mutex only after commit (also for combined unlock).
func (s *Server) stageWindow(ctx context.Context, q *store.Q, sess string, pk int64, t windowTerms, evidence string) (*window, windowReceipt, error) {
	var rec windowReceipt
	raw, err := strictB64(t.Credential, 1023)
	if err != nil {
		return nil, rec, err
	}
	op, _, err := findPasskey(ctx, q, passkeyID(raw))
	if err != nil || op.ID != pk {
		return nil, rec, errForbidden("wrong opening passkey")
	}
	want, err := s.windowTerms(ctx, q, sess, pk, t.ID, windowOpen{t.Org, t.Duration, t.Tab, t.Credential})
	if err != nil || !reflect.DeepEqual(t, want) {
		return nil, rec, errConflict("window terms changed")
	}
	key, _ := parseTab(t.Tab)
	end, err := q.SessionExpiry(ctx, sess)
	if err != nil {
		return nil, rec, err
	}
	now := s.now()
	duration := min(end.Sub(now), time.Duration(t.Duration)*time.Second)
	if duration <= 0 {
		return nil, rec, errConflict("session expired")
	}
	token := ids.Secret(32)
	w := &window{terms: t, session: sess, subject: accessSub(ctx), row: pk, opener: op.id, tab: key, token: sha256.Sum256([]byte(token)), opened: now, absolute: now.Add(duration), idle: now.Add(secs(t.Idle)), presence: now.Add(30 * time.Second)}
	err = q.Audit(ctx, now, "owner", "window_open", "window:"+t.ID, "passkey="+op.id+" "+evidence)
	return w, windowReceipt{t.ID, token, w.absolute}, err
}
func (p *windowPool) publish(w *window) {
	if p.active == nil {
		p.active = map[string]*window{}
	}
	p.prune(w.opened, w.terms.Generation)
	for id, v := range p.active {
		if v.session == w.session {
			delete(p.active, id)
		}
	}
	p.active[w.terms.ID] = w
}
func (s *Server) windowOpenFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, pk, err := s.takeReview(ctx, sess, "window", in)
	if err != nil {
		return nil, err
	}
	var m struct{ Terms string }
	var t windowTerms
	if json.Unmarshal([]byte(c.Canonical), &m) != nil || json.Unmarshal([]byte(m.Terms), &t) != nil {
		return nil, errBad("invalid window")
	}
	pool := &s.seal.windows
	pool.Lock()
	defer pool.Unlock()
	var w *window
	var rec windowReceipt
	err = s.store.Tx(ctx, func(q *store.Q) error {
		w, rec, err = s.stageWindow(ctx, q, sess, pk, t, c.Canonical+" assertion="+string(in.Assertion))
		return err
	})
	if err != nil {
		return nil, err
	}
	pool.publish(w)
	return rec, nil
}

type windowClick struct {
	ID       string         `json:"window_id"`
	Token    string         `json:"token"`
	Proposal string         `json:"proposal_id"`
	Proof    string         `json:"proof"`
	Choice   ordinaryChoice `json:"choice"`
}

func (s *Server) liveWindow(ctx context.Context, q *store.Q, sess string, in windowClick) (*window, error) {
	p := &s.seal.windows
	e, err := q.WindowEpoch(ctx)
	if err != nil {
		return nil, err
	}
	p.prune(s.now(), e)
	w := p.active[in.ID]
	h := sha256.Sum256([]byte(in.Token))
	if w == nil || w.session != sess || w.subject == "" || w.subject != accessSub(ctx) || subtle.ConstantTimeCompare(h[:], w.token[:]) != 1 {
		return nil, errForbidden("window ended or does not belong to this tab")
	}
	if err = s.sealOwner(ctx, q, sess, w.row); err != nil {
		delete(p.active, in.ID)
		return nil, err
	}
	return w, nil
}
func (w *window) allows(a canon.Action) bool {
	return w.terms.Org == a.OrgID && slices.ContainsFunc(w.terms.Rules, func(r windowRule) bool { return r.Set == a.SetID && r.Scope == a.Scope && a.TTLSeconds <= r.Ceiling })
}
func (s *Server) windowPrepare(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in windowClick
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	p := &s.seal.windows
	p.Lock()
	defer p.Unlock()
	var result map[string]string
	err := s.store.Tx(ctx, func(q *store.Q) error {
		w, err := s.liveWindow(ctx, q, sess, in)
		if err != nil {
			return err
		}
		a, err := s.ordinary(ctx, q, sess, w.row, in.Choice)
		if err != nil {
			return err
		}
		if !w.allows(a) {
			return errForbidden("outside signed window")
		}
		text, err := canon.Build(a, canon.NewNonce(), s.now())
		if err != nil {
			return err
		}
		id := ids.Secret(32)
		ttl := min(ChallengeTTL, w.absolute.Sub(s.now()), w.idle.Sub(s.now()))
		w.proposal = &windowProposal{id, text, s.now().Add(ttl)}
		result = map[string]string{"proposal_id": id, "canonical": text}
		return nil
	})
	return result, err
}
func windowMessage(install []byte, wid, proposal string, digest []byte) []byte {
	var b []byte
	for _, f := range [][]byte{[]byte("aqmas-seal"), binary.BigEndian.AppendUint64(nil, 1), []byte("window-confirm"), install, []byte(wid), []byte(proposal), digest} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}
func (s *Server) windowConfirm(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in windowClick
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	p := &s.seal.windows
	p.Lock()
	defer p.Unlock()
	var who string
	var applied *window
	err := s.store.Tx(ctx, func(q *store.Q) error {
		w, err := s.liveWindow(ctx, q, sess, in)
		if err != nil {
			return err
		}
		v := w.proposal
		w.proposal = nil
		if v == nil || v.id != in.Proposal || !s.now().Before(v.expires) {
			return errConflict("stale proposal; review again")
		}
		sig, err := strictB64(in.Proof, 64)
		hash := sha256.Sum256(windowMessage(s.seal.inv.Installation[:], in.ID, in.Proposal, canon.Challenge(v.canonical)))
		if err != nil || len(sig) != 64 || !ecdsa.Verify(w.tab, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errForbidden("invalid tab proof")
		}
		sg, err := canon.Parse(v.canonical)
		if err != nil || !w.allows(sg.Action) {
			return errForbidden("outside signed window")
		}
		who = fmt.Sprintf("%s under window opened by passkey %s at %s [window %s]", strings.Title(sg.Action.Action), w.opener, w.opened.UTC().Format(time.RFC3339), w.terms.ID)
		if err = s.applyOrdinary(ctx, q, sess, w.row, v.canonical, who); err != nil {
			return err
		}
		if !w.live(s.now()) {
			return errConflict("window expired")
		}
		applied = w
		return nil
	})
	if err != nil {
		return nil, err
	}
	applied.idle = s.now().Add(secs(applied.terms.Idle))
	s.bcast.notify()
	s.notify.Send("aqmas: window decision", who, s.cfg.PublicBaseURL+"/")
	return api.OK{OK: true}, nil
}
func (s *Server) windowPresence(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in windowClick
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	p := &s.seal.windows
	p.Lock()
	defer p.Unlock()
	w, err := s.liveWindow(ctx, s.store.Q(), sess, in)
	if err != nil {
		return nil, err
	}
	w.presence = s.now().Add(30 * time.Second)
	return api.OK{OK: true}, nil
}
func (s *Server) windowClose(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		ID string `json:"window_id"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	q := s.store.Q()
	pk, err := q.SessionPasskeyID(ctx, sess)
	if err != nil {
		return nil, err
	}
	if err = s.sealOwner(ctx, q, sess, pk); err != nil {
		return nil, err
	}
	p := &s.seal.windows
	p.Lock()
	defer p.Unlock()
	delete(p.active, in.ID)
	return api.OK{OK: true}, q.Audit(ctx, s.now(), "owner", "window_close", "window:"+in.ID, "")
}
