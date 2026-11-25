package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
)

func (s *Server) envAgentRoutes(m *http.ServeMux) {
	route := func(pattern string, secret bool, f func(context.Context, *store.Q, *http.Request, *store.Host) (any, error)) {
		m.Handle(pattern, s.requireHost(func(w http.ResponseWriter, r *http.Request, h *store.Host) {
			if err := s.bucketsReady(); err != nil {
				s.writeErr(w, r, s.hostNotFound(r.Context(), h, err))
				return
			}
			// No network read inside BEGIN IMMEDIATE.
			if r.Method == http.MethodPost {
				b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
				if err != nil {
					s.writeErr(w, r, errBad("body too large or unreadable"))
					return
				}
				defer clear(b)
				r.Body = io.NopCloser(bytes.NewReader(b))
			}
			ctx := r.Context()
			var out any
			call := &signCall{}
			err := s.store.Tx(ctx, func(q *store.Q) error {
				if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
					return err
				}
				if err := q.SweepEnv(ctx, s.now()); err != nil {
					return err
				}
				var err error
				out, err = f(context.WithValue(ctx, signCallKey{}, call), q, r, h)
				return err
			})
			if err != nil {
				s.writeErr(w, r, s.hostNotFound(ctx, h, err))
				return
			}
			if call.after != nil {
				call.after()
			}
			if secret {
				w.Header().Set("Cache-Control", "no-store")
			}
			writeJSON(w, 200, out)
		}))
	}
	route("GET /v2/env/set", false, func(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
		return q.EnvBinding(ctx, h.ID, r.URL.Query().Get("path"), s.now())
	})
	route("POST /v2/env/upload", true, s.envUpload)
	route("POST /v2/env/requests", false, s.envRequest)
	route("GET /v2/env/requests/{id}", false, func(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
		return q.VisibleEnvRelease(ctx, h.ID, peerIP(r), r.PathValue("id"), false, s.now())
	})
	route("POST /v2/env/requests/{id}/cancel", false, s.envEnd)
	route("GET /v2/env/grants/{id}", false, func(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
		return q.VisibleEnvRelease(ctx, h.ID, peerIP(r), r.PathValue("id"), true, s.now())
	})
	route("POST /v2/env/grants/{id}/checkin", false, s.envEnd)
	route("POST /v2/grants/{id}/collect", true, s.envCollect)
}
func (s *Server) envUpload(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	var in envset.Upload
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	x, err := q.EnvTicket(ctx, h.ID, ids.Hash(in.Ticket), s.now())
	if err != nil {
		return nil, err
	}
	b, err := q.EnvBinding(ctx, h.ID, x.D.Path, s.now())
	if err != nil || b.Class != "owner-device" || !reflect.DeepEqual(b, x.D.Binding) || x.D.Operation != in.Edit.Op {
		return nil, errNotFound()
	}
	defer func() {
		for i := range in.Edit.Entries {
			in.Edit.Entries[i].Value = ""
		}
	}()
	commit, err := in.Edit.Commit(b)
	if err != nil || commit != in.Commitment {
		return nil, errBad("invalid edit commitment")
	}
	x.D.Commitment = commit
	x.D.Changes, err = in.Edit.Changes(b.Names)
	if err != nil {
		return nil, errBad(err.Error())
	}
	// The plaintext is here and the commitment checked: seal each entry to the
	// set's bucket now (no bucket is opened); an unset carries its name only.
	row, err := s.ensureSetBucket(ctx, q, "env-set", b.Set, b.Org)
	if err != nil {
		return nil, err
	}
	var recs []envRecord
	if in.Edit.Op == "unset" {
		recs = []envRecord{{N: in.Edit.Entries[0].Name}}
	} else if recs, err = s.sealEntries(s.sealBucket(row), b.Set, in.Edit.Entries); err != nil {
		return nil, err
	}
	payload, err := recordsJSON(recs)
	if err != nil {
		return nil, err
	}
	blob, err := strictB64(x.D.ID, 32)
	if err != nil || len(blob) != 32 {
		return nil, errBad("invalid draft id")
	}
	if err = q.UploadEnv(ctx, x.D, ids.Hash(in.Ticket), store.CipherRecord{Blob: blob, Payload: payload, Wrap: row.ID}); err != nil {
		return nil, err
	}
	return x.D, q.Audit(ctx, s.now(), "host:"+h.Name, "env_draft_upload", "draft:"+x.D.ID, "set="+b.Set+" commitment="+commit)
}
func (s *Server) envRequest(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	var in struct {
		Binding      envset.Binding
		Mode, Reason string
		TTL          int `json:"ttl_seconds"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	b, err := q.EnvBinding(ctx, h.ID, in.Binding.Path, s.now())
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(b, in.Binding) || b.Revision == 0 || len(b.Names) == 0 {
		return nil, errConflict("revision changed or empty")
	}
	if in.Mode == "get" {
		// `aqmas get`: one secret's value, printed by the requesting process.
		if secret, err := q.IsSecret(ctx, b.Set); err != nil {
			return nil, err
		} else if !secret || len(b.Names) != 1 {
			return nil, errBad("aqmas get delivers a single secret; this is an env set: use aqmas run (or make it a secret in the Vault)")
		}
		if _, deny, err := q.OrgFlags(ctx, b.Org, b.PolicyRevision); err != nil {
			return nil, err
		} else if deny {
			return nil, errForbidden("the owner has turned off aqmas get for this organisation: use aqmas run PATH --why ... -- COMMAND")
		}
	} else if in.Mode != "process" && in.Mode != "file" && in.Mode != "shell" {
		return nil, errBad("invalid delivery mode or reason")
	}
	if len(in.Reason) > MaxReasonLen || strings.TrimSpace(in.Reason) == "" || hasControl(in.Reason, false) {
		return nil, errBad("invalid delivery mode or reason")
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = b.Default
	}
	if ttl == -1 {
		if !b.Forever {
			return nil, errBad("indefinite not offered")
		}
	} else if ttl < 1 {
		return nil, errBad("invalid duration")
	} else {
		ttl = min(ttl, maxFinite)
	}
	peer := peerIP(r)
	if net.ParseIP(peer) == nil {
		return nil, errBad("missing source address")
	}
	now := s.now()
	n, err := s.allPending(ctx, q, h.ID, now)
	if err != nil {
		return nil, err
	}
	out := envset.Release{Binding: b, ID: ids.New(), Mode: in.Mode, Peer: peer, Reason: in.Reason, TTL: ttl, Deadline: now.Add(secs(s.cfg.TTL.PendingExpirySeconds)).UnixMilli(), Status: "pending"}
	// A "don't ask again" rule approves without a tap. The pending limit is
	// about cards waiting for the owner, so it is checked only without one.
	st, err := s.envStandingFor(ctx, q, h.ID, out)
	if err != nil {
		return nil, err
	}
	if st != nil {
		// A rule replaces the owner's tap, not every limit: a host cannot pile up
		// releases nobody collects, nor loop on approvals.
		waiting, recent, err := q.EnvStandingLoad(ctx, st.ID, now, now.Add(secs(s.cfg.TTL.PendingExpirySeconds)-time.Hour))
		if err != nil {
			return nil, err
		}
		if waiting >= MaxStandingUncollected {
			return nil, &apiErr{429, "rate_limited", fmt.Sprintf("%d releases approved without a tap are still waiting to be collected: collect them or let them expire before asking again", waiting)}
		}
		if recent >= MaxStandingPerHour {
			return nil, &apiErr{429, "rate_limited", fmt.Sprintf("this don't-ask-again rule has approved %d releases in the last hour, its limit: wait, or ask the owner", recent)}
		}
	}
	if st == nil && n >= MaxPendingPerHost {
		return nil, &apiErr{429, "rate_limited", "too many pending requests"}
	}
	if err = q.NewEnvRelease(ctx, h.ID, out); err != nil {
		return nil, err
	}
	if err = q.Audit(ctx, now, "host:"+h.Name, "env_request", "request:"+out.ID, b.Path+" mode="+out.Mode); err != nil || st == nil {
		return out, err
	}
	// Never longer than the owner signed: a longer request gets the signed TTL.
	ttl = min(ttl, st.MaxTTL)
	until := now.Add(secs(ttl)).UnixMilli()
	if err = q.ApproveEnvBy(ctx, out.ID, ids.New(), st.ID, ttl, until); err != nil {
		return nil, err
	}
	if err = q.UseEnvStanding(ctx, st.ID, now); err != nil {
		return nil, err
	}
	// The release has its own hold until it is collected, as after a tap.
	if c, _ := ctx.Value(signCallKey{}).(*signCall); c != nil {
		row, hold := st.row, s.envHold(out.ID, until)
		c.after = func() { s.seal.pool.hold(bucketSealID(row), hold); s.bcast.notify() }
	}
	// The answer is "pending" as for every new release (every CLI expects that
	// of a request it just made); its first poll finds it approved.
	return out, q.Audit(ctx, now, "system", "env_auto_approve", "request:"+out.ID, fmt.Sprintf("%s revision=%d mode=%s standing=%s host=%s ttl=%d from=%s", b.Path, b.Revision, out.Mode, st.ID, h.Name, ttl, peer))
}

// Limits on what one "don't ask again" rule issues without a tap.
const (
	MaxStandingUncollected = 4
	MaxStandingPerHour     = 60
)

type envRule struct {
	envset.Standing
	row store.BucketRow
}

// envStandingFor finds the "don't ask again" rule that approves r, or nil:
// same enrolment and observed address, same delivery mode, the exact binding
// the owner approved (set, revision and key names, admission, policy), a
// finite TTL (the release is capped at the signed one), and the set's bucket
// open (a rule issues without a tap only while its bucket is open, like every
// standing rule).
func (s *Server) envStandingFor(ctx context.Context, q *store.Q, host int64, r envset.Release) (*envRule, error) {
	rules, err := q.ActiveEnvStanding(ctx, host, r.Set, s.now())
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	row, err := q.BucketByRef(ctx, "env-set", r.Set)
	if err != nil || !s.seal.pool.isOpen(bucketSealID(row)) {
		return nil, nil
	}
	if limit, err := q.StandingCap(ctx, r.Set); err != nil || limit == 0 {
		return nil, err
	}
	for _, st := range rules {
		if st.Mode == r.Mode && st.Peer == r.Peer && r.TTL > 0 && reflect.DeepEqual(st.Binding, r.Binding) {
			return &envRule{st, row}, nil
		}
	}
	return nil, nil
}

// revokeUnder finishes ending rules: the releases they approved that are not
// collected yet are revoked, and the rules' and those releases' holds dropped.
func (s *Server) revokeUnder(ctx context.Context, q *store.Q, rules ...string) error {
	released, err := q.RevokeEnvUnder(ctx, rules...)
	if err != nil {
		return err
	}
	refs := make([]string, 0, len(rules)+len(released))
	for _, r := range rules {
		refs = append(refs, "envstanding:"+r)
	}
	for _, id := range released {
		refs = append(refs, "env:"+id)
	}
	s.seal.pool.release(refs...)
	return nil
}

func envStandingHold(st envset.Standing) bucketHold {
	return bucketHold{Kind: "standing", Ref: "envstanding:" + st.ID, Reason: "don't-ask-again rule for " + st.Host, Until: time.UnixMilli(st.Expires).UTC()}
}
func (s *Server) envEnd(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	grant := strings.HasSuffix(r.URL.Path, "/checkin")
	v, err := q.VisibleEnvRelease(ctx, h.ID, peerIP(r), r.PathValue("id"), grant, s.now())
	if err != nil {
		return nil, err
	}
	status := "cancelled"
	if grant {
		status = "revoked"
	}
	if err = q.DecideEnv(ctx, v.ID, status, "", 0, 0); err != nil {
		return nil, errConflict("release no longer active")
	}
	s.releaseAfter(ctx, "env:"+v.ID)
	return api.OK{OK: true}, q.Audit(ctx, s.now(), "host:"+h.Name, "env_"+status, "request:"+v.ID, v.Path)
}

// releaseAfter drops holds once the caller's transaction has committed.
func (s *Server) releaseAfter(ctx context.Context, refs ...string) {
	if c, _ := ctx.Value(signCallKey{}).(*signCall); c != nil && s.sealServing() {
		prev := c.after
		c.after = func() {
			if prev != nil {
				prev()
			}
			s.seal.pool.release(refs...)
		}
	}
}
func (s *Server) envCollect(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	v, err := q.VisibleEnvRelease(ctx, h.ID, peerIP(r), r.PathValue("id"), true, s.now())
	if err != nil {
		return nil, err
	}
	if v.Status != "approved" || v.Consumed {
		return nil, errConflict("grant expired, revoked or already collected")
	}
	entries, err := s.values(ctx, q, v.Binding)
	if err != nil {
		return nil, err
	}
	if err = q.ConsumeEnv(ctx, v.Grant, s.now()); err != nil {
		return nil, errConflict("grant no longer collectible")
	}
	v.Consumed = true
	s.releaseAfter(ctx, "env:"+v.ID)
	return envset.Collection{Release: v, Entries: entries}, q.Audit(ctx, s.now(), "host:"+h.Name, "env_collect_"+v.Mode, "grant:"+v.Grant, fmt.Sprintf("%s revision=%d enrollment=%s", v.Path, v.Revision, v.Enrollment))
}

func (s *Server) envWebRoutes(m *http.ServeMux) {
	s.sealedEndpoint(m, "POST /api/ui/seal/env/ticket", s.envTicket)
	for path, fn := range map[string]capHandler{"GET /api/ui/seal/env/state": s.envState, "POST /api/ui/seal/env/challenge": s.envChallenge, "POST /api/ui/seal/env/finish": s.envFinish} {
		s.sealedEndpoint(m, path, fn)
	}
}
func (s *Server) envTicket(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct{ Path, Operation, Enrollment string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if !envset.ValidPath(in.Path) || in.Operation != "import" && in.Operation != "put" && in.Operation != "unset" {
		return nil, errBad("invalid upload scope")
	}
	id := seal.RandomID()
	ticket := ids.Secret(32)
	var draft envset.Draft
	err := s.store.Tx(ctx, func(q *store.Q) error {
		row, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		if err = s.sealOwner(ctx, q, sess, row); err != nil {
			return err
		}
		host, err := q.EnvHost(ctx, in.Enrollment)
		if err != nil {
			return err
		}
		b, err := q.EnvBinding(ctx, host, in.Path, s.now())
		if err != nil || b.Class != "owner-device" {
			return errNotFound()
		}
		if secret, err := q.IsSecret(ctx, b.Set); err != nil {
			return err
		} else if secret {
			return errBad("a secret is replaced in the Vault, not from the CLI")
		}
		draft = envset.Draft{Binding: b, ID: encodeID(id[:]), Operation: in.Operation, Expires: s.now().Add(5 * time.Minute).UnixMilli()}
		return q.NewEnvTicket(ctx, sess, host, draft, ids.Hash(ticket))
	})
	return map[string]any{"ticket": ticket, "draft": draft}, err
}
func (s *Server) envState(ctx context.Context, r *http.Request, sess string) (any, error) {
	var drafts []envset.Draft
	var releases []envset.Release
	var standing []envset.Standing
	caps := map[string]int{}
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		if err = s.sealOwner(ctx, q, sess, pk); err != nil {
			return err
		}
		if err = q.SweepEnv(ctx, s.now()); err != nil {
			return err
		}
		drafts, err = q.Drafts(ctx, sess, s.now())
		if err != nil {
			return err
		}
		if releases, err = q.OwnerEnvReleases(ctx); err != nil {
			return err
		}
		if standing, err = q.ActiveEnvStanding(ctx, 0, "", s.now()); err != nil {
			return err
		}
		// What each waiting card may offer: its set's "longest don't-ask-again".
		for _, r := range releases {
			if caps[r.Set], err = q.StandingCap(ctx, r.Set); err != nil {
				return err
			}
		}
		return nil
	})
	return map[string]any{"drafts": drafts, "releases": releases, "standing": standing, "standing_caps": caps}, err
}

type envChoice struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	TTL    int    `json:"ttl_seconds"`
	// Standing ("don't ask again for ...") rides an approval; it is in the
	// signed text only when chosen, so an approval without it reads as before.
	Standing int `json:"standing_seconds,omitempty"`
}

func (s *Server) envReview(ctx context.Context, q *store.Q, sess string, pk int64, in envChoice) (string, error) {
	if err := s.sealOwner(ctx, q, sess, pk); err != nil {
		return "", err
	}
	if err := q.SweepEnv(ctx, s.now()); err != nil {
		return "", err
	}
	if in.Standing != 0 && in.Action != "approve" {
		return "", errBad("unexpected standing duration")
	}
	switch in.Action {
	case "standing-revoke":
		st, err := q.EnvStanding(ctx, in.ID, s.now())
		if err != nil {
			return "", errConflict("that rule has ended; reload")
		}
		if err = q.IsOrgOwner(ctx, st.Org, sess, pk, s.now()); err != nil {
			return "", errForbidden("organisation approval required")
		}
		if in.TTL != 0 {
			return "", errBad("unexpected duration")
		}
		st.Uses = 0 // a use between review and tap does not change what is signed
		return reviewJSON(st)
	case "commit", "discard":
		x, err := q.EnvDraft(ctx, sess, in.ID, s.now())
		if err != nil {
			return "", err
		}
		if in.Action == "commit" {
			b, err := q.EnvBinding(ctx, x.Host, x.D.Path, s.now())
			if err != nil || b.Class != "owner-device" || !reflect.DeepEqual(b, x.D.Binding) {
				return "", errConflict("draft base revision or admission changed")
			}
		}
		return reviewJSON(x.D)
	case "approve", "deny", "revoke":
		v, host, err := q.EnvRelease(ctx, in.ID, false)
		if err != nil {
			return "", err
		}
		if err = q.IsOrgOwner(ctx, v.Org, sess, pk, s.now()); err != nil {
			return "", errForbidden("organisation approval required")
		}
		if in.Action == "revoke" && v.Status != "approved" || in.Action != "revoke" && v.Status != "pending" {
			return "", errConflict("decision no longer available")
		}
		if in.Action == "approve" {
			b, err := q.EnvBinding(ctx, host, v.Path, s.now())
			if err != nil || !reflect.DeepEqual(b, v.Binding) {
				return "", errConflict("admission or revision changed")
			}
			if in.TTL == -1 {
				if !b.Forever || v.TTL != -1 {
					return "", errBad("indefinite not available")
				}
			} else if in.TTL <= 0 || in.TTL > maxFinite || v.TTL > 0 && in.TTL > v.TTL {
				return "", errBad("duration exceeds request")
			}
			if in.Standing != 0 {
				limit, err := q.StandingCap(ctx, v.Set)
				if err != nil {
					return "", err
				}
				if in.Standing < 60 || in.Standing > limit || in.TTL <= 0 {
					return "", errBad("don't-ask-again is off for this set, or longer than its limit")
				}
			}
		} else if in.TTL != 0 {
			return "", errBad("unexpected duration")
		}
		v.Reason = ""
		return reviewJSON(v)
	default:
		return "", errBad("unknown env decision")
	}
}
func (s *Server) envChallenge(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in envChoice
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	var meta string
	var needs []bucketNeed
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		if meta, err = s.envReview(ctx, q, sess, pk, in); err != nil {
			return err
		}
		if in.Action == "approve" {
			// The set's bucket stays open until the release is collected,
			// revoked or ten minutes pass (§5).
			v, _, err := q.EnvRelease(ctx, in.ID, false)
			if err != nil {
				return err
			}
			row, err := s.setRow(ctx, q, "env-set", v.Set)
			if err != nil {
				return err
			}
			until := int64(0)
			if in.TTL > 0 {
				until = s.now().Add(secs(in.TTL)).UnixMilli()
			}
			holds := []bucketHold{s.envHold(in.ID, until)}
			if in.Standing > 0 {
				holds = append(holds, envStandingHold(envset.Standing{ID: in.ID, Binding: v.Binding, Expires: s.now().Add(secs(in.Standing)).UnixMilli()}))
			}
			// A tap that opens the bucket re-arms the set's rules that were waiting for it.
			rules, err := q.ActiveEnvStanding(ctx, 0, v.Set, s.now())
			if err != nil {
				return err
			}
			for _, st := range rules {
				holds = append(holds, envStandingHold(st))
			}
			needs = []bucketNeed{s.need(row, holds...)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	m := s.reviewFields("env", in.Action, in.ID)
	m["metadata"], m["ttl_seconds"] = meta, in.TTL
	if in.Standing > 0 {
		m["standing_seconds"] = in.Standing
	}
	text, _ := reviewJSON(m)
	return s.beginTap(ctx, sess, "env", in.Action, text, needs, nil)
}
func (s *Server) envFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, pk, settle, err := s.takeReview(ctx, sess, "env", in)
	if err != nil {
		return nil, err
	}
	defer func() { settle(err == nil) }()
	var m struct {
		envChoice
		Metadata     string
		Epoch        seal.ID
		Installation seal.ID
	}
	if json.Unmarshal([]byte(c.Canonical), &m) != nil || m.Epoch != s.seal.opens.Epoch() || m.Installation != s.seal.installation {
		err = errBad("invalid env decision")
		return nil, err
	}
	err = s.store.Tx(ctx, func(q *store.Q) error {
		meta, err := s.envReview(ctx, q, sess, pk, m.envChoice)
		if err != nil || meta != m.Metadata {
			return errConflict("env proposal changed; review again")
		}
		switch m.Action {
		case "discard":
			err = q.DeleteEnvDraft(ctx, m.ID, sess)
		case "commit":
			x, err2 := q.EnvDraft(ctx, sess, m.ID, s.now())
			if err2 != nil {
				return err2
			}
			err = s.commitDraft(ctx, q, x)
		case "approve":
			until := untilRevoked
			if m.TTL > 0 {
				until = s.now().Add(secs(m.TTL))
			}
			if err = q.DecideEnv(ctx, m.ID, "approved", ids.New(), m.TTL, until.UnixMilli()); err == nil && m.Standing > 0 {
				v, host, err2 := q.EnvRelease(ctx, m.ID, false)
				if err2 != nil {
					return err2
				}
				now := s.now()
				err = q.NewEnvStanding(ctx, host, envset.Standing{Binding: v.Binding, ID: v.ID, Mode: v.Mode, Peer: v.Peer, MaxTTL: m.TTL, Created: now.UnixMilli(), Expires: now.Add(secs(m.Standing)).UnixMilli()})
			}
		case "standing-revoke":
			var n int
			if n, err = q.RevokeEnvStanding(ctx, s.now(), m.ID); err == nil && n == 0 {
				err = errConflict("that rule has ended; reload")
			}
			if err == nil {
				// What the rule issued and nobody collected ends with it.
				err = s.revokeUnder(ctx, q, m.ID)
			}
		case "deny":
			err = q.DecideEnv(ctx, m.ID, "denied", "", 0, 0)
		case "revoke":
			// Revoking a release also ends the rule its approval created and
			// the rule that approved it, as revoking a grant does.
			by, err2 := q.EnvReleaseStanding(ctx, m.ID)
			if err2 != nil {
				return err2
			}
			if err = q.DecideEnv(ctx, m.ID, "revoked", "", 0, 0); err == nil {
				_, err = q.RevokeEnvStanding(ctx, s.now(), m.ID, by)
			}
			if err == nil {
				s.seal.pool.release("env:" + m.ID)
				err = s.revokeUnder(ctx, q, m.ID, by)
			}
		}
		if err != nil {
			return err
		}
		return q.Audit(ctx, s.now(), "owner", "env_"+strings.ReplaceAll(m.Action, "-", "_"), "env:"+m.ID, fmt.Sprintf("passkey=%d canonical=%s", pk, c.Canonical))
	})
	if err == nil {
		s.bcast.notify()
		s.notify.Send("aqmas: env decision", "Applied "+m.Action+" [ref "+ref(m.ID)+"]", s.cfg.PublicBaseURL+"/")
	}
	return api.OK{OK: true}, err
}

func (s *Server) allPending(ctx context.Context, q *store.Q, host int64, now time.Time) (int, error) {
	n, err := q.CountPendingRequests(ctx, host, now)
	if s.seal != nil && err == nil {
		e, err := q.EnvPending(ctx, host, now)
		if err != nil {
			return 0, err
		}
		g, err := q.SignPending(ctx, host, now)
		return n + e + g, err
	}
	return n, err
}

// commitDraft merges a CLI draft into the next revision without opening the
// bucket: the draft's entries were sealed at upload (where the commitment was
// checked against the plaintext); unchanged entries keep their ciphertext.
func (s *Server) commitDraft(ctx context.Context, q *store.Q, x store.StagedEnv) error {
	row, err := s.setRow(ctx, q, "env-set", x.D.Set)
	if err != nil {
		return err
	}
	if !bytes.Equal(x.Record.Wrap, row.ID) {
		return errConflict("the draft was sealed to another key; upload it again")
	}
	if secret, err := q.IsSecret(ctx, x.D.Set); err != nil {
		return err
	} else if secret {
		return errConflict("a secret is replaced in the Vault, not from the CLI")
	}
	unset := x.D.Operation == "unset"
	recs, err := parseRecords(x.Record.Payload, !unset)
	if err != nil {
		return err
	}
	if (x.D.Operation == "put" || unset) && len(recs) != 1 {
		return errConflict("edit commitment or manifest mismatch")
	}
	names := make([]envset.Entry, len(recs))
	for i, r := range recs {
		names[i] = envset.Entry{Name: r.N}
	}
	changes, err := envset.Edit{Op: x.D.Operation, Entries: names}.Changes(x.D.Names)
	if err != nil || changes != x.D.Changes {
		return errConflict("edit commitment or manifest mismatch")
	}
	old, _, err := s.revisionRecords(ctx, q, x.D.Binding)
	if err != nil {
		return err
	}
	return s.writeRevision(ctx, q, x.D.Binding, row, mergeRecords(old, x.D.Operation, recs, nil))
}
