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
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
)

func (s *Server) envCipher(ctx context.Context, b envset.Binding, draft string, rec store.CipherRecord, data any, encrypt bool) (store.CipherRecord, error) {
	k, _ := ctx.Value(leaseKey{}).(*seal.Key)
	if k == nil || ctx.Err() != nil {
		return rec, lockedErr()
	}
	role := "env-revision"
	rev := b.Revision
	blob := seal.RandomID()
	if draft != "" {
		role = "env-draft"
		rev++
		raw, err := strictB64(draft, 32)
		if err != nil || len(raw) != 32 {
			return rec, errBad("invalid draft id")
		}
		copy(blob[:], raw)
	}
	if !encrypt {
		if len(rec.Blob) != 32 || draft != "" && !bytes.Equal(blob[:], rec.Blob) {
			s.stopSealed()
			return rec, errConflict("damaged sealed record")
		}
		copy(blob[:], rec.Blob)
	}
	o := seal.Object{Org: b.Org, Service: b.Service, Set: b.Set, Role: role, Revision: uint64(rev), Blob: blob}
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
	if err != nil || json.Unmarshal(p, data) != nil {
		s.stopSealed()
		return rec, errConflict("sealed record failed authentication; relocking")
	}
	return rec, nil
}
func (s *Server) values(ctx context.Context, q *store.Q, b envset.Binding) ([]envset.Entry, error) {
	if b.Revision == 0 {
		return []envset.Entry{}, nil
	}
	r, err := q.EnvCipher(ctx, b.Set, b.Revision)
	if err != nil {
		return nil, err
	}
	var vals []envset.Entry
	_, err = s.envCipher(ctx, b, "", r, &vals, false)
	if err != nil {
		return nil, err
	}
	if envset.Validate(vals) != nil || !slices.Equal(envset.Names(vals), b.Names) {
		return nil, errConflict("damaged env revision")
	}
	return vals, nil
}
func (s *Server) envAgentRoutes(m *http.ServeMux) {
	route := func(pattern string, secret bool, f func(context.Context, *store.Q, *http.Request, *store.Host) (any, error)) {
		m.Handle(pattern, s.requireHost(func(w http.ResponseWriter, r *http.Request, h *store.Host) {
			if s.seal == nil || s.seal.stage != nil {
				s.writeErr(w, r, errNotFound())
				return
			}
			s.optionalLease(r.Context(), func(ctx context.Context) {
				var out any
				err := s.store.Tx(ctx, func(q *store.Q) error {
					if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
						return err
					}
					if err := q.SweepEnv(ctx, s.now()); err != nil {
						return err
					}
					var err error
					out, err = f(ctx, q, r, h)
					return err
				})
				if err != nil {
					s.writeErr(w, r, mapNotFound(err))
					return
				}
				if secret {
					w = s.deliveryWriter(ctx, w)
				}
				writeJSON(w, 200, out)
			})
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
	if !s.authorisedWork(ctx) {
		return nil, lockedErr()
	}
	commit, err := in.Edit.Commit(b)
	if err != nil || commit != in.Commitment {
		return nil, errBad("invalid edit commitment")
	}
	x.D.Commitment = commit
	x.D.Changes, err = in.Edit.Changes(b.Names)
	if err != nil {
		return nil, errBad(err.Error())
	}
	rec, err := s.envCipher(ctx, b, x.D.ID, store.CipherRecord{}, in.Edit, true)
	if err != nil {
		return nil, err
	}
	if err = q.UploadEnv(ctx, x.D, ids.Hash(in.Ticket), rec); err != nil {
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
	if in.Mode != "process" && in.Mode != "file" && in.Mode != "shell" || len(in.Reason) > MaxReasonLen || strings.TrimSpace(in.Reason) == "" || hasControl(in.Reason, false) {
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
	if n >= MaxPendingPerHost {
		return nil, &apiErr{429, "rate_limited", "too many pending requests"}
	}
	out := envset.Release{Binding: b, ID: ids.New(), Mode: in.Mode, Peer: peer, Reason: in.Reason, TTL: ttl, Deadline: now.Add(secs(s.cfg.TTL.PendingExpirySeconds)).UnixMilli(), Status: "pending"}
	if err = q.NewEnvRelease(ctx, h.ID, out); err != nil {
		return nil, err
	}
	return out, q.Audit(ctx, now, "host:"+h.Name, "env_request", "request:"+out.ID, b.Path+" mode="+out.Mode)
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
	return api.OK{OK: true}, q.Audit(ctx, s.now(), "host:"+h.Name, "env_"+status, "request:"+v.ID, v.Path)
}
func (s *Server) envCollect(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	v, err := q.VisibleEnvRelease(ctx, h.ID, peerIP(r), r.PathValue("id"), true, s.now())
	if err != nil {
		return nil, err
	}
	if v.Status != "approved" || v.Consumed {
		return nil, errConflict("grant expired, revoked or already collected")
	}
	if !s.authorisedWork(ctx) {
		return nil, lockedErr()
	}
	entries, err := s.values(ctx, q, v.Binding)
	if err != nil {
		return nil, err
	}
	if err = q.ConsumeEnv(ctx, v.Grant, s.now()); err != nil {
		return nil, errConflict("grant no longer collectible")
	}
	v.Consumed = true
	return envset.Collection{Release: v, Entries: entries}, q.Audit(ctx, s.now(), "host:"+h.Name, "env_collect_"+v.Mode, "grant:"+v.Grant, fmt.Sprintf("%s revision=%d enrollment=%s", v.Path, v.Revision, v.Enrollment))
}

func (s *Server) envWebRoutes(m *http.ServeMux) {
	s.sealedEndpoint(m, "POST /api/ui/seal/env/ticket", s.envTicket)
	for path, fn := range map[string]capHandler{"GET /api/ui/seal/env/state": s.envState, "POST /api/ui/seal/env/challenge": s.envChallenge, "POST /api/ui/seal/env/finish": s.envFinish} {
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
				writeJSON(w, 200, v)
			})
		}))
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
		draft = envset.Draft{Binding: b, ID: encodeID(id[:]), Operation: in.Operation, Expires: s.now().Add(5 * time.Minute).UnixMilli()}
		return q.NewEnvTicket(ctx, sess, host, draft, ids.Hash(ticket))
	})
	return map[string]any{"ticket": ticket, "draft": draft}, err
}
func (s *Server) envState(ctx context.Context, r *http.Request, sess string) (any, error) {
	var drafts []envset.Draft
	var releases []envset.Release
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
		releases, err = q.OwnerEnvReleases(ctx)
		return err
	})
	return map[string]any{"drafts": drafts, "releases": releases}, err
}

type envChoice struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	TTL    int    `json:"ttl_seconds"`
}

func (s *Server) envReview(ctx context.Context, q *store.Q, sess string, pk int64, in envChoice) (string, error) {
	if err := s.sealOwner(ctx, q, sess, pk); err != nil {
		return "", err
	}
	if err := q.SweepEnv(ctx, s.now()); err != nil {
		return "", err
	}
	switch in.Action {
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
		if !s.authorisedWork(ctx) {
			return "", lockedErr()
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
			if !s.authorisedWork(ctx) {
				return "", lockedErr()
			}
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
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		meta, err = s.envReview(ctx, q, sess, pk, in)
		return err
	})
	if err != nil {
		return nil, err
	}
	m := s.reviewFields("env", in.Action, in.ID)
	m["metadata"], m["ttl_seconds"] = meta, in.TTL
	text, _ := reviewJSON(m)
	return s.beginReview(ctx, sess, "env", in.Action, text, nil)
}
func (s *Server) envFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, pk, err := s.takeReview(ctx, sess, "env", in)
	if err != nil {
		return nil, err
	}
	var m struct {
		envChoice
		Metadata     string
		Epoch        seal.ID
		Installation seal.ID
	}
	if json.Unmarshal([]byte(c.Canonical), &m) != nil || m.Epoch != s.seal.attempts.Epoch() || m.Installation != s.seal.inv.Installation {
		return nil, errBad("invalid env decision")
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
			var edit envset.Edit
			if _, err = s.envCipher(ctx, x.D.Binding, x.D.ID, x.Record, &edit, false); err != nil {
				return err
			}
			digest, err := edit.Commit(x.D.Binding)
			changes, e := edit.Changes(x.D.Names)
			if err != nil || e != nil || digest != x.D.Commitment || edit.Op != x.D.Operation || changes != x.D.Changes {
				return errConflict("edit commitment or manifest mismatch")
			}
			old, err := s.values(ctx, q, x.D.Binding)
			if err != nil {
				return err
			}
			values, err := edit.Apply(old)
			if err != nil {
				return errBad("result exceeds env-set limits")
			}
			next := x.D.Binding
			next.Revision++
			rec, err := s.envCipher(ctx, next, "", store.CipherRecord{}, values, true)
			if err != nil {
				return err
			}
			if err = q.ReplaceEnv(ctx, x.D.Binding, envset.Names(values), rec); err != nil {
				return err
			}
		case "approve":
			until := untilRevoked
			if m.TTL > 0 {
				until = s.now().Add(secs(m.TTL))
			}
			err = q.DecideEnv(ctx, m.ID, "approved", ids.New(), m.TTL, until.UnixMilli())
		case "deny":
			err = q.DecideEnv(ctx, m.ID, "denied", "", 0, 0)
		case "revoke":
			err = q.DecideEnv(ctx, m.ID, "revoked", "", 0, 0)
		}
		if err != nil {
			return err
		}
		return q.Audit(ctx, s.now(), "owner", "env_"+m.Action, "env:"+m.ID, fmt.Sprintf("passkey=%d canonical=%s", pk, c.Canonical))
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
		return n + e, err
	}
	return n, err
}
