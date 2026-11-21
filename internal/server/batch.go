package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"net/http"
	"slices"
	"strings"
)

type ordinaryChoice struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	TTL    int    `json:"ttl_seconds"`
}

func (s *Server) ordinary(ctx context.Context, q *store.Q, sess string, pk int64, c ordinaryChoice) (canon.Action, error) {
	var empty canon.Action
	if c.Action != "approve" && c.Action != "deny" || c.Action == "deny" && c.TTL != 0 || c.Action == "approve" && c.TTL < 1 {
		return empty, errBad("expected a finite approval or denial")
	}
	a, err := s.buildActionQ(ctx, q, "request", c.ID, api.ChallengeRequest{Action: c.Action, TTLSeconds: c.TTL})
	if err != nil {
		return empty, err
	}
	if a.OrgID == "" || q.IsOrgOwner(ctx, a.OrgID, sess, pk, s.now()) != nil {
		return empty, errForbidden("scoped approver required")
	}
	r, err := q.GetRequest(ctx, c.ID)
	if err != nil {
		return empty, err
	}
	if !ordinaryRisk(a, r, s.highRisk(r)) {
		return empty, errConflict("this decision requires an individual passkey tap")
	}
	return a, nil
}
func ordinaryRisk(a canon.Action, r *store.Request, high bool) bool {
	if r.TTLRequested <= 0 || r.TTLRequested > a.SoftCap || a.TTLSeconds > a.SoftCap || a.TTLSeconds > a.HardCap || a.Indefinite || a.StandingIndefinite || a.BeyondSoft || a.StandingBeyondSoft || a.StandingSeconds != 0 || a.StandingHours != 0 {
		return false
	}
	switch a.Kind {
	case "ssh":
		return !high && r.LoginUser != "root" && a.LoginUser != "root"
	case "cloudflare":
		return a.Mode == "proxy" && (a.Scope == "cf.read" || a.Scope == "cf.cache.purge")
	}
	return false
}
func (s *Server) applyOrdinary(ctx context.Context, q *store.Q, sess string, pk int64, text, who string) error {
	sg, err := canon.Parse(text)
	if err != nil || sg.V != 2 || sg.Object != "request" {
		return errBad("invalid scoped decision")
	}
	want, err := s.ordinary(ctx, q, sess, pk, ordinaryChoice{sg.ID, sg.Action.Action, sg.TTLSeconds})
	if err != nil || want != sg.Action {
		return errConflict("request or authority changed; review again")
	}
	if err = s.applyQ(context.WithValue(ctx, sessionBindingKey{}, sess), q, sg, pk, who); err != nil {
		return err
	}
	return q.Audit(ctx, s.now(), "owner", "decision_evidence", "request:"+sg.ID, who+" canonical="+text)
}
func (s *Server) approvalRoutes(m *http.ServeMux) {
	s.sealedEndpoint(m, "POST /api/ui/seal/batch/challenge", s.batchBegin)
	s.sealedEndpoint(m, "POST /api/ui/seal/batch/finish", s.batchFinish)
	s.windowRoutes(m)
}
func (s *Server) batchBegin(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		Items []ordinaryChoice `json:"items"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if len(in.Items) < 1 || len(in.Items) > 10 {
		return nil, errBad("select one to ten requests")
	}
	slices.SortFunc(in.Items, func(a, b ordinaryChoice) int { return strings.Compare(a.ID, b.ID) })
	var org, title string
	items := []string{}
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		for i, c := range in.Items {
			a, err := s.ordinary(ctx, q, sess, pk, c)
			if err != nil {
				return err
			}
			if i > 0 && (in.Items[i-1].ID == c.ID || a.OrgID != org) {
				return errBad("duplicate or mixed-organisation selection")
			}
			org, title = a.OrgID, a.OrgTitle
			text, err := canon.Build(a, canon.NewNonce(), s.now())
			if err != nil {
				return err
			}
			items = append(items, text)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	m := s.reviewFields("batch", "decide", ids.Secret(32))
	m["items"], err = reviewJSON(items)
	if err != nil {
		return nil, err
	}
	m["org_id"], m["org_title"], m["count"] = org, title, len(items)
	text, err := reviewJSON(m)
	if err != nil || len(text) > 32<<10 {
		return nil, errBad("batch exceeds 32 KiB; split it")
	}
	return s.beginReview(ctx, sess, "batch", "decide", text, nil)
}
func (s *Server) batchFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in api.DecideRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, pk, err := s.takeReview(ctx, sess, "batch", in)
	if err != nil {
		return nil, err
	}
	var b struct {
		ID, Items           string
		Count               int
		Epoch, Installation string
		Org                 string `json:"org_id"`
	}
	var items []string
	epoch := s.seal.attempts.Epoch()
	if json.Unmarshal([]byte(c.Canonical), &b) != nil || b.Epoch != encodeID(epoch[:]) || b.Installation != encodeID(s.seal.inv.Installation[:]) || json.Unmarshal([]byte(b.Items), &items) != nil || len(items) != b.Count || b.Count < 1 || b.Count > 10 {
		return nil, errConflict("stale batch")
	}
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := s.sealOwner(ctx, q, sess, pk); err != nil {
			return err
		}
		last := ""
		for _, text := range items {
			sg, err := canon.Parse(text)
			if err != nil || sg.OrgID != b.Org || sg.ID <= last {
				return errBad("invalid batch member")
			}
			last = sg.ID
			if err = s.applyOrdinary(ctx, q, sess, pk, text, fmt.Sprintf("batch=%s signed by %s", b.ID, s.passkeyRef(ctx, q, pk))); err != nil {
				return err
			}
		}
		return q.Audit(ctx, s.now(), "owner", "batch_decide", "batch:"+b.ID, c.Canonical+" assertion="+string(in.Assertion))
	})
	if err != nil {
		return nil, err
	}
	s.bcast.notify()
	s.notify.Send("aqmas: batch", fmt.Sprintf("Applied %d reviewed decisions [ref %s]", b.Count, ref(b.ID)), s.cfg.PublicBaseURL+"/")
	return api.OK{OK: true}, nil
}
