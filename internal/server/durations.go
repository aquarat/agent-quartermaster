package server

import (
	"context"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Use an explicit wire flag; the legacy non-null database timestamp remains
// sortable/comparable by all sweeps and active-grant queries. Do not derive
// this date by multiplying a user duration (time.Duration overflows).
var untilRevoked = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

const maxFinite = 315360000 // ten years, well within time.Duration

type limits struct {
	api.DurationPolicy
	DefaultTTL, Hard, StandingMax            int
	Auto, Standing, Forever, StandingForever bool
}

func (s *Server) limits(ctx context.Context, q *store.Q, b organisations.Resource, scope string) (limits, error) {
	p, err := q.OrgPolicy(ctx, b.OrgID, b.PolicyRevision)
	if err != nil {
		return limits{}, err
	}
	r, err := q.ScopeRule(ctx, b.SetID, scope, b.PolicyRevision)
	if err != nil {
		return limits{}, err
	}
	return s.resourceLimits(b, r, p)
}

func (s *Server) resourceLimits(b organisations.Resource, r api.CatalogueRule, p api.DurationPolicy) (limits, error) {
	class := s.cfg.TTL.ForHost(b.Class)
	l := limits{DurationPolicy: p, DefaultTTL: p.Default, Standing: r.Standing, StandingMax: class.MaxStandingHours}
	switch b.Kind {
	case "ssh-ca":
		l.Hard = min(class.MaxSeconds, p.Soft)
		t, ok := s.cfg.Target(b.SetSlug)
		if !ok {
			return l, errNotFound()
		}
		if t.MaxTTLSeconds > 0 {
			l.Hard = min(l.Hard, t.MaxTTLSeconds)
		}
		l.Standing = l.Standing && !t.HighRisk
	case "cloudflare-proxy":
		if s.cf.cat == nil {
			return l, errNotFound()
		}
		scope := r.Scope
		sc, ok := s.cf.cat.Lookup(scope)
		if !ok {
			return l, errNotFound()
		}
		l.Hard = min(s.cfg.TTL.MaxSeconds, sc.MaxTTL)
		switch scope {
		case api.CFScopeAdmin:
			l.Hard = min(l.Hard, 3600)
		case api.CFScopeReadPrivate:
			l.Hard = min(l.Hard, 7200)
		}
		l.DefaultTTL = min(sc.DefaultTTL, l.Hard)
		if b.PolicyRevision > 1 {
			l.DefaultTTL = p.Default
		}
		l.Auto = r.Auto && sc.AutoApprove
		l.Standing = r.Standing && sc.StandingAllowed
		if r.Relax && scope != api.CFScopeAdmin && scope != api.CFScopeReadPrivate {
			l.Hard = maxFinite
			l.Forever = p.Indefinite
			if cap := s.cfg.Cloudflare.Scopes[scope].MaxTTLSeconds; cap > 0 {
				l.Hard = min(l.Hard, cap)
				l.Forever = false
			}
		}
		l.StandingForever = l.Standing && p.StandingIndefinite
	default:
		return l, errNotFound()
	}
	if l.Hard < s.cfg.TTL.MinSeconds {
		return l, errConflict("empty policy range")
	}
	l.DefaultTTL = min(l.Hard, max(l.DefaultTTL, s.cfg.TTL.MinSeconds))
	return l, nil
}

func (l limits) requestTTL(requested, minTTL int, indefinite bool) (int, error) {
	if indefinite {
		if !l.Forever || requested != 0 {
			return 0, errBad("indefinite is unavailable or conflicts with ttl_seconds")
		}
		return -1, nil
	}
	if requested <= 0 {
		return l.DefaultTTL, nil
	}
	return min(max(minTTL, requested), l.Hard), nil
}

func (s *Server) decisionLimits(ctx context.Context, q *store.Q, r *store.Request) (limits, error) {
	b, err := q.BoundResource(ctx, r.HostID, r.ID, s.now())
	if err != nil {
		return limits{}, errConflict("admission or resource changed")
	}
	return s.limits(ctx, q, b, r.Scope)
}

func (s *Server) checkCFChoice(r *store.Request, a canon.Action, l limits) error {
	if a.Indefinite {
		if !l.Forever || r.TTLRequested != -1 || a.TTLSeconds != 0 || a.StandingIndefinite || a.StandingHours != 0 {
			return errBad("indefinite needs a separate eligible grant with no standing rule")
		}
	} else if a.TTLSeconds < s.cfg.TTL.MinSeconds || a.TTLSeconds > l.Hard || r.TTLRequested != -1 && a.TTLSeconds > r.TTLRequested {
		return errBad("selected duration outside requested or signed policy limits")
	}
	if a.StandingHours < 0 || a.StandingHours > l.StandingMax || a.StandingHours > 0 && !l.Standing || a.StandingIndefinite && (!l.StandingForever || a.StandingHours != 0) {
		return errBad("standing duration outside policy")
	}
	return nil
}
