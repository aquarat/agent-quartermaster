package server

import (
	"context"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"golang.org/x/crypto/ssh"
	"strings"
)

// Build the card, challenge and transactional recheck from the same committed
// request binding. Never use a host or organisation asserted by the client.
func (s *Server) bindAction(ctx context.Context, q *store.Q, a canon.Action) (canon.Action, error) {
	if !q.Scoped() {
		return a, nil
	}
	var source string
	switch a.Object {
	case canon.ObjectRequest:
		source = a.ID
		// A bastion session is deliberately outside the catalogue: it has no binding to
		// add. Decided on the stored kind, never on what the action claims.
		if r, err := q.GetRequest(ctx, source); err == nil && r.Kind == api.KindBastion {
			return a, nil
		}
	case canon.ObjectGrant:
		g, err := q.GetGrant(ctx, a.ID)
		if err != nil {
			return a, err
		}
		if g.Kind == api.KindBastion {
			return a, nil
		}
		source = g.RequestID
		a.Indefinite = g.NotAfter.Equal(untilRevoked)
	case canon.ObjectStanding:
		rule, err := q.GetStanding(ctx, a.ID)
		if err != nil {
			return a, err
		}
		source = rule.SourceRequestID
		a.StandingIndefinite = rule.ExpiresAt.Equal(untilRevoked)
	default:
		return a, nil
	}
	r, err := q.GetRequest(ctx, source)
	if err != nil {
		return a, err
	}
	b, err := q.BoundResource(ctx, r.HostID, source, s.now())
	if a.Object != canon.ObjectRequest && a.Action == canon.ActionRevoke {
		b, err = q.RecordedResource(ctx, source)
	}
	if err != nil {
		return a, errConflict("request binding is no longer active")
	}
	a.ScopeBinding = api.ScopeBinding{OrgID: b.OrgID, OrgSlug: b.OrgSlug, OrgTitle: b.OrgTitle, ServiceID: b.ServiceID, ServiceSlug: b.ServiceSlug, ServiceTitle: b.ServiceTitle, SetID: b.SetID, SetSlug: b.SetSlug, SetTitle: b.SetTitle, SetRevision: b.SetRevision, ServiceRevision: b.ServiceRevision, PolicyRevision: b.PolicyRevision, AdmissionGeneration: b.Generation, HostID: b.Enrollment, ProfileRevision: s.profileRevision, MaxStandingHours: s.cfg.TTL.ForHost(b.Class).MaxStandingHours}
	a.Class = b.Class
	a.Address = r.PeerAddress
	l, err := s.limits(ctx, q, b, r.Scope)
	if err != nil {
		return a, err
	}
	a.SoftCap = l.Soft
	a.HardCap = l.Hard
	a.StandingSoftCap = l.StandingSoft
	a.StandingDefault = l.StandingDefault
	a.OffersIndefinite = l.Forever && r.TTLRequested == -1
	a.OffersStanding = l.Standing && (r.Kind != api.KindSSH || !s.highRisk(r))
	a.OffersStandingIndefinite = l.StandingForever
	a.BeyondSoft = a.Indefinite || a.TTLSeconds > l.Soft
	a.StandingBeyondSoft = a.StandingIndefinite || a.StandingHours > l.StandingSoft/3600 || a.StandingSeconds > l.StandingSoft
	if a.StandingSeconds > 0 && (!a.OffersStanding || a.StandingSeconds > l.StandingMax*3600) {
		return a, errBad("standing choice exceeds current policy")
	}
	switch r.Kind {
	case api.KindSSH:
		t, ok := s.cfg.Target(r.TargetHost)
		if !ok || b.Kind != "ssh-ca" {
			return a, errConflict("SSH authority changed")
		}
		a.Principal = r.Principal
		a.TargetAddress = r.TargetAddress
		a.TargetPort = r.TargetPort
		a.KeyFingerprint = r.KeyFingerprint
		a.SSHCA = s.sshPin()
		a.CertProfile = "source-address;permit-pty;permit-port-forwarding"
		a.HostKey = "unpinned"
		if t.HostKey != "" {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
			if err != nil {
				return a, err
			}
			a.HostKey = ssh.FingerprintSHA256(pk)
		}
	case api.KindCloudflare:
		if b.Kind != "cloudflare-proxy" || s.cf.cat == nil {
			return a, errConflict("Cloudflare authority changed")
		}
		res, err := s.cf.cat.Reparse(r.Scope, r.ScopeParams, r.Mode)
		if err != nil {
			return a, err
		}
		a.AccountID = s.cfg.Cloudflare.AccountID
		var pairs []string
		for _, k := range []string{"db", "tunnel", "zone"} {
			if id := res.IDs[k]; id != "" {
				pairs = append(pairs, k+"="+id)
			}
		}
		a.ResourceIDs = strings.Join(pairs, ";")
	default:
		return a, errConflict("unsupported kind")
	}
	return a, nil
}

type sessionBindingKey struct{}
