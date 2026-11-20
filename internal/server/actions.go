package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/policy"
	"github.com/aquarat/agent-quartermaster/internal/server/sshcert"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

func secs(n int) time.Duration { return time.Duration(n) * time.Second }

// issueGrant signs the SSH certificate for an approved request inside the caller's transaction.
// Validity starts at approval time (now), not request time.
func (s *Server) issueGrant(ctx context.Context, q *store.Q, req *store.Request, ttl int, now time.Time) (*store.Grant, error) {
	tgt, ok := s.cfg.Target(req.TargetHost)
	if !ok || !tgt.AllowsUser(req.LoginUser) {
		return nil, errConflict("target or login user no longer configured")
	}
	pub, err := sshcert.ParseEd25519(req.PublicKey)
	if err != nil {
		return nil, errConflict("stored public key invalid")
	}
	nb, na := sshcert.Validity(now, secs(ttl))
	g := &store.Grant{
		ID:         ids.New(),
		RequestID:  req.ID,
		HostID:     req.HostID,
		HostName:   req.HostName,
		Kind:       req.Kind,
		TargetHost: tgt.Name,
		LoginUser:  req.LoginUser,
		Principals: []string{tgt.Principal(req.LoginUser)},
		NotBefore:  nb,
		NotAfter:   na,
	}
	serial, err := q.InsertGrant(ctx, g)
	if err != nil {
		return nil, err
	}
	g.Serial = serial
	cert, err := sshcert.Sign(s.pki.SSHSigner, sshcert.Params{
		Serial:        uint64(serial),
		KeyID:         fmt.Sprintf("aqmas:%s:%s:%s", g.ID, req.HostName, tgt.Name),
		Principals:    g.Principals,
		SourceAddress: req.PeerAddress,
		ApprovedAt:    now,
		TTL:           secs(ttl),
		PublicKey:     pub,
	})
	if err != nil {
		return nil, err
	}
	g.Certificate = sshcert.Marshal(cert)
	if err := q.SetGrantCert(ctx, serial, g.Certificate); err != nil {
		return nil, err
	}
	return g, nil
}

// buildAction assembles the action the owner is asked to sign for one object, validating the
// approver's choices against the current state. It never trusts anything but the object's
// stored state and the approver's ttl/standing choice.
func (s *Server) buildAction(ctx context.Context, object, id string, in api.ChallengeRequest) (canon.Action, error) {
	q := s.store.Q()
	now := s.now()
	if _, err := q.ExpireStale(ctx, now); err != nil {
		return canon.Action{}, err
	}
	a := canon.Action{Action: in.Action, Object: object, ID: id}
	switch object {
	case canon.ObjectRequest:
		if in.Action != canon.ActionApprove && in.Action != canon.ActionDeny {
			return a, errBad("action must be approve or deny")
		}
		r, err := q.GetRequest(ctx, id)
		if err != nil {
			return a, mapNotFound(err)
		}
		if r.Status != api.StatusPending {
			return a, statusErr(r.Status)
		}
		a.RequestingHost, a.Kind, a.Target, a.LoginUser, a.KeyFingerprint = r.HostName, r.Kind, r.TargetHost, r.LoginUser, r.KeyFingerprint
		if in.Action == canon.ActionApprove {
			ttl, err := policy.ApproverTTL(r.TTLRequested, in.TTLSeconds, s.cfg.TTL)
			if err != nil {
				return a, errBad(err.Error())
			}
			if err := policy.StandingHours(in.StandingHours, s.cfg.TTL); err != nil {
				return a, errBad(err.Error())
			}
			a.TTLSeconds, a.StandingHours = ttl, in.StandingHours
		} else if in.TTLSeconds != 0 || in.StandingHours != 0 {
			return a, errBad("deny takes no ttl_seconds or standing_hours")
		}
	case canon.ObjectEnrollment:
		if in.Action != canon.ActionApprove && in.Action != canon.ActionDeny {
			return a, errBad("action must be approve or deny")
		}
		if in.TTLSeconds != 0 || in.StandingHours != 0 {
			return a, errBad("enrollments take no ttl_seconds or standing_hours")
		}
		e, err := q.GetEnrollment(ctx, id)
		if err != nil {
			return a, mapNotFound(err)
		}
		if e.Status != api.StatusPending {
			return a, statusErr(e.Status)
		}
		a.RequestingHost, a.Kind, a.KeyFingerprint = e.Hostname, "enrollment", e.KeyFingerprint
		if _, err := q.ActiveHostByName(ctx, e.Hostname); err == nil {
			a.Replaces = true // approving revokes the current host of that name
		} else if !errors.Is(err, store.ErrNotFound) {
			return a, err
		}
	case canon.ObjectStanding:
		if in.Action != canon.ActionRevoke || in.TTLSeconds != 0 || in.StandingHours != 0 {
			return a, errBad("standing approvals can only be revoked")
		}
		st, err := q.GetStanding(ctx, id)
		if err != nil {
			return a, mapNotFound(err)
		}
		if st.RevokedAt != nil {
			return a, errConflict("already revoked")
		}
		a.RequestingHost, a.Kind, a.Target, a.LoginUser, a.TTLSeconds = st.HostName, st.Kind, st.TargetHost, st.LoginUser, st.MaxTTL
	case canon.ObjectGrant:
		if in.Action != canon.ActionRevoke || in.TTLSeconds != 0 || in.StandingHours != 0 {
			return a, errBad("grants can only be revoked")
		}
		g, err := q.GetGrant(ctx, id)
		if err != nil {
			return a, mapNotFound(err)
		}
		if g.RevokedAt != nil {
			return a, errConflict("already revoked")
		}
		a.RequestingHost, a.Kind, a.Target, a.LoginUser = g.HostName, g.Kind, g.TargetHost, g.LoginUser
	case canon.ObjectPasskey:
		if in.Action != canon.ActionAdd || in.TTLSeconds != 0 || in.StandingHours != 0 {
			return a, errBad(`action must be "add"`)
		}
	default:
		return a, errBad("unknown object")
	}
	return a, nil
}

func mapNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound()
	}
	return err
}

func statusErr(status string) error {
	if status == api.StatusExpired {
		return errExpired("already expired")
	}
	return errConflict("already " + status)
}

// apply performs exactly the signed action, inside one transaction, re-checking state.
func (s *Server) apply(ctx context.Context, sg canon.Signed, passkeyID int64) error {
	now := s.now()
	a := sg.Action
	detail := fmt.Sprintf("passkey=%d nonce=%s", passkeyID, sg.Nonce[:8])
	return s.store.Tx(ctx, func(q *store.Q) error {
		if _, err := q.ExpireStale(ctx, now); err != nil {
			return err
		}
		switch a.Object {
		case canon.ObjectRequest:
			r, err := q.GetRequest(ctx, a.ID)
			if err != nil {
				return mapNotFound(err)
			}
			// The stored request must still be the one that was signed.
			if r.HostName != a.RequestingHost || r.Kind != a.Kind || r.TargetHost != a.Target ||
				r.LoginUser != a.LoginUser || r.KeyFingerprint != a.KeyFingerprint {
				return errConflict("request changed since the challenge was issued")
			}
			if a.Action == canon.ActionDeny {
				if err := q.DecideRequest(ctx, r.ID, api.StatusDenied, "denied by owner", now); err != nil {
					return decideErr(err)
				}
				return q.Audit(ctx, now, "owner", "deny", "request:"+r.ID, detail)
			}
			if a.TTLSeconds <= 0 || a.TTLSeconds > r.TTLRequested || a.TTLSeconds > s.cfg.TTL.MaxSeconds {
				return errConflict("signed ttl outside policy")
			}
			if err := q.DecideRequest(ctx, r.ID, api.StatusApproved, "approved by owner", now); err != nil {
				return decideErr(err)
			}
			g, err := s.issueGrant(ctx, q, r, a.TTLSeconds, now)
			if err != nil {
				return err
			}
			if err := q.Audit(ctx, now, "owner", "approve", "request:"+r.ID,
				fmt.Sprintf("grant=%s %s@%s for %s ttl=%d key=%s src=%s %s", g.ID, r.LoginUser, r.TargetHost, r.HostName, a.TTLSeconds, r.KeyFingerprint, r.PeerAddress, detail)); err != nil {
				return err
			}
			if a.StandingHours > 0 {
				if a.StandingHours > s.cfg.TTL.MaxStandingHours {
					return errConflict("signed standing_hours outside policy")
				}
				st := &store.Standing{
					ID: ids.New(), HostID: r.HostID, HostName: r.HostName, Kind: r.Kind, TargetHost: r.TargetHost,
					LoginUser: r.LoginUser, MaxTTL: a.TTLSeconds, CreatedAt: now,
					ExpiresAt: now.Add(time.Duration(a.StandingHours) * time.Hour), SourceRequestID: r.ID,
				}
				if err := q.InsertStanding(ctx, st); err != nil {
					return err
				}
				return q.Audit(ctx, now, "owner", "standing_create", "standing:"+st.ID,
					fmt.Sprintf("host=%s %s@%s max_ttl=%d hours=%d %s", r.HostName, r.LoginUser, r.TargetHost, a.TTLSeconds, a.StandingHours, detail))
			}
			return nil

		case canon.ObjectEnrollment:
			e, err := q.GetEnrollment(ctx, a.ID)
			if err != nil {
				return mapNotFound(err)
			}
			if e.Hostname != a.RequestingHost || e.KeyFingerprint != a.KeyFingerprint {
				return errConflict("enrollment changed since the challenge was issued")
			}
			if a.Action == canon.ActionDeny {
				if err := q.DecideEnrollment(ctx, e.ID, api.StatusDenied, "denied by owner", "", now); err != nil {
					return decideErr(err)
				}
				return q.Audit(ctx, now, "owner", "enroll_deny", "enrollment:"+e.ID, "hostname="+e.Hostname+" "+detail)
			}
			csr, err := pki.ParseCSR(e.CSRPEM)
			if err != nil {
				return errConflict("stored CSR invalid")
			}
			replaced := ""
			old, err := q.ActiveHostByName(ctx, e.Hostname)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			// The owner signed whether this replaces an existing host; the state must still agree.
			if (old != nil) != a.Replaces {
				return errConflict("host list changed since the challenge was issued; start again")
			}
			if old != nil {
				if err := q.RevokeHost(ctx, old.ID, now); err != nil {
					return err
				}
				replaced = fmt.Sprintf(" replaced_host_id=%d", old.ID)
				if err := q.Audit(ctx, now, "owner", "host_revoke", "host:"+old.Name, fmt.Sprintf("host_id=%d replaced by enrollment %s", old.ID, e.ID)); err != nil {
					return err
				}
			}
			der, err := s.pki.IssueClientCert(csr, e.Hostname, now, s.cfg.ClientCertDays)
			if err != nil {
				return err
			}
			if err := q.DecideEnrollment(ctx, e.ID, api.StatusApproved, "approved by owner", pemCert(der), now); err != nil {
				return decideErr(err)
			}
			if _, err := q.InsertHost(ctx, &store.Host{Name: e.Hostname, CertSHA256: pki.CertFingerprint(der), EnrollmentID: e.ID,
				CreatedAt: now, NotAfter: now.Add(time.Duration(s.cfg.ClientCertDays) * 24 * time.Hour)}); err != nil {
				return err
			}
			return q.Audit(ctx, now, "owner", "enroll_approve", "enrollment:"+e.ID, "hostname="+e.Hostname+" key="+e.KeyFingerprint+replaced+" "+detail)

		case canon.ObjectStanding:
			if err := q.RevokeStanding(ctx, a.ID, now); err != nil {
				return decideErr(err)
			}
			return q.Audit(ctx, now, "owner", "standing_revoke", "standing:"+a.ID, detail)

		case canon.ObjectGrant:
			g, err := q.GetGrant(ctx, a.ID)
			if err != nil {
				return mapNotFound(err)
			}
			if err := q.RevokeGrant(ctx, a.ID, now); err != nil {
				return decideErr(err)
			}
			if err := q.MarkRequestRevoked(ctx, g.RequestID); err != nil {
				return err
			}
			return q.Audit(ctx, now, "owner", "grant_revoke", "grant:"+a.ID, "certificate stays valid until "+g.NotAfter.Format(time.RFC3339)+" "+detail)
		}
		return errBad("unsupported action")
	})
}

func decideErr(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return errConflict("already decided, revoked or expired")
	}
	return err
}
