package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/aaguid"
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
	if !ok || !tgt.AllowsUser(req.LoginUser) || tgt.Principal(req.LoginUser) != req.Principal || tgt.Address != req.TargetAddress || tgt.Port != req.TargetPort || tgt.MaxTTLSeconds > 0 && ttl > tgt.MaxTTLSeconds {
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
	case "update":
		if in.Action != "approve" || in.TTLSeconds != 0 || in.StandingHours != 0 || in.Nickname != "" {
			return a, errBad("expected update approval")
		}
		return s.updateAction(id)
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
		h, err := q.GetHost(ctx, r.HostID)
		if err != nil || h.RevokedAt != nil {
			return a, errConflict("the requesting host's identity was revoked")
		}
		if r.Kind == api.KindCloudflare {
			return s.buildCFRequestAction(a, r, in, s.cfg.TTL.ForHost(h.Class).MaxStandingHours)
		}
		a.TargetAddress, a.TargetPort = r.TargetAddress, r.TargetPort
		a.Address, a.Principal = r.PeerAddress, r.Principal
		a.RequestingHost, a.Kind, a.Target, a.LoginUser, a.KeyFingerprint = r.HostName, r.Kind, r.TargetHost, r.LoginUser, r.KeyFingerprint
		if in.Action == canon.ActionApprove {
			ttl, err := policy.ApproverTTL(r.TTLRequested, in.TTLSeconds, s.cfg.TTL)
			if err != nil {
				return a, errBad(err.Error())
			}
			if err := policy.StandingHours(in.StandingHours, s.cfg.TTL.ForHost(h.Class)); err != nil {
				return a, errBad(err.Error())
			}
			if in.StandingHours > 0 && s.highRisk(r) {
				return a, errBad("no standing approvals for high-risk requests (high_risk target, root, or TTL above 4 h)")
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
		a.Class, a.Address = e.Class, e.PeerAddress
		if old, err := q.ActiveHostByName(ctx, e.Hostname); err == nil {
			a.ReplacesID = old.EnrollmentID
			a.Replaces = true // approving revokes the current host of that name
		} else if !errors.Is(err, store.ErrNotFound) {
			return a, err
		}
	case canon.ObjectHost:
		if in.Action != canon.ActionRevoke || in.TTLSeconds != 0 || in.StandingHours != 0 || in.Nickname != "" {
			return a, errBad("hosts can only be revoked")
		}
		e, err := q.GetEnrollment(ctx, id)
		if err != nil {
			return a, mapNotFound(err)
		}
		h, err := q.ActiveHostByName(ctx, e.Hostname)
		if err != nil || h.EnrollmentID != id {
			return a, errConflict("host identity no longer active")
		}
		a.RequestingHost, a.Class, a.Address = h.Name, h.Class, e.PeerAddress
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
		a.Scope, a.ScopeParams, a.Mode = st.Scope, st.ScopeParams, st.Mode // kind "cloudflare"; empty for ssh
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
		a.Scope, a.ScopeParams, a.Mode = g.Scope, g.ScopeParams, g.Mode // kind "cloudflare"; empty for ssh
	case canon.ObjectPasskey:
		if in.TTLSeconds != 0 || in.StandingHours != 0 {
			return a, errBad("passkey actions take no ttl_seconds or standing_hours")
		}
		switch in.Action {
		case canon.ActionAdd:
			if id != "new" {
				return a, errBad(`adding a passkey: POST /api/ui/passkeys/challenge {"action":"add"}`)
			}
			// An optional nickname for the new passkey is part of what the owner signs;
			// register/finish then uses exactly it.
			if strings.TrimSpace(in.Nickname) != "" {
				n, err := normalizeNickname(in.Nickname)
				if err != nil {
					return a, err
				}
				all, err := loadPasskeys(ctx, q)
				if err != nil {
					return a, err
				}
				if nicknameTaken(all, n, 0) {
					return a, errConflict("another passkey already has that name")
				}
				a.NewNickname = n
			}
		case canon.ActionRename, canon.ActionRemove:
			p, all, err := findPasskey(ctx, q, id)
			if err != nil {
				return a, err
			}
			a.Nickname = p.Name
			if in.Action == canon.ActionRemove {
				if in.Nickname != "" {
					return a, errBad("remove takes no nickname")
				}
				if len(all) <= 1 {
					return a, errConflict("refusing to remove the last passkey: add another one first")
				}
				break
			}
			n, err := normalizeNickname(in.Nickname)
			if err != nil {
				return a, err
			}
			if n == p.Name {
				return a, errBad("that is already its name")
			}
			if nicknameTaken(all, n, p.ID) {
				return a, errConflict("another passkey already has that name")
			}
			a.NewNickname = n
		default:
			return a, errBad("action must be add, rename or remove")
		}
	default:
		return a, errBad("unknown object")
	}
	return a, nil
}

// buildCFRequestAction is buildAction for a pending Cloudflare request (docs/API.md 5.4).
func (s *Server) buildCFRequestAction(a canon.Action, r *store.Request, in api.ChallengeRequest, maxStanding int) (canon.Action, error) {
	a.RequestingHost, a.Kind, a.Scope, a.ScopeParams, a.Mode, a.IPCondition = r.HostName, r.Kind, r.Scope, r.ScopeParams, r.Mode, r.IPCondition
	if in.Action != canon.ActionApprove {
		if in.TTLSeconds != 0 || in.StandingHours != 0 {
			return a, errBad("deny takes no ttl_seconds or standing_hours")
		}
		return a, nil
	}
	res, err := s.cfCheckApprovable(r)
	if err != nil {
		return a, err
	}
	ttl, err := policy.ApproverTTL(r.TTLRequested, in.TTLSeconds, s.cfg.TTL)
	if err != nil {
		return a, errBad(err.Error())
	}
	p := s.cfg.TTL
	p.MaxStandingHours = maxStanding
	if err := policy.StandingHours(in.StandingHours, p); err != nil {
		return a, errBad(err.Error())
	}
	if in.StandingHours > 0 && !(res.Scope.StandingAllowed && r.Mode == api.CFModeProxy) {
		return a, errBad("no standing approvals for this scope or for child tokens")
	}
	a.TTLSeconds, a.StandingHours = ttl, in.StandingHours
	return a, nil
}

// applyCFApprove approves a Cloudflare request inside apply's transaction, re-checking the
// signed values against the current config and policy.
func (s *Server) applyCFApprove(ctx context.Context, q *store.Q, r *store.Request, a canon.Action, detail string, now time.Time, maxStanding int) error {
	res, err := s.cfCheckApprovable(r)
	if err != nil {
		return err
	}
	if a.TTLSeconds <= 0 || a.TTLSeconds > r.TTLRequested || a.TTLSeconds > res.Scope.MaxTTL || a.TTLSeconds > s.cfg.TTL.MaxSeconds {
		return errConflict("signed ttl outside policy")
	}
	if a.StandingHours > 0 && (a.StandingHours > maxStanding || !res.Scope.StandingAllowed || r.Mode != api.CFModeProxy) {
		return errConflict("signed standing_hours outside policy")
	}
	if err := q.DecideRequest(ctx, r.ID, api.StatusApproved, "approved by owner", now); err != nil {
		return decideErr(err)
	}
	g, err := s.issueCFGrant(ctx, q, r, a.TTLSeconds, now)
	if err != nil {
		return err
	}
	what := cfDesc(r.Scope, r.ScopeParams)
	if err := q.Audit(ctx, now, "owner", "approve", "request:"+r.ID,
		fmt.Sprintf("grant=%s cloudflare %s mode=%s for %s ttl=%d ip=%s src=%s %s", g.ID, what, r.Mode, r.HostName, a.TTLSeconds, r.IPCondition, r.PeerAddress, detail)); err != nil {
		return err
	}
	if a.StandingHours == 0 {
		return nil
	}
	st := &store.Standing{
		ID: ids.New(), HostID: r.HostID, HostName: r.HostName, Kind: r.Kind, MaxTTL: a.TTLSeconds, CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(a.StandingHours) * time.Hour), SourceRequestID: r.ID, PeerAddress: r.PeerAddress,
		Scope: r.Scope, ScopeParams: r.ScopeParams, Mode: r.Mode,
	}
	if err := q.InsertStanding(ctx, st); err != nil {
		return err
	}
	return q.Audit(ctx, now, "owner", "standing_create", "standing:"+st.ID,
		fmt.Sprintf("host=%s cloudflare %s mode=%s max_ttl=%d hours=%d %s", r.HostName, what, r.Mode, a.TTLSeconds, a.StandingHours, detail))
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
	return s.store.Tx(ctx, func(q *store.Q) error {
		// Which passkey signed (resolved before a remove deletes it) and the nonce prefix.
		detail := fmt.Sprintf("signed by %s nonce=%s", s.passkeyRef(ctx, q, passkeyID), sg.Nonce[:8])
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
			if r.Kind == api.KindSSH && (r.PeerAddress != a.Address || r.Principal != a.Principal) {
				return errConflict("SSH request changed")
			}
			if r.TargetAddress != a.TargetAddress || r.TargetPort != a.TargetPort || r.HostName != a.RequestingHost || r.Kind != a.Kind || r.TargetHost != a.Target ||
				r.LoginUser != a.LoginUser || r.KeyFingerprint != a.KeyFingerprint ||
				r.Scope != a.Scope || r.ScopeParams != a.ScopeParams || r.Mode != a.Mode || r.IPCondition != a.IPCondition {
				return errConflict("request changed since the challenge was issued")
			}
			h, err := q.GetHost(ctx, r.HostID)
			if err != nil || h.RevokedAt != nil {
				return errConflict("the requesting host's identity was revoked")
			}
			if a.Action == canon.ActionDeny {
				if err := q.DecideRequest(ctx, r.ID, api.StatusDenied, "denied by owner", now); err != nil {
					return decideErr(err)
				}
				if r.Kind == api.KindCloudflare {
					return q.Audit(ctx, now, "owner", "deny", "request:"+r.ID,
						fmt.Sprintf("cloudflare %s mode=%s for %s %s", cfDesc(r.Scope, r.ScopeParams), r.Mode, r.HostName, detail))
				}
				return q.Audit(ctx, now, "owner", "deny", "request:"+r.ID, detail)
			}
			p := s.cfg.TTL.ForHost(h.Class)
			if r.Kind == api.KindCloudflare {
				return s.applyCFApprove(ctx, q, r, a, detail, now, p.MaxStandingHours)
			}
			if a.TTLSeconds <= 0 || a.TTLSeconds > r.TTLRequested || a.TTLSeconds > p.MaxSeconds {
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
				if a.StandingHours > p.MaxStandingHours || s.highRisk(r) {
					return errConflict("signed standing_hours outside policy")
				}
				st := &store.Standing{
					ID: ids.New(), HostID: r.HostID, HostName: r.HostName, Kind: r.Kind, TargetHost: r.TargetHost,
					LoginUser: r.LoginUser, MaxTTL: a.TTLSeconds, CreatedAt: now,
					ExpiresAt: now.Add(time.Duration(a.StandingHours) * time.Hour), SourceRequestID: r.ID,
					PeerAddress: r.PeerAddress,
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
			if e.Class != a.Class || e.PeerAddress != a.Address || e.Hostname != a.RequestingHost || e.KeyFingerprint != a.KeyFingerprint {
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
			if (old != nil) != a.Replaces || old != nil && old.EnrollmentID != a.ReplacesID {
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
			return q.Audit(ctx, now, "owner", "enroll_approve", "enrollment:"+e.ID, "hostname="+e.Hostname+" class="+e.Class+" key="+e.KeyFingerprint+replaced+" "+detail)
		case canon.ObjectHost:
			h, err := q.ActiveHostByName(ctx, a.RequestingHost)
			if err != nil || h.EnrollmentID != a.ID || h.Class != a.Class {
				return errConflict("host identity changed")
			}
			e, err := q.GetEnrollment(ctx, h.EnrollmentID)
			if err != nil {
				return err
			}
			if e.PeerAddress != a.Address {
				return errConflict("host address changed")
			}
			if err := q.RevokeHost(ctx, h.ID, now); err != nil {
				return decideErr(err)
			}
			return q.Audit(ctx, now, "owner", "host_revoke", "host:"+h.Name, "enrollment="+a.ID+" "+detail)

		case canon.ObjectStanding:
			st, err := q.GetStanding(ctx, a.ID)
			if err != nil {
				return mapNotFound(err)
			}
			if st.HostName != a.RequestingHost || st.Kind != a.Kind || st.TargetHost != a.Target || st.LoginUser != a.LoginUser ||
				st.Scope != a.Scope || st.ScopeParams != a.ScopeParams || st.Mode != a.Mode {
				return errConflict("standing approval changed since the challenge was issued")
			}
			if err := q.RevokeStanding(ctx, a.ID, now); err != nil {
				return decideErr(err)
			}
			if st.Kind == api.KindCloudflare {
				return q.Audit(ctx, now, "owner", "standing_revoke", "standing:"+a.ID,
					fmt.Sprintf("host=%s cloudflare %s mode=%s %s", st.HostName, cfDesc(st.Scope, st.ScopeParams), st.Mode, detail))
			}
			return q.Audit(ctx, now, "owner", "standing_revoke", "standing:"+a.ID, detail)

		case canon.ObjectGrant:
			g, err := q.GetGrant(ctx, a.ID)
			if err != nil {
				return mapNotFound(err)
			}
			if g.HostName != a.RequestingHost || g.Kind != a.Kind || g.TargetHost != a.Target || g.LoginUser != a.LoginUser ||
				g.Scope != a.Scope || g.ScopeParams != a.ScopeParams || g.Mode != a.Mode {
				return errConflict("grant changed since the challenge was issued")
			}
			if err := q.RevokeGrant(ctx, a.ID, now); err != nil {
				return decideErr(err)
			}
			if err := q.MarkRequestRevoked(ctx, g.RequestID); err != nil {
				return err
			}
			// "Stop this" also stops the standing approval created with this grant, and the one
			// that auto-approved it, if any: otherwise the agent's next request would be approved
			// again at once. Both only reduce access, so they need no separate signature.
			if n, err := q.RevokeStandingFromRequest(ctx, g.RequestID, now); err != nil {
				return err
			} else if n > 0 {
				detail += fmt.Sprintf(" standing_revoked=%d", n)
			}
			if rq, err := q.GetRequest(ctx, g.RequestID); err != nil {
				return err
			} else if rq.StandingID != "" {
				if err := q.RevokeStanding(ctx, rq.StandingID, now); err == nil {
					detail += " standing_revoked=" + rq.StandingID
				} else if !errors.Is(err, store.ErrConflict) {
					return err
				}
			}
			if g.Kind == api.KindCloudflare {
				what := "proxy access ends now"
				if g.Mode == api.CFModeToken {
					what = "child token deleted upstream"
				}
				return q.Audit(ctx, now, "owner", "grant_revoke", "grant:"+a.ID, "cloudflare "+cfDesc(g.Scope, g.ScopeParams)+" — "+what+" "+detail)
			}
			return q.Audit(ctx, now, "owner", "grant_revoke", "grant:"+a.ID, "certificate stays valid until "+g.NotAfter.Format(time.RFC3339)+" "+detail)

		case canon.ObjectPasskey:
			// Adding is applied by register/begin, never here.
			if a.Action != canon.ActionRename && a.Action != canon.ActionRemove {
				return errBad("unsupported passkey action")
			}
			p, all, err := findPasskey(ctx, q, a.ID)
			if err != nil {
				return err
			}
			// The passkey must still be the one that was signed, by the nickname shown.
			if p.Name != a.Nickname {
				return errConflict("the passkey was renamed since the challenge was issued; start again")
			}
			if a.Action == canon.ActionRename {
				n, err := normalizeNickname(a.NewNickname)
				if err != nil || n != a.NewNickname {
					return errConflict("signed nickname is not valid")
				}
				if nicknameTaken(all, n, p.ID) {
					return errConflict("another passkey already has that name")
				}
				if err := q.RenamePasskey(ctx, p.ID, p.Name, n); err != nil {
					return decideErr(err)
				}
				return q.Audit(ctx, now, "owner", "passkey_rename", "passkey:"+p.id, fmt.Sprintf("from %q to %q %s", p.Name, n, detail))
			}
			// Never remove the last passkey: the owner could no longer sign in, and only the
			// enroll code on the bastion could recover (enforced here, inside the transaction).
			if len(all) <= 1 {
				return errConflict("refusing to remove the last passkey: add another one first")
			}
			ended, err := q.DeletePasskey(ctx, p.ID)
			if err != nil {
				return mapNotFound(err)
			}
			u, au := aaguid.Lookup(p.cred.Authenticator.AAGUID)
			return q.Audit(ctx, now, "owner", "passkey_remove", "passkey:"+p.id,
				fmt.Sprintf("nickname=%q authenticator=%q aaguid=%s sessions_ended=%d %s", p.Name, au.Name, u, ended, detail))
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
