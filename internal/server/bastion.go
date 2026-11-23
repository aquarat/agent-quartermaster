package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/notify"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/sshcert"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Access to the bastion itself (docs/BASTION-ACCESS.md). A bastion session is a request of
// its own kind. Nothing in this file is reachable from the standing-rule, policy-auto, batch
// or window paths: those build and apply organisation-bound "ssh" and "cloudflare" decisions
// only, and the bastion kind has no organisation binding and no standing field.

const (
	// bastionCollect is how long after approval a root certificate may be collected.
	bastionCollect = 5 * time.Minute
	// bastionInspectDefault is the TTL of an inspect request that names none.
	bastionInspectDefault = 3600
	bastionRootDefault    = 1800
	profileInspect        = "source-address;force-command"
	profileRoot           = "source-address;permit-pty"
	alertSent             = "sent"
	alertFailed           = "failed"
	alertOff              = "off"
	// inspectCommand is the forced command of the inspect account, in sshd's configuration
	// and in every inspect certificate.
	inspectCommand = "/usr/local/bin/aqmasd inspect"
)

func (s *Server) bastionCfg() (config.Bastion, error) {
	if !s.bastionOn || !s.cfg.Bastion.Enabled() {
		return config.Bastion{}, errNotFound()
	}
	return s.cfg.Bastion, nil
}

// bastionLevel derives the level of a stored request from its login user. A request whose
// user is neither account (the configuration changed) has no level and cannot be decided.
func bastionLevel(b config.Bastion, loginUser string) string {
	switch loginUser {
	case config.InspectUser:
		return api.LevelInspect
	case b.AdminUser:
		return api.LevelRoot
	}
	return ""
}

// bastionMax is the longest certificate of a level for a host of this class.
func (s *Server) bastionMax(level, class string) int {
	if level == api.LevelRoot {
		return canon.BastionRootMaxSeconds
	}
	return s.cfg.TTL.ForHost(class).MaxSeconds
}

// openBuckets lists the labels of the buckets that something keeps open: a grant, a
// standing rule, a window. A bucket held only by an approval that is being applied this
// instant is not "open": it closes when that approval settles.
func (s *Server) openBuckets(ctx context.Context, q *store.Q) []string {
	out := []string{}
	if !s.sealServing() {
		return out
	}
	for id, v := range s.seal.pool.snapshot() {
		if !slices.ContainsFunc(v.Holds, func(h bucketHold) bool { return h.Kind != "instant" }) {
			continue
		}
		label := fmt.Sprintf("(unlisted bucket %x)", id[:6])
		if row, err := q.Bucket(ctx, id[:]); err == nil && row.Label != "" {
			label = row.Label
		}
		out = append(out, label)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func hostKeyFingerprint(line string) string {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pk)
}

// ---- agent API ----

func (s *Server) bastionAgentRoutes(mux *http.ServeMux) {
	mux.Handle("GET /v1/bastion", s.requirePersonal(s.handleBastionInfo))
	mux.Handle("POST /v1/bastion/requests", s.requirePersonal(s.handleBastionCreate))
	mux.Handle("GET /v1/bastion/requests/{id}", s.requirePersonal(s.handleBastionStatus))
	mux.Handle("POST /v1/bastion/requests/{id}/cancel", s.requirePersonal(s.handleBastionCancel))
	mux.Handle("POST /v1/setup-requests", s.requirePersonal(s.handleSetupRequestCreate))
	mux.Handle("GET /v1/setup-requests/{id}", s.requirePersonal(s.handleSetupRequestStatus))
	mux.Handle("POST /v1/setup-requests/{id}/cancel", s.requirePersonal(s.handleSetupRequestCancel))
}

func (s *Server) handleBastionInfo(w http.ResponseWriter, r *http.Request, h *store.Host) {
	b, err := s.bastionCfg()
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	allowed := s.bastionAllowed(h.EnrollmentID, peerIP(r))
	writeJSON(w, http.StatusOK, api.BastionInfo{Name: b.Name, Address: b.Address, Port: b.Port, InspectUser: config.InspectUser, AdminUser: b.AdminUser,
		RootAllowed: allowed, InspectMaxSeconds: s.bastionMax(api.LevelInspect, h.Class), InspectDefault: min(bastionInspectDefault, s.bastionMax(api.LevelInspect, h.Class)),
		RootMaxSeconds: canon.BastionRootMaxSeconds, Tasks: maint.AgentTasks})
}

// validReason: a bastion request always says why.
func validReason(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errBad("a reason is required (--why)")
	}
	if len(reason) > MaxReasonLen || !utf8.ValidString(reason) || hasControl(reason, true) {
		return errBad("reason must be at most 500 bytes of text")
	}
	return nil
}

func (s *Server) handleBastionCreate(w http.ResponseWriter, r *http.Request, h *store.Host) {
	b, err := s.bastionCfg()
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var in api.BastionRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if in.Level != api.LevelInspect && in.Level != api.LevelRoot {
		s.writeErr(w, r, errBad(`level must be "inspect" or "root"`))
		return
	}
	if err := validReason(in.Reason); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := validRequester(in.Requester); err != nil {
		s.writeErr(w, r, err)
		return
	}
	pub, err := sshcert.ParseEd25519(in.PublicKey)
	if err != nil {
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	// The agent's wish is clamped into the level's range; the owner can only shorten it.
	ttl, top := in.TTLSeconds, s.bastionMax(in.Level, h.Class)
	if ttl < 0 {
		s.writeErr(w, r, errBad("ttl_seconds must not be negative"))
		return
	}
	if ttl == 0 {
		ttl = bastionInspectDefault
		if in.Level == api.LevelRoot {
			ttl = bastionRootDefault
		}
	}
	ttl = max(min(ttl, top), s.cfg.TTL.MinSeconds)
	now := s.now()
	req := &store.Request{
		ID: ids.New(), HostID: h.ID, HostName: h.Name, PeerAddress: peerIP(r), Kind: api.KindBastion,
		RequestedTarget: b.Name, TargetHost: b.Name, TargetAddress: b.Address, TargetPort: b.Port,
		LoginUser: b.User(in.Level), Principal: b.Principal(in.Level),
		PublicKey: string(ssh.MarshalAuthorizedKey(pub)), KeyFingerprint: ssh.FingerprintSHA256(pub),
		Reason: in.Reason, Requester: in.Requester, TTLRequested: ttl, Status: api.StatusPending,
		CreatedAt: now, ExpiresAt: now.Add(secs(s.cfg.TTL.PendingExpirySeconds)),
	}
	if _, err := sshcert.SourceAddress(req.PeerAddress); err != nil {
		s.writeErr(w, r, errBad("cannot determine peer address"))
		return
	}
	ctx := r.Context()
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
			return err
		}
		if in.Level == api.LevelRoot {
			// Refused before anything is queued or pushed: a host the owner did not allow
			// cannot even put a root card in front of the owner.
			if !s.bastionAllowed(h.EnrollmentID, req.PeerAddress) {
				return errForbidden("this host (at this address) is not allowed to ask for root on the bastion; the owner sets that under Admin → Bastion access")
			}
		}
		if err := s.pendingRoom(ctx, q, h.ID, now); err != nil {
			return err
		}
		// Not InsertPersonalRequest: a bastion request has no catalogue binding.
		if err := q.InsertRequest(ctx, req); err != nil {
			return err
		}
		return q.Audit(ctx, now, "host:"+h.Name, "request", "request:"+req.ID,
			fmt.Sprintf("bastion %s %s ttl=%d key=%s from=%s", in.Level, req.Principal, ttl, req.KeyFingerprint, req.PeerAddress))
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	url := s.approveURL(req.ID)
	text := fmt.Sprintf("aqmas: %s wants to read logs on the bastion (inspect)", h.Name)
	if in.Level == api.LevelRoot {
		text = fmt.Sprintf("aqmas: %s asks for ROOT ON THE BASTION", h.Name)
	}
	s.notify.Send("aqmas: "+h.Name, text, url)
	writeJSON(w, http.StatusCreated, api.RequestCreated{ID: req.ID, Status: req.Status, ApproveURL: url, PollAfterMS: PollAfterMS, ExpiresAt: req.ExpiresAt})
}

// pendingRoom applies the shared per-host limit on undecided work, maintenance requests
// included.
func (s *Server) pendingRoom(ctx context.Context, q *store.Q, host int64, now time.Time) error {
	n, err := s.allPending(ctx, q, host, now)
	if err != nil {
		return err
	}
	m, err := q.CountPendingSetup(ctx, host, now)
	if err != nil {
		return err
	}
	if n+m >= MaxPendingPerHost {
		return &apiErr{http.StatusTooManyRequests, api.ErrRateLimited, "too many pending requests from this host"}
	}
	return nil
}

// bastionRequest loads a bastion request of this host; anything else is "not found".
func bastionRequest(ctx context.Context, q *store.Q, id string, host int64) (*store.Request, error) {
	req, err := q.GetRequest(ctx, id)
	if err != nil || req.HostID != host || req.Kind != api.KindBastion {
		return nil, errNotFound()
	}
	return req, nil
}

func (s *Server) handleBastionStatus(w http.ResponseWriter, r *http.Request, h *store.Host) {
	if _, err := s.bastionCfg(); err != nil {
		s.writeErr(w, r, err)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	var req *store.Request
	// A root request stays "pending" for the requester until its alert was attempted:
	// the certificate is not available before, so neither is the news of the approval.
	err := s.longPoll(ctx, parseWait(r.URL.Query().Get("wait")), func() (bool, error) {
		var err error
		q := s.store.Q()
		if req, err = bastionRequest(ctx, q, id, h.ID); err != nil {
			return false, err
		}
		if req.Status == api.StatusPending && !s.now().Before(req.ExpiresAt) {
			req.Status = api.StatusExpired
		}
		if req.Status == api.StatusApproved {
			g, err := q.GrantByRequest(ctx, req.ID)
			if err != nil {
				return false, err
			}
			bg, err := q.GetBastionGrant(ctx, g.ID)
			if err != nil {
				return false, err
			}
			if bg.Level == api.LevelRoot && bg.Alert == "" && s.now().Before(bg.ApprovedAt.Add(bastionCollect)) {
				req.Status = api.StatusPending
			}
		}
		return req.Status != api.StatusPending, nil
	})
	if err != nil {
		s.writeErr(w, r, mapNotFound(err))
		return
	}
	if ctx.Err() != nil {
		return
	}
	out := &api.RequestStatus{ID: req.ID, Kind: req.Kind, Status: req.Status, DecidedAt: req.DecidedAt, DecisionNote: req.DecisionNote}
	if req.Status == api.StatusPending {
		out.DecidedAt, out.DecisionNote = nil, ""
	}
	if req.Status == api.StatusApproved {
		if err := s.bastionDeliver(ctx, r, req, out); err != nil {
			s.writeErr(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// bastionDeliver attaches the grant to an approved request's status. An inspect certificate
// is public material and is returned on every poll, like an SSH grant. A root certificate is
// returned once: after the alert attempt was recorded, within bastionCollect of the approval,
// to the address it is bound to, and after closing every bucket again when the owner chose so.
func (s *Server) bastionDeliver(ctx context.Context, r *http.Request, req *store.Request, out *api.RequestStatus) error {
	b, err := s.bastionCfg()
	if err != nil {
		return err
	}
	q := s.store.Q()
	g, err := q.GrantByRequest(ctx, req.ID)
	if err != nil {
		return err
	}
	bg, err := q.GetBastionGrant(ctx, g.ID)
	if err != nil {
		return err
	}
	if g.TargetHost != b.Name || req.TargetAddress != b.Address || req.TargetPort != b.Port || bastionLevel(b, g.LoginUser) != bg.Level {
		return errConflict("bastion configuration changed; request again")
	}
	now := s.now()
	grant := &api.Grant{ID: g.ID, Kind: g.Kind, NotBefore: g.NotBefore, NotAfter: g.NotAfter, SSH: &api.SSHGrant{
		Principals: g.Principals, TargetHost: b.Name, TargetAddress: b.Address, TargetPort: b.Port, LoginUser: g.LoginUser,
		KnownHostsLine: sshcert.KnownHostsLine(b.Name, b.Address, b.Port, b.HostKey)}}
	out.Grant = grant
	if bg.Level != api.LevelRoot {
		grant.SSH.Certificate = g.Certificate
		return nil
	}
	if bg.DeliveredAt != nil {
		out.DecisionNote = "the certificate was already collected: a root certificate is handed out once"
		return nil
	}
	if bg.Alert == "" || !now.Before(bg.ApprovedAt.Add(bastionCollect)) {
		// Never alerted (the broker stopped between approval and alert) or never collected.
		return s.voidBastionGrant(ctx, req, g, out, "not collected in time")
	}
	if peerIP(r) != req.PeerAddress {
		return errConflict("collect the certificate from the address that asked for it")
	}
	if bg.CloseBuckets && s.sealServing() && !s.closeAllDrained() {
		// Again at the moment of delivery: whatever was opened since the approval closes,
		// and a key that an operation is still using is waited for. The requester retries.
		return &apiErr{http.StatusServiceUnavailable, api.ErrConflict, "a credential is still in use on the bastion; retrying"}
	}
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.MarkBastionDelivered(ctx, g.ID, now, now.Add(-bastionCollect)); err != nil {
			return err
		}
		return q.Audit(ctx, now, "host:"+req.HostName, "bastion_cert_delivered", "grant:"+g.ID,
			fmt.Sprintf("root %s to=%s key=%s until=%s", g.Principals, req.PeerAddress, req.KeyFingerprint, g.NotAfter.UTC().Format(time.RFC3339)))
	})
	if errors.Is(err, store.ErrConflict) {
		// Lost a race with another poll, or the grant was revoked meanwhile.
		out.DecisionNote = "the certificate is no longer available"
		return nil
	}
	if err != nil {
		return err
	}
	grant.SSH.Certificate = g.Certificate
	s.bcast.notify()
	return nil
}

// voidBastionGrant revokes a root grant whose certificate was never handed out.
func (s *Server) voidBastionGrant(ctx context.Context, req *store.Request, g *store.Grant, out *api.RequestStatus, why string) error {
	now := s.now()
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.RevokeGrant(ctx, g.ID, now); err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
		if err := q.MarkRequestRevoked(ctx, req.ID); err != nil {
			return err
		}
		return q.Audit(ctx, now, "system", "grant_revoke", "grant:"+g.ID, "bastion root certificate never delivered: "+why)
	})
	if err != nil {
		return err
	}
	out.Status, out.Grant, out.DecisionNote = api.StatusRevoked, nil, "root certificate "+why
	s.bcast.notify()
	return nil
}

func (s *Server) handleBastionCancel(w http.ResponseWriter, r *http.Request, h *store.Host) {
	id := r.PathValue("id")
	ctx := r.Context()
	now := s.now()
	var req *store.Request
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if _, err := q.ExpireStale(ctx, now); err != nil {
			return err
		}
		var err error
		if req, err = bastionRequest(ctx, q, id, h.ID); err != nil {
			return err
		}
		if err := q.CancelRequest(ctx, id, h.ID, now); err != nil {
			return statusErr(req.Status)
		}
		if req, err = q.GetRequest(ctx, id); err != nil {
			return err
		}
		return q.Audit(ctx, now, "host:"+h.Name, "request_cancel", "request:"+id, "")
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	writeJSON(w, http.StatusOK, api.RequestStatus{ID: req.ID, Kind: req.Kind, Status: req.Status, DecidedAt: req.DecidedAt, DecisionNote: req.DecisionNote})
}

// ---- the decision ----

// bastionAction builds the action the owner signs for a bastion request from the stored
// request, the root-owned configuration, the allowlist and what is open right now. The only
// things taken from the approver are the action, a shorter TTL and the close choice.
func (s *Server) bastionAction(ctx context.Context, q *store.Q, r *store.Request, h *store.Host, in api.ChallengeRequest) (canon.Action, error) {
	a := canon.Action{Action: in.Action, Object: canon.ObjectRequest, ID: r.ID, Kind: api.KindBastion}
	b, err := s.bastionCfg()
	if err != nil {
		return a, errConflict("access to the bastion is not installed")
	}
	level := bastionLevel(b, r.LoginUser)
	if level == "" || r.TargetHost != b.Name || r.TargetAddress != b.Address || r.TargetPort != b.Port || r.Principal != b.Principal(level) {
		return a, errConflict("the bastion's configuration changed since this was requested; ask again")
	}
	if in.StandingHours != 0 || in.StandingSeconds != 0 || in.Indefinite || in.StandingIndefinite || in.Nickname != "" || in.Plan != "" {
		return a, errBad("a bastion session takes no standing or indefinite choice: every one needs its own approval")
	}
	a.Level, a.RequestingHost, a.HostID, a.Address = level, r.HostName, h.EnrollmentID, r.PeerAddress
	a.Target, a.TargetAddress, a.TargetPort, a.LoginUser, a.Principal, a.KeyFingerprint = b.Name, b.Address, b.Port, r.LoginUser, r.Principal, r.KeyFingerprint
	a.SSHCA, a.HostKey, a.CertProfile = s.sshPin(), hostKeyFingerprint(b.HostKey), profileInspect
	if a.HostKey == "" {
		return a, errConflict("the bastion's host key is not configured")
	}
	a.Sealed, a.OpenBuckets = s.seal != nil, canon.OpenList(nil)
	if level == api.LevelRoot {
		a.CertProfile = profileRoot
	}
	if in.Action == canon.ActionDeny {
		if in.TTLSeconds != 0 || in.CloseBuckets != nil {
			return a, errBad("deny takes no ttl_seconds or close_buckets")
		}
		return a, nil
	}
	if in.Action != canon.ActionApprove {
		return a, errBad("action must be approve or deny")
	}
	ttl := in.TTLSeconds
	if ttl == 0 {
		ttl = r.TTLRequested
	}
	// Shorter than asked is the owner's choice; longer, or beyond the level's cap, is refused
	// rather than clamped, so what is signed is always what was chosen.
	if ttl < s.cfg.TTL.MinSeconds || ttl > r.TTLRequested || ttl > s.bastionMax(level, h.Class) {
		return a, errBad("ttl_seconds is outside what this bastion session allows")
	}
	a.TTLSeconds = ttl
	if level != api.LevelRoot {
		if in.CloseBuckets != nil {
			return a, errBad("close_buckets belongs to a root session")
		}
		return a, nil
	}
	if !s.bastionAllowed(h.EnrollmentID, r.PeerAddress) {
		return a, errConflict("this host is not on the bastion allowlist")
	}
	a.AlertChannel = s.notify.Configured()
	if !a.Sealed {
		if in.CloseBuckets != nil && *in.CloseBuckets {
			return a, errBad("the store is not sealed: there are no buckets to close")
		}
		return a, nil
	}
	if in.CloseBuckets == nil {
		return a, errBad("choose whether to close all open buckets first (close_buckets)")
	}
	a.OpenBuckets, a.CloseBuckets = canon.OpenList(s.openBuckets(ctx, q)), *in.CloseBuckets
	return a, nil
}

// applyBastion applies a signed bastion decision inside apply's transaction. Everything the
// card said is rebuilt from current state and must still be what was signed; the open list
// is the one exception, and it may only have shrunk.
func (s *Server) applyBastion(ctx context.Context, q *store.Q, r *store.Request, a canon.Action, detail string, now time.Time) error {
	if r.Kind != api.KindBastion || a.Kind != api.KindBastion || a.StandingHours != 0 || a.StandingSeconds != 0 || a.Indefinite || a.StandingIndefinite || a.OrgID != "" {
		return errConflict("not a bastion decision")
	}
	h, err := q.GetHost(ctx, r.HostID)
	if err != nil || h.RevokedAt != nil {
		return errConflict("the requesting host's identity was revoked")
	}
	choice := api.ChallengeRequest{Action: a.Action, TTLSeconds: a.TTLSeconds}
	if a.Action == canon.ActionApprove && a.Level == api.LevelRoot && a.Sealed {
		choice.CloseBuckets = &a.CloseBuckets
	}
	want, err := s.bastionAction(ctx, q, r, h, choice)
	if err != nil {
		return errConflict("this bastion decision can no longer be applied: " + err.Error())
	}
	signedOpen, err := canon.ParseOpenList(a.OpenBuckets)
	if err != nil {
		return errConflict("invalid open-bucket list")
	}
	openNow, _ := canon.ParseOpenList(want.OpenBuckets)
	want.OpenBuckets = a.OpenBuckets
	if want != a {
		return errConflict("the request, the allowlist or the bastion's configuration changed since the card was shown; review again")
	}
	if a.Action == canon.ActionDeny {
		if err := q.DecideRequest(ctx, r.ID, api.StatusDenied, "denied by owner", now); err != nil {
			return decideErr(err)
		}
		return q.Audit(ctx, now, "owner", "deny", "request:"+r.ID, fmt.Sprintf("bastion %s for %s %s", a.Level, r.HostName, detail))
	}
	if err := q.DecideRequest(ctx, r.ID, api.StatusApproved, "approved by owner", now); err != nil {
		return decideErr(err)
	}
	g, err := s.issueBastionGrant(ctx, q, r, a, now)
	if err != nil {
		return err
	}
	bg := &store.BastionGrant{GrantID: g.ID, Level: a.Level, CloseBuckets: a.CloseBuckets, ApprovedAt: now, Alert: alertOff}
	if a.Level != api.LevelRoot {
		if err := q.Audit(ctx, now, "owner", "approve", "request:"+r.ID,
			fmt.Sprintf("grant=%s bastion inspect %s for %s enrollment=%s ttl=%d key=%s src=%s %s", g.ID, r.Principal, r.HostName, a.HostID, a.TTLSeconds, r.KeyFingerprint, r.PeerAddress, detail)); err != nil {
			return err
		}
		return q.InsertBastionGrant(ctx, bg)
	}
	bg.Alert = "" // recorded after the commit, before the certificate can be collected
	if a.CloseBuckets {
		// The certificate is signed (the CA was open for this tap); now nothing stays open.
		// If anything below fails the transaction rolls back and no certificate exists, with
		// the buckets closed all the same.
		bg.Closed = len(openNow)
		if !s.closeAllDrained() {
			return errConflict("a credential is in use this instant and could not be closed; approve again in a moment")
		}
		if left := s.openBuckets(ctx, q); len(left) != 0 {
			return errConflict("buckets could not be closed: " + strings.Join(left, ", "))
		}
	} else {
		for _, label := range s.openBuckets(ctx, q) {
			if !slices.Contains(signedOpen, label) {
				return errConflict("“" + label + "” was opened after this card was shown; review the card again")
			}
		}
	}
	// The audit row and the grant commit together or not at all.
	if err := q.Audit(ctx, now, "owner", "bastion_root", "request:"+r.ID,
		fmt.Sprintf("grant=%s ROOT %s for %s enrollment=%s ttl=%d key=%s src=%s sealed=%t open=%s close=%t closed=%d %s",
			g.ID, r.Principal, r.HostName, a.HostID, a.TTLSeconds, r.KeyFingerprint, r.PeerAddress, a.Sealed, a.OpenBuckets, a.CloseBuckets, bg.Closed, detail)); err != nil {
		return err
	}
	return q.InsertBastionGrant(ctx, bg)
}

// issueBastionGrant signs the certificate of a bastion session: source-address always,
// permit-pty for root only, never port forwarding.
func (s *Server) issueBastionGrant(ctx context.Context, q *store.Q, r *store.Request, a canon.Action, now time.Time) (*store.Grant, error) {
	pub, err := sshcert.ParseEd25519(r.PublicKey)
	if err != nil {
		return nil, errConflict("stored public key invalid")
	}
	if ssh.FingerprintSHA256(pub) != a.KeyFingerprint {
		return nil, errConflict("stored public key changed")
	}
	nb, na := sshcert.Validity(now, secs(a.TTLSeconds))
	g := &store.Grant{ID: ids.New(), RequestID: r.ID, HostID: r.HostID, HostName: r.HostName, Kind: api.KindBastion, TargetHost: a.Target,
		LoginUser: a.LoginUser, Principals: []string{a.Principal}, NotBefore: nb, NotAfter: na, PeerAddress: r.PeerAddress}
	serial, err := q.InsertGrant(ctx, g)
	if err != nil {
		return nil, err
	}
	g.Serial = serial
	// Inspect: no extension at all, and the forced command is in the certificate itself, so
	// the account stays confined even if the sshd drop-in that also forces it were lost.
	ext, critical := map[string]string{}, map[string]string{"force-command": inspectCommand}
	if a.Level == api.LevelRoot {
		ext, critical = map[string]string{"permit-pty": ""}, nil
	}
	var cert *ssh.Certificate
	err = s.withCA(ctx, q, seal.RoleSSHCA, func(p *pki.PKI) error {
		var err error
		cert, err = sshcert.Sign(p.SSHSigner, sshcert.Params{Serial: uint64(serial), KeyID: fmt.Sprintf("aqmas:%s:%s:bastion-%s", g.ID, r.HostName, a.Level),
			Principals: g.Principals, SourceAddress: r.PeerAddress, ApprovedAt: now, TTL: secs(a.TTLSeconds), PublicKey: pub, Extensions: ext, Critical: critical})
		return err
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

// afterBastionDecision runs after the decision committed. For an approved root session it
// sends the alert synchronously and records the outcome: until that record exists the
// requester cannot collect the certificate.
func (s *Server) afterBastionDecision(ctx context.Context, sg canon.Signed) (api.BastionDecision, error) {
	// The decision is committed. Nothing from here on may depend on the owner's browser
	// still being connected: neither the alert nor its record.
	ctx = context.WithoutCancel(ctx)
	a := sg.Action
	out := api.BastionDecision{ID: a.ID, Kind: api.KindBastion, Level: a.Level, Status: api.StatusDenied}
	q := s.store.Q()
	if a.Action != canon.ActionApprove {
		s.notify.Send("aqmas: decision", fmt.Sprintf("aqmas: deny bastion %s for %s [ref %s]", a.Level, a.RequestingHost, ref(a.ID)), s.cfg.PublicBaseURL+"/")
		return out, nil
	}
	out.Status = api.StatusApproved
	g, err := q.GrantByRequest(ctx, a.ID)
	if err != nil {
		return out, err
	}
	bg, err := q.GetBastionGrant(ctx, g.ID)
	if err != nil {
		return out, err
	}
	out.Closed, out.Alert = bg.Closed, bg.Alert
	if a.Level != api.LevelRoot {
		s.notify.Send("aqmas: decision", fmt.Sprintf("aqmas: approve bastion inspect for %s, ttl %ds [ref %s]", a.RequestingHost, a.TTLSeconds, ref(a.ID)), s.cfg.PublicBaseURL+"/")
		return out, nil
	}
	buckets := "the store is not sealed"
	if a.Sealed {
		buckets = fmt.Sprintf("%d bucket(s) closed first", bg.Closed)
		if !a.CloseBuckets {
			buckets = "open buckets were LEFT OPEN: " + a.OpenBuckets
		}
	}
	text := fmt.Sprintf("ROOT session on the bastion approved for %s (%s), %d min; %s [ref %s]", a.RequestingHost, a.Address, (a.TTLSeconds+59)/60, buckets, ref(a.ID))
	// The owner's browser going away must not skip the alert or its record.
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out.Alert = alertSent
	switch err := s.notify.Deliver(actx, "aqmas: ROOT ON THE BASTION", text, s.cfg.PublicBaseURL+"/"); {
	case errors.Is(err, notify.ErrNoChannel):
		out.Alert = alertOff
	case err != nil:
		out.Alert = alertFailed
	}
	now := s.now()
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.SetBastionAlert(ctx, g.ID, out.Alert, now); err != nil {
			return err
		}
		return q.Audit(ctx, now, "system", "bastion_root_alert", "grant:"+g.ID, "alert "+out.Alert)
	})
	if err != nil {
		// Without the record the certificate is never handed out.
		return out, errConflict("the alert outcome could not be recorded; the certificate will not be issued. Ask again.")
	}
	return out, nil
}

// closeAllDrained closes every bucket, hold, window and pending tap and reports whether every
// key is gone from memory. A key that an operation is using at that instant is wiped when
// the operation ends: it is waited for briefly, and "not drained" means do not issue yet.
func (s *Server) closeAllDrained() bool {
	if !s.sealServing() {
		return true
	}
	s.closeAll()
	for i := 0; i < 20; i++ {
		if s.seal.pool.held() == 0 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return s.seal.pool.held() == 0
}

// ---- allowlist ----

// bastionAllowList reads the allowlist that root keeps (the "bastion-allow" Setup task
// writes it next to the configuration). The broker can read it and cannot change it; sshd
// enforces the same addresses on the admin account's principals line.
func (s *Server) bastionAllowList() []maint.AllowedHost {
	if s.bastionAllowFile == "" {
		return nil
	}
	return maint.ReadAllow(s.bastionAllowFile)
}

// bastionAllowed: the enrollment is listed and the request came from its listed address.
func (s *Server) bastionAllowed(enrollment, address string) bool {
	return slices.ContainsFunc(s.bastionAllowList(), func(h maint.AllowedHost) bool { return h.ID == enrollment && h.Address == address })
}

// ---- web views ----

func (s *Server) bastionItem(ctx context.Context, rq *store.Request) (*api.PendingItem, error) {
	q := s.store.Q()
	it := &api.PendingItem{ID: rq.ID, Kind: rq.Kind, CreatedAt: rq.CreatedAt, ExpiresAt: rq.ExpiresAt, RequestingHost: rq.HostName, RequestingAddress: rq.PeerAddress,
		Requester: rq.Requester, Reason: rq.Reason, TTLRequested: rq.TTLRequested, TTLMax: rq.TTLRequested, Risk: "normal"}
	pb := &api.PendingBastion{Target: rq.TargetHost, TargetAddress: rq.TargetAddress, TargetPort: rq.TargetPort, LoginUser: rq.LoginUser, Principal: rq.Principal,
		KeyFingerprint: rq.KeyFingerprint, SSHCA: s.sshPin(), Sealed: s.seal != nil, OpenBuckets: []string{}, CertProfile: profileInspect}
	it.Bastion = pb
	if h, err := q.GetHost(ctx, rq.HostID); err == nil {
		pb.HostID = h.EnrollmentID
	}
	b, err := s.bastionCfg()
	if err != nil {
		// Shown, so it can be denied or left to expire; it cannot be approved.
		pb.Level = "unknown"
		return it, nil
	}
	pb.Level, pb.HostKey = bastionLevel(b, rq.LoginUser), hostKeyFingerprint(b.HostKey)
	if pb.Level == api.LevelRoot {
		it.Risk, pb.CertProfile, pb.OpenBuckets = "high", profileRoot, s.openBuckets(ctx, q)
		pb.AlertChannel = s.notify.Configured()
	}
	since := s.now().Add(-7 * 24 * time.Hour)
	if it.SimilarRecent, err = q.CountSimilar(ctx, rq.HostID, rq.TargetHost, rq.LoginUser, since); err != nil {
		return nil, err
	}
	return it, nil
}

func (s *Server) bastionWebRoutes(m *http.ServeMux) {
	m.Handle("GET /api/ui/bastion", s.requireSession(s.handleBastionView))
	m.Handle("POST /api/ui/setup-requests/{id}/dismiss", s.requireSession(s.handleSetupRequestDismiss))
}

func (s *Server) handleBastionView(w http.ResponseWriter, r *http.Request, _ string) {
	ctx := r.Context()
	v := api.BastionView{InspectUser: config.InspectUser, SSHCA: s.sshPin(), Sealed: s.seal != nil, Hosts: []api.BastionHost{}, Sessions: []api.BastionSession{},
		Tasks: []string{maint.TaskBastionAccess, maint.TaskBastionAllow, maint.TaskBastionRemove, maint.TaskOSUpdate, maint.TaskReboot, maint.TaskRestartTunnel, maint.TaskRestartBroker, maint.TaskDiskUsage, maint.TaskJournalVacuum}}
	if !s.bastionOn {
		writeJSON(w, http.StatusOK, v)
		return
	}
	if b := s.cfg.Bastion; b.Enabled() {
		v.Enabled, v.Name, v.Address, v.Port, v.AdminUser = true, b.Name, b.Address, b.Port, b.AdminUser
	}
	q := s.store.Q()
	now := s.now()
	hosts, err := q.Hosts(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	allow := s.bastionAllowList()
	for _, h := range hosts {
		if h.RevokedAt != nil || !now.Before(h.NotAfter) {
			continue
		}
		bh := api.BastionHost{ID: h.ID, Name: h.Name, Class: h.Class, Address: h.Address}
		if i := slices.IndexFunc(allow, func(a maint.AllowedHost) bool { return a.ID == h.ID }); i >= 0 {
			bh.Allowed, bh.AllowedAddress = true, allow[i].Address
		}
		v.Hosts = append(v.Hosts, bh)
	}
	// Listed enrollments that are no longer live hosts: shown so they can be removed.
	for _, a := range allow {
		if !slices.ContainsFunc(v.Hosts, func(h api.BastionHost) bool { return h.ID == a.ID }) {
			v.Hosts = append(v.Hosts, api.BastionHost{ID: a.ID, Name: a.Name, Address: a.Address, Allowed: true, AllowedAddress: a.Address, Gone: true})
		}
	}
	v.AlertChannel = s.notify.Configured()
	grants, err := q.BastionSessions(ctx, 20)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for _, g := range grants {
		bg, err := q.GetBastionGrant(ctx, g.ID)
		if err != nil {
			continue
		}
		status := g.Status(now)
		if status == api.StatusApproved {
			status = "active"
		}
		v.Sessions = append(v.Sessions, api.BastionSession{GrantID: g.ID, Level: bg.Level, RequestingHost: g.HostName, LoginUser: g.LoginUser, NotBefore: g.NotBefore, NotAfter: g.NotAfter,
			Status: status, CloseBuckets: bg.CloseBuckets, Closed: bg.Closed, Alert: bg.Alert, DeliveredAt: bg.DeliveredAt})
	}
	if v.RootUntil, err = q.ActiveBastionRoot(ctx, now); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
