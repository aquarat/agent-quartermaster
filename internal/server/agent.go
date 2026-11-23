package server

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/policy"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/sshcert"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

type ctxKey int

const (
	ctxHost ctxKey = iota
	ctxSession
	ctxAccessSub
)

// AgentHandler returns the agent API handler (serve it with PKI().TLSConfig()).
func (s *Server) AgentHandler() http.Handler {
	if s.maintenance || s.sealSetup {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "organisation cutover: fleet access paused", http.StatusServiceUnavailable)
		})
	}
	mux := http.NewServeMux()
	s.envAgentRoutes(mux)
	s.signAgentRoutes(mux)
	mux.Handle("GET /v1/releases/latest", s.requireHost(s.latestRelease))
	mux.Handle("GET /v1/releases/{version}/{asset}", s.requireHost(s.releaseAsset))
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/enroll/{id}", s.handleEnrollStatus)
	create := s.handleCreateRequest
	mux.Handle("POST /v1/requests", s.requirePersonal(create))
	if s.store.Q().Scoped() {
		mux.Handle("POST /v2/personal/requests", s.requirePersonal(create))
	}
	mux.Handle("GET /v1/requests/{id}", s.requirePersonal(s.handleRequestStatus))
	mux.Handle("POST /v1/requests/{id}/cancel", s.requirePersonal(s.handleCancel))
	mux.Handle("GET /v1/grants", s.requirePersonal(s.handleGrants))
	mux.Handle("GET /v1/ssh-ca", s.requirePersonal(s.handleSSHCA))
	mux.Handle("GET /v1/ssh-target", s.requirePersonal(s.handleResolveTarget))
	// Milestone 2 (404 when cloudflare.enabled is false).
	mux.Handle("GET /v1/cf/catalogue", s.requirePersonal(s.handleCFCatalogue))
	mux.Handle("GET /v1/cf/snapshots", s.requirePersonal(s.handleCFSnapshots))
	mux.Handle("GET /v1/cf/snapshots/{id}", s.requirePersonal(s.handleCFSnapshot))
	proxy := s.requireHostCF(s.handleCFProxy)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil {
			s.writeErr(w, r, errForbidden("TLS required"))
			return
		}
		if isCFProxyPath(r) {
			proxy.ServeHTTP(w, r) // any method; the proxy validates path and method itself
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) requirePersonal(next func(http.ResponseWriter, *http.Request, *store.Host)) http.Handler {
	return s.requireHost(func(w http.ResponseWriter, r *http.Request, h *store.Host) {
		if err := s.store.Q().PersonalAdmission(r.Context(), h.ID, s.now()); err != nil {
			s.writeErr(w, r, mapNotFound(err))
			return
		}
		next(w, r, h)
	})
}

// requireHost authenticates the caller by its verified client certificate: issued by the
// internal CA (checked in the TLS handshake), known to the store, not revoked, CN matching.
func (s *Server) requireHost(next func(http.ResponseWriter, *http.Request, *store.Host)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, err := s.hostFromTLS(r)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		next(w, r, h)
	})
}

func (s *Server) hostFromTLS(r *http.Request) (*store.Host, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil, errUnauth("client certificate required")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	// Belt and braces: the handshake already verified against ClientCAs with clientAuth usage.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       s.pki.ClientCAPool(),
		CurrentTime: s.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, errUnauth("client certificate not valid")
	}
	h, err := s.store.Q().HostByCert(r.Context(), pki.CertFingerprint(leaf.Raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, errForbidden("host not enrolled")
	}
	if err != nil {
		return nil, err
	}
	if h.RevokedAt != nil {
		return nil, errForbidden("host enrollment revoked")
	}
	if h.Name != leaf.Subject.CommonName {
		return nil, errForbidden("certificate name mismatch")
	}
	return h, nil
}

// approveURL links to the UI with the item highlighted (fragment: no server routing needed).
func (s *Server) approveURL(id string) string {
	return s.cfg.PublicBaseURL + "/#r=" + id
}

// ---- enrollment ----

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in api.EnrollRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if in.Class == "" {
		in.Class = api.ClassAgent
	}
	if in.Class != api.ClassAgent && in.Class != api.ClassOwner {
		s.writeErr(w, r, errBad("unknown enrollment class"))
		return
	}
	if !config.ValidName(in.Hostname) {
		s.writeErr(w, r, errBad("hostname must match [a-z0-9][a-z0-9-]{0,62}"))
		return
	}
	if len(in.Note) > MaxReasonLen || !utf8.ValidString(in.Note) || hasControl(in.Note, true) {
		s.writeErr(w, r, errBad("note too long or contains control characters"))
		return
	}
	if l := len(in.PollToken); l < 32 || l > 128 || hasControl(in.PollToken, false) {
		s.writeErr(w, r, errBad("poll_token must be 32-128 characters (random, kept by the enrolling host)"))
		return
	}
	if len(in.SSHHostKeyFingerprints) > 16 {
		s.writeErr(w, r, errBad("too many ssh_host_key_fingerprints"))
		return
	}
	for _, fp := range in.SSHHostKeyFingerprints {
		if len(fp) > 200 || hasControl(fp, false) {
			s.writeErr(w, r, errBad("bad ssh_host_key_fingerprints entry"))
			return
		}
	}
	csr, err := pki.ParseCSR(in.CSRPEM)
	if err != nil {
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	now := s.now()
	e := &store.Enrollment{
		Class:          in.Class,
		ID:             ids.New(),
		Hostname:       in.Hostname,
		CSRPEM:         in.CSRPEM,
		KeyFingerprint: pki.PublicKeyFingerprint(csr.PublicKey),
		SSHHostKeyFPs:  in.SSHHostKeyFingerprints,
		Note:           in.Note,
		PeerAddress:    peerIP(r),
		CreatedAt:      now,
		ExpiresAt:      now.Add(secs(s.cfg.TTL.EnrollmentExpirySeconds)),
		PollTokenHash:  ids.Hash(in.PollToken),
	}
	ctx := r.Context()
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if _, err := q.ExpireStale(ctx, now); err != nil {
			return err
		}
		n, err := q.CountPendingEnrollments(ctx, now)
		if err != nil {
			return err
		}
		if n >= MaxPendingEnrolls {
			return &apiErr{http.StatusTooManyRequests, api.ErrRateLimited, "too many pending enrollments"}
		}
		if n, err := q.CountPendingEnrollmentsFrom(ctx, e.PeerAddress, now); err != nil {
			return err
		} else if n >= MaxPendingEnrollsPerIP {
			return &apiErr{http.StatusTooManyRequests, api.ErrRateLimited, "too many pending enrollments from this address"}
		}
		if err := q.InsertEnrollment(ctx, e); err != nil {
			return err
		}
		return q.Audit(ctx, now, "system", "enroll_request", "enrollment:"+e.ID,
			fmt.Sprintf("hostname=%s from=%s key=%s", e.Hostname, e.PeerAddress, e.KeyFingerprint))
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	url := s.approveURL(e.ID)
	s.notify.Send("aqmas: enrollment", fmt.Sprintf("aqmas: %s wants to enroll as %s", e.PeerAddress, e.Hostname), url)
	writeJSON(w, http.StatusCreated, api.EnrollResponse{ID: e.ID, Status: api.StatusPending, ApproveURL: url, PollAfterMS: PollAfterMS})
}

func (s *Server) handleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	// Only the enroller (who holds the poll token) may see the status or collect the
	// certificate: otherwise anyone who learns the id (it is in the approve link and the push
	// notification) could collect the once-only certificate first and force a re-enrollment.
	token := r.Header.Get(api.EnrollTokenHeader)
	if e, err := s.store.Q().GetEnrollment(ctx, id); err != nil || token == "" ||
		subtle.ConstantTimeCompare([]byte(ids.Hash(token)), []byte(e.PollTokenHash)) != 1 {
		s.writeErr(w, r, errNotFound())
		return
	}
	var e *store.Enrollment
	err := s.longPoll(ctx, parseWait(r.URL.Query().Get("wait")), func() (bool, error) {
		var err error
		e, err = s.store.Q().GetEnrollment(ctx, id)
		if err != nil {
			return false, err
		}
		// Expiry is applied in memory here (the sweeper persists it): polling causes no writes.
		if e.Status == api.StatusPending && !s.now().Before(e.ExpiresAt) {
			e.Status = api.StatusExpired
		}
		return e.Status != api.StatusPending, nil
	})
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, errNotFound())
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	// An already-signed certificate is public material: delivering it needs no bucket.
	out := api.EnrollStatus{ID: e.ID, Status: e.Status}
	if e.Status == api.StatusApproved && !e.CertDelivered {
		ok, err := s.store.Q().MarkCertDelivered(ctx, e.ID)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if ok {
			out.ClientCertPEM = e.CertPEM
			out.CACertPEM = string(s.pki.CAPEM)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- access requests ----

func requireActiveIdentity(ctx context.Context, q *store.Q, id int64) error {
	h, err := q.GetHost(ctx, id)
	if err != nil {
		return err
	}
	if h.RevokedAt != nil {
		return errForbidden("host enrollment revoked")
	}
	return nil
}

func (s *Server) handleResolveTarget(w http.ResponseWriter, r *http.Request, h *store.Host) {
	t, err := s.cfg.Resolve(r.URL.Query().Get("target"), r.URL.Query().Get("user"))
	if err != nil {
		if s.store.Q().Scoped() {
			s.writeErr(w, r, errNotFound())
			return
		}
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	cap := s.cfg.TTL.ForHost(h.Class).MaxSeconds
	if s.store.Q().Scoped() {
		b, err := s.store.Q().PersonalResource(r.Context(), h.ID, "ssh-ca", t.Name, s.now())
		if err != nil {
			s.writeErr(w, r, mapNotFound(err))
			return
		}
		l, err := s.limits(r.Context(), s.store.Q(), b, "")
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		cap = l.Hard
	}
	writeJSON(w, http.StatusOK, api.ResolvedTarget{Name: t.Name, Address: t.Address, Port: t.Port, MaxSeconds: cap})
}

func validRequester(rq api.Requester) error {
	if len(rq.Tool) > 32 || len(rq.SessionID) > api.MaxSessionIDBytes || len(rq.CWD) > api.MaxCWDBytes || len(rq.User) > 64 || rq.PID < 0 {
		return errBad("requester field too long")
	}
	for _, f := range []string{rq.Tool, rq.SessionID, rq.CWD, rq.User} {
		if !utf8.ValidString(f) || hasControl(f, false) {
			return errBad("requester contains control characters")
		}
	}
	return nil
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request, h *store.Host) {
	var in api.AccessRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if in.Kind != api.KindCloudflare && (in.Kind != api.KindSSH || in.SSH == nil || in.Cloudflare != nil) {
		s.writeErr(w, r, errBad(`kind must be "ssh" with an ssh object, or "cloudflare" with a cloudflare object`))
		return
	}
	if len(in.Reason) > MaxReasonLen || !utf8.ValidString(in.Reason) || hasControl(in.Reason, true) {
		s.writeErr(w, r, errBad("reason must be at most 500 bytes of text"))
		return
	}
	if err := validRequester(in.Requester); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if in.Kind == api.KindCloudflare {
		s.handleCreateCloudflare(w, r, h, &in)
		return
	}
	if in.Indefinite {
		s.writeErr(w, r, errBad("indefinite SSH requires KRL distribution"))
		return
	}
	tgt, err := s.cfg.Resolve(in.SSH.TargetHost, in.SSH.LoginUser)
	if err != nil {
		if s.store.Q().Scoped() {
			s.writeErr(w, r, errNotFound())
			return
		}
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	pub, err := sshcert.ParseEd25519(in.SSH.PublicKey)
	if err != nil {
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	now := s.now()
	ttl := policy.ClampTTL(in.TTLSeconds, s.cfg.TTL.ForHost(h.Class))
	if tgt.MaxTTLSeconds > 0 && ttl > tgt.MaxTTLSeconds {
		ttl = tgt.MaxTTLSeconds // config validation keeps it >= ttl.min_seconds
	}
	req := &store.Request{
		RequestedTarget: in.SSH.TargetHost, TargetAddress: tgt.Address, TargetPort: tgt.Port,
		Principal:      tgt.Principal(in.SSH.LoginUser),
		ID:             ids.New(),
		HostID:         h.ID,
		HostName:       h.Name,
		PeerAddress:    peerIP(r),
		Kind:           in.Kind,
		TargetHost:     tgt.Name,
		LoginUser:      in.SSH.LoginUser,
		PublicKey:      string(ssh.MarshalAuthorizedKey(pub)),
		KeyFingerprint: ssh.FingerprintSHA256(pub),
		Reason:         in.Reason,
		Requester:      in.Requester,
		TTLRequested:   ttl,
		Status:         api.StatusPending,
		CreatedAt:      now,
		ExpiresAt:      now.Add(secs(s.cfg.TTL.PendingExpirySeconds)),
	}
	if _, err := sshcert.SourceAddress(req.PeerAddress); err != nil {
		s.writeErr(w, r, errBad("cannot determine peer address"))
		return
	}
	ctx := r.Context()
	var standingUsed *store.Standing
	// A standing rule issues only while the SSH CA is open. If it closes
	// between that check and the signature (Close all, a rekey), the request
	// is queued for the owner instead of failing: the transaction is retried
	// once without standing rules.
	skipStanding := false
	tx := func(q *store.Q) error {
		if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
			return err
		}
		if q.Scoped() {
			b, err := q.PersonalResource(ctx, h.ID, "ssh-ca", tgt.Name, s.now())
			if err != nil {
				return mapNotFound(err)
			}
			l, err := s.limits(ctx, q, b, "")
			if err != nil {
				return err
			}
			ttl, err = l.requestTTL(in.TTLSeconds, s.cfg.TTL.MinSeconds, false)
			if err != nil {
				return err
			}
			req.TTLRequested = ttl
		}
		rules, err := q.ActiveStanding(ctx, h.ID, now)
		if err != nil {
			return err
		}
		// A standing rule issues without a tap only while the SSH CA is open (§5).
		if skipStanding || !s.caOpen(ctx, q, seal.RoleSSHCA) {
			rules = nil
		}
		cand := policy.Candidate{HostID: h.ID, PeerAddress: req.PeerAddress, Kind: req.Kind, Target: req.TargetHost, LoginUser: req.LoginUser, TTL: ttl}
		for _, st := range rules {
			rule := policy.Rule{HostID: st.HostID, PeerAddress: st.PeerAddress, Kind: st.Kind, Target: st.TargetHost, LoginUser: st.LoginUser,
				MaxTTL: st.MaxTTL, ExpiresAt: st.ExpiresAt, Revoked: st.RevokedAt != nil}
			if !policy.Matches(rule, cand, now) {
				continue
			}
			source, err := q.GetRequest(ctx, st.SourceRequestID)
			if err != nil {
				return err
			}
			if source.Principal != req.Principal || source.TargetAddress != tgt.Address || source.TargetPort != tgt.Port || s.highRisk(req) {
				continue
			}
			req.Status = api.StatusApproved
			req.StandingID = st.ID
			req.DecidedAt = &now
			req.DecisionNote = "standing approval " + st.ID
			if err := q.InsertPersonalRequest(ctx, req); err != nil {
				return err
			}
			if err := q.UseStanding(ctx, st.ID, now); err != nil {
				return err
			}
			g, err := s.issueGrant(ctx, q, req, ttl, now)
			if err != nil {
				if isLocked(err) {
					return errStandingClosed
				}
				return err
			}
			standingUsed = st
			return q.Audit(ctx, now, "system", "auto_approve", "request:"+req.ID,
				fmt.Sprintf("standing=%s grant=%s host=%s %s@%s ttl=%d key=%s from=%s", st.ID, g.ID, h.Name, req.LoginUser, req.TargetHost, ttl, req.KeyFingerprint, req.PeerAddress))
		}
		if n, err := s.allPending(ctx, q, h.ID, now); err != nil {
			return err
		} else if n >= MaxPendingPerHost {
			return &apiErr{http.StatusTooManyRequests, api.ErrRateLimited, "too many pending requests from this host"}
		}
		if err := q.InsertPersonalRequest(ctx, req); err != nil {
			return err
		}
		return q.Audit(ctx, now, "host:"+h.Name, "request", "request:"+req.ID,
			fmt.Sprintf("%s %s@%s ttl=%d key=%s from=%s", req.Kind, req.LoginUser, req.TargetHost, ttl, req.KeyFingerprint, req.PeerAddress))
	}
	err = s.store.Tx(ctx, tx)
	if errors.Is(err, errStandingClosed) {
		skipStanding, standingUsed = true, nil
		req.Status, req.StandingID, req.DecidedAt, req.DecisionNote = api.StatusPending, "", nil, ""
		err = s.store.Tx(ctx, tx)
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if standingUsed != nil {
		s.holdCA(ctx, seal.RoleSSHCA, standingHold(standingUsed))
	}
	s.bcast.notify()
	url := s.approveURL(req.ID)
	if req.Status == api.StatusPending {
		s.notify.Send("aqmas: "+h.Name, fmt.Sprintf("aqmas: %s wants ssh %s@%s", h.Name, req.LoginUser, req.TargetHost), url)
	}
	writeJSON(w, http.StatusCreated, api.RequestCreated{ID: req.ID, Status: req.Status, ApproveURL: url, PollAfterMS: PollAfterMS, ExpiresAt: req.ExpiresAt})
}

func (s *Server) handleRequestStatus(w http.ResponseWriter, r *http.Request, h *store.Host) {
	id := r.PathValue("id")
	ctx := r.Context()
	var req *store.Request
	err := s.longPoll(ctx, parseWait(r.URL.Query().Get("wait")), func() (bool, error) {
		var err error
		req, err = s.store.Q().PersonalStatus(ctx, id, h.ID, s.now())
		if err != nil {
			return false, err
		}
		// Host isolation: another host's request is indistinguishable from a missing one.
		if req.HostID != h.ID {
			return false, store.ErrNotFound
		}
		if req.Status == api.StatusPending && !s.now().Before(req.ExpiresAt) {
			req.Status = api.StatusExpired
		}
		return req.Status != api.StatusPending, nil
	})
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, errNotFound())
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if ctx.Err() != nil {
		return
	}
	var out *api.RequestStatus
	err = s.store.Tx(ctx, func(q *store.Q) error {
		req, err := q.PersonalStatus(ctx, id, h.ID, s.now())
		if err != nil {
			return mapNotFound(err)
		}
		out, err = s.requestStatus(ctx, q, req)
		return err
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	// Token mode: the first poll after approval mints the child token and carries its value.
	if err := s.deliverToken(w, r, h, out); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// requestStatus builds the agent-facing status; the grant (with certificate) is included only
// while the request is approved.
func (s *Server) requestStatus(ctx context.Context, q *store.Q, req *store.Request) (*api.RequestStatus, error) {
	out := &api.RequestStatus{ID: req.ID, Kind: req.Kind, Status: req.Status, DecidedAt: req.DecidedAt, DecisionNote: req.DecisionNote}
	if req.Status != api.StatusApproved {
		return out, nil
	}
	// An approved grant's certificate is already signed: no bucket is needed to deliver it.
	g, err := q.GrantByRequest(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	if g.Kind == api.KindCloudflare {
		out.Grant = s.cfGrantView(g)
		return out, nil
	}
	tgt, _ := s.cfg.Target(g.TargetHost)
	if req.TargetAddress != "" && (tgt.Address != req.TargetAddress || tgt.Port != req.TargetPort) {
		return nil, errConflict("SSH destination changed; request again")
	}
	out.Grant = &api.Grant{
		ID: g.ID, Kind: g.Kind, NotBefore: g.NotBefore, NotAfter: g.NotAfter,
		SSH: &api.SSHGrant{
			Certificate:    g.Certificate,
			Principals:     g.Principals,
			TargetHost:     g.TargetHost,
			TargetAddress:  tgt.Address,
			TargetPort:     tgt.Port,
			LoginUser:      g.LoginUser,
			KnownHostsLine: sshcert.KnownHostsLine(tgt.Name, tgt.Address, tgt.Port, tgt.HostKey),
		},
	}
	return out, nil
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request, h *store.Host) {
	id := r.PathValue("id")
	ctx := r.Context()
	now := s.now()
	var req *store.Request
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if _, err := q.ExpireStale(ctx, now); err != nil {
			return err
		}
		var err error
		if req, err = q.PersonalStatus(ctx, id, h.ID, now); err != nil {
			return errNotFound() // another host's request is indistinguishable from a missing one
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

// handleSSHCA publishes the SSH user CA public key (GET /v1/ssh-ca).
func (s *Server) handleSSHCA(w http.ResponseWriter, r *http.Request, _ *store.Host) {
	writeJSON(w, http.StatusOK, api.SSHCA{
		PublicKey:   s.pki.SSHCAPublicLine(),
		Fingerprint: s.sshPin(),
	})
}

func (s *Server) handleGrants(w http.ResponseWriter, r *http.Request, h *store.Host) {
	active := r.URL.Query().Get("active")
	now := s.now()
	gs, err := s.store.Q().HostGrants(r.Context(), h.ID, active == "1" || active == "true", now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	out := api.GrantList{Grants: []api.GrantSummary{}}
	for _, g := range gs {
		out.Grants = append(out.Grants, api.GrantSummary{Indefinite: g.NotAfter.Equal(untilRevoked), ID: g.ID, Kind: g.Kind, Status: g.Status(now), TargetHost: g.TargetHost,
			LoginUser: g.LoginUser, NotBefore: g.NotBefore, NotAfter: g.NotAfter, Scope: g.Scope, ScopeParams: g.ScopeParams, Mode: g.Mode})
	}
	writeJSON(w, http.StatusOK, out)
}

// pemCert encodes DER as a PEM certificate.
func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// errStandingClosed rolls back a standing approval whose bucket closed after
// the check; the request is then queued.
var errStandingClosed = errors.New("standing rule's bucket closed")

// isLocked reports a closed bucket (423), as withBucket returns it.
func isLocked(err error) bool {
	var ae *apiErr
	return errors.Is(err, errBucketClosed) || errors.As(err, &ae) && ae.status == http.StatusLocked
}
