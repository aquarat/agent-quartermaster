package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/cfaccess"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/webui"
)

// Content-Security-Policy for every web response: same-origin only, no inline script or style,
// no framing.
const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// WebHandler returns the web UI + web API handler (plain HTTP on 127.0.0.1 behind cloudflared).
func (s *Server) WebHandler() http.Handler {
	api := http.NewServeMux()
	// Unauthenticated (still behind Access when configured).
	api.HandleFunc("GET /api/ui/session", s.handleSession)
	api.HandleFunc("POST /api/ui/login/begin", s.handleLoginBegin)
	api.HandleFunc("POST /api/ui/login/finish", s.handleLoginFinish)
	api.HandleFunc("POST /api/ui/passkeys/register/begin", s.handleRegisterBegin)
	api.HandleFunc("POST /api/ui/passkeys/register/finish", s.handleRegisterFinish)
	// Session required.
	api.Handle("POST /api/ui/logout", s.requireSession(s.handleLogout))
	api.Handle("GET /api/ui/state", s.requireSession(s.handleState))
	api.Handle("GET /api/ui/requests/{id}", s.requireSession(s.handleRequestItem))
	api.Handle("GET /api/ui/enrollments/{id}", s.requireSession(s.handleEnrollmentItem))
	for _, o := range []struct{ path, object, verb string }{
		{"requests", canon.ObjectRequest, "decide"},
		{"enrollments", canon.ObjectEnrollment, "decide"},
		{"standing", canon.ObjectStanding, "revoke"},
		{"grants", canon.ObjectGrant, "revoke"},
	} {
		api.Handle("POST /api/ui/"+o.path+"/{id}/challenge", s.requireSession(s.challengeHandler(o.object)))
		api.Handle("POST /api/ui/"+o.path+"/{id}/"+o.verb, s.requireSession(s.decideHandler(o.object)))
	}
	api.Handle("POST /api/ui/passkeys/challenge", s.requireSession(s.challengeHandler(canon.ObjectPasskey)))

	static := webui.Handler()
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	root.Handle("/api/", s.apiGuard(api))
	root.Handle("/", static)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)")
		if r.URL.Path != "/healthz" && s.access != nil {
			id, err := s.access.Verify(r.Context(), r.Header.Get(cfaccess.Header))
			if err == nil && s.cfg.Access.OwnerEmail != "" && !strings.EqualFold(id.Email, s.cfg.Access.OwnerEmail) {
				err = errors.New("not the owner's Access identity")
			}
			if err != nil {
				s.log.Warn("cloudflare access token rejected", "path", r.URL.Path, "error", err)
				s.writeErr(w, r, errForbidden("Cloudflare Access token missing or invalid"))
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxAccessSub, id.Sub))
		}
		root.ServeHTTP(w, r)
	})
}

// apiGuard enforces CSRF defences on the web API: POSTs need the custom header, a JSON content
// type and (when the browser sends one) a same-origin Origin. SameSite=Strict cookies do the rest.
func (s *Server) apiGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get(csrfHeader) != "1" {
				s.writeErr(w, r, errForbidden("missing "+csrfHeader+" header"))
				return
			}
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				s.writeErr(w, r, errBad("Content-Type must be application/json"))
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != s.cfg.PublicBaseURL {
				s.writeErr(w, r, errForbidden("cross-origin request refused"))
				return
			}
			if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
				s.writeErr(w, r, errForbidden("cross-site request refused"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- sessions ----

func accessSub(ctx context.Context) string {
	v, _ := ctx.Value(ctxAccessSub).(string)
	return v
}

func (s *Server) sessionHash(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return "", false
	}
	h := ids.Hash(c.Value)
	// With Access configured, a session only works with the Access identity it was created under.
	ok, err := s.store.Q().SessionValid(r.Context(), h, accessSub(r.Context()), s.now())
	if err != nil || !ok {
		return "", false
	}
	return h, true
}

func (s *Server) requireSession(next func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := s.sessionHash(r)
		if !ok {
			s.writeErr(w, r, errUnauth("log in with your passkey"))
			return
		}
		next(w, r, h)
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	_, ok := s.sessionHash(r)
	n, err := s.store.Q().CountPasskeys(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": ok, "owner": api.UIOwner{Name: s.cfg.OwnerName, Passkeys: n}})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess string) {
	_ = s.store.Q().DeleteSession(r.Context(), sess)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ceremonyBegin is the response to login/begin and passkeys/register/begin.
type ceremonyBegin struct {
	ChallengeID string `json:"challenge_id"`
	PublicKey   any    `json:"public_key"`
}

// ceremonyFinish is the body of login/finish and passkeys/register/finish. The browser's
// PublicKeyCredential JSON may be sent as "assertion" (login), "credential" (register), or
// "attestation".
type ceremonyFinish struct {
	ChallengeID string          `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"`
	Credential  json.RawMessage `json:"credential"`
	Attestation json.RawMessage `json:"attestation"`
	Name        string          `json:"name"`
}

func (f ceremonyFinish) payload() json.RawMessage {
	for _, p := range []json.RawMessage{f.Credential, f.Attestation, f.Assertion} {
		if len(p) > 0 && string(p) != "null" {
			return p
		}
	}
	return nil
}

func randomChallenge() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o, err := s.loadOwner(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if len(o.creds) == 0 {
		s.writeErr(w, r, errConflict("no passkey registered yet; register one with an enroll code"))
		return
	}
	ch := randomChallenge()
	now := s.now()
	// Discoverable login: no allowCredentials, user verification required.
	as, _, err := s.wa.BeginDiscoverableLogin(webauthn.WithChallenge(ch), webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	c := &store.Challenge{ID: ids.New(), Purpose: "login", SessionData: base64.RawURLEncoding.EncodeToString(ch),
		CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL)}
	if err := s.store.Q().InsertChallenge(ctx, c); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ceremonyBegin{ChallengeID: c.ID, PublicKey: as.Response})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in ceremonyFinish
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	now := s.now()
	c, err := s.consume(ctx, in.ChallengeID, "login", now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	ch, err := base64.RawURLEncoding.DecodeString(c.SessionData)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	pkID, err := s.verifyAssertion(ctx, ch, in.payload())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	cookie := ids.Secret(32)
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.InsertSession(ctx, ids.Hash(cookie), pkID, accessSub(ctx), now, now.Add(SessionTTL)); err != nil {
			return err
		}
		return q.Audit(ctx, now, "owner", "login", fmt.Sprintf("passkey:%d", pkID), "")
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: cookie, Path: "/", MaxAge: int(SessionTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) consume(ctx context.Context, id, purpose string, now time.Time) (*store.Challenge, error) {
	if id == "" {
		return nil, errBad("challenge_id required")
	}
	c, err := s.store.Q().ConsumeChallenge(ctx, id, purpose, now)
	switch {
	case errors.Is(err, store.ErrExpired):
		return nil, errExpired("challenge expired; start again")
	case errors.Is(err, store.ErrNotFound):
		return nil, errConflict("unknown or already used challenge")
	case err != nil:
		return nil, err
	}
	return c, nil
}

// ---- passkey registration ----

type registerBegin struct {
	EnrollCode  string          `json:"enroll_code"`
	ChallengeID string          `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"`
}

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in registerBegin
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	now := s.now()
	o, err := s.loadOwner(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	c := &store.Challenge{ID: ids.New(), Purpose: "register", CreatedAt: now, ExpiresAt: now.Add(RegisterTTL)}
	if len(o.creds) == 0 {
		// Bootstrap: the one-time code from `aqmasd passkey-enroll-code`.
		if in.EnrollCode == "" || len(in.EnrollCode) > 64 {
			s.writeErr(w, r, errForbidden("enroll_code required for the first passkey"))
			return
		}
		h := ids.Hash(normalizeCode(in.EnrollCode))
		ok, err := s.store.Q().EnrollCodeValid(ctx, h, now)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if !ok {
			s.log.Warn("passkey enroll code rejected", "from", r.Header.Get("Cf-Connecting-Ip"))
			s.writeErr(w, r, errForbidden("enroll code invalid, used or expired"))
			return
		}
		c.ObjectType, c.ObjectID = "enroll_code", h
	} else {
		// Another passkey: an authenticated session plus an assertion for a passkey/register challenge.
		sess, ok := s.sessionHash(r)
		if !ok {
			s.writeErr(w, r, errUnauth("log in first"))
			return
		}
		sg, pkID, err := s.verifyAction(ctx, sess, canon.ObjectPasskey, "", in.ChallengeID, in.Assertion)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if sg.Action.Action != canon.ActionAdd {
			s.writeErr(w, r, errBad("challenge is not for registering a passkey"))
			return
		}
		c.ObjectType, c.ObjectID, c.SessionHash = "session", fmt.Sprintf("passkey:%d", pkID), sess
	}
	var excl []protocol.CredentialDescriptor
	for _, cr := range o.creds {
		excl = append(excl, cr.Descriptor())
	}
	cc, sd, err := s.wa.BeginRegistration(o,
		webauthn.WithExclusions(excl),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		// The web UI always asks for credProps; requesting it here makes that output solicited.
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	sdj, err := json.Marshal(sd)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	c.SessionData = string(sdj)
	if err := s.store.Q().InsertChallenge(ctx, c); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ceremonyBegin{ChallengeID: c.ID, PublicKey: cc.Response})
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in ceremonyFinish
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if len(in.Name) > 64 || !utf8.ValidString(in.Name) || hasControl(in.Name, false) {
		s.writeErr(w, r, errBad("name too long"))
		return
	}
	now := s.now()
	c, err := s.consume(ctx, in.ChallengeID, "register", now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if c.SessionHash != "" {
		if sess, ok := s.sessionHash(r); !ok || sess != c.SessionHash {
			s.writeErr(w, r, errForbidden("registration was started in another session"))
			return
		}
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(c.SessionData), &sd); err != nil {
		s.writeErr(w, r, err)
		return
	}
	payload := in.payload()
	if payload == nil {
		s.writeErr(w, r, errBad("credential required"))
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(payload)
	if err != nil {
		s.writeErr(w, r, errBad("credential could not be parsed"))
		return
	}
	o, err := s.loadOwner(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	cred, err := s.wa.CreateCredential(o, sd, parsed)
	if err != nil {
		s.log.Warn("passkey registration rejected", "error", err)
		s.writeErr(w, r, errForbidden("passkey registration rejected"))
		return
	}
	if !cred.Flags.UserVerified {
		s.writeErr(w, r, errForbidden("user verification required"))
		return
	}
	cj, err := json.Marshal(cred)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	err = s.store.Tx(ctx, func(q *store.Q) error {
		n, err := q.CountPasskeys(ctx)
		if err != nil {
			return err
		}
		detail := ""
		switch c.ObjectType {
		case "enroll_code":
			if n != 0 {
				return errConflict("a passkey already exists; enroll codes only bootstrap the first one")
			}
			if err := q.ConsumeEnrollCode(ctx, c.ObjectID, now); err != nil {
				return errForbidden("enroll code invalid, used or expired")
			}
			detail = "first passkey via enroll code"
		case "session":
			if n == 0 {
				return errConflict("no existing passkey")
			}
			detail = "approved by " + c.ObjectID
		default:
			return errBad("bad registration challenge")
		}
		id, err := q.InsertPasskey(ctx, &store.Passkey{CredentialID: cred.ID, CredentialJSON: string(cj), Name: in.Name, CreatedAt: now})
		if err != nil {
			return err
		}
		return q.Audit(ctx, now, "owner", "passkey_register", fmt.Sprintf("passkey:%d", id), detail)
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- state ----

// uiItem is api.PendingItem plus the fields the web UI uses that internal/api lacks yet
// (docs/CONTRACT-NOTES-server.md).
type uiItem struct {
	api.PendingItem
	Status     string             `json:"status,omitempty"`
	Enrollment *pendingEnrollment `json:"enrollment,omitempty"`
}

type pendingEnrollment struct {
	CSRFingerprint         string   `json:"csr_fingerprint"`
	SSHHostKeyFingerprints []string `json:"ssh_host_key_fingerprints"`
	ReplacesExisting       bool     `json:"replaces_existing"`
}

type uiGrant struct {
	api.GrantSummary
	RequestingHost string `json:"requesting_host"`
}

type uiState struct {
	Owner    api.UIOwner            `json:"owner"`
	Pending  []uiItem               `json:"pending"`
	Standing []api.StandingApproval `json:"standing"`
	Grants   []uiGrant              `json:"grants"`
	Recent   []api.AuditEntry       `json:"recent"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request, _ string) {
	ctx := r.Context()
	now := s.now()
	q := s.store.Q()
	if _, err := q.ExpireStale(ctx, now); err != nil {
		s.writeErr(w, r, err)
		return
	}
	n, err := q.CountPasskeys(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	out := uiState{Owner: api.UIOwner{Name: s.cfg.OwnerName, Passkeys: n}, Pending: []uiItem{}, Standing: []api.StandingApproval{}, Grants: []uiGrant{}}
	reqs, err := q.PendingRequests(ctx, now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for _, rq := range reqs {
		it, err := s.requestItem(ctx, rq)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		out.Pending = append(out.Pending, uiItem{PendingItem: *it})
	}
	ens, err := q.PendingEnrollments(ctx, now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for _, e := range ens {
		out.Pending = append(out.Pending, s.enrollmentItem(ctx, e))
	}
	sts, err := q.ActiveStanding(ctx, 0, now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for _, st := range sts {
		out.Standing = append(out.Standing, api.StandingApproval{ID: st.ID, RequestingHost: st.HostName, Kind: st.Kind,
			TargetHost: st.TargetHost, LoginUser: st.LoginUser, MaxTTLSeconds: st.MaxTTL, ExpiresAt: st.ExpiresAt, Uses: st.Uses})
	}
	gs, err := q.ActiveGrants(ctx, now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for _, g := range gs {
		out.Grants = append(out.Grants, uiGrant{GrantSummary: api.GrantSummary{ID: g.ID, Kind: g.Kind, Status: g.Status(now),
			TargetHost: g.TargetHost, LoginUser: g.LoginUser, NotBefore: g.NotBefore, NotAfter: g.NotAfter}, RequestingHost: g.HostName})
	}
	if out.Recent, err = q.RecentAudit(ctx, 50); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) requestItem(ctx context.Context, rq *store.Request) (*api.PendingItem, error) {
	similar, err := s.store.Q().CountSimilar(ctx, rq.HostID, rq.TargetHost, rq.LoginUser, s.now().Add(-7*24*time.Hour))
	if err != nil {
		return nil, err
	}
	risk := "normal"
	if tgt, ok := s.cfg.Target(rq.TargetHost); !ok || tgt.HighRisk || rq.LoginUser == "root" || rq.TTLRequested > 4*3600 {
		risk = "high"
	}
	return &api.PendingItem{
		ID: rq.ID, Kind: rq.Kind, CreatedAt: rq.CreatedAt, ExpiresAt: rq.ExpiresAt,
		RequestingHost: rq.HostName, RequestingAddress: rq.PeerAddress, Requester: rq.Requester, Reason: rq.Reason,
		SSH:          &api.PendingSSH{TargetHost: rq.TargetHost, LoginUser: rq.LoginUser, KeyFingerprint: rq.KeyFingerprint},
		TTLRequested: rq.TTLRequested, TTLMax: rq.TTLRequested, Risk: risk, SimilarRecent: similar,
	}, nil
}

func (s *Server) enrollmentItem(ctx context.Context, e *store.Enrollment) uiItem {
	risk, replaces := "normal", false
	if _, err := s.store.Q().ActiveHostByName(ctx, e.Hostname); err == nil {
		risk, replaces = "high", true // replaces an existing host identity
	}
	fps := e.SSHHostKeyFPs
	if fps == nil {
		fps = []string{}
	}
	return uiItem{
		PendingItem: api.PendingItem{
			ID: e.ID, Kind: "enrollment", CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt,
			RequestingHost: e.Hostname, RequestingAddress: e.PeerAddress, Reason: e.Note, Risk: risk,
		},
		Enrollment: &pendingEnrollment{CSRFingerprint: e.KeyFingerprint, SSHHostKeyFingerprints: fps, ReplacesExisting: replaces},
	}
}

func (s *Server) handleRequestItem(w http.ResponseWriter, r *http.Request, _ string) {
	rq, err := s.store.Q().GetRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, mapNotFound(err))
		return
	}
	it, err := s.requestItem(r.Context(), rq)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, uiItem{PendingItem: *it, Status: rq.Status})
}

func (s *Server) handleEnrollmentItem(w http.ResponseWriter, r *http.Request, _ string) {
	e, err := s.store.Q().GetEnrollment(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, mapNotFound(err))
		return
	}
	it := s.enrollmentItem(r.Context(), e)
	it.Status = e.Status
	writeJSON(w, http.StatusOK, it)
}

// notifyDecision pushes what was just signed and applied, as an out-of-band check: if code on
// the approval origin showed one action but had another signed, this push reveals it.
func (s *Server) notifyDecision(sg canon.Signed) {
	a := sg.Action
	text := fmt.Sprintf("aqmas: %s %s %s", a.Action, a.Object, a.ID)
	switch a.Object {
	case canon.ObjectRequest:
		text = fmt.Sprintf("aqmas: %s %s %s@%s for %s, ttl %ds, standing %dh", a.Action, a.Kind, a.LoginUser, a.Target, a.RequestingHost, a.TTLSeconds, a.StandingHours)
	case canon.ObjectEnrollment:
		text = fmt.Sprintf("aqmas: %s enrollment of %s (replaces existing: %t)", a.Action, a.RequestingHost, a.Replaces)
	case canon.ObjectStanding, canon.ObjectGrant:
		text = fmt.Sprintf("aqmas: %s %s %s@%s for %s", a.Action, a.Object, a.LoginUser, a.Target, a.RequestingHost)
	}
	text += fmt.Sprintf(" [ref %s]", ref(a.ID))
	s.notify.Send("aqmas: decision", text, s.cfg.PublicBaseURL+"/")
}

// ref is the short reference the UI and CLI show: the last 6 characters of the id, upper-cased.
func ref(id string) string {
	if len(id) > 6 {
		id = id[len(id)-6:]
	}
	return strings.ToUpper(id)
}

// ---- per-action challenge / decide ----

func (s *Server) challengeHandler(object string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sess string) {
		ctx := r.Context()
		var in api.ChallengeRequest
		if err := decode(r, &in); err != nil {
			s.writeErr(w, r, err)
			return
		}
		id := r.PathValue("id")
		if object == canon.ObjectPasskey {
			id = "new"
		}
		a, err := s.buildAction(ctx, object, id, in)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		now := s.now()
		text, err := canon.Build(a, canon.NewNonce(), now)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		o, err := s.loadOwner(ctx)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		opts, err := s.requestOptions(o, canon.Challenge(text))
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		c := &store.Challenge{ID: ids.New(), Purpose: "action", ObjectType: object, ObjectID: id, Canonical: text,
			SessionHash: sess, CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL)}
		if err := s.store.Q().InsertChallenge(ctx, c); err != nil {
			s.writeErr(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, api.ChallengeResponse{ChallengeID: c.ID, Canonical: text, PublicKey: opts})
	}
}

// verifyAction consumes an action challenge and verifies the assertion against exactly the
// stored canonical text. id "" skips the object-id check (passkey registration).
func (s *Server) verifyAction(ctx context.Context, sess, object, id, challengeID string, assertion json.RawMessage) (canon.Signed, int64, error) {
	c, err := s.consume(ctx, challengeID, "action", s.now())
	if err != nil {
		return canon.Signed{}, 0, err
	}
	if c.SessionHash != sess {
		return canon.Signed{}, 0, errForbidden("challenge was issued to another session")
	}
	if c.ObjectType != object || (id != "" && c.ObjectID != id) {
		return canon.Signed{}, 0, errBad("challenge is for a different object")
	}
	sg, err := canon.Parse(c.Canonical)
	if err != nil {
		return canon.Signed{}, 0, err
	}
	if sg.Object != object || sg.ID != c.ObjectID {
		return canon.Signed{}, 0, errBad("challenge is for a different object")
	}
	pkID, err := s.verifyAssertion(ctx, canon.Challenge(c.Canonical), assertion)
	if err != nil {
		return canon.Signed{}, 0, err
	}
	return sg, pkID, nil
}

func (s *Server) decideHandler(object string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sess string) {
		ctx := r.Context()
		var in struct {
			ChallengeID string          `json:"challenge_id"`
			Assertion   json.RawMessage `json:"assertion"`
		}
		if err := decode(r, &in); err != nil {
			s.writeErr(w, r, err)
			return
		}
		id := r.PathValue("id")
		sg, pkID, err := s.verifyAction(ctx, sess, object, id, in.ChallengeID, in.Assertion)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if err := s.apply(ctx, sg, pkID); err != nil {
			s.writeErr(w, r, err)
			return
		}
		s.bcast.notify()
		s.notifyDecision(sg)
		switch object {
		case canon.ObjectRequest:
			rq, err := s.store.Q().GetRequest(ctx, id)
			if err != nil {
				s.writeErr(w, r, err)
				return
			}
			// The web UI gets the status, never the certificate.
			writeJSON(w, http.StatusOK, api.RequestStatus{ID: rq.ID, Kind: rq.Kind, Status: rq.Status, DecidedAt: rq.DecidedAt, DecisionNote: rq.DecisionNote})
		case canon.ObjectEnrollment:
			e, err := s.store.Q().GetEnrollment(ctx, id)
			if err != nil {
				s.writeErr(w, r, err)
				return
			}
			writeJSON(w, http.StatusOK, api.EnrollStatus{ID: e.ID, Status: e.Status})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "status": api.StatusRevoked})
		}
	}
}
