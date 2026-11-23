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

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/aaguid"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/cfaccess"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
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
	api.Handle("GET /api/ui/hosts", s.requireSession(s.handleHosts))
	api.Handle("GET /api/ui/updates", s.requireSession(s.handleUpdates))
	api.Handle("GET /api/ui/help", s.requireSession(s.handleHelp))
	api.Handle("GET /api/ui/migration", s.requireSession(s.migrationPreview))
	api.Handle("GET /api/ui/catalogue", s.requireSession(s.catalogueHandler))
	for object := range canon.CatalogueActions {
		base := "/api/ui/catalogue/" + object + "/{id}/"
		api.Handle("POST "+base+"challenge", s.requireSession(s.challengeHandler(object)))
		api.Handle("POST "+base+"decide", s.requireSession(s.decideHandler(object)))
	}
	api.Handle("GET /api/ui/requests/{id}", s.requireSession(s.handleRequestItem))
	api.Handle("GET /api/ui/enrollments/{id}", s.requireSession(s.handleEnrollmentItem))
	for _, o := range []struct{ path, object, verb string }{
		{"requests", canon.ObjectRequest, "decide"},
		{"migrations", canon.Migration, "activate"},
		{"updates", "update", "decide"},
		{"enrollments", canon.ObjectEnrollment, "decide"},
		{"standing", canon.ObjectStanding, "revoke"},
		{"grants", canon.ObjectGrant, "revoke"},
		{"hosts", canon.ObjectHost, "revoke"},
	} {
		api.Handle("POST /api/ui/"+o.path+"/{id}/challenge", s.requireSession(s.challengeHandler(o.object)))
		api.Handle("POST /api/ui/"+o.path+"/{id}/"+o.verb, s.requireSession(s.decideHandler(o.object)))
	}
	s.bastionWebRoutes(api)
	api.Handle("POST /api/ui/passkeys/challenge", s.requireSession(s.challengeHandler(canon.ObjectPasskey)))
	api.Handle("POST /api/ui/passkeys/{id}/challenge", s.requireSession(s.challengeHandler(canon.ObjectPasskey)))
	api.Handle("POST /api/ui/passkeys/{id}/rename", s.requireSession(s.passkeyChangeHandler(canon.ActionRename)))
	api.Handle("POST /api/ui/passkeys/{id}/remove", s.requireSession(s.passkeyChangeHandler(canon.ActionRemove)))

	static := webui.Handler()
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.DB().PingContext(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	s.sealRoutes(api)
	s.setupRoutes(api)
	root.Handle("/api/", s.apiGuard(s.guardedWeb(api)))
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
		if s.maintenance && r.Method != "GET" {
			p := r.URL.Path
			allowed := p == "/api/ui/login/begin" || p == "/api/ui/login/finish" || p == "/api/ui/logout" || p == "/api/ui/setup/cancel"
			if s.cutover != nil {
				prefix := "/api/ui/migrations/" + s.cutover.ID + "/"
				allowed = allowed || p == prefix+"challenge" || p == prefix+"activate"
			}
			if !allowed {
				s.writeErr(w, r, errConflict("broker fenced for personal cutover"))
				return
			}
		}
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
		next(w, r.WithContext(context.WithValue(r.Context(), verifiedSignerKey{}, new(verifiedIdentity))), h)
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	_, ok := s.sessionHash(r)
	n, err := s.store.Q().CountPasskeys(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, api.UISession{Authenticated: ok, Owner: api.UIOwner{Name: s.cfg.OwnerName, Passkeys: n}})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess string) {
	if err := s.store.Q().DeleteSession(r.Context(), sess); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if s.seal != nil {
		s.seal.windows.logout(sess)
		s.seal.vault.logout(sess)
		s.reconcileHolds(r.Context()) // the session's windows end: their holds go
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, api.OK{OK: true})
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
	writeJSON(w, http.StatusOK, api.CeremonyBegin{ChallengeID: c.ID, PublicKey: as.Response})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in api.LoginFinish
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
	pkID, err := s.verifyAssertion(ctx, ch, in.Assertion)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	cookie := ids.Secret(32)
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.InsertSession(ctx, ids.Hash(cookie), pkID, accessSub(ctx), now, now.Add(SessionTTL)); err != nil {
			return err
		}
		return q.Audit(ctx, now, "owner", "login", s.passkeyRef(ctx, q, pkID), "")
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: cookie, Path: "/", MaxAge: int(SessionTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, api.OK{OK: true})
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

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if s.seal != nil {
		s.writeErr(w, r, errConflict("sealed enrollment requires an explicit signed capability"))
		return
	}
	ctx := r.Context()
	var in api.RegisterBegin
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
		sg, pkID, settle, err := s.verifyAction(ctx, sess, canon.ObjectPasskey, "", in.ChallengeID, in.Assertion, nil)
		settle(false)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if sg.Action.Action != canon.ActionAdd {
			s.writeErr(w, r, errBad("challenge is not for registering a passkey"))
			return
		}
		c.ObjectType, c.ObjectID, c.SessionHash = "session", s.passkeyRef(ctx, s.store.Q(), pkID), sess
		// The nickname the owner signed for the new passkey ("" = name it after the
		// authenticator); register/finish uses exactly this.
		c.Canonical = sg.NewNickname
	}
	var excl []protocol.CredentialDescriptor
	for _, cr := range o.creds {
		excl = append(excl, cr.Descriptor())
	}
	cc, sd, err := s.wa.BeginRegistration(o,
		webauthn.WithExclusions(excl),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		// The web UI always asks for credProps; requesting it here makes that output solicited.
		webauthn.WithExtensions(webauthn.WithExtensionCredProps(), webauthn.WithExtensionPRFSupport()),
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
	writeJSON(w, http.StatusOK, api.CeremonyBegin{ChallengeID: c.ID, PublicKey: cc.Response})
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if s.seal != nil {
		s.writeErr(w, r, errConflict("sealed enrollment requires an explicit signed capability"))
		return
	}
	ctx := r.Context()
	var in api.RegisterFinish
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	nickname := ""
	if strings.TrimSpace(in.Name) != "" {
		n, err := normalizeNickname(in.Name)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		nickname = n
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
	payload := []byte(in.Credential)
	if len(payload) == 0 || string(payload) == "null" {
		s.writeErr(w, r, errBad("credential required"))
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(payload)
	if !publicExtensionsOnly(payload, true) {
		s.writeErr(w, r, errBad("unexpected client extension output"))
		return
	}
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
	var info api.PasskeyInfo
	err = s.store.Tx(ctx, func(q *store.Q) error {
		all, err := loadPasskeys(ctx, q)
		if err != nil {
			return err
		}
		n := len(all)
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
			// Only the signed nickname counts (see register/begin); a different name sent
			// here is refused rather than silently dropped.
			if nickname != "" && nickname != c.Canonical {
				return errBad("name differs from the nickname signed with the add action")
			}
			nickname = c.Canonical
			if nickname != "" && nicknameTaken(all, nickname, 0) {
				return errConflict("another passkey took that name meanwhile; remove or rename it, then add again")
			}
			detail = "approved by " + c.ObjectID
		default:
			return errBad("bad registration challenge")
		}
		// Nickname: the owner's choice, else the authenticator's name (else "Passkey N"), made
		// unique so the nickname in a signed rename/remove names exactly one passkey.
		name := nickname
		if name == "" {
			if _, a := aaguid.Lookup(cred.Authenticator.AAGUID); a != aaguid.Unknown {
				name = a.Name
			} else {
				name = fmt.Sprintf("Passkey %d", n+1)
			}
		}
		name = uniqueNickname(all, name)
		p := &store.Passkey{CredentialID: cred.ID, CredentialJSON: string(cj), Name: name, CreatedAt: now}
		id, err := q.InsertPasskey(ctx, p)
		if err != nil {
			return err
		}
		p.ID = id
		sp := storedPasskey{Passkey: p, cred: *cred, id: passkeyID(cred.ID)}
		info = sp.info(0)
		return q.Audit(ctx, now, "owner", "passkey_register", "passkey:"+sp.id,
			fmt.Sprintf("nickname=%q authenticator=%q synced=%t %s", name, info.Authenticator, info.BackupEligible, detail))
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	s.notify.Send("aqmas: passkey added", fmt.Sprintf("aqmas: passkey %q (%s) added [id %s]", info.Nickname, info.Authenticator, ref(info.ID)), s.cfg.PublicBaseURL+"/")
	writeJSON(w, http.StatusOK, api.RegisterResult{OK: true, Passkey: &info})
}

// ---- state ----

func (s *Server) handleState(w http.ResponseWriter, r *http.Request, sess string) {
	if s.sealSetup {
		writeJSON(w, 200, api.UIState{SealEnabled: true, Owner: api.UIOwner{Name: s.cfg.OwnerName}})
		return
	}
	if s.maintenance {
		writeJSON(w, 200, struct {
			api.UIState
			Migration *cutoverReview `json:"migration"`
		}{api.UIState{Owner: api.UIOwner{Name: s.cfg.OwnerName}, Pending: []api.PendingItem{}, Grants: []api.GrantSummary{}, Standing: []api.StandingApproval{}}, s.cutover})
		return
	}
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
	out := api.UIState{Owner: api.UIOwner{Name: s.cfg.OwnerName, Passkeys: n}, Pending: []api.PendingItem{}, Standing: []api.StandingApproval{}, Grants: []api.GrantSummary{}}
	reqs, err := q.PendingRequests(ctx, now)
	out.CatalogueEnabled = q.Scoped() && (s.seal == nil || s.seal.mode == modeBuckets)
	out.SealEnabled = s.seal != nil
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
		out.Pending = append(out.Pending, *it)
	}
	if s.bastionOn {
		tasks, err := s.setupItems(ctx, sess)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		out.Pending = append(out.Pending, tasks...)
		if out.BastionRootUntil, err = q.ActiveBastionRoot(ctx, now); err != nil {
			s.writeErr(w, r, err)
			return
		}
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
		a, err := s.bindAction(ctx, q, canon.Action{Object: "standing", Action: "revoke", ID: st.ID, Kind: st.Kind})
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		out.Standing = append(out.Standing, api.StandingApproval{Indefinite: st.ExpiresAt.Equal(untilRevoked), ScopedFacts: a.CardFacts(), ID: st.ID, RequestingHost: st.HostName, Kind: st.Kind,
			TargetHost: st.TargetHost, LoginUser: st.LoginUser, MaxTTLSeconds: st.MaxTTL, ExpiresAt: st.ExpiresAt, Uses: st.Uses,
			Scope: st.Scope, ScopeParams: st.ScopeParams, Mode: st.Mode})
	}
	gs, err := q.ActiveGrants(ctx, now)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for _, g := range gs {
		a, err := s.bindAction(ctx, q, canon.Action{Object: "grant", Action: "revoke", ID: g.ID, Kind: g.Kind})
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		out.Grants = append(out.Grants, api.GrantSummary{Indefinite: g.NotAfter.Equal(untilRevoked), ScopedFacts: a.CardFacts(), ID: g.ID, Kind: g.Kind, Status: g.Status(now),
			TargetHost: g.TargetHost, LoginUser: g.LoginUser, NotBefore: g.NotBefore, NotAfter: g.NotAfter, RequestingHost: g.HostName,
			Scope: g.Scope, ScopeParams: g.ScopeParams, Mode: g.Mode})
	}
	if out.Recent, err = q.RecentAudit(ctx, 50); err != nil {
		s.writeErr(w, r, err)
		return
	}
	pks, err := loadPasskeys(ctx, q)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	cur, err := q.SessionPasskeyID(ctx, sess)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, err)
		return
	}
	out.Passkeys = make([]api.PasskeyInfo, 0, len(pks))
	for i := range pks {
		p := pks[i].info(cur)
		if s.seal != nil {
			p.RawID = encodeID(pks[i].CredentialID)
			if s.sealServing() {
				// The last time this passkey's wraps were proven: the latest tested scope wrap.
				wraps, err := q.ScopeWraps(ctx, pks[i].ID)
				if err != nil {
					s.writeErr(w, r, err)
					return
				}
				for _, w := range wraps {
					if w.Tested != nil && (p.TestedAt == nil || w.Tested.After(*p.TestedAt)) {
						p.TestedAt = w.Tested
					}
				}
				bwraps, err := q.BrowserWraps(ctx, 0)
				if err != nil {
					s.writeErr(w, r, err)
					return
				}
				for _, bw := range bwraps {
					if bw.Passkey == pks[i].ID && bw.Tested != nil && (p.TestedAt == nil || bw.Tested.After(*p.TestedAt)) {
						p.TestedAt = bw.Tested
					}
				}
			}
		}
		out.Passkeys = append(out.Passkeys, p)
	}
	writeJSON(w, http.StatusOK, out)
}

// highRisk marks requests the card flags as risk "high": unknown or high_risk targets, root,
// TTLs above 4 h. Standing approvals are refused for them.
func (s *Server) highRisk(rq *store.Request) bool {
	tgt, ok := s.cfg.Target(rq.TargetHost)
	return !ok || tgt.HighRisk || rq.LoginUser == "root" || rq.TTLRequested > 4*3600
}

func (s *Server) requestItem(ctx context.Context, rq *store.Request) (*api.PendingItem, error) {
	if rq.Kind == api.KindBastion {
		return s.bastionItem(ctx, rq)
	}
	a, err := s.bindAction(ctx, s.store.Q(), canon.Action{Object: "request", ID: rq.ID, Kind: rq.Kind})
	if err != nil {
		return nil, err
	}
	h, err := s.store.Q().GetHost(ctx, rq.HostID)
	if err != nil {
		return nil, err
	}
	maxHours := s.cfg.TTL.ForHost(h.Class).MaxStandingHours
	if rq.Kind == api.KindCloudflare {
		it, err := s.cfRequestItem(ctx, rq)
		if err == nil {
			it.MaxStandingHours = maxHours
			it.ScopedFacts = a.CardFacts()
			if a.OrgID != "" {
				it.Cloudflare.StandingAllowed = a.OffersStanding
				if rq.TTLRequested == -1 {
					l, err := s.decisionLimits(ctx, s.store.Q(), rq)
					if err != nil {
						return nil, err
					}
					it.TTLRequested = l.DefaultTTL
					it.TTLMax = l.Hard
				}
			}
		}
		return it, err
	}
	var similar int
	since := s.now().Add(-7 * 24 * time.Hour)
	if s.store.Q().Scoped() {
		similar, err = s.store.Q().CountBoundSimilar(ctx, rq.ID, since)
	} else {
		similar, err = s.store.Q().CountSimilar(ctx, rq.HostID, rq.TargetHost, rq.LoginUser, since)
	}
	if err != nil {
		return nil, err
	}
	risk := "normal"
	if s.highRisk(rq) {
		risk = "high"
	}
	return &api.PendingItem{
		ScopedFacts: a.CardFacts(),
		ID:          rq.ID, Kind: rq.Kind, CreatedAt: rq.CreatedAt, ExpiresAt: rq.ExpiresAt,
		RequestingHost: rq.HostName, RequestingAddress: rq.PeerAddress, Requester: rq.Requester, Reason: rq.Reason,
		MaxStandingHours: maxHours, SSH: &api.PendingSSH{Principal: rq.Principal, RequestedTarget: rq.RequestedTarget, TargetAddress: rq.TargetAddress, TargetPort: rq.TargetPort, TargetHost: rq.TargetHost, LoginUser: rq.LoginUser, KeyFingerprint: rq.KeyFingerprint},
		TTLRequested: rq.TTLRequested, TTLMax: rq.TTLRequested, Risk: risk, SimilarRecent: similar,
	}, nil
}

// cfRequestItem is the approval card of a Cloudflare request (docs/API.md 5.7).
func (s *Server) cfRequestItem(ctx context.Context, rq *store.Request) (*api.PendingItem, error) {
	var similar int
	var err error
	since := s.now().Add(-7 * 24 * time.Hour)
	if s.store.Q().Scoped() {
		similar, err = s.store.Q().CountBoundSimilar(ctx, rq.ID, since)
	} else {
		similar, err = s.store.Q().CountSimilarScope(ctx, rq.HostID, rq.Scope, since)
	}
	if err != nil {
		return nil, err
	}
	pc := &api.PendingCloudflare{Scope: rq.Scope, Params: map[string]string{}, ScopeParams: rq.ScopeParams, Mode: rq.Mode,
		IPCondition: rq.IPCondition, Title: rq.Scope, Risk: api.CFRiskHigh}
	if p, err := cfscope.ParseParams(rq.ScopeParams); err == nil {
		pc.Params = p
	}
	if s.cf.cat != nil {
		if sc, ok := s.cf.cat.Lookup(rq.Scope); ok {
			pc.Title, pc.Description, pc.Risk = sc.Title, sc.Description, sc.Risk
			pc.StandingAllowed = sc.StandingAllowed && rq.Mode == api.CFModeProxy
		}
		if res, err := s.cf.cat.Reparse(rq.Scope, rq.ScopeParams, rq.Mode); err == nil {
			pc.Permissions, pc.Notes = res.Permissions, res.Notes
		} else if rq.Status == api.StatusPending {
			pc.StandingAllowed = false
			pc.Notes = append(pc.Notes, "This request can no longer be approved: "+err.Error())
		}
	} else if rq.Status == api.StatusPending {
		pc.Notes = []string{"Cloudflare is not enabled on this aqmasd: this request cannot be approved."}
	}
	risk := "normal"
	if pc.Risk == api.CFRiskHigh || pc.Risk == api.CFRiskAdmin {
		risk = "high"
	}
	return &api.PendingItem{
		ID: rq.ID, Kind: rq.Kind, CreatedAt: rq.CreatedAt, ExpiresAt: rq.ExpiresAt,
		RequestingHost: rq.HostName, RequestingAddress: rq.PeerAddress, Requester: rq.Requester, Reason: rq.Reason,
		Cloudflare: pc, TTLRequested: rq.TTLRequested, TTLMax: rq.TTLRequested, Risk: risk, SimilarRecent: similar,
	}, nil
}

func (s *Server) enrollmentItem(ctx context.Context, e *store.Enrollment) api.PendingItem {
	risk, replaces := "normal", false
	replacesID := ""
	p := s.cfg.TTL.ForHost(e.Class)
	if old, err := s.store.Q().ActiveHostByName(ctx, e.Hostname); err == nil {
		replacesID = old.EnrollmentID
		risk, replaces = "high", true // replaces an existing host identity
	}
	fps := e.SSHHostKeyFPs
	if fps == nil {
		fps = []string{}
	}
	return api.PendingItem{
		ID: e.ID, Kind: "enrollment", CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt,
		RequestingHost: e.Hostname, RequestingAddress: e.PeerAddress, Reason: e.Note, Risk: risk,
		Enrollment: &api.PendingEnrollment{MaxSSHSeconds: p.MaxSeconds, MaxStandingHours: p.MaxStandingHours, ReplacesID: replacesID, Class: e.Class, CSRFingerprint: e.KeyFingerprint, SSHHostKeyFingerprints: fps, ReplacesExisting: replaces},
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
	it.Status = rq.Status
	writeJSON(w, http.StatusOK, it)
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
		if a.Kind == api.KindCloudflare {
			text = fmt.Sprintf("aqmas: %s cloudflare %s (%s) for %s, ttl %ds, standing %dh", a.Action, cfDesc(a.Scope, a.ScopeParams), a.Mode, a.RequestingHost, a.TTLSeconds, a.StandingHours)
		}
	case canon.ObjectEnrollment:
		text = fmt.Sprintf("aqmas: %s enrollment of %s (%s, replaces existing: %t)", a.Action, a.RequestingHost, a.Class, a.Replaces)
	case canon.ObjectHost:
		text = fmt.Sprintf("aqmas: revoke host %s (%s from %s)", a.RequestingHost, a.Class, a.Address)
	case canon.ObjectStanding, canon.ObjectGrant:
		text = fmt.Sprintf("aqmas: %s %s %s@%s for %s", a.Action, a.Object, a.LoginUser, a.Target, a.RequestingHost)
		if a.Kind == api.KindCloudflare {
			text = fmt.Sprintf("aqmas: %s %s cloudflare %s (%s) for %s", a.Action, a.Object, cfDesc(a.Scope, a.ScopeParams), a.Mode, a.RequestingHost)
		}
	case canon.ObjectPasskey:
		if a.Action == canon.ActionRename {
			text = fmt.Sprintf("aqmas: rename passkey %q to %q", a.Nickname, a.NewNickname)
		} else {
			text = fmt.Sprintf("aqmas: %s passkey %q", a.Action, a.Nickname)
		}
	}
	text += fmt.Sprintf(" [ref %s]", ref(a.ID))
	if canon.CatalogueActions[a.Object] != nil {
		var change api.CatalogueChange
		if json.Unmarshal([]byte(a.Plan), &change) == nil {
			text = change.Org.Slug + ": " + text
		}
	}
	if a.Indefinite || a.StandingIndefinite {
		text += " INDEFINITE until revoked"
	}
	if a.BeyondSoft || a.StandingBeyondSoft {
		text += " (beyond soft cap)"
	}
	if a.OrgID != "" {
		text = a.OrgSlug + "/" + a.ServiceSlug + "/" + a.SetSlug + ": " + text
	}
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
		if object == canon.ObjectPasskey && id == "" {
			id = "new" // POST /api/ui/passkeys/challenge: adding a passkey
		}
		var a canon.Action
		var err error
		if canon.CatalogueActions[object] != nil {
			a, err = s.catalogueChallenge(ctx, sess, object, id, in)
		} else {
			a, err = s.buildAction(ctx, object, id, in)
		}
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if a.OrgID != "" {
			q := s.store.Q()
			key, err := q.SessionPasskeyID(ctx, sess)
			if err != nil || q.IsOrgOwner(ctx, a.OrgID, sess, key, s.now()) != nil {
				s.writeErr(w, r, errForbidden("not an organisation approver"))
				return
			}
		}
		if object == "update" && s.seal != nil && s.seal.mode == modeMigration {
			s.writeErr(w, r, migrationErr())
			return
		}
		// The buckets this decision needs come from stored state and the choice (§4.1).
		needs, err := s.decisionNeeds(ctx, s.store.Q(), a)
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
		opts, t, err := s.actionOptions(ctx, sess, text, needs, nil)
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
		if t != nil {
			t.canonical = text
			s.seal.taps.put(c.ID, t, now)
		}
		writeJSON(w, http.StatusOK, api.ChallengeResponse{ChallengeID: c.ID, Canonical: text, PublicKey: opts, Open: t.offer()})
	}
}

// verifyAction consumes an action challenge and verifies the assertion against exactly the
// stored canonical text (bound to its open descriptor when the challenge offered one). id ""
// skips the object-id check (passkey registration). settle is never nil; see verifyTap.
func (s *Server) verifyAction(ctx context.Context, sess, object, id, challengeID string, assertion json.RawMessage, pkt *api.OpenPacket) (canon.Signed, int64, func(bool), error) {
	noop := func(bool) {}
	c, err := s.consume(ctx, challengeID, "action", s.now())
	if err != nil {
		return canon.Signed{}, 0, noop, err
	}
	drop := func() {
		if s.seal != nil {
			s.seal.taps.take(c.ID)
		}
	}
	if c.SessionHash != sess {
		drop()
		return canon.Signed{}, 0, noop, errForbidden("challenge was issued to another session")
	}
	if c.ObjectType != object || (id != "" && c.ObjectID != id) {
		drop()
		return canon.Signed{}, 0, noop, errBad("challenge is for a different object")
	}
	sg, err := canon.Parse(c.Canonical)
	if err != nil {
		drop()
		return canon.Signed{}, 0, noop, err
	}
	if sg.Object != object || sg.ID != c.ObjectID {
		drop()
		return canon.Signed{}, 0, noop, errBad("challenge is for a different object")
	}
	pkID, settle, err := s.verifyTap(ctx, sess, c.ID, c.Canonical, assertion, pkt)
	if err != nil {
		return canon.Signed{}, 0, noop, err
	}
	return sg, pkID, settle, nil
}

func (s *Server) decideHandler(object string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sess string) {
		ctx := r.Context()
		var in api.DecideRequest
		if err := decode(r, &in); err != nil {
			s.writeErr(w, r, err)
			return
		}
		id := r.PathValue("id")
		sg, pkID, settle, err := s.verifyAction(ctx, sess, object, id, in.ChallengeID, in.Assertion, in.Open)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		settled := false
		defer func() {
			if !settled {
				settle(false)
			}
		}()
		if object == "update" {
			s.queueUpdate(w, r, sg, in.Assertion, pkID)
			return
		}
		if canon.CatalogueActions[object] != nil {
			if err := s.catalogueApply(ctx, sess, pkID, sg); err != nil {
				s.writeErr(w, r, err)
				return
			}
			s.bcast.notify()
			s.notifyDecision(sg)
			writeJSON(w, 200, api.OK{OK: true})
			return
		}
		if object == canon.Migration {
			if err := s.activate(ctx, sess, pkID, sg); err != nil {
				s.writeErr(w, r, err)
				return
			}
			s.notify.Send("aqmas: personal", "Activated personal catalogue [ref "+ref(id)+"]", s.cfg.PublicBaseURL+"/")
			writeJSON(w, 200, api.OK{OK: true})
			return
		}
		if err := s.apply(context.WithValue(ctx, sessionBindingKey{}, sess), sg, pkID); err != nil {
			s.writeErr(w, r, err)
			return
		}
		settle(true)
		settled = true
		if s.seal != nil {
			s.reconcileHolds(ctx) // revokes end holds; new standing rules get their own
		}
		if object == canon.ObjectRequest && sg.Kind == api.KindBastion {
			// Root: the alert is attempted and its outcome recorded here, before the
			// requester can collect the certificate.
			out, err := s.afterBastionDecision(ctx, sg)
			s.bcast.notify()
			if err != nil {
				s.writeErr(w, r, err)
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if object == canon.ObjectGrant {
			s.afterGrantRevoke(ctx, id) // token grants: delete the child token upstream now
		}
		if s.cf.minter != nil && (object == canon.ObjectHost || object == canon.ObjectEnrollment && sg.Replaces && sg.Action.Action == canon.ActionApprove) {
			s.sweepTokens(ctx)
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
			writeJSON(w, http.StatusOK, api.RevokeResult{OK: true, ID: id, Status: api.StatusRevoked})
		}
	}
}

// passkeyChangeHandler applies a signed passkey rename or remove. The endpoint's verb must be
// the signed action, so an assertion for "rename A" can be used neither to remove A nor to
// touch any other passkey (verifyAction binds it to A's id).
func (s *Server) passkeyChangeHandler(verb string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sess string) {
		ctx := r.Context()
		var in api.DecideRequest
		if err := decode(r, &in); err != nil {
			s.writeErr(w, r, err)
			return
		}
		id := r.PathValue("id")
		if in.Open != nil {
			s.writeErr(w, r, errBad("this action opens no bucket"))
			return
		}
		sg, pkID, settle, err := s.verifyAction(ctx, sess, canon.ObjectPasskey, id, in.ChallengeID, in.Assertion, nil)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		settle(false)
		if sg.Action.Action != verb {
			s.writeErr(w, r, errBad("the signed action is "+sg.Action.Action+", not "+verb))
			return
		}
		if err := s.apply(context.WithValue(ctx, sessionBindingKey{}, sess), sg, pkID); err != nil {
			s.writeErr(w, r, err)
			return
		}
		s.bcast.notify()
		s.notifyDecision(sg)
		out := api.PasskeyChange{OK: true, ID: id, Action: verb, Nickname: sg.Nickname}
		if verb == canon.ActionRemove && s.seal != nil {
			s.seal.opens.Invalidate()
			s.seal.taps.clear()
			s.seal.capabilities.wipe()
			_ = s.store.CheckpointWAL(ctx)
		}
		if verb == canon.ActionRename {
			out.Nickname = sg.NewNickname
		}
		if _, ok := s.sessionHash(r); !ok {
			// The removed passkey was this session's: the session ended with it.
			out.SignedOut = true
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		}
		writeJSON(w, http.StatusOK, out)
	}
}
