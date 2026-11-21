package server

// Milestone 2: Cloudflare requests, grants, child-token delivery, the proxy mount and the token
// sweeper (docs/CLOUDFLARE.md, docs/API.md section 5). The proxy itself, the snapshot store and
// the minter's HTTP calls live in internal/server/cfproxy; the scope catalogue in cfscope.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfproxy"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/policy"
	"github.com/aquarat/agent-quartermaster/internal/server/secretfile"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Cloudflare tunables.
const (
	// CFProxyTimeout bounds one proxied call (read and write deadlines on its connection):
	// long enough for a 100 MiB upload on a slow link, unlike the agent API's 30 s default.
	CFProxyTimeout = 15 * time.Minute
	// cfUpstreamTimeout bounds one minter call (mint, delete, list).
	cfUpstreamTimeout = 30 * time.Second
	// Sweeper periods (docs/CLOUDFLARE.md section 5).
	cfTokenSweepEvery  = time.Minute
	cfOrphanSweepEvery = 15 * time.Minute
	cfPruneEvery       = time.Hour
	// maxParentTokenBytes bounds a parent token file.
	maxParentTokenBytes = 16 << 10
)

// tokenMinter is what core needs of *cfproxy.Minter (tests inject a fake).
type tokenMinter interface {
	Mint(ctx context.Context, req cfproxy.MintRequest) (*cfproxy.Minted, error)
	Delete(ctx context.Context, id string) error
	ListAqmas(ctx context.Context) ([]cfproxy.UpstreamToken, error)
}

// cfProxy is what core needs of *cfproxy.Proxy (tests inject a fake).
type cfProxy interface {
	Serve(w http.ResponseWriter, r *http.Request, c cfproxy.Caller)
	ServeSnapshotList(w http.ResponseWriter, r *http.Request, c cfproxy.Caller)
	ServeSnapshotGet(w http.ResponseWriter, r *http.Request, c cfproxy.Caller, id string)
	Prune(ctx context.Context, now time.Time) error
}

var (
	_ tokenMinter = (*cfproxy.Minter)(nil)
	_ cfProxy     = (*cfproxy.Proxy)(nil)
)

// cfState is the Cloudflare part of a Server (zero when Cloudflare is disabled).
type cfState struct {
	cat    *cfscope.Catalogue
	proxy  cfProxy
	minter tokenMinter // nil: token mode off
	// sweeper bookkeeping (only touched by the sweeper goroutine and tests)
	lastTokenSweep, lastOrphanSweep, lastPrune time.Time
}

// setupCloudflare loads the parent tokens and builds the catalogue, proxy and minter. Any
// failure is fatal: aqmasd does not start with a half-configured Cloudflare section.
func (s *Server) setupCloudflare(o Options) error {
	cf := &s.cfg.Cloudflare
	cat, err := cfscope.NewCatalogue(cf)
	if err != nil {
		return err
	}
	var proxyTok string
	var provider func(context.Context) (string, error)
	if s.seal != nil {
		provider = func(ctx context.Context) (string, error) {
			b, err := s.secret(ctx, "cf-proxy")
			defer clear(b)
			return string(b), err
		}
	} else {
		proxyTok, err = loadParentToken("proxy", cf.ProxyTokenCredential, cf.ProxyTokenFile)
	}
	if err != nil {
		return err
	}
	var minterTok string
	if !s.store.Q().Scoped() && (cf.MinterTokenCredential != "" || cf.MinterTokenFile != "") {
		if minterTok, err = loadParentToken("minter", cf.MinterTokenCredential, cf.MinterTokenFile); err != nil {
			return err
		}
	}
	snapDir := cf.SnapshotDir
	if snapDir == "" {
		snapDir = filepath.Join(s.cfg.DataDir, "cf-snapshots")
	}
	var serviceID string
	if s.store.Q().Scoped() {
		if err := s.store.DB().QueryRow(`SELECT v.id FROM services v JOIN personal_cutover c ON c.org_id=v.org_id WHERE v.provider='cloudflare' AND v.slug='dns-cdn'`).Scan(&serviceID); err != nil {
			return err
		}
		snapDir = filepath.Join(snapDir, "services", serviceID)
	}
	newProxy := o.newCFProxy
	if newProxy == nil {
		newProxy = func(po cfproxy.Options) (cfProxy, error) { return cfproxy.New(po) }
	}
	p, err := newProxy(cfproxy.Options{
		Config:      cf,
		Catalogue:   cat,
		Grants:      cfGrantSource{s},
		ProxyToken:  proxyTok,
		Parent:      provider,
		SnapshotDir: snapDir,
		ServiceID:   serviceID,
		Notify:      func(title, text string) { s.notify.Send(title, text, s.cfg.PublicBaseURL+"/") },
		Log:         s.log,
		Now:         s.now,
		HTTPClient:  o.HTTPClient,
	})
	if err != nil {
		return fmt.Errorf("cloudflare proxy: %w", err)
	}
	s.cf.cat, s.cf.proxy = cat, p
	if minterTok != "" {
		client := o.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: cfUpstreamTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		}
		s.cf.minter = cfproxy.NewMinter(cf, minterTok, client)
	}
	tokenMode := s.cf.minter != nil && len(cf.TokenIPCondition) > 0
	if s.cf.minter != nil && len(cf.TokenIPCondition) == 0 {
		s.log.Warn("cloudflare: a minter token is configured but token_ip_condition is empty: token mode stays off")
	}
	s.log.Info("cloudflare enabled", "account", cf.AccountID, "zones", len(cf.Zones), "tunnels", len(cf.Tunnels),
		"d1_databases", len(cf.D1Databases), "scopes", len(cat.Scopes()), "token_mode", tokenMode, "snapshot_dir", snapDir)
	for _, w := range cf.Warnings() {
		s.log.Warn("cloudflare: " + w)
	}
	return nil
}

// loadParentToken reads a Cloudflare parent token once at start: from the systemd credential
// cred (under $CREDENTIALS_DIRECTORY) or from file (owned by aqmasd's uid, mode 0600 or 0400).
// Errors never contain the file's contents.
func loadParentToken(what, cred, file string) (string, error) {
	var b []byte
	var err error
	switch {
	case cred != "":
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return "", fmt.Errorf("cloudflare %s token: credential %q is configured but $CREDENTIALS_DIRECTORY is not set (run aqmasd under systemd with LoadCredential=%s:<file>)", what, cred, cred)
		}
		b, err = readSecretFile(filepath.Join(dir, cred), false)
	case file != "":
		b, err = readSecretFile(file, true)
	default:
		return "", fmt.Errorf("cloudflare %s token: not configured", what)
	}
	if err != nil {
		return "", fmt.Errorf("cloudflare %s token: %w", what, err)
	}
	tok := strings.TrimSpace(string(b))
	clear(b)
	if tok == "" {
		return "", fmt.Errorf("cloudflare %s token: the file is empty", what)
	}
	for _, r := range tok {
		if r <= 0x20 || r >= 0x7f {
			return "", fmt.Errorf("cloudflare %s token: the file holds more than one printable ASCII word", what)
		}
	}
	return tok, nil
}

// readSecretFile reads a small regular file. strict additionally requires it to be owned by
// the running uid with mode 0600 or 0400 (a token file outside systemd's credential store).
func readSecretFile(path string, strict bool) ([]byte, error) {
	return secretfile.Read(path, !strict, maxParentTokenBytes)
}

// ---- GrantSource for the proxy ----

type cfGrantSource struct{ s *Server }

var _ cfproxy.GrantSource = cfGrantSource{}

func (gs cfGrantSource) ProxyGrants(ctx context.Context, hostID int64, gids []string, now time.Time) ([]cfproxy.Grant, error) {
	if len(gids) > 16 {
		gids = gids[:16] // the proxy accepts at most 8; never let a header fan out into many queries
	}
	gl, err := gs.s.store.Q().ActiveProxyGrants(ctx, hostID, gids, now)
	if err != nil {
		return nil, err
	}
	out := make([]cfproxy.Grant, 0, len(gl))
	for _, g := range gl {
		out = append(out, cfproxy.Grant{ID: g.ID, HostID: g.HostID, HostName: g.HostName, PeerAddress: g.PeerAddress,
			Scope: g.Scope, ScopeParams: g.ScopeParams, Mode: g.Mode, NotAfter: g.NotAfter, Ref: ref(g.RequestID)})
	}
	return out, nil
}

var _ cfproxy.ScopeLister = cfGrantSource{}

// ActiveScopes lists the scopes of the host's active Cloudflare grants (sensitive snapshots).
func (gs cfGrantSource) ActiveScopes(ctx context.Context, hostID int64, now time.Time) ([]string, error) {
	peer, _ := ctx.Value(snapshotPeerKey{}).(string)
	return gs.s.store.Q().CFScopesAt(ctx, hostID, now, peer)
}

type snapshotPeerKey struct{}

func (gs cfGrantSource) HasActiveGrant(ctx context.Context, hostID int64, now time.Time) (bool, error) {
	if gs.s.store.Q().Scoped() {
		scopes, err := gs.ActiveScopes(ctx, hostID, now)
		return len(scopes) > 0, err
	}
	return gs.s.store.Q().HasActiveCFGrant(ctx, hostID, now)
}

func (gs cfGrantSource) Audit(ctx context.Context, actor, action, object, detail string) error {
	err := gs.s.store.Q().Audit(ctx, gs.s.now(), actor, action, object, detail)
	if err == nil {
		gs.s.bcast.notify()
	}
	return err
}

// ---- requests ----

// cfTTL clamps a requested TTL for a scope: 0 or less means the scope's default; the result
// lies in [ttl.min_seconds, min(scope max, ttl.max_seconds)].
func (s *Server) cfTTL(requested int, sc *cfscope.Scope) int {
	hi := min(sc.MaxTTL, s.cfg.TTL.MaxSeconds)
	ttl := requested
	if ttl <= 0 {
		ttl = sc.DefaultTTL
	}
	ttl = max(ttl, s.cfg.TTL.MinSeconds)
	return min(ttl, hi)
}

// ipCondition is the child-token IP condition in canonical form: the configured CIDRs, sorted,
// joined by ",".
func (s *Server) ipCondition() string {
	c := slices.Clone(s.cfg.Cloudflare.TokenIPCondition)
	slices.Sort(c)
	return strings.Join(c, ",")
}

func (s *Server) handleCreateCloudflare(w http.ResponseWriter, r *http.Request, h *store.Host, in *api.AccessRequest) {
	if s.store.Q().Scoped() {
		alias, kind := "proxy", "cloudflare-proxy"
		if in.Cloudflare != nil && in.Cloudflare.Mode == api.CFModeToken {
			alias, kind = "mint", "cloudflare-mint"
		}
		if _, err := s.store.Q().PersonalResource(r.Context(), h.ID, kind, alias, s.now()); err != nil {
			s.writeErr(w, r, mapNotFound(err))
			return
		}
	}
	if s.cf.cat == nil {
		s.writeErr(w, r, errBad("Cloudflare is not enabled on this aqmasd"))
		return
	}
	if in.Cloudflare == nil || in.SSH != nil {
		s.writeErr(w, r, errBad(`kind "cloudflare" needs a cloudflare object and no ssh object`))
		return
	}
	res, err := s.cf.cat.Resolve(*in.Cloudflare)
	if err != nil {
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	if res.Mode == api.CFModeToken && s.cf.minter == nil {
		s.writeErr(w, r, errBad("child tokens are not configured on this aqmasd (no minter token): use mode proxy"))
		return
	}
	peer := peerIP(r)
	if net.ParseIP(peer) == nil {
		s.writeErr(w, r, errBad("cannot determine peer address"))
		return
	}
	now := s.now()
	ttl := s.cfTTL(in.TTLSeconds, res.Scope)
	req := &store.Request{
		ID:           ids.New(),
		HostID:       h.ID,
		HostName:     h.Name,
		PeerAddress:  peer,
		Kind:         api.KindCloudflare,
		Reason:       in.Reason,
		Requester:    in.Requester,
		TTLRequested: ttl,
		Status:       api.StatusPending,
		CreatedAt:    now,
		ExpiresAt:    now.Add(secs(s.cfg.TTL.PendingExpirySeconds)),
		Scope:        res.Scope.Name,
		ScopeParams:  res.ScopeParams,
		Mode:         res.Mode,
	}
	if res.Mode == api.CFModeToken {
		req.IPCondition = s.ipCondition()
	}
	what := cfDesc(req.Scope, req.ScopeParams)
	ctx := r.Context()
	err = s.store.Tx(ctx, func(q *store.Q) error {
		auto, standing := res.Scope.AutoApprove, res.Scope.StandingAllowed
		if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
			return err
		}
		if q.Scoped() {
			kind, alias := "cloudflare-proxy", "proxy"
			if req.Mode == api.CFModeToken {
				kind, alias = "cloudflare-mint", "mint"
			}
			b, err := q.PersonalResource(ctx, h.ID, kind, alias, s.now())
			if err != nil {
				return mapNotFound(err)
			}
			l, err := s.limits(ctx, q, b, req.Scope)
			if err != nil {
				return err
			}
			ttl, err = l.requestTTL(in.TTLSeconds, s.cfg.TTL.MinSeconds, in.Indefinite)
			if err != nil {
				return err
			}
			req.TTLRequested = ttl
			auto = l.Auto && ttl > 0 && ttl <= l.Soft
			standing = l.Standing && ttl > 0
		} else if in.Indefinite {
			return errBad("indefinite requires activated organisation policy")
		}
		approve := func(note string) (*store.Grant, error) {
			req.Status, req.DecidedAt, req.DecisionNote = api.StatusApproved, &now, note
			if err := q.InsertPersonalRequest(ctx, req); err != nil {
				return nil, err
			}
			return s.issueCFGrant(ctx, q, req, ttl, now)
		}
		// cf.read and cf.cache.purge in proxy mode need no approval.
		if s.authorisedWork(ctx) && auto && res.Mode == api.CFModeProxy {
			// Auto-approval needs no owner, so cap how many identical grants a host may hold:
			// the CLI reuses an active grant; a flood is a sign of a loop or a compromise.
			if n, err := q.CountActiveCFGrantsLike(ctx, h.ID, req.Scope, req.ScopeParams, req.Mode, now); err != nil {
				return err
			} else if n >= MaxAutoCFGrants {
				return &apiErr{http.StatusTooManyRequests, api.ErrRateLimited,
					fmt.Sprintf("this host already holds %d active %s grants; reuse one (aqmas list)", n, req.Scope)}
			}
			g, err := approve("auto-approved (" + req.Scope + ")")
			if err != nil {
				return err
			}
			return q.Audit(ctx, now, "system", "cf_auto_approve", "request:"+req.ID,
				fmt.Sprintf("grant=%s host=%s %s mode=%s ttl=%d from=%s", g.ID, h.Name, what, req.Mode, ttl, peer))
		}
		if s.authorisedWork(ctx) && standing && res.Mode == api.CFModeProxy {
			rules, err := q.ActiveStanding(ctx, h.ID, now)
			if err != nil {
				return err
			}
			cand := policy.Candidate{HostID: h.ID, PeerAddress: peer, Kind: req.Kind, Scope: req.Scope, ScopeParams: req.ScopeParams, Mode: req.Mode, TTL: ttl}
			for _, st := range rules {
				rule := policy.Rule{HostID: st.HostID, PeerAddress: st.PeerAddress, Kind: st.Kind, Target: st.TargetHost, LoginUser: st.LoginUser,
					MaxTTL: st.MaxTTL, ExpiresAt: st.ExpiresAt, Revoked: st.RevokedAt != nil, Scope: st.Scope, ScopeParams: st.ScopeParams, Mode: st.Mode}
				if !policy.Matches(rule, cand, now) {
					continue
				}
				req.StandingID = st.ID
				g, err := approve("standing approval " + st.ID)
				if err != nil {
					return err
				}
				if err := q.UseStanding(ctx, st.ID, now); err != nil {
					return err
				}
				return q.Audit(ctx, now, "system", "auto_approve", "request:"+req.ID,
					fmt.Sprintf("standing=%s grant=%s host=%s cloudflare %s mode=%s ttl=%d from=%s", st.ID, g.ID, h.Name, what, req.Mode, ttl, peer))
			}
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
			fmt.Sprintf("cloudflare %s mode=%s ttl=%d from=%s", what, req.Mode, ttl, peer))
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	url := s.approveURL(req.ID)
	if req.Status == api.StatusPending {
		text := fmt.Sprintf("aqmas: %s wants %s (%s)", h.Name, what, fmtTTL(ttl))
		if req.Mode == api.CFModeToken {
			text = fmt.Sprintf("aqmas: %s wants a Cloudflare token %s (%s)", h.Name, what, fmtTTL(ttl))
		}
		if req.Scope == api.CFScopeAdmin {
			text = "aqmas: BREAK-GLASS cf.admin for " + h.Name
		}
		s.notify.Send("aqmas: "+h.Name, text, url)
	}
	writeJSON(w, http.StatusCreated, api.RequestCreated{ID: req.ID, Status: req.Status, ApproveURL: url, PollAfterMS: PollAfterMS, ExpiresAt: req.ExpiresAt})
}

// cfDesc is "<scope> <scope_params>" (or the scope alone when it has no parameters).
func cfDesc(scope, scopeParams string) string {
	if scopeParams == "" {
		return scope
	}
	return scope + " " + scopeParams
}

// fmtTTL renders seconds compactly: "2h", "1h30m", "45m", "90s".
func fmtTTL(sec int) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d > time.Hour && d%time.Minute == 0:
		return fmt.Sprintf("%dh%dm", d/time.Hour, (d%time.Hour)/time.Minute)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", sec)
}

// cfCheckApprovable re-validates a stored Cloudflare request against the current config: the
// scope and its parameters must still resolve, and token mode needs the minter and an unchanged
// IP condition (the owner signs ip_condition; the token must carry exactly it).
func (s *Server) cfCheckApprovable(r *store.Request) (*cfscope.Resolved, error) {
	if s.cf.cat == nil {
		return nil, errConflict("Cloudflare is no longer enabled on this aqmasd")
	}
	res, err := s.cf.cat.Reparse(r.Scope, r.ScopeParams, r.Mode)
	if err != nil {
		return nil, errConflict("the scope or its parameters are no longer valid: " + err.Error())
	}
	if r.Mode == api.CFModeToken {
		if s.cf.minter == nil {
			return nil, errConflict("child tokens are no longer configured on this aqmasd")
		}
		if r.IPCondition != s.ipCondition() {
			return nil, errConflict("cloudflare.token_ip_condition changed since the request; ask again")
		}
	}
	return res, nil
}

// issueCFGrant records the grant for an approved Cloudflare request inside the caller's
// transaction. Validity starts at approval (now).
func (s *Server) issueCFGrant(ctx context.Context, q *store.Q, req *store.Request, ttl int, now time.Time) (*store.Grant, error) {
	if s.cf.cat == nil {
		return nil, errConflict("Cloudflare is no longer enabled on this aqmasd")
	}
	if _, err := s.cf.cat.Reparse(req.Scope, req.ScopeParams, req.Mode); err != nil {
		return nil, errConflict("the scope or its parameters are no longer valid: " + err.Error())
	}
	g := &store.Grant{
		ID:          ids.New(),
		RequestID:   req.ID,
		HostID:      req.HostID,
		HostName:    req.HostName,
		Kind:        api.KindCloudflare,
		NotBefore:   now,
		NotAfter:    now.Add(secs(ttl)),
		PeerAddress: req.PeerAddress,
		Scope:       req.Scope,
		ScopeParams: req.ScopeParams,
		Mode:        req.Mode,
		IPCondition: req.IPCondition,
	}
	if ttl == 0 && q.Scoped() && req.TTLRequested == -1 {
		g.NotAfter = untilRevoked
	}
	serial, err := q.InsertGrant(ctx, g)
	if err != nil {
		return nil, err
	}
	g.Serial = serial
	return g, nil
}

// ---- grant delivery ----

// cfGrantView is the agent-facing Cloudflare grant (never the token value).
func (s *Server) cfGrantView(g *store.Grant) *api.Grant {
	cg := &api.CloudflareGrant{
		Scope: g.Scope, ScopeParams: g.ScopeParams, Mode: g.Mode,
		AccountID: s.cfg.Cloudflare.AccountID, ProxyPath: cfproxy.PathPrefix,
		TokenID: g.TokenID, TokenDelivered: g.TokenDelivered,
	}
	if p, err := cfscope.ParseParams(g.ScopeParams); err == nil && len(p) > 0 {
		cg.Params = p
	}
	if g.Mode == api.CFModeToken && g.IPCondition != "" {
		cg.IPCondition = strings.Split(g.IPCondition, ",")
	}
	if s.cf.cat != nil {
		if res, err := s.cf.cat.Reparse(g.Scope, g.ScopeParams, g.Mode); err == nil {
			cg.Permissions = res.Permissions
		}
	}
	return &api.Grant{Indefinite: g.NotAfter.Equal(untilRevoked), ID: g.ID, Kind: g.Kind, NotBefore: g.NotBefore, NotAfter: g.NotAfter, Cloudflare: cg}
}

// tokenName is the upstream name of a grant's child token.
func tokenName(g *store.Grant) string { return "aqmas:" + g.ID + ":" + g.HostName }

// tokenNameRE matches tokenName's form exactly: ids are 26-character ULIDs, hosts valid names.
var tokenNameRE = regexp.MustCompile(`^aqmas:[0-9A-HJKMNP-TV-Z]{26}:[a-z0-9][a-z0-9-]{0,62}$`)

// MaxAutoCFGrants caps a host's active auto-approved grants of one scope+params.
const MaxAutoCFGrants = 4

var errMintFailed = &apiErr{http.StatusBadGateway, api.CFErrUpstream, "minting the Cloudflare token failed; poll again to retry"}

// deliverToken mints the child token of a token-mode grant on its first delivery
// (docs/CLOUDFLARE.md section 5): claim the delivery in the database, mint, record the token id
// and put the value in out (once; it is never stored). A failed mint undoes the claim and
// answers 502 so the next poll retries.
func (s *Server) deliverToken(w http.ResponseWriter, r *http.Request, h *store.Host, out *api.RequestStatus) error {
	if out.Grant == nil || out.Grant.Cloudflare == nil {
		return nil
	}
	cg := out.Grant.Cloudflare
	if cg.Mode != api.CFModeToken || cg.TokenDelivered {
		return nil
	}
	ctx := r.Context()
	now := s.now()
	g, err := s.store.Q().GetGrant(ctx, out.Grant.ID)
	if err != nil {
		return err
	}
	if !g.Active(now) {
		return nil
	}
	if s.cf.minter == nil {
		return errConflict("child tokens are no longer configured on this aqmasd")
	}
	if s.cf.cat == nil {
		return errConflict("Cloudflare is no longer enabled on this aqmasd")
	}
	res, err := s.cf.cat.Reparse(g.Scope, g.ScopeParams, g.Mode)
	if err != nil {
		return errConflict("the scope or its parameters are no longer valid: " + err.Error())
	}
	won, err := s.store.Q().MarkTokenDelivering(ctx, g.ID, now)
	if err != nil {
		return err
	}
	if !won { // another poll is minting or has delivered it
		cg.TokenDelivered = true
		return nil
	}
	// This poll may already have waited most of the agent API's write timeout: give the mint
	// and the answer their own time, or a minted (and recorded) token could never be delivered.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(cfUpstreamTimeout + 15*time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.log.Warn("cloudflare: cannot extend write deadline for token delivery", "error", err)
	}
	// Finish (or undo) the mint even if this client goes away mid-call.
	bg := context.WithoutCancel(ctx)
	unmark := func() {
		if err := s.store.Q().UnmarkTokenDelivered(bg, g.ID); err != nil {
			s.log.Error("cloudflare: could not undo a token delivery claim", "grant", g.ID, "error", err)
		}
	}
	mctx, cancel := context.WithTimeout(bg, cfUpstreamTimeout)
	defer cancel()
	m, err := s.cf.minter.Mint(mctx, cfproxy.MintRequest{
		Name: tokenName(g), NotBefore: now, ExpiresOn: g.NotAfter, IPIn: strings.Split(g.IPCondition, ","), Resolved: res,
	})
	if err == nil && (m == nil || m.ID == "" || m.Value == "") {
		if m != nil && m.ID != "" {
			s.deleteUpstream(bg, m.ID)
		}
		err = errors.New("minter returned no token")
	}
	if err != nil {
		unmark()
		s.log.Warn("cloudflare: child token mint failed", "grant", g.ID, "host", h.Name, "error", err)
		return errMintFailed
	}
	if ctx.Err() != nil {
		// The agent is gone and would never see the value: delete it, let the next poll mint again.
		s.deleteUpstream(bg, m.ID)
		unmark()
		return ctx.Err()
	}
	err = s.store.Tx(bg, func(q *store.Q) error {
		if err := q.SetTokenID(bg, g.ID, m.ID); err != nil {
			return err
		}
		return q.Audit(bg, now, "host:"+h.Name, "cf_token_mint", "grant:"+g.ID,
			fmt.Sprintf("token_id=%s %s expires=%s ip=%s permissions=%s", m.ID, cfDesc(g.Scope, g.ScopeParams),
				g.NotAfter.Format(time.RFC3339), g.IPCondition, strings.Join(res.Permissions, "; ")))
	})
	if err != nil {
		s.deleteUpstream(bg, m.ID)
		unmark()
		return err
	}
	// Revoked while minting? Then the token must not be handed out (the sweeper would delete
	// it within a minute anyway; do it now).
	if g2, err := s.store.Q().GetGrant(bg, g.ID); err == nil && g2.RevokedAt != nil {
		if err := s.deleteGrantToken(bg, g2); err != nil {
			s.log.Warn("cloudflare: deleting a token revoked during its mint failed (the sweeper retries)", "grant", g.ID, "error", err)
		}
		out.Status, out.Grant = api.StatusRevoked, nil
		return nil
	}
	s.bcast.notify()
	cg.Token, cg.TokenID, cg.TokenDelivered = m.Value, m.ID, true
	return nil
}

// deleteUpstream deletes a token by id, best effort (the orphan sweep catches failures).
func (s *Server) deleteUpstream(ctx context.Context, tokenID string) {
	if s.cf.minter == nil {
		return
	}
	dctx, cancel := context.WithTimeout(ctx, cfUpstreamTimeout)
	defer cancel()
	if err := s.cf.minter.Delete(dctx, tokenID); err != nil {
		s.log.Warn("cloudflare: token delete failed (the sweeper retries)", "token_id", tokenID, "error", err)
	}
}

// deleteGrantToken deletes a grant's child token upstream and records it.
func (s *Server) deleteGrantToken(ctx context.Context, g *store.Grant) error {
	if g.TokenID == "" || g.TokenDeletedAt != nil {
		return nil
	}
	if s.cf.minter == nil {
		return errors.New("no minter token configured")
	}
	dctx, cancel := context.WithTimeout(ctx, cfUpstreamTimeout)
	defer cancel()
	if err := s.cf.minter.Delete(dctx, g.TokenID); err != nil {
		return err
	}
	now := s.now()
	why := "expired"
	if g.RevokedAt != nil {
		why = "revoked"
	}
	return s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.MarkTokenDeleted(ctx, g.ID, now); err != nil {
			return err
		}
		return q.Audit(ctx, now, "system", "cf_token_delete", "grant:"+g.ID, fmt.Sprintf("token_id=%s %s", g.TokenID, why))
	})
}

// afterGrantRevoke deletes a revoked token grant's child token at once (best effort; the
// sweeper retries every minute).
func (s *Server) afterGrantRevoke(ctx context.Context, id string) {
	g, err := s.store.Q().GetGrant(ctx, id)
	if err != nil || g.Kind != api.KindCloudflare || g.Mode != api.CFModeToken || g.TokenID == "" {
		return
	}
	if err := s.deleteGrantToken(context.WithoutCancel(ctx), g); err != nil {
		s.log.Warn("cloudflare: deleting a revoked grant's token failed (the sweeper retries)", "grant", g.ID, "error", err)
	}
}

// ---- sweeper ----

// cfSweep runs the Cloudflare housekeeping that is due: token deletion (every minute), the
// upstream orphan check (every 15 minutes) and snapshot pruning (hourly).
func (s *Server) cfSweep(ctx context.Context) {
	if s.cf.cat == nil {
		return
	}
	now := s.now()
	if s.cf.minter != nil && now.Sub(s.cf.lastTokenSweep) >= cfTokenSweepEvery {
		s.cf.lastTokenSweep = now
		s.sweepTokens(ctx)
	}
	if s.cf.minter != nil && now.Sub(s.cf.lastOrphanSweep) >= cfOrphanSweepEvery {
		s.cf.lastOrphanSweep = now
		s.sweepOrphans(ctx)
	}
	if s.cf.proxy != nil && now.Sub(s.cf.lastPrune) >= cfPruneEvery {
		s.cf.lastPrune = now
		if err := s.cf.proxy.Prune(ctx, now); err != nil {
			s.log.Warn("cloudflare: snapshot prune failed", "error", err)
		}
	}
}

// sweepTokens deletes the child tokens of expired and revoked token grants.
func (s *Server) sweepTokens(ctx context.Context) {
	gs, err := s.store.Q().TokenGrantsToDelete(ctx, s.now())
	if err != nil {
		s.log.Warn("cloudflare: token sweep query failed", "error", err)
		return
	}
	for _, g := range gs {
		if ctx.Err() != nil {
			return
		}
		if err := s.deleteGrantToken(ctx, g); err != nil {
			s.log.Warn("cloudflare: token delete failed (retrying next minute)", "grant", g.ID, "token_id", g.TokenID, "error", err)
		}
	}
}

// sweepOrphans lists upstream aqmas:* tokens and deletes those past their expiry or unknown to
// aqmasd (no grant, another token id, revoked or expired grant).
func (s *Server) sweepOrphans(ctx context.Context) {
	lctx, cancel := context.WithTimeout(ctx, cfUpstreamTimeout)
	ups, err := s.cf.minter.ListAqmas(lctx)
	cancel()
	if err != nil {
		s.log.Warn("cloudflare: listing aqmas tokens failed", "error", err)
		return
	}
	for _, up := range ups {
		if ctx.Err() != nil {
			return
		}
		now := s.now()
		g, why := s.orphanReason(ctx, up, now)
		if why == "" {
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, cfUpstreamTimeout)
		err := s.cf.minter.Delete(dctx, up.ID)
		cancel()
		if err != nil {
			s.log.Warn("cloudflare: orphan token delete failed", "token_id", up.ID, "error", err)
			continue
		}
		name := sanitizeLine(up.Name, 200)
		object := "token:" + sanitizeLine(up.ID, 64)
		err = s.store.Tx(ctx, func(q *store.Q) error {
			if g != nil {
				object = "grant:" + g.ID
				if g.TokenID == up.ID {
					if err := q.MarkTokenDeleted(ctx, g.ID, now); err != nil {
						return err
					}
				}
			}
			return q.Audit(ctx, now, "system", "cf_token_orphan", object, fmt.Sprintf("token_id=%s name=%s %s", sanitizeLine(up.ID, 64), name, why))
		})
		if err != nil {
			s.log.Error("cloudflare: recording an orphan token delete failed", "token_id", up.ID, "error", err)
		}
		s.notify.Send("aqmas: Cloudflare token", fmt.Sprintf("aqmas: deleted Cloudflare token %s (%s)", name, why), s.cfg.PublicBaseURL+"/")
	}
}

// orphanReason says why an upstream aqmas:* token must go ("" = it is a live grant's token, or
// one being minted right now). The grant is returned when the name refers to one.
func (s *Server) orphanReason(ctx context.Context, up cfproxy.UpstreamToken, now time.Time) (*store.Grant, string) {
	// Only ever touch tokens aqmasd itself names ("aqmas:<grant id>:<host>"): a token the owner
	// happens to name "aqmas: ..." (e.g. the parents) is never deleted.
	if !tokenNameRE.MatchString(up.Name) {
		return nil, ""
	}
	if !up.ExpiresOn.IsZero() && !now.Before(up.ExpiresOn) {
		g, _ := s.grantForTokenName(ctx, up.Name)
		return g, "expired"
	}
	g, err := s.grantForTokenName(ctx, up.Name)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, "" // database trouble: try again next time
		}
		return nil, "unknown to aqmasd"
	}
	switch {
	case g.TokenID == "" && g.TokenDelivered && g.Active(now):
		return g, "" // minting in progress: SetTokenID follows
	case g.TokenID != up.ID:
		return g, "not the grant's recorded token"
	case g.RevokedAt != nil:
		return g, "grant revoked"
	case !now.Before(g.NotAfter):
		return g, "grant expired"
	}
	return g, ""
}

// grantForTokenName finds the token-mode grant an "aqmas:<grant id>:<host>" name refers to.
func (s *Server) grantForTokenName(ctx context.Context, name string) (*store.Grant, error) {
	parts := strings.Split(name, ":")
	if len(parts) != 3 || parts[0] != "aqmas" || parts[1] == "" || len(parts[1]) > 64 {
		return nil, store.ErrNotFound
	}
	g, err := s.store.Q().GetGrant(ctx, parts[1])
	if err != nil {
		return nil, err
	}
	if g.Kind != api.KindCloudflare || g.Mode != api.CFModeToken || tokenName(g) != name {
		return nil, store.ErrNotFound
	}
	return g, nil
}

// ---- agent endpoints ----

func (s *Server) cfCaller(r *http.Request, h *store.Host) cfproxy.Caller {
	return cfproxy.Caller{HostID: h.ID, HostName: h.Name, PeerAddress: peerIP(r)}
}

// handleCFProxy serves ANY /cf/client/v4/... for an authenticated host. Uploads may be large
// (100 MiB), so this route gets its own read/write deadlines instead of the API's 30 s.
func (s *Server) handleCFProxy(w http.ResponseWriter, r *http.Request, h *store.Host) {
	if s.cf.proxy == nil {
		s.writeErr(w, r, errNotFound())
		return
	}
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(CFProxyTimeout)
	if err := rc.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.log.Warn("cloudflare proxy: cannot extend read deadline", "error", err)
	}
	if err := rc.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.log.Warn("cloudflare proxy: cannot extend write deadline", "error", err)
	}
	s.cf.proxy.Serve(w, r, s.cfCaller(r, h))
}

func (s *Server) handleCFCatalogue(w http.ResponseWriter, r *http.Request, h *store.Host) {
	if s.cf.cat == nil {
		s.writeErr(w, r, errNotFound())
		return
	}
	cat := s.cf.cat.API()
	if s.store.Q().Scoped() {
		ctx := r.Context()
		err := s.store.Tx(ctx, func(q *store.Q) error {
			b, err := q.PersonalResource(ctx, h.ID, "cloudflare-proxy", "proxy", s.now())
			if err != nil {
				return mapNotFound(err)
			}
			for i := range cat.Scopes {
				sc := &cat.Scopes[i]
				l, err := s.limits(ctx, q, b, sc.Name)
				if err != nil {
					return err
				}
				sc.Modes = []string{api.CFModeProxy}
				sc.AutoApprove = l.Auto
				sc.StandingAllowed = l.Standing
				sc.DefaultTTL = l.DefaultTTL
				sc.MaxTTL = l.Hard
				sc.IndefiniteAvailable = l.Forever
			}
			return nil
		})
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, cat)
}

// cfSnapshotAccess: snapshots need Cloudflare enabled and an active Cloudflare grant.
func (s *Server) cfSnapshotAccess(r *http.Request, h *store.Host) error {
	if s.cf.proxy == nil {
		return errNotFound()
	}
	ok, err := (cfGrantSource{s}).HasActiveGrant(r.Context(), h.ID, s.now())
	if err != nil {
		return err
	}
	if !ok {
		return errForbidden("reading snapshots needs an active Cloudflare grant (cf.read is auto-approved)")
	}
	return nil
}

func (s *Server) handleCFSnapshots(w http.ResponseWriter, r *http.Request, h *store.Host) {
	r = r.WithContext(context.WithValue(r.Context(), snapshotPeerKey{}, peerIP(r)))
	if err := s.cfSnapshotAccess(r, h); err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.optionalLease(r.Context(), func(ctx context.Context) {
		if !s.authorisedWork(ctx) {
			s.writeErr(w, r, lockedErr())
			return
		}
		defer boundDelivery(ctx, w)()
		s.cf.proxy.ServeSnapshotList(s.deliveryWriter(ctx, w), r.WithContext(ctx), s.cfCaller(r, h))
	})
}

func (s *Server) handleCFSnapshot(w http.ResponseWriter, r *http.Request, h *store.Host) {
	r = r.WithContext(context.WithValue(r.Context(), snapshotPeerKey{}, peerIP(r)))
	if err := s.cfSnapshotAccess(r, h); err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.optionalLease(r.Context(), func(ctx context.Context) {
		if !s.authorisedWork(ctx) {
			s.writeErr(w, r, lockedErr())
			return
		}
		defer boundDelivery(ctx, w)()
		s.cf.proxy.ServeSnapshotGet(s.deliveryWriter(ctx, w), r.WithContext(ctx), s.cfCaller(r, h), r.PathValue("id"))
	})
}

// requireHostCF is requireHost for the proxy: refusals get a Cloudflare-shaped body so tools
// such as wrangler print the reason (docs/API.md 5.5).
func (s *Server) requireHostCF(next func(http.ResponseWriter, *http.Request, *store.Host)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, err := s.hostFromTLS(r)
		if err == nil {
			err = mapNotFound(s.store.Q().PersonalAdmission(r.Context(), h.ID, s.now()))
		}
		if err == nil && s.store.Q().Scoped() {
			_, err = s.store.Q().PersonalResource(r.Context(), h.ID, "cloudflare-proxy", "proxy", s.now())
			err = mapNotFound(err)
		}
		if err == nil {
			s.optionalLease(r.Context(), func(ctx context.Context) {
				if !s.authorisedWork(ctx) {
					err = lockedErr()
					return
				}
				defer boundDelivery(ctx, w)()
				next(s.deliveryWriter(ctx, w), r.WithContext(ctx), h)
			})
			if err == nil {
				return
			}
		}
		if err != nil {
			var ae *apiErr
			if !errors.As(err, &ae) {
				s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
				ae = errInternal()
			}
			body, _ := json.Marshal(map[string]any{
				"success":  false,
				"errors":   []map[string]any{{"code": api.CFErrorNumeric, "message": "aqmas " + ae.code + ": " + ae.msg}},
				"messages": []any{},
				"result":   nil,
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ae.status)
			w.Write(body)
			return
		}
	})
}

// isCFProxyPath reports whether the request is for the proxy. The ESCAPED path is checked so a
// percent-encoded prefix never reaches the proxy, and the mux (which cleans and redirects
// paths) never sees proxy paths: the proxy validates them itself (docs/CLOUDFLARE.md 3.1).
func isCFProxyPath(r *http.Request) bool {
	p := r.URL.EscapedPath()
	return p == cfproxy.PathPrefix || strings.HasPrefix(p, cfproxy.PathPrefix+"/")
}
