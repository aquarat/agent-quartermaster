// Package cfproxy is aqmasd's Cloudflare API proxy (docs/CLOUDFLARE.md sections 3-5): path
// normalisation, grant selection, scope matching (cfscope), the deny-list, guard rails,
// automatic snapshots before/after writes, parent-token injection, response redaction,
// synthetic endpoints, per-host rate limits and audit, plus the snapshot store and its agent
// endpoints, and the child-token minter client.
//
// The parent tokens are never logged, never put in an error, never written to disk.
package cfproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// ErrNotImplemented marks contract stubs (none left; kept for callers).
var ErrNotImplemented = errors.New("cfproxy: not implemented")

// PathPrefix is where the proxy is mounted on the agent API.
const PathPrefix = "/cf/client/v4"

// Caller is the authenticated host (core does the mTLS check before calling the proxy).
type Caller struct {
	HostID      int64
	HostName    string
	PeerAddress string // as seen on the mTLS connection
}

// Grant is an active proxy-mode Cloudflare grant as core stores it.
type Grant struct {
	ID          string
	HostID      int64
	HostName    string
	PeerAddress string // address of the request that created the grant
	Scope       string
	ScopeParams string
	Mode        string
	NotAfter    time.Time
	// Ref is the request's short reference shown on the card and by the CLI (optional; it
	// goes into write pushes as "[ref X]").
	Ref string
}

// GrantSource is implemented by core over its store.
type GrantSource interface {
	// ProxyGrants returns, in the order of ids, those grants that belong to hostID, are kind
	// "cloudflare" and mode "proxy", approved, not revoked and not expired at now. Unknown or
	// foreign ids are skipped silently.
	ProxyGrants(ctx context.Context, hostID int64, ids []string, now time.Time) ([]Grant, error)
	// HasActiveGrant reports whether hostID holds any active Cloudflare grant (either mode):
	// the condition for reading snapshots.
	HasActiveGrant(ctx context.Context, hostID int64, now time.Time) (bool, error)
	// Audit appends to the audit log (actor "host:<name>" or "system").
	Audit(ctx context.Context, actor, action, object, detail string) error
}

// Options configures a Proxy.
type Options struct {
	Config     *config.Cloudflare
	Catalogue  *cfscope.Catalogue
	Grants     GrantSource
	ProxyToken string // the proxy parent token (never logged)
	// SnapshotDir is where snapshots live (core resolves the default <data_dir>/cf-snapshots).
	SnapshotDir string
	Notify      func(title, text string) // ntfy push (may be nil)
	Log         *slog.Logger
	Now         func() time.Time
	HTTPClient  *http.Client // upstream client (tests inject one)
}

// Proxy serves the proxy and snapshot endpoints.
type Proxy struct {
	o      Options
	cfg    *config.Cloudflare
	cat    *cfscope.Catalogue
	base   *url.URL
	client *http.Client
	log    *slog.Logger
	lim    *limiter
	snaps  *snapStore

	rate, writeRate    int
	maxBody, uploadMax int64
	retentionDays      int
	vmu                sync.Mutex
	versions           map[verKey]int64 // tunnel config version each host last read
	zmu                sync.Mutex
	zoneNames          map[string]string // unconfigured zone id -> name (cf.admin)
}

type verKey struct {
	host   int64
	tunnel string
}

// New prepares the proxy (creates SnapshotDir 0700 if missing).
func New(o Options) (*Proxy, error) {
	if o.Config == nil || o.Catalogue == nil || o.Grants == nil {
		return nil, errors.New("cfproxy: Config, Catalogue and Grants are required")
	}
	if o.ProxyToken == "" {
		return nil, errors.New("cfproxy: no proxy parent token")
	}
	cfg := o.Config
	apiBase := cfg.APIBase
	if apiBase == "" {
		apiBase = "https://api.cloudflare.com/client/v4"
	}
	base, err := url.Parse(strings.TrimRight(apiBase, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && !(base.Scheme == "http" && cfg.AllowInsecureAPIBase)) || base.RawQuery != "" || base.User != nil {
		return nil, errors.New("cfproxy: api_base must be an https URL without query or user info")
	}
	var client http.Client
	if o.HTTPClient != nil {
		client = *o.HTTPClient
	} else {
		client = http.Client{Timeout: 10 * time.Minute}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	st, err := newSnapStore(o.SnapshotDir)
	if err != nil {
		return nil, err
	}
	p := &Proxy{o: o, cfg: cfg, cat: o.Catalogue, base: base, client: &client, log: o.Log, lim: newLimiter(), snaps: st,
		rate: cfg.RatePerMinute, writeRate: cfg.WriteRatePerMinute, maxBody: cfg.MaxBodyBytes, uploadMax: cfg.UploadMaxBodyBytes,
		retentionDays: cfg.SnapshotRetentionDays, versions: map[verKey]int64{}, zoneNames: map[string]string{}}
	if p.rate <= 0 {
		p.rate = 600
	}
	if p.writeRate <= 0 {
		p.writeRate = 60
	}
	if p.maxBody <= 0 {
		p.maxBody = 2 << 20
	}
	if p.uploadMax <= 0 {
		p.uploadMax = 100 << 20
	}
	if p.retentionDays <= 0 || p.retentionDays > 7 {
		p.retentionDays = 7
	}
	return p, nil
}

func (p *Proxy) now() time.Time { return p.o.Now() }

func (p *Proxy) notify(title, text string) {
	if p.o.Notify != nil {
		p.o.Notify(title, text)
	}
}

// Prune applies snapshot retention (retention days + newest per object key). core calls it
// from its sweeper about hourly.
func (p *Proxy) Prune(ctx context.Context, now time.Time) error {
	n, err := p.snaps.prune(now, p.retentionDays)
	if n > 0 {
		p.log.Info("cf snapshots pruned", "count", n)
	}
	return err
}

// ---- grants ----

var grantIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const maxOfferedGrants = 8

func parseGrantHeader(h string) ([]string, *refusal) {
	var out []string
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !grantIDRE.MatchString(part) {
			return nil, refuse(http.StatusBadRequest, api.CFErrBadRequest, "malformed "+api.CFGrantHeader)
		}
		out = append(out, part)
	}
	if len(out) > maxOfferedGrants {
		return nil, refuse(http.StatusBadRequest, api.CFErrBadRequest, fmt.Sprintf("at most %d grants per call", maxOfferedGrants))
	}
	return out, nil
}

type candidate struct {
	g   Grant
	res *cfscope.Resolved
}

// candidates: the offered grants usable by this caller from this address, in offer order.
func (p *Proxy) candidates(ctx context.Context, c Caller, ids []string, now time.Time) ([]candidate, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	gs, err := p.o.Grants.ProxyGrants(ctx, c.HostID, ids, now)
	if err != nil {
		return nil, err
	}
	var out []candidate
	for _, g := range gs {
		if g.HostID != c.HostID || g.PeerAddress == "" || g.PeerAddress != c.PeerAddress || g.Mode != api.CFModeProxy || !now.Before(g.NotAfter) {
			continue
		}
		res, err := p.cat.Reparse(g.Scope, g.ScopeParams, g.Mode)
		if err != nil {
			p.log.Warn("cf proxy: grant no longer valid against the config", "grant", g.ID, "error", err)
			continue
		}
		out = append(out, candidate{g: g, res: res})
	}
	return out, nil
}

// parseOverrides reads X-Aqmas-Override (cf.admin only).
func parseOverrides(h string, admin bool) (map[string]bool, *refusal) {
	if strings.TrimSpace(h) == "" {
		return nil, nil
	}
	if !admin {
		return nil, refuse(http.StatusBadRequest, api.CFErrBadRequest, api.CFOverrideHeader+" needs a cf.admin grant")
	}
	out := map[string]bool{}
	for _, n := range strings.Split(h, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if neverOverridable[n] {
			return nil, refuse(http.StatusBadRequest, api.CFErrBadRequest, "guard "+n+" can never be overridden")
		}
		if !overridable[n] {
			return nil, refuse(http.StatusBadRequest, api.CFErrBadRequest, "unknown guard "+asciiOnly(n))
		}
		out[n] = true
	}
	return out, nil
}

// ---- refusals, audit, logs ----

func (p *Proxy) refused(ctx context.Context, w http.ResponseWriter, c Caller, call cfscope.Call, grantID string, rf *refusal, audit, push bool) {
	if grantID != "" {
		w.Header().Set(api.CFGrantUsedHeader, grantID)
	}
	writeRefusal(w, rf)
	p.log.Info("cf proxy refused", "method", call.Method, "path", call.Path, "code", rf.code, "guard", rf.guard, "status", rf.status, "grant", grantID, "host", c.HostName)
	if audit {
		obj := "host:" + c.HostName
		if grantID != "" {
			obj = "grant:" + grantID
		}
		detail := fmt.Sprintf("%s %s code=%s", call.Method, call.Path, rf.code)
		if rf.guard != "" {
			detail += " guard=" + rf.guard
		}
		if err := p.o.Grants.Audit(ctx, "host:"+c.HostName, "cf_refused", obj, clip(detail, 1000)); err != nil {
			p.log.Error("cf proxy: audit", "error", err)
		}
	}
	if push {
		p.notify("aqmas: "+c.HostName, clip(fmt.Sprintf("aqmas: %s REFUSED %s %s (%s)", c.HostName, call.Method, call.Path, rf.msg), 300))
	}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- Serve ----

// Serve handles one proxied call; r.URL.Path starts with PathPrefix. core has authenticated
// the caller.
func (p *Proxy) Serve(w http.ResponseWriter, r *http.Request, c Caller) {
	ctx := r.Context()
	now := p.now()
	call, rf := normalise(r)
	if rf != nil {
		if call.Path == "" {
			call = cfscope.Call{Method: r.Method, Path: "(rejected)"}
		}
		p.refused(ctx, w, c, call, "", rf, false, false)
		return
	}
	if ok, wait := p.lim.take(c.HostID, false, p.rate, now); !ok {
		rf := refuse(http.StatusTooManyRequests, api.CFErrRateLimited, "too many Cloudflare calls from this host")
		rf.retryAfter = wait
		p.refused(ctx, w, c, call, "", rf, false, false)
		return
	}
	ids, rf := parseGrantHeader(r.Header.Get(api.CFGrantHeader))
	if rf != nil {
		p.refused(ctx, w, c, call, "", rf, false, false)
		return
	}
	cands, err := p.candidates(ctx, c, ids, now)
	if err != nil {
		p.log.Error("cf proxy: grants", "error", err)
		p.refused(ctx, w, c, call, "", refuse(http.StatusInternalServerError, api.CFErrUpstream, "internal error"), false, false)
		return
	}
	if cfscope.IsSynthetic(call) {
		p.serveSynthetic(w, call, c, cands)
		return
	}
	if d := p.cat.CheckDeny(call); d.Denied {
		p.refused(ctx, w, c, call, "", refuse(http.StatusForbidden, api.CFErrDenied, "on aqmas's deny-list ("+d.Reason+"); no grant can do this"), true, d.Push)
		return
	}
	var chosen *candidate
	var route cfscope.Route
	for i := range cands {
		if rt, ok := p.cat.Match(cands[i].res, call); ok {
			chosen, route = &cands[i], rt
			break
		}
	}
	if chosen == nil {
		for _, cd := range cands {
			if p.cat.ExtraDenied(cd.res.Scope.Name, call) {
				p.refused(ctx, w, c, call, cd.g.ID, refuse(http.StatusForbidden, api.CFErrDenied, "denied by aqmasd's config for scope "+cd.res.Scope.Name), true, false)
				return
			}
		}
		held := make([]*cfscope.Resolved, 0, len(cands))
		for _, cd := range cands {
			held = append(held, cd.res)
		}
		rf := refuse(http.StatusForbidden, api.CFErrNoGrant, "no offered grant allows "+call.Method+" "+call.Path)
		rf.needs = p.cat.NeedsScopeFor(call, held)
		if rf.needs != "" {
			rf.msg += " (request: " + rf.needs + ")"
		}
		p.refused(ctx, w, c, call, "", rf, cfscope.IsWrite(call.Method), false)
		return
	}
	admin := chosen.res.Scope.Name == api.CFScopeAdmin
	overrides, rf := parseOverrides(r.Header.Get(api.CFOverrideHeader), admin)
	if rf != nil {
		p.refused(ctx, w, c, call, chosen.g.ID, rf, true, false)
		return
	}
	if route.Write {
		// JWT asset uploads (many per deploy) count only towards the all-calls limit.
		if !route.JWTPassthrough {
			if ok, wait := p.lim.take(c.HostID, true, p.writeRate, now); !ok {
				rf := refuse(http.StatusTooManyRequests, api.CFErrRateLimited, "too many Cloudflare writes from this host")
				rf.retryAfter = wait
				p.refused(ctx, w, c, call, chosen.g.ID, rf, false, false)
				return
			}
		}
		p.serveWrite(w, r, c, call, chosen, route, overrides)
		return
	}
	p.serveRead(w, r, c, call, chosen, route)
}

// serveRead forwards a GET with the parent token and redacts the answer.
func (p *Proxy) serveRead(w http.ResponseWriter, r *http.Request, c Caller, call cfscope.Call, cd *candidate, route cfscope.Route) {
	ctx := r.Context()
	t0 := time.Now()
	resp, err := p.do(ctx, call.Method, call.Path, call.Query, nil, 0, r.Header, "Bearer "+p.o.ProxyToken)
	if err != nil {
		p.log.Warn("cf proxy: upstream", "error", err, "path", call.Path)
		p.refused(ctx, w, c, call, cd.g.ID, refuse(http.StatusBadGateway, api.CFErrUpstream, "Cloudflare unreachable"), false, false)
		return
	}
	defer resp.Body.Close()
	up, rf := readUpstream(resp, route)
	if rf != nil {
		p.refused(ctx, w, c, call, cd.g.ID, rf, false, false)
		return
	}
	if up.doc != nil && resp.StatusCode/100 == 2 && strings.HasSuffix(route.Template, "/cfd_tunnel/{tunnel}/configurations") {
		if v := num(obj(up.doc["result"])["version"]); v >= 0 {
			p.setVersion(c.HostID, route.Vars["tunnel"], v)
		}
	}
	h := w.Header()
	h.Set(api.CFGrantUsedHeader, cd.g.ID)
	up.write(w, nil)
	p.log.Info("cf proxy", "method", call.Method, "path", call.Path, "status", resp.StatusCode, "grant", cd.g.ID, "host", c.HostName, "duration_ms", time.Since(t0).Milliseconds())
}

func (p *Proxy) setVersion(host int64, tunnel string, v int64) {
	p.vmu.Lock()
	defer p.vmu.Unlock()
	p.versions[verKey{host, strings.ToLower(tunnel)}] = v
}

func (p *Proxy) lastVersion(host int64, tunnel string) (int64, bool) {
	p.vmu.Lock()
	defer p.vmu.Unlock()
	v, ok := p.versions[verKey{host, strings.ToLower(tunnel)}]
	return v, ok
}

// zoneName returns a zone id's name: configured, or (cf.admin on an unconfigured zone) read
// from Cloudflare once.
func (p *Proxy) zoneName(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	if n := p.cat.ZoneName(id); n != "" {
		return n, nil
	}
	p.zmu.Lock()
	n, ok := p.zoneNames[id]
	p.zmu.Unlock()
	if ok {
		return n, nil
	}
	ar, err := p.get(ctx, "/zones/"+id)
	if err != nil {
		return "", err
	}
	n = strings.ToLower(str(obj(ar.result)["name"]))
	if !ar.ok() || n == "" {
		return "", fmt.Errorf("zone lookup answered %d", ar.status)
	}
	p.zmu.Lock()
	p.zoneNames[id] = n
	p.zmu.Unlock()
	return n, nil
}

// ---- synthetic endpoints (docs/CLOUDFLARE.md 3.2) ----

var hostLabelRE = regexp.MustCompile(`[^a-z0-9.-]`)

func (p *Proxy) serveSynthetic(w http.ResponseWriter, call cfscope.Call, c Caller, cands []candidate) {
	if len(cands) == 0 {
		rf := refuse(http.StatusForbidden, api.CFErrNoGrant, "offer an active Cloudflare proxy grant (cf.read is enough)")
		rf.needs = api.CFScopeRead
		p.refused(context.Background(), w, c, call, "", rf, false, false)
		return
	}
	g := cands[0].g
	w.Header().Set(api.CFGrantUsedHeader, g.ID)
	acct := p.cfg.AccountID
	q, _ := url.ParseQuery(call.Query)
	firstPage := q.Get("page") == "" || q.Get("page") == "1"
	info := func(n int) map[string]any {
		return map[string]any{"page": 1, "per_page": 20, "count": n, "total_count": 1, "total_pages": 1}
	}
	switch call.Path {
	case "/user/tokens/verify":
		writeResult(w, map[string]any{"id": "aqmas:" + g.ID, "status": "active", "expires_on": g.NotAfter.UTC().Format(time.RFC3339)}, nil)
	case "/user":
		host := hostLabelRE.ReplaceAllString(strings.ToLower(c.HostName), "-")
		writeResult(w, map[string]any{"id": "aqmas", "email": "aqmas-proxy@" + host + ".invalid"}, nil)
	case "/accounts":
		res := []any{}
		if firstPage {
			res = append(res, map[string]any{"id": acct, "name": "aqmas proxy"})
		}
		writeResult(w, res, info(len(res)))
	case "/memberships":
		res := []any{}
		if firstPage {
			res = append(res, map[string]any{"id": acct, "account": map[string]any{"id": acct, "name": "aqmas proxy"}, "status": "accepted"})
		}
		writeResult(w, res, info(len(res)))
	}
	p.log.Info("cf proxy", "method", call.Method, "path", call.Path, "status", 200, "grant", g.ID, "host", c.HostName, "synthetic", true)
}
