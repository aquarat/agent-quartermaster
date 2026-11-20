// Package fakecf is an in-memory fake of the parts of the Cloudflare API v4 that aqmas
// (aqmasd's proxy, its child-token minter) and wrangler use. It is a test helper only: it
// never talks to the network, keeps everything in memory and answers Cloudflare-shaped JSON
// ({"success","errors","messages","result"[,"result_info"]}).
//
// It records every request (method, escaped path, query, which credential was presented, body
// size, status) and exposes the record at GET /__fake/requests (DELETE clears it) and the
// child-token state at GET /__fake/tokens. Token values are never exposed there.
//
// Credentials: the parent token(s) given to New are valid bearers for every route. Tokens
// minted with POST /user/tokens become valid bearers (not for /user/tokens itself) from
// not_before until expires_on or deletion. Upload JWTs issued by the Workers assets upload
// session and the Pages upload-token call are the only credential the upload routes accept
// (POST /accounts/*/workers/assets/upload[/{hash}], POST /pages/assets/*). An unknown bearer
// gets 401 with Cloudflare's error shape.
package fakecf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Prefix is where the API lives (as on api.cloudflare.com).
const Prefix = "/client/v4"

// Named maps a name to a Cloudflare id (zones, tunnels, D1 databases).
type Named struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Options configures a Fake.
type Options struct {
	// Tokens are the parent API tokens (at least one). Never printed or exposed.
	Tokens      []string
	AccountID   string // 32 hex
	AccountName string
	Zones       []Named
	Tunnels     []Named
	D1          []Named
	// PagesProjects are created up front (wrangler pages deploy needs an existing project
	// when it runs non-interactively).
	PagesProjects []string
	// SingleAssetUploads sets the wrangler_single_asset_uploads claim in Workers assets upload
	// JWTs, so wrangler uploads with POST /accounts/{acct}/workers/assets/upload/{hash}.
	SingleAssetUploads bool
	// Now is the clock (tests); default time.Now.
	Now func() time.Time
}

// Request is one recorded request.
type Request struct {
	At         time.Time `json:"at"`
	Method     string    `json:"method"`
	Path       string    `json:"path"` // escaped, as received, including /client/v4
	Query      string    `json:"query,omitempty"`
	Credential string    `json:"credential"` // parent, child, upload-jwt, none, invalid
	TokenID    string    `json:"token_id,omitempty"`
	JWTKind    string    `json:"jwt_kind,omitempty"`
	BodyBytes  int64     `json:"body_bytes"`
	Status     int       `json:"status"`
	Route      string    `json:"route,omitempty"` // the matched pattern ("" = not routed)
	UserAgent  string    `json:"user_agent,omitempty"`
}

// TokenState is a minted child token as /__fake/tokens shows it (no value).
type TokenState struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Status    string          `json:"status"` // active, expired, deleted
	IssuedOn  time.Time       `json:"issued_on"`
	NotBefore time.Time       `json:"not_before"`
	ExpiresOn time.Time       `json:"expires_on"`
	Deleted   bool            `json:"deleted"`
	Policies  json.RawMessage `json:"policies,omitempty"`
	Condition json.RawMessage `json:"condition,omitempty"`
	Uses      int             `json:"uses"`
}

type childToken struct {
	TokenState
	value string
	seq   int
}

type jwtInfo struct {
	kind    string // workers-upload, workers-completion, pages-upload
	exp     time.Time
	script  string
	project string
	pending map[string]bool // workers-upload: hashes still to upload
}

// Fake is the fake API. Use it as an http.Handler.
type Fake struct {
	o   Options
	mux *http.ServeMux

	mu       sync.Mutex
	reqs     []Request
	children map[string]*childToken // by id
	jwts     map[string]*jwtInfo    // by value

	zones      map[string]*zone // by id
	tunnels    map[string]*tunnel
	apps       *coll
	appPol     map[string]*coll // app id -> legacy app-scoped policies
	policies   *coll
	groups     *coll
	scripts    map[string]*script
	wAssets    map[string]bool // uploaded Workers asset hashes
	pages      map[string]*pagesProject
	pAssets    map[string]bool // uploaded Pages asset hashes
	d1         map[string]*d1db
	wSubdomain string
	wDomains   *coll
	r2         *coll
}

// New returns a Fake with the configured objects pre-created.
func New(o Options) (*Fake, error) {
	if len(o.Tokens) == 0 {
		return nil, errors.New("fakecf: at least one parent token")
	}
	for _, t := range o.Tokens {
		if len(t) < 8 {
			return nil, errors.New("fakecf: parent tokens must be at least 8 characters")
		}
	}
	if o.AccountID == "" {
		o.AccountID = "0123456789abcdef0123456789abcdef"
	}
	if o.AccountName == "" {
		o.AccountName = "fake account"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	f := &Fake{
		o:          o,
		children:   map[string]*childToken{},
		jwts:       map[string]*jwtInfo{},
		zones:      map[string]*zone{},
		tunnels:    map[string]*tunnel{},
		apps:       newColl(),
		appPol:     map[string]*coll{},
		policies:   newColl(),
		groups:     newColl(),
		scripts:    map[string]*script{},
		wAssets:    map[string]bool{},
		pages:      map[string]*pagesProject{},
		pAssets:    map[string]bool{},
		d1:         map[string]*d1db{},
		wSubdomain: "fake-subdomain",
		wDomains:   newColl(),
		r2:         newColl(),
	}
	for _, z := range o.Zones {
		f.zones[z.ID] = newZone(z, f.now())
	}
	for _, t := range o.Tunnels {
		f.tunnels[t.ID] = &tunnel{named: t, version: 1, created: f.now(),
			config: json.RawMessage(`{"ingress":[{"service":"http_status:404"}],"warp-routing":{"enabled":false}}`)}
	}
	for _, d := range o.D1 {
		db, err := openD1()
		if err != nil {
			return nil, err
		}
		f.d1[d.ID] = &d1db{named: d, db: db, created: f.now()}
	}
	for _, p := range o.PagesProjects {
		f.pages[p] = newPagesProject(p, f.now())
	}
	f.routes()
	return f, nil
}

// SetSingleAssetUploads switches Options.SingleAssetUploads for later upload sessions.
func (f *Fake) SetSingleAssetUploads(on bool) {
	f.mu.Lock()
	f.o.SingleAssetUploads = on
	f.mu.Unlock()
}

// Close releases the D1 databases.
func (f *Fake) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.d1 {
		d.db.Close()
	}
	return nil
}

func (f *Fake) now() time.Time { return f.o.Now().UTC() }

// Requests returns a copy of the request record.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.reqs...)
}

// ClearRequests empties the request record.
func (f *Fake) ClearRequests() {
	f.mu.Lock()
	f.reqs = nil
	f.mu.Unlock()
}

// Tokens returns the child-token state (no values), oldest first.
func (f *Fake) Tokens() []TokenState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenStatesLocked()
}

func (f *Fake) tokenStatesLocked() []TokenState {
	ts := make([]*childToken, 0, len(f.children))
	for _, t := range f.children {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].seq < ts[j].seq })
	out := []TokenState{}
	for _, t := range ts {
		s := t.TokenState
		s.Status = f.childStatus(t)
		out = append(out, s)
	}
	return out
}

func (f *Fake) childStatus(t *childToken) string {
	switch {
	case t.Deleted:
		return "deleted"
	case !f.now().Before(t.ExpiresOn):
		return "expired"
	}
	return "active"
}

// ---- request handling ----

type ctxKey struct{}

// call is the per-request state handlers see.
type call struct {
	w       http.ResponseWriter
	r       *http.Request
	rec     *Request
	child   *childToken
	jwt     *jwtInfo
	jwtVal  string
	parent  bool
	written bool
	status  int
}

type handler func(c *call)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
func (c *countingReader) Close() error { return c.r.Close() }

// ServeHTTP implements http.Handler.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/__fake/") {
		f.serveFake(w, r)
		return
	}
	sw := &statusWriter{ResponseWriter: w}
	cr := &countingReader{r: r.Body}
	r.Body = cr
	path := r.URL.EscapedPath()
	if r.RequestURI != "" && strings.HasPrefix(r.RequestURI, "/") {
		path, _, _ = strings.Cut(r.RequestURI, "?")
	}
	rec := Request{At: f.now(), Method: r.Method, Path: path, Query: r.URL.RawQuery, UserAgent: r.UserAgent()}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(cr, 512<<20))
		rec.BodyBytes = cr.n
		rec.Status = sw.status
		f.mu.Lock()
		f.reqs = append(f.reqs, rec)
		f.mu.Unlock()
	}()
	if !strings.HasPrefix(r.URL.Path, Prefix+"/") {
		cfError(sw, http.StatusNotFound, 7000, "No route for that URI")
		return
	}
	h, pattern := f.mux.Handler(r)
	rec.Route = pattern
	c := &call{w: sw, r: r, rec: &rec}
	if !f.authenticate(c) {
		return
	}
	if pattern == "" {
		// Not routed (404) or wrong method (405): Cloudflare's shapes.
		probe := httptestRecorder{h: http.Header{}}
		h.ServeHTTP(&probe, r)
		if probe.code == http.StatusMethodNotAllowed {
			cfError(sw, http.StatusMethodNotAllowed, 10000, "Method not allowed for this route")
			return
		}
		cfError(sw, http.StatusNotFound, 7003, "Could not route to "+sanitizePath(path)+", perhaps your object identifier is invalid?")
		return
	}
	f.mux.ServeHTTP(sw, r.WithContext(contextWith(r, c)))
}

type httptestRecorder struct {
	h    http.Header
	code int
}

func (h *httptestRecorder) Header() http.Header { return h.h }
func (h *httptestRecorder) Write(b []byte) (int, error) {
	if h.code == 0 {
		h.code = 200
	}
	return len(b), nil
}
func (h *httptestRecorder) WriteHeader(c int) { h.code = c }

// jwtRoute reports whether the route takes an upload JWT instead of an API token.
func jwtRoute(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	p := strings.TrimPrefix(path, Prefix)
	if strings.HasPrefix(p, "/pages/assets/") {
		return true
	}
	seg := strings.Split(strings.TrimPrefix(p, "/"), "/")
	return (len(seg) == 5 || len(seg) == 6) && seg[0] == "accounts" && seg[2] == "workers" && seg[3] == "assets" && seg[4] == "upload"
}

func (f *Fake) authenticate(c *call) bool {
	r := c.r
	auth := r.Header.Get("Authorization")
	bearer, ok := strings.CutPrefix(auth, "Bearer ")
	if auth == "" {
		c.rec.Credential = "none"
		if r.Header.Get("X-Auth-Key") != "" || r.Header.Get("X-Auth-Email") != "" {
			c.rec.Credential = "invalid"
		}
		cfError(c.w, http.StatusUnauthorized, 10001, "Unable to authenticate request")
		return false
	}
	if !ok || bearer == "" {
		c.rec.Credential = "invalid"
		cfError(c.w, http.StatusUnauthorized, 10001, "Unable to authenticate request")
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if jwtRoute(r.Method, c.rec.Path) {
		if j := f.jwts[bearer]; j != nil {
			c.rec.Credential = "upload-jwt"
			c.rec.JWTKind = j.kind
			if !f.now().Before(j.exp) {
				cfError(c.w, http.StatusUnauthorized, 8000013, "upload JWT expired")
				return false
			}
			c.jwt, c.jwtVal = j, bearer
			return true
		}
		c.rec.Credential = "invalid"
		if f.isAPIToken(bearer) {
			c.rec.Credential = "api-token-on-jwt-route"
		}
		cfError(c.w, http.StatusUnauthorized, 8000013, "Authentication error: this route needs an upload JWT")
		return false
	}
	for _, t := range f.o.Tokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(bearer)) == 1 {
			c.rec.Credential = "parent"
			c.parent = true
			return true
		}
	}
	for _, t := range f.children {
		if subtle.ConstantTimeCompare([]byte(t.value), []byte(bearer)) == 1 {
			c.rec.Credential = "child"
			c.rec.TokenID = t.ID
			if t.Deleted || !f.now().Before(t.ExpiresOn) || f.now().Before(t.NotBefore.Add(-time.Minute)) {
				cfError(c.w, http.StatusUnauthorized, 1000, "Invalid API Token")
				return false
			}
			t.Uses++
			c.child = t
			return true
		}
	}
	c.rec.Credential = "invalid"
	if _, isJWT := f.jwts[bearer]; isJWT {
		c.rec.Credential = "upload-jwt-on-api-route"
	}
	cfError(c.w, http.StatusUnauthorized, 1000, "Invalid API Token")
	return false
}

func (f *Fake) isAPIToken(v string) bool {
	for _, t := range f.o.Tokens {
		if t == v {
			return true
		}
	}
	for _, t := range f.children {
		if t.value == v {
			return true
		}
	}
	return false
}

// serveFake answers the inspection endpoints.
func (f *Fake) serveFake(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/__fake/requests" && r.Method == http.MethodGet:
		writeRaw(w, http.StatusOK, f.Requests())
	case r.URL.Path == "/__fake/requests" && r.Method == http.MethodDelete:
		f.ClearRequests()
		writeRaw(w, http.StatusOK, map[string]bool{"ok": true})
	case r.URL.Path == "/__fake/tokens" && r.Method == http.MethodGet:
		writeRaw(w, http.StatusOK, f.Tokens())
	case r.URL.Path == "/__fake/state" && r.Method == http.MethodGet:
		writeRaw(w, http.StatusOK, f.State())
	default:
		http.Error(w, "unknown fake endpoint", http.StatusNotFound)
	}
}

// ---- response helpers ----

type cfErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type envelope struct {
	Success    bool        `json:"success"`
	Errors     []cfErr     `json:"errors"`
	Messages   []any       `json:"messages"`
	Result     any         `json:"result"`
	ResultInfo *resultInfo `json:"result_info,omitempty"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

func writeRaw(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func cfError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Cf-Ray", "fake0000000000-LHR")
	writeRaw(w, status, envelope{Success: false, Errors: []cfErr{{Code: code, Message: msg}}, Messages: []any{}, Result: nil})
}

func (c *call) ok(result any) { c.okStatus(http.StatusOK, result) }

func (c *call) okStatus(status int, result any) {
	c.w.Header().Set("Cf-Ray", "fake0000000000-LHR")
	writeRaw(c.w, status, envelope{Success: true, Errors: []cfErr{}, Messages: []any{}, Result: result})
}

func (c *call) err(status, code int, msg string) { cfError(c.w, status, code, msg) }

// paged answers a list with Cloudflare's page/per_page pagination.
func (c *call) paged(items []any, defPer int) {
	q := c.r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	per, _ := strconv.Atoi(q.Get("per_page"))
	if page < 1 {
		page = 1
	}
	if per < 1 {
		per = defPer
	}
	total := len(items)
	pages := (total + per - 1) / per
	start := min((page-1)*per, total)
	end := min(start+per, total)
	if items == nil {
		items = []any{}
	}
	out := items[start:end]
	c.w.Header().Set("Cf-Ray", "fake0000000000-LHR")
	writeRaw(c.w, http.StatusOK, envelope{Success: true, Errors: []cfErr{}, Messages: []any{}, Result: out,
		ResultInfo: &resultInfo{Page: page, PerPage: per, Count: len(out), TotalCount: total, TotalPages: pages}})
}

// body decodes a JSON request body into v (max 32 MiB).
func (c *call) body(v any) bool {
	data, err := io.ReadAll(io.LimitReader(c.r.Body, 32<<20))
	if err != nil {
		c.err(http.StatusBadRequest, 10002, "could not read body")
		return false
	}
	if err := json.Unmarshal(data, v); err != nil {
		c.err(http.StatusBadRequest, 10002, "Invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func (c *call) pv(name string) string { return c.r.PathValue(name) }

// ---- ids and JWTs ----

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// newJWT issues an unsigned JWT-shaped upload credential (wrangler decodes the payload for
// exp and mode claims) and remembers it. Call with f.mu held.
func (f *Fake) newJWTLocked(info *jwtInfo, claims map[string]any) string {
	if claims == nil {
		claims = map[string]any{}
	}
	claims["exp"] = info.exp.Unix()
	claims["jti"] = randHex(12)
	claims["kind"] = info.kind
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pl, _ := json.Marshal(claims)
	v := hdr + "." + base64.RawURLEncoding.EncodeToString(pl) + "." + randHex(16)
	f.jwts[v] = info
	return v
}

func sanitizePath(p string) string {
	if len(p) > 200 {
		p = p[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, p)
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }

// ---- generic object collection ----

// coll is an ordered map of JSON objects by id.
type coll struct {
	ids  []string
	objs map[string]map[string]any
}

func newColl() *coll { return &coll{objs: map[string]map[string]any{}} }

func (c *coll) put(id string, o map[string]any) {
	if _, ok := c.objs[id]; !ok {
		c.ids = append(c.ids, id)
	}
	c.objs[id] = o
}

func (c *coll) get(id string) map[string]any { return c.objs[id] }

func (c *coll) del(id string) bool {
	if _, ok := c.objs[id]; !ok {
		return false
	}
	delete(c.objs, id)
	for i, v := range c.ids {
		if v == id {
			c.ids = append(c.ids[:i], c.ids[i+1:]...)
			break
		}
	}
	return true
}

func (c *coll) list() []any {
	out := make([]any, 0, len(c.ids))
	for _, id := range c.ids {
		out = append(out, c.objs[id])
	}
	return out
}

func clone(o map[string]any) map[string]any {
	b, _ := json.Marshal(o)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}

// State is a summary of the fake's objects for tests (no token values).
func (f *Fake) State() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	tun := map[string]any{}
	for id, t := range f.tunnels {
		tun[id] = map[string]any{"version": t.version, "config": t.config}
	}
	scripts := map[string]any{}
	for n, s := range f.scripts {
		sec := []string{}
		for k := range s.secrets {
			sec = append(sec, k)
		}
		sort.Strings(sec)
		scripts[n] = map[string]any{"versions": len(s.versions), "deployments": len(s.deployments), "secrets": sec,
			"schedules": s.schedules, "has_assets": s.hasAssets, "subdomain_enabled": s.subdomain}
	}
	pages := map[string]any{}
	for n, p := range f.pages {
		pages[n] = map[string]any{"deployments": p.deployments.list()}
	}
	dns := map[string]any{}
	for id, z := range f.zones {
		dns[id] = len(z.dns.ids)
	}
	return map[string]any{"tunnels": tun, "scripts": scripts, "pages": pages, "dns_records": dns,
		"access_apps": len(f.apps.ids), "workers_assets": len(f.wAssets), "pages_assets": len(f.pAssets)}
}
