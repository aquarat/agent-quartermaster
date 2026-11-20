package fakecf

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// StandIn is a test stand-in for aqmasd's Cloudflare proxy (docs/API.md 5.5), for client and
// wrangler tests while the real proxy is built elsewhere. It does NOT implement scopes, the
// deny-list, guard rails or snapshots; it only reproduces the wire behaviour the client
// depends on: the X-Aqmas-Grant check (via Allow), Cloudflare-shaped refusals with
// X-Aqmas-Error / X-Aqmas-Needs-Scope, parent-token injection, JWT passthrough on upload
// routes, the synthetic identity endpoints, header whitelists and byte-exact paths. Mount it
// at /cf/client/v4/ behind the mTLS check.
type StandIn struct {
	// Upstream is the fake Cloudflare base URL ("http://127.0.0.1:PORT"; /client/v4 is added).
	Upstream    string
	ParentToken string
	AccountID   string
	// Allow picks the grant for a call from the offered ids; "" refuses with no_grant and
	// needsScope (may be "") as the hint.
	Allow func(r *http.Request, method, cfPath string, offered []string) (used, needsScope string)
	// OnWrite may add headers (snapshots, warnings) to the response of a successful write.
	OnWrite func(method, cfPath string, h http.Header)
	Client  *http.Client

	mu         sync.Mutex
	calls      []StandInCall
	violations []string
}

// StandInCall is one call the stand-in saw.
type StandInCall struct {
	Method    string `json:"method"`
	Path      string `json:"path"` // escaped Cloudflare path below /client/v4
	Query     string `json:"query,omitempty"`
	Offered   string `json:"offered,omitempty"`
	GrantUsed string `json:"grant_used,omitempty"`
	AuthKind  string `json:"auth"` // none, jwt, other
	BodyBytes int64  `json:"body_bytes"`
	Status    int    `json:"status"`
	Refused   string `json:"refused,omitempty"`
}

// Calls returns what the stand-in saw.
func (p *StandIn) Calls() []StandInCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]StandInCall(nil), p.calls...)
}

// Violations lists contract breaches by the client (e.g. Authorization on a non-upload
// route, the shim's own bearer forwarded).
func (p *StandIn) Violations() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.violations...)
}

func (p *StandIn) violate(s string) {
	p.mu.Lock()
	p.violations = append(p.violations, s)
	p.mu.Unlock()
}

// JWTRoute reports the upload routes where the client's Authorization (an upload JWT) is
// forwarded instead of the parent token.
func JWTRoute(method, cfPath string) bool { return jwtRoute(method, Prefix+cfPath) }

func refuse(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("X-Aqmas-Error", code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"success": false, "messages": []any{}, "result": nil,
		"errors": []any{map[string]any{"code": 10403, "message": "aqmas " + code + ": " + msg}}})
}

func (p *StandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := r.RequestURI
	path, query, _ := strings.Cut(uri, "?")
	cfPath, ok := strings.CutPrefix(path, "/cf/client/v4")
	rec := StandInCall{Method: r.Method, Path: cfPath, Query: query, Offered: r.Header.Get("X-Aqmas-Grant"), AuthKind: "none"}
	cr := &countingReader{r: r.Body}
	r.Body = cr
	sw := &statusWriter{ResponseWriter: w}
	defer func() {
		rec.BodyBytes = cr.n
		rec.Status = sw.status
		p.mu.Lock()
		p.calls = append(p.calls, rec)
		p.mu.Unlock()
	}()
	auth := r.Header.Get("Authorization")
	isJWT := JWTRoute(r.Method, cfPath)
	switch {
	case auth == "":
	case strings.HasPrefix(auth, "Bearer aqmas-shim-"):
		rec.AuthKind = "other"
		p.violate("shim bearer forwarded on " + r.Method + " " + cfPath)
	case isJWT && strings.Count(strings.TrimPrefix(auth, "Bearer "), ".") == 2:
		rec.AuthKind = "jwt"
	default:
		rec.AuthKind = "other"
		p.violate("Authorization sent on non-upload route " + r.Method + " " + cfPath)
	}
	if !ok || !strings.HasPrefix(cfPath, "/") || strings.Contains(cfPath, "//") {
		rec.Refused = "bad_path"
		refuse(sw, http.StatusBadRequest, "bad_path", "path not accepted")
		return
	}
	for _, h := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		if r.Header.Get(h) != "" {
			rec.Refused = "bad_request"
			refuse(sw, http.StatusBadRequest, "bad_request", "method override headers are refused")
			return
		}
	}
	var offered []string
	for _, g := range strings.Split(rec.Offered, ",") {
		if g = strings.TrimSpace(g); g != "" {
			offered = append(offered, g)
		}
	}
	if len(offered) > 8 {
		rec.Refused = "bad_request"
		refuse(sw, http.StatusBadRequest, "bad_request", "at most 8 grants")
		return
	}
	used, needs := "", ""
	if p.Allow != nil {
		used, needs = p.Allow(r, r.Method, cfPath, offered)
	}
	if used == "" {
		rec.Refused = "no_grant"
		if needs != "" {
			sw.Header().Set("X-Aqmas-Needs-Scope", needs)
		}
		refuse(sw, http.StatusForbidden, "no_grant", "no offered grant allows "+r.Method+" "+sanitizePath(cfPath))
		return
	}
	rec.GrantUsed = used
	sw.Header().Set("X-Aqmas-Grant-Used", used)
	// Synthetic endpoints (CLOUDFLARE.md 3.2).
	if r.Method == http.MethodGet {
		var res any
		switch cfPath {
		case "/user/tokens/verify":
			res = map[string]any{"id": "aqmas:" + used, "status": "active", "expires_on": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
		case "/user":
			res = map[string]any{"id": "aqmas", "email": "aqmas-proxy@testhost.invalid"}
		case "/accounts":
			res = []any{map[string]any{"id": p.AccountID, "name": "aqmas proxy"}}
		case "/memberships":
			res = []any{map[string]any{"id": "aqmas", "status": "accepted", "account": map[string]any{"id": p.AccountID, "name": "aqmas proxy"}}}
		}
		if res != nil {
			writeRaw(sw, http.StatusOK, envelope{Success: true, Errors: []cfErr{}, Messages: []any{}, Result: res})
			return
		}
	}
	u, err := url.Parse(p.Upstream)
	if err != nil {
		refuse(sw, http.StatusBadGateway, "upstream", "bad upstream")
		return
	}
	u.Opaque = Prefix + cfPath
	u.RawQuery = query
	var body io.Reader = r.Body
	if r.ContentLength == 0 {
		body = http.NoBody
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, "", body)
	if err != nil {
		refuse(sw, http.StatusBadGateway, "upstream", err.Error())
		return
	}
	up.URL, up.Host, up.ContentLength = u, u.Host, r.ContentLength
	for _, k := range []string{"Content-Type", "Accept", "If-Match", "If-None-Match"} {
		if v := r.Header.Get(k); v != "" {
			up.Header.Set(k, v)
		}
	}
	if isJWT && auth != "" {
		up.Header.Set("Authorization", auth)
	} else {
		up.Header.Set("Authorization", "Bearer "+p.ParentToken)
	}
	up.Header.Set("User-Agent", "aqmasd-standin")
	cl := p.Client
	if cl == nil {
		cl = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := cl.Do(up)
	if err != nil {
		refuse(sw, http.StatusBadGateway, "upstream", "Cloudflare unreachable")
		return
	}
	defer resp.Body.Close()
	for _, k := range []string{"Content-Type", "Content-Disposition", "Cf-Ray", "Retry-After", "Etag", "Last-Modified"} {
		if v := resp.Header.Values(k); len(v) > 0 {
			sw.Header()[k] = v
		}
	}
	if r.Method != http.MethodGet && resp.StatusCode < 300 && p.OnWrite != nil {
		p.OnWrite(r.Method, cfPath, sw.Header())
	}
	sw.WriteHeader(resp.StatusCode)
	io.Copy(sw, resp.Body)
}
