package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// ProxyPrefix is where aqmasd mounts the Cloudflare proxy on the agent API (API.md 5.5).
const ProxyPrefix = "/cf/client/v4"

// MaxGrantsOffered is the most grant ids X-Aqmas-Grant may carry.
const MaxGrantsOffered = 8

// MaxUploadBytes is the largest body the shim forwards (the proxy's upload limit).
const MaxUploadBytes = 100 << 20

// CFInfo is what the proxy says about a call in its X-Aqmas-* response headers.
type CFInfo struct {
	GrantUsed      string
	SnapshotBefore string
	SnapshotAfter  string
	Warnings       []string
	Error          string // X-Aqmas-Error: a CFErr* code when aqmasd refused the call
	NeedsScope     string // X-Aqmas-Needs-Scope: "<scope> <scope_params>"
}

// ParseCFInfo reads the aqmas headers (values sanitized; they are printed).
func ParseCFInfo(h http.Header) CFInfo {
	in := CFInfo{
		GrantUsed:      sanitize(h.Get(api.CFGrantUsedHeader)),
		SnapshotBefore: sanitize(h.Get(api.CFSnapshotBeforeHeader)),
		SnapshotAfter:  sanitize(h.Get(api.CFSnapshotAfterHeader)),
		Error:          sanitize(h.Get(api.CFErrorHeader)),
		NeedsScope:     sanitize(strings.TrimSpace(h.Get(api.CFNeedsScopeHeader))),
	}
	for _, w := range h.Values(api.CFWarningHeader) {
		in.Warnings = append(in.Warnings, sanitize(w))
	}
	return in
}

// IsRefusal reports a refusal code that maps to exit 3 (API.md 5.6).
func (i CFInfo) IsRefusal() bool {
	switch i.Error {
	case api.CFErrNoGrant, api.CFErrDenied, api.CFErrGuardRail:
		return true
	}
	return false
}

// CFRefusalError is an aqmas refusal from the proxy (no_grant, denied, guard_rail): exit 3.
type CFRefusalError struct {
	Code       string
	Message    string
	NeedsScope string
}

func (e *CFRefusalError) Error() string {
	msg := "aqmasd refused the call: " + sanitize(e.Code)
	if e.Message != "" {
		msg += ": " + sanitize(e.Message)
	}
	return msg
}

// CFStatusError is a non-2xx answer passed through from Cloudflare (or an aqmas error that is
// not a refusal, such as bad_path or rate_limited): exit 1, or 5 for 502-504.
type CFStatusError struct {
	Status  int
	Code    string // X-Aqmas-Error, if aqmasd answered
	Message string
}

func (e *CFStatusError) Error() string {
	s := fmt.Sprintf("HTTP %d", e.Status)
	if e.Code != "" {
		s += " (aqmas " + sanitize(e.Code) + ")"
	}
	if e.Message != "" {
		s += ": " + sanitize(e.Message)
	}
	return s
}

// cfErrorMessage extracts errors[].message from a Cloudflare-shaped body.
func cfErrorMessage(body []byte) string {
	var env struct {
		Errors []struct {
			Code    any    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	var parts []string
	for _, e := range env.Errors {
		if e.Message != "" {
			parts = append(parts, e.Message)
		}
	}
	return strings.Join(parts, "; ")
}

// CFCatalogue fetches GET /v1/cf/catalogue.
func (c *APIClient) CFCatalogue(ctx context.Context) (*api.CFCatalogue, error) {
	var out api.CFCatalogue
	if err := c.do(ctx, http.MethodGet, "/v1/cf/catalogue", nil, &out); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.HTTPStatus == http.StatusNotFound {
			return nil, fmt.Errorf("Cloudflare access is not enabled on aqmasd (%w)", err)
		}
		return nil, err
	}
	return &out, nil
}

// CFSnapshots lists snapshots (GET /v1/cf/snapshots).
func (c *APIClient) CFSnapshots(ctx context.Context, q url.Values) (*api.CFSnapshotList, error) {
	var out api.CFSnapshotList
	path := "/v1/cf/snapshots"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CFSnapshot fetches one snapshot with its content (GET /v1/cf/snapshots/{id}).
func (c *APIClient) CFSnapshot(ctx context.Context, id string) (*api.CFSnapshot, error) {
	var out api.CFSnapshot
	saved := c.maxRsp
	c.maxRsp = 64 << 20 // snapshots can be large (a Cloudflare object up to the proxy's 32 MiB)
	defer func() { c.maxRsp = saved }()
	if err := c.do(ctx, http.MethodGet, "/v1/cf/snapshots/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActiveCFProxyGrants returns the host's active Cloudflare proxy-mode grants, in the order
// they should be offered: specific scopes first (server order), cf.admin last, so a
// break-glass grant is used only when nothing narrower allows the call.
func (c *APIClient) ActiveCFProxyGrants(ctx context.Context) ([]api.GrantSummary, error) {
	gl, err := c.ActiveGrants(ctx)
	if err != nil {
		return nil, err
	}
	var out, admin []api.GrantSummary
	for _, g := range gl.Grants {
		if g.Kind != api.KindCloudflare || (g.Mode != "" && g.Mode != api.CFModeProxy) || !safeID(g.ID) {
			continue
		}
		if g.Status != "" && g.Status != api.StatusApproved && g.Status != "active" {
			continue
		}
		if g.Scope == api.CFScopeAdmin {
			admin = append(admin, g)
		} else {
			out = append(out, g)
		}
	}
	return append(out, admin...), nil
}

// grantIDs returns at most MaxGrantsOffered ids, keeping order and dropping duplicates.
func grantIDs(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, id := range l {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) > MaxGrantsOffered {
		out = out[:MaxGrantsOffered]
	}
	return out
}

// proxyPathRE is what the client lets through as an escaped Cloudflare path (the server
// normalises and checks it again, CLOUDFLARE.md 3.1).
var proxyPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,=:@/%-]*$`)
var proxyQueryRE = regexp.MustCompile(`^[A-Za-z0-9._~%=&+,:*-]*$`)

// ProxyCall is one request through aqmasd's Cloudflare proxy.
type ProxyCall struct {
	Method string
	// Path is the escaped Cloudflare path below /client/v4 ("/zones/<id>/dns_records"); it is
	// sent byte for byte.
	Path  string
	Query string // raw query, without "?"
	// Header holds the forwarded request headers (Content-Type, Accept, If-Match,
	// If-None-Match, and Authorization only for upload-JWT routes).
	Header        http.Header
	Body          io.Reader
	ContentLength int64 // -1 unknown
	Grants        []string
	Overrides     []string
}

// Proxy sends c through the proxy with mTLS. The caller closes the response body.
func (c *APIClient) Proxy(ctx context.Context, pc *ProxyCall) (*http.Response, error) {
	if !proxyPathRE.MatchString(pc.Path) {
		return nil, &UsageError{Msg: fmt.Sprintf("invalid Cloudflare path %q", sanitize(pc.Path))}
	}
	if !proxyQueryRE.MatchString(pc.Query) || len(pc.Query) > 2048 {
		return nil, &UsageError{Msg: fmt.Sprintf("invalid query %q (encode it; at most 2048 bytes)", sanitize(pc.Query))}
	}
	u, err := url.Parse(c.base)
	if err != nil {
		return nil, err
	}
	// Opaque keeps the escaped path exactly as given (no re-encoding by net/url).
	u.Opaque = ProxyPrefix + pc.Path
	u.RawQuery = pc.Query
	body := pc.Body
	if body == nil {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, pc.Method, "", body)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host
	if pc.Body == nil {
		req.ContentLength = 0
	} else {
		req.ContentLength = pc.ContentLength
	}
	for _, k := range []string{"Content-Type", "Accept", "If-Match", "If-None-Match", "Authorization"} {
		if v := pc.Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}
	if len(pc.Grants) > 0 {
		req.Header.Set(api.CFGrantHeader, strings.Join(grantIDs(pc.Grants), ","))
	}
	if len(pc.Overrides) > 0 {
		req.Header.Set(api.CFOverrideHeader, strings.Join(pc.Overrides, ","))
	}
	req.Header.Set("User-Agent", "aqmas/"+Version)
	resp, err := c.proxyHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrCancelled
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, &UnreachableError{Err: fmt.Errorf("%s %s%s: %w", pc.Method, ProxyPrefix, pc.Path, err)}
	}
	return resp, nil
}

// canonicalScopeParams renders params as API.md 5.4 scope_params (keys sorted, k=v joined
// by ";").
func canonicalScopeParams(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+p[k])
	}
	return strings.Join(parts, ";")
}
