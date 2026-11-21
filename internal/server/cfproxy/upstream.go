package cfproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const userAgent = "aqmasd-cfproxy/2"

// Request headers forwarded to Cloudflare (docs/CLOUDFLARE.md 3.1). The Workers API date
// header changes how POST .../subdomain behaves and wrangler sends it.
var forwardRequestHeaders = []string{"Content-Type", "Accept", "If-Match", "If-None-Match", "Cloudflare-Workers-Script-Api-Date"}

// Response headers passed back.
var forwardResponseHeaders = []string{"Content-Type", "Content-Disposition", "Cf-Ray", "Retry-After", "ETag", "Last-Modified"}

// upstreamURL joins api_base and an escaped path (and raw query) byte for byte.
func (p *Proxy) upstreamURL(escPath, rawQuery string) (*url.URL, error) {
	dec, err := url.PathUnescape(escPath)
	if err != nil {
		return nil, err
	}
	u := *p.base
	u.Path = p.base.Path + dec
	u.RawPath = p.base.EscapedPath() + escPath
	u.RawQuery = rawQuery
	u.Fragment, u.RawFragment = "", ""
	if u.EscapedPath() != p.base.EscapedPath()+escPath {
		return nil, errors.New("path would be re-encoded")
	}
	return &u, nil
}

// do sends one request upstream. auth is the full Authorization value. Redirects are never
// followed (the client's CheckRedirect returns the 3xx).
func (p *Proxy) do(ctx context.Context, method, escPath, rawQuery string, body io.Reader, clen int64, hdr http.Header, auth string) (*http.Response, error) {
	u, err := p.upstreamURL(escPath, rawQuery)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, errors.New("cannot build upstream request")
	}
	req.URL = u // keep RawPath exactly
	if body != nil {
		req.ContentLength = clen
	}
	for _, h := range forwardRequestHeaders {
		if v := hdr.Values(h); len(v) > 0 {
			req.Header[h] = append([]string(nil), v...)
		}
	}
	if auth == "" {
		token := p.o.ProxyToken
		if p.o.Parent != nil {
			token, err = p.o.Parent(ctx)
			if err != nil {
				return nil, err
			}
		}
		if token == "" {
			return nil, errors.New("cloudflare parent unavailable")
		}
		auth = "Bearer " + token
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("User-Agent", userAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, scrubErr(err)
	}
	return resp, nil
}

// scrubErr drops the URL from transport errors (paths and queries stay out of logs that
// might be shared; the token is a header and never appears in them anyway).
func scrubErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s upstream: %w", ue.Op, ue.Err)
	}
	return err
}

// apiResult is a parsed Cloudflare JSON answer.
type apiResult struct {
	status int
	body   []byte
	doc    map[string]any // the whole document
	result any            // doc["result"]
}

// get makes an aqmasd-internal GET with the parent token (snapshots, guard-rail lookups).
func (p *Proxy) get(ctx context.Context, pathAndQuery string) (*apiResult, error) {
	path, query, _ := strings.Cut(pathAndQuery, "?")
	resp, err := p.do(ctx, http.MethodGet, path, query, nil, 0, http.Header{"Accept": {"application/json"}}, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("upstream redirect %d refused", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRedactBytes+1))
	if err != nil {
		return nil, scrubErr(err)
	}
	if len(b) > maxRedactBytes {
		return nil, errors.New("upstream answer too large")
	}
	ar := &apiResult{status: resp.StatusCode, body: b}
	if v, err := decodeJSON(b); err == nil {
		if m, ok := v.(map[string]any); ok {
			ar.doc = m
			ar.result = m["result"]
		}
	}
	return ar, nil
}

func (a *apiResult) ok() bool { return a.status >= 200 && a.status < 300 && a.doc != nil }

// getAll pages through a list endpoint (page/per_page, result_info.total_pages), at most
// maxPages pages.
func (p *Proxy) getAll(ctx context.Context, path string, perPage, maxPages int) ([]any, error) {
	var out []any
	for page := 1; page <= maxPages; page++ {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		ar, err := p.get(ctx, fmt.Sprintf("%s%spage=%d&per_page=%d", path, sep, page, perPage))
		if err != nil {
			return nil, err
		}
		if !ar.ok() {
			return nil, fmt.Errorf("upstream answered %d", ar.status)
		}
		items, _ := ar.result.([]any)
		out = append(out, items...)
		info := obj(ar.doc["result_info"])
		tp := num(info["total_pages"])
		if len(items) == 0 || (tp > 0 && int64(page) >= tp) || (tp == 0 && len(items) < perPage) {
			return out, nil
		}
	}
	return nil, errors.New("too many pages")
}
