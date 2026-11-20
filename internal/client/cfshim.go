package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// shimRetryBodyMax: bodies up to this size are buffered so a call refused with no_grant can be
// retried once after the grant list is refreshed; larger ones (uploads) stream and are not
// retried.
const shimRetryBodyMax = 1 << 20

// shimRefreshEvery throttles refreshing the grant list after no_grant answers (a variable for
// tests).
var shimRefreshEvery = 2 * time.Second

// Shim is the local Cloudflare API endpoint `aqmas cf env` gives to a command
// (CLOUDFLARE_API_BASE_URL=http://127.0.0.1:<port>/client/v4). It accepts only requests that
// carry its random per-run bearer and Host 127.0.0.1:<port> (upload routes excepted, where the
// upload JWT is the credential and is forwarded), and forwards them to aqmasd's proxy with this
// host's mTLS certificate and grant list. The bearer never leaves this process.
type Shim struct {
	e        *Env
	c        *APIClient
	bearer   string
	hostport string
	ln       net.Listener
	srv      *http.Server

	mu          sync.Mutex
	grants      []string
	pinned      []string // always offered first (--grant, --request results)
	explicit    bool     // only pinned grants; never refreshed
	lastRefresh time.Time
	hinted      map[string]bool
}

// ShimOptions configures StartShim.
type ShimOptions struct {
	// Grants are offered first. With Explicit, only they are offered; otherwise the host's
	// active proxy grants follow and the list is refreshed after a no_grant answer.
	Grants   []string
	Explicit bool
}

// StartShim listens on 127.0.0.1:0 and serves until Close.
func (e *Env) StartShim(ctx context.Context, c *APIClient, o ShimOptions) (*Shim, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("shim: %w", err)
	}
	s := &Shim{e: e, c: c, bearer: "aqmas-shim-" + hex.EncodeToString(b), hostport: ln.Addr().String(), ln: ln,
		pinned: grantIDs(o.Grants), explicit: o.Explicit, hinted: map[string]bool{}}
	s.grants = s.pinned
	if !o.Explicit {
		if err := s.refresh(ctx, true); err != nil {
			ln.Close()
			return nil, err
		}
	}
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go s.srv.Serve(ln)
	return s, nil
}

// BaseURL is the CLOUDFLARE_API_BASE_URL value.
func (s *Shim) BaseURL() string { return "http://" + s.hostport + "/client/v4" }

// Bearer is the per-run token the command must present.
func (s *Shim) Bearer() string { return s.bearer }

// Grants returns the grant ids currently offered.
func (s *Shim) Grants() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.grants...)
}

// Close stops the listener and in-flight calls.
func (s *Shim) Close() error { return s.srv.Close() }

// refresh reloads the host's active proxy grants. It reports whether the list changed.
func (s *Shim) refresh(ctx context.Context, force bool) error {
	if s.explicit {
		return nil
	}
	s.mu.Lock()
	if !force && time.Since(s.lastRefresh) < shimRefreshEvery {
		s.mu.Unlock()
		return nil
	}
	s.lastRefresh = time.Now()
	s.mu.Unlock()
	gs, err := s.c.ActiveCFProxyGrants(ctx)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(gs))
	for _, g := range gs {
		ids = append(ids, g.ID)
	}
	s.mu.Lock()
	s.grants = grantIDs(s.pinned, ids)
	s.mu.Unlock()
	return nil
}

// isJWTPath reports the upload routes where the upload JWT (not the shim bearer, not the parent
// token) is the credential: POST /accounts/{acct}/workers/assets/upload[/{hash}] and
// POST /pages/assets/{check-missing,upload,upsert-hashes} (CLOUDFLARE.md 2.1 "J").
func isJWTPath(method, cfPath string) bool {
	if method != http.MethodPost {
		return false
	}
	if rest, ok := strings.CutPrefix(cfPath, "/pages/assets/"); ok {
		return rest != "" && !strings.Contains(rest, "/")
	}
	seg := strings.Split(strings.TrimPrefix(cfPath, "/"), "/")
	return (len(seg) == 5 || len(seg) == 6) && seg[0] == "accounts" && seg[1] != "" && seg[2] == "workers" &&
		seg[3] == "assets" && seg[4] == "upload" && (len(seg) == 5 || seg[5] != "")
}

func shimError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(api.CFErrorHeader, code)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"success":  false,
		"errors":   []any{map[string]any{"code": api.CFErrorNumeric, "message": "aqmas shim " + code + ": " + msg}},
		"messages": []any{},
		"result":   nil,
	})
}

// ServeHTTP checks and forwards one call.
func (s *Shim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// DNS rebinding and browsers: only our exact Host, never a cross-origin page.
	if r.Host != s.hostport {
		shimError(w, http.StatusMisdirectedRequest, api.CFErrBadRequest, "wrong Host header")
		return
	}
	if r.Header.Get("Origin") != "" {
		shimError(w, http.StatusForbidden, api.CFErrBadRequest, "browser requests are not accepted")
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		shimError(w, http.StatusMethodNotAllowed, api.CFErrBadRequest, "method not allowed")
		return
	}
	// The escaped path, byte for byte, from the request line.
	uri := r.RequestURI
	path, query, _ := strings.Cut(uri, "?")
	cfPath, ok := strings.CutPrefix(path, "/client/v4")
	if !ok || !strings.HasPrefix(cfPath, "/") {
		shimError(w, http.StatusNotFound, api.CFErrBadPath, "only /client/v4/... is served here")
		return
	}
	jwtRoute := isJWTPath(r.Method, cfPath)
	auth := r.Header.Get("Authorization")
	bearer, isBearer := strings.CutPrefix(auth, "Bearer ")
	ours := isBearer && subtle.ConstantTimeCompare([]byte(bearer), []byte(s.bearer)) == 1
	fwd := http.Header{}
	for _, k := range []string{"Content-Type", "Accept", "If-Match", "If-None-Match"} {
		if v := r.Header.Get(k); v != "" {
			fwd.Set(k, v)
		}
	}
	switch {
	case jwtRoute && !ours && isBearer && bearer != "":
		fwd.Set("Authorization", "Bearer "+bearer) // the upload JWT is the credential here
	case jwtRoute && ours:
		// our own bearer is never forwarded; aqmasd will refuse the upload without a JWT
	case !ours:
		w.Header().Set("WWW-Authenticate", `Bearer realm="aqmas shim"`)
		shimError(w, http.StatusUnauthorized, "unauthenticated", "missing or wrong bearer (use the CLOUDFLARE_API_TOKEN aqmas cf env set)")
		return
	}
	if r.ContentLength > MaxUploadBytes {
		shimError(w, http.StatusRequestEntityTooLarge, api.CFErrBadRequest, "body larger than 100 MiB")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	defer body.Close()

	var buffered []byte
	replayable := false
	switch {
	case r.ContentLength == 0 && r.Header.Get("Transfer-Encoding") == "":
		replayable = true
	case r.ContentLength > 0 && r.ContentLength <= shimRetryBodyMax:
		b, err := io.ReadAll(body)
		if err != nil {
			shimError(w, http.StatusBadRequest, api.CFErrBadRequest, "could not read the request body")
			return
		}
		buffered, replayable = b, true
	}
	call := func(grants []string) (*http.Response, error) {
		pc := &ProxyCall{Method: r.Method, Path: cfPath, Query: query, Header: fwd, Grants: grants, ContentLength: -1}
		switch {
		case buffered != nil:
			pc.Body, pc.ContentLength = bytes.NewReader(buffered), int64(len(buffered))
		case replayable:
			pc.Body = nil
		default:
			pc.Body, pc.ContentLength = body, r.ContentLength
		}
		return s.c.Proxy(r.Context(), pc)
	}
	grants := s.Grants()
	resp, err := call(grants)
	if err == nil && resp.Header.Get(api.CFErrorHeader) == api.CFErrNoGrant && replayable && !s.explicit {
		// A grant approved since the list was loaded (e.g. in another terminal) is picked up.
		if s.refresh(r.Context(), false) == nil {
			if now := s.Grants(); strings.Join(now, ",") != strings.Join(grants, ",") {
				resp.Body.Close()
				resp, err = call(now)
			}
		}
	}
	if err != nil {
		var ue *UsageError
		if errors.As(err, &ue) {
			shimError(w, http.StatusBadRequest, api.CFErrBadPath, sanitize(ue.Msg))
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			shimError(w, http.StatusRequestEntityTooLarge, api.CFErrBadRequest, "body larger than 100 MiB")
			return
		}
		shimError(w, http.StatusBadGateway, api.CFErrUpstream, "aqmasd unreachable: "+sanitize(err.Error()))
		return
	}
	defer resp.Body.Close()
	s.report(r.Method, cfPath, resp)
	for _, k := range []string{"Content-Type", "Content-Disposition", "Cf-Ray", "Retry-After", "Etag", "Last-Modified"} {
		if v := resp.Header.Values(k); len(v) > 0 {
			w.Header()[k] = v
		}
	}
	for k, v := range resp.Header {
		if strings.HasPrefix(k, "X-Aqmas-") {
			w.Header()[k] = v
		}
	}
	w.WriteHeader(resp.StatusCode)
	streamCopy(w, resp.Body)
}

// report prints what the agent's tool would not show: refusals with a ready request command,
// snapshots and guard-rail warnings of writes.
func (s *Shim) report(method, cfPath string, resp *http.Response) {
	info := ParseCFInfo(resp.Header)
	p := sanitize(cfPath)
	if len(p) > 120 {
		p = p[:120] + "..."
	}
	switch {
	case info.Error == api.CFErrNoGrant:
		key := info.NeedsScope
		s.mu.Lock()
		seen := s.hinted[key]
		s.hinted[key] = true
		s.mu.Unlock()
		if seen {
			return
		}
		if cmd := NeedsScopeCommand(info.NeedsScope); cmd != "" {
			s.e.logf("cf env: no grant allows %s %s; request one with: %s", method, p, cmd)
		} else {
			s.e.logf("cf env: no grant allows %s %s (no scope but cf.admin would)", method, p)
		}
	case info.Error != "":
		s.e.logf("cf env: %s %s refused by aqmasd: %s", method, p, info.Error)
	}
	if info.SnapshotBefore != "" || info.SnapshotAfter != "" {
		s.e.logf("cf env: %s %s: snapshot before %s, after %s", method, p, orDash(info.SnapshotBefore), orDash(info.SnapshotAfter))
	}
	for _, w := range info.Warnings {
		s.e.logf("cf env: %s %s: warning: %s", method, p, w)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// streamCopy copies src to w, flushing after each chunk (no full buffering).
func streamCopy(w http.ResponseWriter, src io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			rc.Flush()
		}
		if err != nil {
			return
		}
	}
}
