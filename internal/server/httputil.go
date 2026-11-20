package server

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

const maxBody = 64 << 10

type apiErr struct {
	status int
	code   string
	msg    string
}

func (e *apiErr) Error() string { return e.code + ": " + e.msg }

func errBad(msg string) *apiErr       { return &apiErr{http.StatusBadRequest, "bad_request", msg} }
func errUnauth(msg string) *apiErr    { return &apiErr{http.StatusUnauthorized, "unauthenticated", msg} }
func errForbidden(msg string) *apiErr { return &apiErr{http.StatusForbidden, "forbidden", msg} }
func errNotFound() *apiErr            { return &apiErr{http.StatusNotFound, "not_found", "not found"} }
func errConflict(msg string) *apiErr  { return &apiErr{http.StatusConflict, "conflict", msg} }
func errExpired(msg string) *apiErr   { return &apiErr{http.StatusGone, "expired", msg} }
func errInternal() *apiErr {
	return &apiErr{http.StatusInternalServerError, "internal", "internal error"}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiErr
	if !errors.As(err, &ae) {
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		ae = errInternal()
	}
	writeJSON(w, ae.status, api.Error{Code: ae.code, Message: ae.msg})
}

// decode reads a JSON body of at most maxBody bytes into v.
func decode(r *http.Request, v any) error {
	body := http.MaxBytesReader(nil, r.Body, maxBody)
	b, err := io.ReadAll(body)
	if err != nil {
		return errBad("body too large or unreadable")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errBad("invalid JSON body")
	}
	return nil
}

// peerIP returns the TCP peer address (never a forwarded header).
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return host
}

func hasControl(s string, allowNewline bool) bool {
	for _, r := range s {
		if (r < 0x20 && !(allowNewline && (r == '\n' || r == '\t'))) || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return true
		}
	}
	return false
}

func sanitizeLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}
