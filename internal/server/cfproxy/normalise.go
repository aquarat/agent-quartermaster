package cfproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
)

// refusal is one of aqmasd's own answers (docs/API.md 5.5): Cloudflare-shaped body plus
// X-Aqmas-Error.
type refusal struct {
	status     int
	code       string // api.CFErr*
	msg        string
	guard      string // guard_rail: the guard's name
	needs      string // no_grant: X-Aqmas-Needs-Scope
	retryAfter int    // rate_limited: seconds
}

func refuse(status int, code, msg string) *refusal {
	return &refusal{status: status, code: code, msg: msg}
}

func (rf *refusal) text() string {
	if rf.guard != "" {
		return "aqmas " + rf.code + ": " + rf.guard + ": " + rf.msg
	}
	return "aqmas " + rf.code + ": " + rf.msg
}

// cfError is Cloudflare's error envelope.
type cfError struct {
	Success  bool          `json:"success"`
	Errors   []cfErrorItem `json:"errors"`
	Messages []any         `json:"messages"`
	Result   any           `json:"result"`
}

type cfErrorItem struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeRefusal(w http.ResponseWriter, rf *refusal) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set(api.CFErrorHeader, rf.code)
	if rf.needs != "" {
		h.Set(api.CFNeedsScopeHeader, rf.needs)
	}
	if rf.retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(rf.retryAfter))
	}
	if rf.status == http.StatusMethodNotAllowed {
		h.Set("Allow", "GET, POST, PUT, PATCH, DELETE")
	}
	w.WriteHeader(rf.status)
	_ = json.NewEncoder(w).Encode(cfError{Errors: []cfErrorItem{{Code: api.CFErrorNumeric, Message: asciiOnly(rf.text())}}, Messages: []any{}})
}

// writeResult answers with Cloudflare's success envelope (synthetic endpoints).
func writeResult(w http.ResponseWriter, result any, info any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	body := map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}
	if info != nil {
		body["result_info"] = info
	}
	_ = json.NewEncoder(w).Encode(body)
}

// asciiOnly keeps printable ASCII (header and message safety).
func asciiOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

const (
	maxPathLen  = 4096
	maxQueryLen = 2048
)

var methodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

func pathByteOK(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("._~-!$&'()*+,=:@/%", c) >= 0
}

func queryByteOK(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("._~-%=&+,:*", c) >= 0
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// validPercent: every '%' starts a %XX escape.
func validPercent(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}

// normalise checks method, method-override headers, the escaped path and the query
// (docs/CLOUDFLARE.md 3.1). The escaped path is kept byte for byte.
func normalise(r *http.Request) (cfscope.Call, *refusal) {
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return cfscope.Call{}, refuse(http.StatusMethodNotAllowed, api.CFErrBadRequest, "method not allowed")
	}
	for _, h := range methodOverrideHeaders {
		if _, ok := r.Header[http.CanonicalHeaderKey(h)]; ok {
			return cfscope.Call{}, refuse(http.StatusBadRequest, api.CFErrBadRequest, "method-override headers are refused")
		}
	}
	uri := r.RequestURI
	if uri == "" { // not from a server (tests constructing requests by hand)
		uri = r.URL.RequestURI()
	}
	if !strings.HasPrefix(uri, PathPrefix+"/") {
		return cfscope.Call{}, refuse(http.StatusBadRequest, api.CFErrBadPath, "path must start with "+PathPrefix+"/")
	}
	rest := uri[len(PathPrefix):]
	path, query, _ := strings.Cut(rest, "?")
	segs, msg := checkPath(path)
	if msg != "" {
		return cfscope.Call{}, refuse(http.StatusBadRequest, api.CFErrBadPath, msg)
	}
	if msg := checkQuery(query); msg != "" {
		return cfscope.Call{}, refuse(http.StatusBadRequest, api.CFErrBadPath, msg)
	}
	return cfscope.Call{Method: r.Method, Path: path, Segments: segs, Query: query}, nil
}

func checkPath(path string) ([]string, string) {
	if len(path) < 2 || path[0] != '/' {
		return nil, "empty path"
	}
	if len(path) > maxPathLen {
		return nil, "path too long"
	}
	for i := 0; i < len(path); i++ {
		if !pathByteOK(path[i]) {
			return nil, "character not allowed in path"
		}
	}
	if !validPercent(path) {
		return nil, "invalid percent-encoding"
	}
	segs := strings.Split(path[1:], "/")
	for _, s := range segs {
		switch s {
		case "":
			return nil, "empty path segment (// or trailing /)"
		case ".", "..":
			return nil, "dot segment in path"
		}
		if strings.Contains(s, "%") {
			d, err := url.PathUnescape(s)
			if err != nil || d == "" || d == "." || d == ".." || strings.ContainsAny(d, "/\\\x00") {
				return nil, "percent-encoded segment decodes to a forbidden value"
			}
		}
	}
	return segs, ""
}

func checkQuery(q string) string {
	if len(q) > maxQueryLen {
		return "query too long"
	}
	for i := 0; i < len(q); i++ {
		if !queryByteOK(q[i]) {
			return "character not allowed in query"
		}
	}
	if !validPercent(q) {
		return "invalid percent-encoding in query"
	}
	return ""
}
