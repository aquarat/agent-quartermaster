package server

import (
	"net/http"
	"strings"
)

// guardedWeb fences the web API only while a seal is being staged
// (seal-import / bucket-migrate): the staging page, sign-in and Setup's
// read-only views. A serving format-2 broker has no lock state and no route
// allowlist: each operation that needs a bucket refuses on its own (423).
func (s *Server) guardedWeb(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.sealSetup {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/api/ui/seal/"), p == "/api/ui/login/begin", p == "/api/ui/login/finish", p == "/api/ui/session", p == "/api/ui/logout":
		case r.Method == http.MethodGet && (p == "/api/ui/state" || p == "/api/ui/help" || p == "/api/ui/setup"):
		case r.Method == http.MethodPost && p == "/api/ui/setup/cancel":
		default:
			if _, ok := s.sessionHash(r); !ok {
				s.writeErr(w, r, errUnauth("log in first"))
				return
			}
			s.writeErr(w, r, &apiErr{423, "locked", "the store is being sealed; finish or cancel setup first"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
