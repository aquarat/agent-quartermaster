package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
)

func (s *Server) authorisedWork(ctx context.Context) bool {
	return s.seal == nil && !s.sealSetup || ctx.Value(leaseKey{}) != nil && ctx.Err() == nil
}

// One state observation for each request. In particular a request which was
// accepted queue-only cannot turn into a silent approval on concurrent unlock.
func (s *Server) optionalLease(ctx context.Context, op func(context.Context)) {
	if s.seal == nil || s.isLocked() {
		op(ctx)
		return
	}
	if err := s.withLease(ctx, func(c context.Context) error { op(c); return nil }); err != nil {
		op(ctx)
	}
}

// Header and body go through the same fence as signer and proxy leases. An
// already-started write cannot be retracted. If headers were sent, truncate
// rather than allowing a new chunk to leave a draining broker.
type fencedWriter struct {
	http.ResponseWriter
	gate    *seal.Gate
	started bool
}

func (w *fencedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *fencedWriter) WriteHeader(status int) {
	if err := w.gate.Publish(func() error { w.started = true; w.ResponseWriter.WriteHeader(status); return nil }); err != nil && !w.started {
		w.ResponseWriter.Header().Del("Content-Length")
		w.ResponseWriter.WriteHeader(423)
		w.started = true
	}
}
func (w *fencedWriter) Write(b []byte) (n int, err error) {
	err = w.gate.Publish(func() error { var e error; w.started = true; n, e = w.ResponseWriter.Write(b); return e })
	if err != nil && !w.started {
		w.WriteHeader(423)
	}
	return
}
func (s *Server) deliveryWriter(ctx context.Context, w http.ResponseWriter) http.ResponseWriter {
	if s.seal != nil && ctx.Value(leaseKey{}) != nil {
		return &fencedWriter{ResponseWriter: w, gate: s.seal.gate}
	}
	return w
}

func (s *Server) signer(ctx context.Context, role string) (*pki.PKI, error) {
	if !s.authorisedWork(ctx) {
		return nil, lockedErr()
	}
	if s.seal == nil {
		return s.pki, nil
	}
	b, err := s.secret(ctx, role)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	p, err := s.pki.WithPrivate(role, b)
	if err != nil {
		s.stopSealed()
	}
	return p, err
}

// Wait for the deadline callback so it cannot outlive this handler.
func boundDelivery(ctx context.Context, w http.ResponseWriter) func() {
	if ctx.Value(leaseKey{}) == nil {
		return func() {}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = http.NewResponseController(w).SetWriteDeadline(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}
}

func (s *Server) guardedWeb(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.seal == nil && !s.sealSetup {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/ui/seal/") || p == "/api/ui/login/begin" || p == "/api/ui/login/finish" || p == "/api/ui/session" || p == "/api/ui/logout" {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := s.sessionHash(r); !ok {
			s.writeErr(w, r, errUnauth("log in first"))
			return
		}
		s.optionalLease(r.Context(), func(ctx context.Context) {
			if !s.authorisedWork(ctx) {
				switch r.Method {
				case "GET":
					switch p {
					case "/api/ui/state", "/api/ui/help", "/api/ui/hosts", "/api/ui/updates", "/api/ui/setup":
					default:
						if !itemPath(p, "requests", "") && !itemPath(p, "enrollments", "") {
							s.writeErr(w, r, lockedErr())
							return
						}
					}
				case "POST":
					allowed := s.sealSetup && p == "/api/ui/setup/cancel"
					if !s.sealSetup {
						for _, k := range []string{"requests", "enrollments", "standing", "grants", "hosts", "passkeys"} {
							verb := "revoke"
							if k == "requests" || k == "enrollments" {
								verb = "decide"
							}
							if k == "passkeys" {
								verb = "remove"
							}
							allowed = allowed || itemPath(p, k, verb) || itemPath(p, k, "challenge")
						}
					}
					if !allowed {
						s.writeErr(w, r, lockedErr())
						return
					}
				default:
					s.writeErr(w, r, lockedErr())
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
}
func itemPath(path, group, verb string) bool {
	p, ok := strings.CutPrefix(path, "/api/ui/"+group+"/")
	if !ok {
		return false
	}
	id, rest, slash := strings.Cut(p, "/")
	return id != "" && slash == (verb != "") && rest == verb
}
func lockedDecision(object, action string) bool {
	switch object {
	case "request", "enrollment":
		return action == "deny"
	case "grant", "standing", "host":
		return action == "revoke"
	case "passkey":
		return action == "remove"
	}
	return false
}
