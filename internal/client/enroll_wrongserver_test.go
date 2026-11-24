package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func wantNotAgentAPI(t *testing.T, err error, extra ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	for _, s := range append([]string{"does not look like the aqmas agent API", "https://HOST:8443", "Help page in the web UI", "--ca-pin"}, extra...) {
		if !strings.Contains(err.Error(), s) {
			t.Fatalf("error lacks %q: %v", s, err)
		}
	}
}

// A chain the public web trusts is not the agent API's: enrolment stops before it asks
// anyone to pin a public CA, and before it sends anything.
func TestEnrollPublicChainIsNotTheAgentAPI(t *testing.T) {
	f := newFakeServer(t)
	old := publicRoots
	t.Cleanup(func() { publicRoots = old })
	publicRoots = func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		p.AddCert(f.serverCA.cert) // stands in for a public certificate authority
		return p, nil
	}
	e := newTestEnv(t)
	e.StdinIsTTY = true
	e.Stdin = strings.NewReader("yes\n")
	err := e.Enroll(context.Background(), EnrollOptions{Name: "agenthost", Server: f.URL()})
	wantNotAgentAPI(t, err, "public certificate authority", "Nothing was pinned or sent")
	if f.enrollPosts != 0 || strings.Contains(e.stderr.String(), "Pin this certificate") {
		t.Fatalf("posts=%d, prompt shown: %s", f.enrollPosts, e.stderr)
	}
	if _, err := os.Stat(e.Paths.ConfigFile()); !os.IsNotExist(err) {
		t.Error("config written")
	}
	// An explicit pin is the owner's statement about the CA and is honoured as before.
	e = newTestEnv(t)
	if err := e.Enroll(context.Background(), EnrollOptions{Name: "agenthost", Server: f.URL(), CAPin: f.pin()}); err != nil {
		t.Fatalf("explicit pin under a publicly trusted chain: %v", err)
	}
	// A private chain is offered for pinning as before.
	publicRoots = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
	e = newTestEnv(t)
	e.StdinIsTTY = true
	e.Stdin = strings.NewReader("yes\n")
	if err := e.Enroll(context.Background(), EnrollOptions{Name: "otherhost", Server: f.URL()}); err != nil {
		t.Fatalf("private chain: %v", err)
	}
}

// Behind a verified pin, a redirect or a web page in place of the enrolment answer is named
// for what it is, instead of "server: http_302: Found".
func TestEnrollAgainstAWebUI(t *testing.T) {
	for name, c := range map[string]struct {
		handler http.HandlerFunc
		want    string
	}{
		"sign-in redirect": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://sso.example.com/login?next=x", http.StatusFound)
		}, "HTTP 302, a redirect to sso.example.com"},
		"page": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!doctype html><title>aqmas</title>"))
		}, "HTTP 200 with a web page"},
		"page for a missing route": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
		}, "HTTP 404 with a web page"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(c.handler)
			srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			srv.StartTLS()
			t.Cleanup(srv.Close)
			e := newTestEnv(t)
			err := e.Enroll(context.Background(), EnrollOptions{Name: "agenthost", Server: srv.URL, CAPin: FormatPin(CertPin(srv.Certificate()))})
			wantNotAgentAPI(t, err, c.want)
			if strings.Contains(err.Error(), "http_302") {
				t.Fatalf("raw status leaked as the message: %v", err)
			}
			if _, err := os.Stat(e.Paths.ConfigFile()); !os.IsNotExist(err) {
				t.Error("config written")
			}
		})
	}
}
