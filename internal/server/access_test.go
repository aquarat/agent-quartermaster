package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAccessJWTRequired(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kid": "k1", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}}})
	}))
	defer jwks.Close()
	cfg := testConfig(t.TempDir())
	cfg.Access.TeamDomain, cfg.Access.AUD = "team.example.com", "AUD1"
	s, err := New(Options{Config: cfg, AccessCertsURL: jwks.URL, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	web := httptest.NewServer(s.WebHandler())
	defer web.Close()
	get := func(path, tok string) int {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", web.URL+path, nil)
		if tok != "" {
			req.Header.Set("Cf-Access-Jwt-Assertion", tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://team.example.com", "aud": "AUD1", "exp": time.Now().Add(time.Hour).Unix()})
	tok.Header["kid"] = "k1"
	signed, _ := tok.SignedString(k)
	mustStatus(t, "UI without token", get("/", ""), 403)
	mustStatus(t, "API without token", get("/api/ui/session", ""), 403)
	mustStatus(t, "garbage token", get("/api/ui/session", "x.y.z"), 403)
	mustStatus(t, "valid token", get("/api/ui/session", signed), 200)
	mustStatus(t, "healthz", get("/healthz", ""), 200)
}

func TestAuditAppendOnly(t *testing.T) {
	e := newEnv(t)
	q := e.s.store.Q()
	if err := q.Audit(t.Context(), time.Now(), "system", "x", "y", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.store.DB().Exec("UPDATE audit SET detail = 'tampered'"); err == nil {
		t.Fatal("audit row updated")
	}
	if _, err := e.s.store.DB().Exec("DELETE FROM audit"); err == nil {
		t.Fatal("audit row deleted")
	}
}
