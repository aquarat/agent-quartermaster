package cfaccess

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestServer serves a JWKS for key under kid "k1" and mints tokens.
type TestServer struct {
	*httptest.Server
	Key *rsa.PrivateKey
}

func NewTestServer(t *testing.T) *TestServer {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	ts := &TestServer{Key: k}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "RSA", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}}})
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *TestServer) Token(iss, aud string, exp time.Time, key *rsa.PrivateKey) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": iss, "aud": []string{aud}, "exp": exp.Unix(), "email": "owner@example.com"})
	tok.Header["kid"] = "k1"
	s, _ := tok.SignedString(key)
	return s
}

func TestVerify(t *testing.T) {
	ts := NewTestServer(t)
	v := New("team.example.com", "AUD1")
	v.CertsURL = ts.URL
	ctx := context.Background()
	good := ts.Token("https://team.example.com", "AUD1", time.Now().Add(time.Hour), ts.Key)
	if email, err := v.Verify(ctx, good); err != nil || email != "owner@example.com" {
		t.Fatalf("good token: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, tok := range map[string]string{
		"empty":     "",
		"wrong aud": ts.Token("https://team.example.com", "AUD2", time.Now().Add(time.Hour), ts.Key),
		"wrong iss": ts.Token("https://evil.example.com", "AUD1", time.Now().Add(time.Hour), ts.Key),
		"expired":   ts.Token("https://team.example.com", "AUD1", time.Now().Add(-time.Hour), ts.Key),
		"wrong key": ts.Token("https://team.example.com", "AUD1", time.Now().Add(time.Hour), other),
		"none alg":  "eyJhbGciOiJub25lIiwia2lkIjoiazEifQ.eyJpc3MiOiJodHRwczovL3RlYW0uZXhhbXBsZS5jb20iLCJhdWQiOiJBVUQxIn0.",
	} {
		if _, err := v.Verify(ctx, tok); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
