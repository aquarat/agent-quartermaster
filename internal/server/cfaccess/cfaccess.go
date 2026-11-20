// Package cfaccess validates Cloudflare Access application tokens (Cf-Access-Jwt-Assertion).
// It is defence in depth on the web listener; the security boundary is the per-action passkey
// assertion.
package cfaccess

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Header is the request header Cloudflare Access sets.
const Header = "Cf-Access-Jwt-Assertion"

// Verifier checks Access JWTs against the team's signing keys.
type Verifier struct {
	Issuer   string // https://<team_domain>
	AUD      string
	CertsURL string // https://<team_domain>/cdn-cgi/access/certs
	Client   *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	lastTry   time.Time // last fetch attempt (successful or not): limits refetches
}

// New returns a verifier for team domain and application AUD.
func New(teamDomain, aud string) *Verifier {
	return &Verifier{
		Issuer:   "https://" + teamDomain,
		AUD:      aud,
		CertsURL: "https://" + teamDomain + "/cdn-cgi/access/certs",
		Client:   &http.Client{Timeout: 10 * time.Second},
	}
}

type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.CertsURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cfaccess: certs: HTTP %d", resp.StatusCode)
	}
	var set jwks
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("cfaccess: certs: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) > 4 {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	if len(keys) == 0 {
		return errors.New("cfaccess: certs: no RSA keys")
	}
	v.keys, v.fetchedAt = keys, time.Now()
	return nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok && time.Since(v.fetchedAt) < 24*time.Hour {
		return k, nil
	}
	// Unknown kid (rotation) or stale cache: refetch, at most once a minute.
	if time.Since(v.lastTry) > time.Minute || (v.keys == nil && time.Since(v.lastTry) > 5*time.Second) {
		v.lastTry = time.Now()
		if err := v.refresh(ctx); err != nil {
			return nil, err
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("cfaccess: unknown key id")
}

// Identity is who Cloudflare Access authenticated.
type Identity struct {
	Email string
	Sub   string
}

// Verify validates a token: RS256 signature by a current team key, issuer, audience, expiry.
func (v *Verifier) Verify(ctx context.Context, token string) (Identity, error) {
	if token == "" {
		return Identity{}, errors.New("cfaccess: missing token")
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.key(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.AUD),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return Identity{}, fmt.Errorf("cfaccess: %w", err)
	}
	var id Identity
	id.Email, _ = claims["email"].(string)
	id.Sub, _ = claims["sub"].(string)
	return id, nil
}
