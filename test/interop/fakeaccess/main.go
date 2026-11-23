// fakeaccess stands in for Cloudflare Access in the migration interop test
// (test/interop/run-migrate.sh): approval windows need a verified Access identity.
//
// It is an HTTP proxy for exactly one HTTPS host, the team domain: a CONNECT to
// TEAM:443 is answered with TLS from a throwaway CA (written to -ca-out, which the
// broker trusts through SSL_CERT_FILE) serving the team's JWKS at
// /cdn-cgi/access/certs. It writes one RS256 Access token (sub, email, iss, aud,
// two hours) to -token-out for the owner helper's Cf-Access-Jwt-Assertion header.
// Test-only: every key lives in memory and dies with the process.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "proxy address")
	team := flag.String("team", "team.example.com", "Access team domain")
	aud := flag.String("aud", "", "application AUD")
	caOut := flag.String("ca-out", "", "write the CA certificate (PEM) here")
	tokenOut := flag.String("token-out", "", "write the Access token here")
	flag.Parse()
	if *aud == "" || *caOut == "" || *tokenOut == "" {
		log.Fatal("fakeaccess: -aud, -ca-out and -token-out are required")
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fakeaccess test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	check(err)
	ca, err := x509.ParseCertificate(caDER)
	check(err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: *team}, DNSNames: []string{*team},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &leafKey.PublicKey, caKey)
	check(err)
	check(os.WriteFile(*caOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://" + *team, "aud": []string{*aud}, "sub": "interop-owner-sub", "email": "owner@example.com",
		"iat": now.Unix(), "exp": now.Add(2 * time.Hour).Unix()})
	tok.Header["kid"] = "interop"
	text, err := tok.SignedString(signer)
	check(err)
	check(os.WriteFile(*tokenOut, []byte(text), 0o600))

	b64 := base64.RawURLEncoding.EncodeToString
	certs := map[string]any{"keys": []map[string]string{{"kid": "interop", "kty": "RSA", "alg": "RS256", "n": b64(signer.N.Bytes()), "e": b64(big.NewInt(int64(signer.E)).Bytes())}}}
	team443 := net.JoinHostPort(*team, "443")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	jwks := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(certs)
	})

	ln, err := net.Listen("tcp", *listen)
	check(err)
	log.Printf("fakeaccess: proxy on %s for %s", ln.Addr(), team443)
	check(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != team443 {
			http.Error(w, "fakeaccess proxies only "+team443, http.StatusForbidden)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
				return
			}
			c := tls.Server(conn, tlsCfg)
			br := bufio.NewReader(c)
			for {
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				rw := &response{h: http.Header{}}
				jwks.ServeHTTP(rw, req)
				res := &http.Response{StatusCode: rw.code(), ProtoMajor: 1, ProtoMinor: 1, Header: rw.h, ContentLength: int64(len(rw.body)), Body: io.NopCloser(bytes.NewReader(rw.body))}
				if res.Write(c) != nil {
					return
				}
			}
		}()
	})))
}

type response struct {
	h      http.Header
	status int
	body   []byte
}

func (r *response) Header() http.Header         { return r.h }
func (r *response) Write(b []byte) (int, error) { r.body = append(r.body, b...); return len(b), nil }
func (r *response) WriteHeader(code int)        { r.status = code }
func (r *response) code() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

func check(err error) {
	if err != nil {
		log.Fatal("fakeaccess: ", err)
	}
}
