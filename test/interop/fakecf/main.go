// Command fakecf serves the in-memory fake Cloudflare API (internal/testutil/fakecf) for the
// interop tests: aqmasd's api_base points at it instead of api.cloudflare.com.
//
//	go run ./test/interop/fakecf -listen 127.0.0.1:8787 -token-file /tmp/x/parent-tokens \
//	    -account 0123...  -zone example.com=aaaa... -tunnel home=1111-... -d1 times=9999-... \
//	    [-pages site] [-single-asset-uploads] [-tls-ca-out /tmp/x/fakecf-ca.pem]
//
// The token file holds one parent token per line (blank lines and # comments ignored); the
// tokens are never printed. The API is at <url>/client/v4; GET <url>/__fake/requests lists the
// recorded requests (DELETE clears), GET <url>/__fake/tokens the minted child tokens (no
// values), GET <url>/__fake/state a summary. With -tls-ca-out it serves HTTPS with a fresh
// self-signed certificate for 127.0.0.1 and writes that certificate (PEM) to the given path.
// It prints one line "fakecf: listening on <url>" when ready.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/testutil/fakecf"
)

type namedList []fakecf.Named

func (n *namedList) String() string { return fmt.Sprint(*n) }
func (n *namedList) Set(v string) error {
	name, id, ok := strings.Cut(v, "=")
	if !ok || name == "" || id == "" {
		return fmt.Errorf("want NAME=ID, got %q", v)
	}
	*n = append(*n, fakecf.Named{Name: name, ID: id})
	return nil
}

type strList []string

func (s *strList) String() string     { return strings.Join(*s, ",") }
func (s *strList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	var zones, tunnels, d1 namedList
	var pages strList
	listen := flag.String("listen", "127.0.0.1:8787", "address to listen on")
	tokenFile := flag.String("token-file", "", "file with the fake parent token(s), one per line (required)")
	account := flag.String("account", "0123456789abcdef0123456789abcdef", "account id")
	single := flag.Bool("single-asset-uploads", false, "make wrangler upload Workers assets one per request (POST .../workers/assets/upload/{hash})")
	caOut := flag.String("tls-ca-out", "", "serve HTTPS with a self-signed certificate and write it (PEM) here")
	flag.Var(&zones, "zone", "zone NAME=ID (32 hex), repeatable")
	flag.Var(&tunnels, "tunnel", "tunnel NAME=ID (UUID), repeatable")
	flag.Var(&d1, "d1", "D1 database NAME=ID (UUID), repeatable")
	flag.Var(&pages, "pages", "Pages project to pre-create, repeatable")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("fakecf: ")
	if *tokenFile == "" {
		log.Fatal("-token-file is required")
	}
	data, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatalf("token file: %v", err)
	}
	var tokens []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			tokens = append(tokens, l)
		}
	}
	f, err := fakecf.New(fakecf.Options{Tokens: tokens, AccountID: *account, Zones: zones, Tunnels: tunnels, D1: d1,
		PagesProjects: pages, SingleAssetUploads: *single})
	if err != nil {
		log.Fatal(err) // never includes token values
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 30 * time.Second}
	scheme := "http"
	if *caOut != "" {
		cert, pemData, err := selfSigned()
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*caOut, pemData, 0o644); err != nil {
			log.Fatal(err)
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		scheme = "https"
	}
	fmt.Printf("fakecf: listening on %s://%s\n", scheme, ln.Addr())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	f.Close()
}

func selfSigned() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "fakecf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
