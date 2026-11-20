package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Trust is the client's view of which server certificates are acceptable. Exactly one trust
// anchor is used: the pinned server CA certificate (from a PEM file) or, before that file
// exists, a certificate in the presented chain whose SHA-256 matches the pin.
type Trust struct {
	CA  *x509.Certificate // pinned CA certificate, if known
	Pin []byte            // SHA-256 of the pinned certificate's DER, if known

	mu      sync.Mutex
	matched *x509.Certificate // the anchor that verified the last connection
}

// ParsePin parses "sha256:<hex>" (colons inside the hex are allowed, as openssl prints them).
func ParsePin(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(strings.ToLower(s), "sha256:")
	if !ok {
		return nil, fmt.Errorf("CA pin must look like sha256:<64 hex digits>")
	}
	rest = strings.ReplaceAll(rest, ":", "")
	b, err := hex.DecodeString(rest)
	if err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("CA pin must look like sha256:<64 hex digits>")
	}
	return b, nil
}

// FormatPin renders a fingerprint as "sha256:<hex>".
func FormatPin(fp []byte) string { return "sha256:" + hex.EncodeToString(fp) }

// CertPin returns the SHA-256 of a certificate's DER encoding.
func CertPin(c *x509.Certificate) []byte {
	s := sha256.Sum256(c.Raw)
	return s[:]
}

// LoadTrust builds the trust from config: the CA PEM file and/or the fingerprint.
func LoadTrust(c *Config) (*Trust, error) {
	t := &Trust{}
	if c.ServerCASHA256 != "" {
		pin, err := ParsePin(c.ServerCASHA256)
		if err != nil {
			return nil, fmt.Errorf("server_ca_sha256: %w", err)
		}
		t.Pin = pin
	}
	if c.ServerCA != "" {
		path := expandHome(c.ServerCA)
		if err := checkPrivatePath(path, false); err != nil {
			return nil, fmt.Errorf("server_ca: %w", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("server_ca: %w", err)
		}
		ca, err := parseSingleCertPEM(data)
		if err != nil {
			return nil, fmt.Errorf("server_ca %s: %w", path, err)
		}
		if t.Pin != nil && !equalBytes(CertPin(ca), t.Pin) {
			return nil, fmt.Errorf("server_ca %s does not match server_ca_sha256", path)
		}
		t.CA = ca
		t.Pin = CertPin(ca)
	}
	if t.Pin == nil {
		return nil, errors.New("config pins no server CA (server_ca or server_ca_sha256); re-run `aqmas enroll`")
	}
	return t, nil
}

func parseSingleCertPEM(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM CERTIFICATE block")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("expected exactly one certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Matched returns the anchor certificate that verified the most recent connection.
func (t *Trust) Matched() *x509.Certificate {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.matched
}

// verify checks the presented chain against the single pinned anchor, including the server
// name and the serverAuth EKU (so a fleet host's client certificate from the same internal
// CA can never pass as the server).
func (t *Trust) verify(serverName string, certs []*x509.Certificate, now time.Time) error {
	if len(certs) == 0 {
		return errors.New("server presented no certificate")
	}
	var anchor *x509.Certificate
	if t.CA != nil {
		anchor = t.CA
	} else if t.Pin != nil {
		for _, c := range certs {
			if equalBytes(CertPin(c), t.Pin) {
				anchor = c
				break
			}
		}
		if anchor == nil {
			return fmt.Errorf("server certificate chain does not contain the pinned CA %s (presented: %s)",
				FormatPin(t.Pin), describeChain(certs))
		}
	} else {
		return errors.New("no pinned server CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		DNSName:       serverName,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("server certificate does not verify against the pinned CA %s: %w", FormatPin(CertPin(anchor)), err)
	}
	t.mu.Lock()
	t.matched = anchor
	t.mu.Unlock()
	return nil
}

func describeChain(certs []*x509.Certificate) string {
	var parts []string
	for _, c := range certs {
		parts = append(parts, fmt.Sprintf("%q %s", c.Subject.CommonName, FormatPin(CertPin(c))))
	}
	return strings.Join(parts, ", ")
}

// TLSConfig returns a TLS 1.3 client config that verifies the server with t and presents
// clientCert when non-nil.
func (t *Trust) TLSConfig(serverName string, clientCert *tls.Certificate, now func() time.Time) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// Standard verification is replaced (not skipped): VerifyConnection below runs on
		// every handshake, including resumed ones, and checks the chain against the pin.
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return t.verify(serverName, cs.PeerCertificates, now())
		},
	}
	if clientCert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		}
	}
	return cfg
}

// serverHostPort splits the server URL into host (for name verification) and host:port.
func serverHostPort(server string) (host, hostport string, err error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", "", fmt.Errorf("server URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", "", fmt.Errorf("server URL must be https://, got %q", server)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("server URL must be https://host[:port] only, got %q", server)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("server URL has no host: %q", server)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return host, net.JoinHostPort(host, port), nil
}

// ProbeChain connects without verification and returns the presented chain. It is used only
// to show the owner a fingerprint for trust-on-first-use; nothing is sent over the connection.
func ProbeChain(ctx context.Context, server string) ([]*x509.Certificate, error) {
	host, hostport, err := serverHostPort(server)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	d := tls.Dialer{Config: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // probe only; the chain is shown to the owner
		VerifyConnection: func(cs tls.ConnectionState) error {
			chain = cs.PeerCertificates
			return nil
		},
	}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, &UnreachableError{Err: err}
	}
	conn.Close()
	if len(chain) == 0 {
		return nil, &UnreachableError{Err: errors.New("server presented no certificate")}
	}
	return chain, nil
}

// TOFUCandidate picks the certificate to pin from a presented chain: the top-most CA
// certificate, or the leaf when the server sent no CA certificate.
func TOFUCandidate(chain []*x509.Certificate) *x509.Certificate {
	for i := len(chain) - 1; i >= 0; i-- {
		c := chain[i]
		if c.BasicConstraintsValid && c.IsCA {
			return c
		}
	}
	return chain[0]
}

// ConfirmTOFU shows the candidate and asks the user to type "yes". It must only be called when
// stdin is a terminal.
func ConfirmTOFU(ctx context.Context, in io.Reader, out io.Writer, server string, chain []*x509.Certificate, cand *x509.Certificate) (bool, error) {
	fmt.Fprintf(out, "aqmas: no CA pin given for %s. The server presented:\n", sanitize(server))
	for i, c := range chain {
		fmt.Fprintf(out, "  [%d] subject %q issuer %q\n      %s  valid %s .. %s  CA=%v\n", i,
			sanitize(c.Subject.String()), sanitize(c.Issuer.String()), FormatPin(CertPin(c)),
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), c.IsCA)
	}
	if !(cand.BasicConstraintsValid && cand.IsCA) {
		fmt.Fprintf(out, "WARNING: the server sent no CA certificate, so only its own certificate can be pinned;\n"+
			"  when the server renews it, this host must re-enroll. Prefer --ca-pin with the CA fingerprint.\n")
	}
	fmt.Fprintf(out, "Pin this certificate as the server CA?\n  %q\n  %s\n", sanitize(cand.Subject.String()), FormatPin(CertPin(cand)))
	fmt.Fprintf(out, "Compare it with the server CA fingerprint on the bastion first. Type yes to trust it: ")
	type answer struct {
		line string
		err  error
	}
	ch := make(chan answer, 1)
	go func() {
		line, err := bufio.NewReader(in).ReadString('\n')
		ch <- answer{line, err}
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(out)
		return false, ErrCancelled
	case a := <-ch:
		if a.err != nil && !errors.Is(a.err, io.EOF) {
			return false, a.err
		}
		return strings.TrimSpace(a.line) == "yes", nil
	}
}
