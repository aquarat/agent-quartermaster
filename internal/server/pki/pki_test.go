package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGenerateLoadAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	p, err := Load(dir, []string{"192.0.2.60", "bastion"}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{SSHCAKeyFile, ClientCAKeyFile, ServerKeyFile} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v %v", f, st.Mode().Perm(), err)
		}
	}
	if !strings.HasPrefix(p.SSHCAPublicLine(), "ssh-ed25519 ") {
		t.Fatal(p.SSHCAPublicLine())
	}
	if !slices.Equal(certSANs(p.ServerLeaf), []string{"192.0.2.60", "bastion"}) || p.ServerLeaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("server cert %v", certSANs(p.ServerLeaf))
	}
	// Reload: same CA.
	p2, err := Load(dir, []string{"bastion", "192.0.2.60"}, true)
	if err != nil || !p2.CACert.Equal(p.CACert) || !p2.ServerLeaf.Equal(p.ServerLeaf) {
		t.Fatal("reload changed key material")
	}
	// SAN change reissues the server cert under the same CA.
	p3, _ := Load(dir, []string{"bastion"}, true)
	if p3.ServerLeaf.Equal(p.ServerLeaf) || p3.ServerLeaf.CheckSignatureFrom(p.CACert) != nil {
		t.Fatal("server cert not reissued")
	}
	// Group-readable key: refused.
	os.Chmod(filepath.Join(dir, ClientCAKeyFile), 0o640)
	if _, err := Load(dir, nil, true); err == nil || !strings.Contains(err.Error(), "group/other") {
		t.Fatalf("group-readable key accepted: %v", err)
	}
	os.Chmod(filepath.Join(dir, ClientCAKeyFile), 0o600)
	os.Chmod(dir, 0o755)
	if _, err := Load(dir, nil, true); err == nil {
		t.Fatal("world-readable ca dir accepted")
	}
	os.Chmod(dir, 0o700)
	if _, err := LoadCAs(filepath.Join(t.TempDir(), "none")); err != ErrNotInitialised {
		t.Fatalf("missing dir: %v", err)
	}
}

func TestIssueClientCertAndCSR(t *testing.T) {
	p, err := Load(filepath.Join(t.TempDir(), "ca"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, k)
	csr, err := ParseCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	cd, err := p.IssueClientCert(csr, "build-box", time.Now(), 730)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(cd)
	if c.Subject.CommonName != "build-box" || c.IsCA || !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("client cert %+v", c.Subject)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: p.ClientCAPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	// RSA and P-384 CSRs refused.
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rder, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rk)
	if _, err := ParseCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rder}))); err == nil {
		t.Fatal("RSA CSR accepted")
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k384)
	if _, err := ParseCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der384}))); err == nil {
		t.Fatal("P-384 CSR accepted")
	}
	if tc := p.TLSConfig(); tc.MinVersion != 0x0304 {
		t.Fatal("TLS 1.3 not enforced")
	}
}
