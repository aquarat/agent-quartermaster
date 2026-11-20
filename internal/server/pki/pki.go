// Package pki manages aqmasd's key material: the SSH user CA (Ed25519), the internal client CA
// (ECDSA P-256) that issues host client certificates and verifies mTLS, and the agent-API TLS
// server certificate issued by that same CA. Keys are generated on first start, written with
// mode 0600, and refused if group/other can read them.
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// File names inside <data_dir>/ca.
const (
	SSHCAKeyFile    = "ssh_user_ca"
	SSHCAPubFile    = "ssh_user_ca.pub"
	ClientCAKeyFile = "client_ca.key"
	ClientCACrtFile = "client_ca.crt"
	ServerKeyFile   = "server.key"
	ServerCrtFile   = "server.crt"
)

// ErrNotInitialised is returned by Load with create=false when the key material is missing.
var ErrNotInitialised = errors.New("pki: key material not found (start `aqmasd serve` once to generate it)")

// PKI holds the loaded key material.
type PKI struct {
	Dir        string
	SSHSigner  ssh.Signer
	CACert     *x509.Certificate
	CAKey      *ecdsa.PrivateKey
	CAPEM      []byte
	ServerCert tls.Certificate
	ServerLeaf *x509.Certificate
}

// Load reads (and with create=true, generates) the key material in dir. sans are the agent-API
// server certificate's subject alternative names; the server certificate is reissued when they
// change or it is near expiry.
func Load(dir string, sans []string, create bool) (*PKI, error) {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotInitialised
		}
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("pki: %s is accessible by group/other (mode %v); chmod 700 it", dir, st.Mode().Perm())
	}
	p := &PKI{Dir: dir}
	if err := p.loadSSHCA(create); err != nil {
		return nil, err
	}
	if err := p.loadClientCA(create); err != nil {
		return nil, err
	}
	if err := p.loadServer(sans, create); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadCAs reads the existing SSH user CA and client CA only (no generation, no server cert).
func LoadCAs(dir string) (*PKI, error) {
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotInitialised
		}
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("pki: %s is accessible by group/other (mode %v); chmod 700 it", dir, st.Mode().Perm())
	}
	p := &PKI{Dir: dir}
	if err := p.loadSSHCA(false); err != nil {
		return nil, err
	}
	if err := p.loadClientCA(false); err != nil {
		return nil, err
	}
	return p, nil
}

// readSecret reads a private key file, refusing it when group/other have any access.
func readSecret(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("pki: refusing %s: mode %v is group/other accessible (want 0600)", path, st.Mode().Perm())
	}
	return os.ReadFile(path)
}

// writeFile writes atomically with the given mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func (p *PKI) path(name string) string { return filepath.Join(p.Dir, name) }

func (p *PKI) loadSSHCA(create bool) error {
	kp := p.path(SSHCAKeyFile)
	if !exists(kp) {
		if !create {
			return ErrNotInitialised
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		blk, err := ssh.MarshalPrivateKey(priv, "aqmas-user-ca")
		if err != nil {
			return err
		}
		if err := writeFile(kp, pem.EncodeToMemory(blk), 0o600); err != nil {
			return err
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return err
		}
		pub := bytes.TrimSpace(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		if err := writeFile(p.path(SSHCAPubFile), append(pub, []byte(" aqmas-user-ca\n")...), 0o644); err != nil {
			return err
		}
	}
	b, err := readSecret(kp)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return fmt.Errorf("pki: ssh ca: %w", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return errors.New("pki: ssh ca key is not ed25519")
	}
	p.SSHSigner = signer
	return nil
}

// SSHCAPublicLine returns the SSH user CA public key in authorized_keys format (one line).
func (p *PKI) SSHCAPublicLine() string {
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(p.SSHSigner.PublicKey()))) + " aqmas-user-ca"
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}

func (p *PKI) loadClientCA(create bool) error {
	kp, cp := p.path(ClientCAKeyFile), p.path(ClientCACrtFile)
	if !exists(kp) {
		if !create {
			return ErrNotInitialised
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:          randSerial(),
			Subject:               pkix.Name{CommonName: "aqmas internal CA", Organization: []string{"agent-quartermaster"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLenZero:        true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return err
		}
		kder, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := writeFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
			return err
		}
		if err := writeFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return err
		}
	}
	kb, err := readSecret(kp)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(kb)
	if blk == nil {
		return errors.New("pki: client CA key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("pki: client CA key is not ECDSA")
	}
	cb, err := os.ReadFile(cp)
	if err != nil {
		return err
	}
	cblk, _ := pem.Decode(cb)
	if cblk == nil {
		return errors.New("pki: client CA cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return err
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&ek.PublicKey) {
		return errors.New("pki: client CA cert does not match key")
	}
	p.CAKey, p.CACert = ek, cert
	p.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return nil
}

func normSANs(sans []string) []string {
	out := slices.Clone(sans)
	if len(out) == 0 {
		out = []string{"localhost", "127.0.0.1"}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func certSANs(c *x509.Certificate) []string {
	var out []string
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	slices.Sort(out)
	return out
}

func (p *PKI) loadServer(sans []string, create bool) error {
	want := normSANs(sans)
	kp, cp := p.path(ServerKeyFile), p.path(ServerCrtFile)
	reissue := !exists(kp) || !exists(cp)
	if !reissue {
		cb, err := os.ReadFile(cp)
		if err != nil {
			return err
		}
		if blk, _ := pem.Decode(cb); blk == nil {
			reissue = true
		} else if c, err := x509.ParseCertificate(blk.Bytes); err != nil {
			reissue = true
		} else if !slices.Equal(certSANs(c), want) || time.Until(c.NotAfter) < 60*24*time.Hour || c.CheckSignatureFrom(p.CACert) != nil {
			reissue = true
		}
	}
	if reissue {
		if !create {
			return ErrNotInitialised
		}
		var key *ecdsa.PrivateKey
		if exists(kp) {
			kb, err := readSecret(kp)
			if err != nil {
				return err
			}
			if blk, _ := pem.Decode(kb); blk != nil {
				if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
					key, _ = k.(*ecdsa.PrivateKey)
				}
			}
		}
		if key == nil {
			var err error
			if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
				return err
			}
			kder, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return err
			}
			if err := writeFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
				return err
			}
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: randSerial(),
			Subject:      pkix.Name{CommonName: "aqmasd"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.AddDate(2, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		for _, s := range want {
			if ip := net.ParseIP(s); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, s)
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CACert, &key.PublicKey, p.CAKey)
		if err != nil {
			return err
		}
		if err := writeFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return err
		}
	}
	kb, err := readSecret(kp)
	if err != nil {
		return err
	}
	cb, err := os.ReadFile(cp)
	if err != nil {
		return err
	}
	tc, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return err
	}
	p.ServerCert = tc
	p.ServerLeaf, err = x509.ParseCertificate(tc.Certificate[0])
	return err
}

// ClientCAPool returns a pool containing only the internal client CA.
func (p *PKI) ClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.CACert)
	return pool
}

// TLSConfig returns the agent-API TLS configuration: TLS 1.3 only, client certificates verified
// against the internal CA when presented (handlers decide which paths require one).
func (p *PKI) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{p.ServerCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    p.ClientCAPool(),
	}
}

// ParseCSR decodes a PEM CSR, checks its signature and that its key is ECDSA P-256 or Ed25519.
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr_pem: no CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("csr_pem: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr_pem: bad signature: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("csr_pem: ECDSA key must be P-256")
		}
	case ed25519.PublicKey:
	default:
		return nil, errors.New("csr_pem: key must be ECDSA P-256 or Ed25519")
	}
	return csr, nil
}

// PublicKeyFingerprint returns "SHA256:<hex>" of the PKIX-encoded public key.
func PublicKeyFingerprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(der)
	return "SHA256:" + hex.EncodeToString(h[:])
}

// CertFingerprint returns the hex SHA-256 of a certificate's DER encoding.
func CertFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// IssueClientCert issues a host client certificate (CN = hostname, clientAuth only) for the
// CSR's public key. The CSR's subject is ignored; only its key is used.
func (p *PKI) IssueClientCert(csr *x509.CertificateRequest, hostname string, now time.Time, days int) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"aqmas host"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, p.CACert, csr.PublicKey, p.CAKey)
}
