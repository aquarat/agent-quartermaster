package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"
)

// WithPrivate attaches one ephemeral signer to a copy of the public state.
// Refuse a decrypted key which doesn't match the active public catalogue.
func (p *PKI) WithPrivate(role string, b []byte) (*PKI, error) {
	q := *p
	switch role {
	case "ssh-ca":
		s, err := ssh.ParsePrivateKey(b)
		if err != nil || !bytes.Equal(s.PublicKey().Marshal(), p.SSHPublic.Marshal()) {
			return nil, errors.New("pki: SSH CA key mismatch")
		}
		q.SSHSigner = s
	case "internal-ca":
		blk, rest := pem.Decode(b)
		if blk == nil || len(rest) != 0 || blk.Type != "PRIVATE KEY" {
			return nil, errors.New("pki: invalid private PEM")
		}
		defer clear(blk.Bytes)
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		ek, ok := k.(*ecdsa.PrivateKey)
		if err != nil || !ok || !ek.PublicKey.Equal(p.CACert.PublicKey) {
			return nil, errors.New("pki: internal CA key mismatch")
		}
		q.CAKey = ek
	default:
		return nil, errors.New("pki: unknown signer")
	}
	return &q, nil
}
func (p *PKI) CheckPrivate(role string, b []byte) error { _, err := p.WithPrivate(role, b); return err }

// LoadPublic reads only trust anchors. Printing pins, verifying the signed
// personal catalogue and rendering approval cards do not need private keys.
func LoadPublic(dir string) (*PKI, error) {
	p := &PKI{Dir: dir}
	b, err := os.ReadFile(p.path(SSHCAPubFile))
	if err != nil {
		return nil, err
	}
	key, _, opts, rest, err := ssh.ParseAuthorizedKey(b)
	if err != nil || len(rest) != 0 || len(opts) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("pki: invalid SSH CA public key")
	}
	p.SSHPublic = key
	b, err = os.ReadFile(p.path(ClientCACrtFile))
	if err != nil {
		return nil, err
	}
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" || len(rest) != 0 || !bytes.Equal(b, pem.EncodeToMemory(blk)) {
		return nil, errors.New("pki: invalid internal CA PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("pki: invalid internal CA")
	}
	p.CACert = cert
	p.CAPEM = b
	return p, nil
}

// LoadLeaf opens the disk-theft exception. Never reissues, creates a file,
// consults a signer or changes the receiver after validation fails.
func (p *PKI) LoadLeaf(sans []string) error {
	st, err := os.Lstat(p.Dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0o700 {
		return errors.New("pki: unsafe leaf key directory")
	}
	kb, err := readSecret(p.path(ServerKeyFile))
	if err != nil {
		return err
	}
	defer clear(kb)
	cb, err := os.ReadFile(p.path(ServerCrtFile))
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return err
	}
	c := pair.Leaf
	if c == nil || len(pair.Certificate) != 1 || c.IsCA || !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || len(c.UnknownExtKeyUsage) != 0 || !slices.Equal(certSANs(c), normSANs(sans)) || len(c.URIs)+len(c.EmailAddresses) != 0 {
		return errors.New("pki: invalid agent TLS server leaf profile")
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: p.ClientCAPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return err
	}
	pair.Certificate = append(pair.Certificate, p.CACert.Raw)
	p.ServerCert = pair
	p.ServerLeaf = c
	return nil
}
