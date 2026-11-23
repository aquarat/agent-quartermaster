// Package sshcert signs short-lived OpenSSH user certificates exactly as docs/DESIGN.md says.
package sshcert

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ClockSkew is how far before approval a certificate becomes valid.
const ClockSkew = time.Minute

// Params describes one certificate.
type Params struct {
	Serial        uint64
	KeyID         string
	Principals    []string
	SourceAddress string // requester's IP as seen on the mTLS connection
	ApprovedAt    time.Time
	TTL           time.Duration
	PublicKey     ssh.PublicKey
	// Extensions replaces the default permit-pty + permit-port-forwarding when not nil (an
	// empty map means no extension). Critical adds critical options besides source-address.
	Extensions map[string]string
	Critical   map[string]string
}

// ParseEd25519 parses an authorized_keys line and accepts only a plain ssh-ed25519 key
// (no certificates, no options, no other algorithms).
func ParseEd25519(line string) (ssh.PublicKey, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return nil, errors.New("public_key: one authorized_keys line required")
	}
	pub, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}
	if len(opts) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("public_key: options or trailing data not allowed")
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("public_key: must be ssh-ed25519, got %s", pub.Type())
	}
	return pub, nil
}

// SourceAddress normalises an IP (IPv4-mapped IPv6 is unmapped) into a single-host CIDR.
func SourceAddress(ip string) (string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("source address: %w", err)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}

// Validity returns the certificate window: approval - ClockSkew .. approval + ttl.
func Validity(approvedAt time.Time, ttl time.Duration) (time.Time, time.Time) {
	return approvedAt.Add(-ClockSkew).Truncate(time.Second), approvedAt.Add(ttl).Truncate(time.Second)
}

// Sign issues the certificate with the CA signer.
func Sign(ca ssh.Signer, p Params) (*ssh.Certificate, error) {
	if p.PublicKey == nil || p.PublicKey.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("sshcert: ed25519 public key required")
	}
	if len(p.Principals) == 0 || p.KeyID == "" || p.Serial == 0 || p.TTL <= 0 {
		return nil, errors.New("sshcert: principals, key id, serial and ttl are required")
	}
	src, err := SourceAddress(p.SourceAddress)
	if err != nil {
		return nil, err
	}
	nb, na := Validity(p.ApprovedAt, p.TTL)
	ext := map[string]string{"permit-pty": "", "permit-port-forwarding": ""}
	if p.Extensions != nil {
		ext = p.Extensions
	}
	critical := map[string]string{"source-address": src}
	for k, v := range p.Critical {
		if k == "source-address" || k == "" || v == "" {
			return nil, errors.New("sshcert: invalid critical option")
		}
		critical[k] = v
	}
	cert := &ssh.Certificate{
		Key:             p.PublicKey,
		Serial:          p.Serial,
		CertType:        ssh.UserCert,
		KeyId:           p.KeyID,
		ValidPrincipals: p.Principals,
		ValidAfter:      uint64(nb.Unix()),
		ValidBefore:     uint64(na.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: critical,
			Extensions:      ext,
		},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return cert, nil
}

// Marshal returns the certificate in authorized_keys format (one line, no newline).
func Marshal(c *ssh.Certificate) string {
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(c)))
}

// KnownHostsLine builds a known_hosts line for a pinned host key ("" when none is pinned).
func KnownHostsLine(name, address string, port int, hostKey string) string {
	if hostKey == "" {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
	if err != nil {
		return ""
	}
	hosts := []string{name, address}
	if port != 0 && port != 22 {
		hosts = []string{fmt.Sprintf("[%s]:%d", name, port), fmt.Sprintf("[%s]:%d", address, port)}
	}
	return strings.Join(hosts, ",") + " " + string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub)))
}
