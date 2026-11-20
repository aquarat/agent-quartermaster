package sshcert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSignContents(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	approved := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	c, err := Sign(ca, Params{Serial: 42, KeyID: "aqmas:G:build-box:db-1", Principals: []string{"alice@db-1"},
		SourceAddress: "::ffff:192.0.2.50", ApprovedAt: approved, TTL: 30 * time.Minute, PublicKey: sp})
	if err != nil {
		t.Fatal(err)
	}
	if c.Serial != 42 || c.KeyId != "aqmas:G:build-box:db-1" || c.CertType != ssh.UserCert || !slices.Equal(c.ValidPrincipals, []string{"alice@db-1"}) {
		t.Fatalf("cert %+v", c)
	}
	if c.ValidAfter != uint64(approved.Add(-time.Minute).Unix()) || c.ValidBefore != uint64(approved.Add(30*time.Minute).Unix()) {
		t.Fatal("validity")
	}
	if c.CriticalOptions["source-address"] != "192.0.2.50/32" || len(c.CriticalOptions) != 1 {
		t.Fatalf("critical options %v", c.CriticalOptions)
	}
	exts := []string{}
	for k := range c.Extensions {
		exts = append(exts, k)
	}
	slices.Sort(exts)
	if !slices.Equal(exts, []string{"permit-port-forwarding", "permit-pty"}) {
		t.Fatalf("extensions %v", exts)
	}
	if string(c.SignatureKey.Marshal()) != string(ca.PublicKey().Marshal()) {
		t.Fatal("signature key")
	}
	line := Marshal(c)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || !strings.HasPrefix(line, "ssh-ed25519-cert-v01@openssh.com ") {
		t.Fatalf("marshal %q %v", line, err)
	}
	checker := ssh.CertChecker{SupportedCriticalOptions: []string{"source-address"}, Clock: func() time.Time { return approved }}
	if err := checker.CheckCert("alice@db-1", parsed.(*ssh.Certificate)); err != nil {
		t.Fatal(err)
	}
	if v6, _ := SourceAddress("fe80::1%eth0"); v6 != "fe80::1/128" {
		t.Fatalf("v6 source %q", v6)
	}
}

func TestRejectsNonEd25519(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rp, _ := ssh.NewPublicKey(&rk.PublicKey)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ep, _ := ssh.NewPublicKey(&ek.PublicKey)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	edp, _ := ssh.NewPublicKey(pub)
	good := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(edp)))
	for name, line := range map[string]string{
		"rsa":     string(ssh.MarshalAuthorizedKey(rp)),
		"ecdsa":   string(ssh.MarshalAuthorizedKey(ep)),
		"options": "restrict " + good,
		"two":     good + "\n" + good,
		"empty":   "",
	} {
		if _, err := ParseEd25519(line); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseEd25519(good + " comment"); err != nil {
		t.Fatal(err)
	}
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	if _, err := Sign(ca, Params{Serial: 1, KeyID: "k", Principals: []string{"p"}, SourceAddress: "10.0.0.1", ApprovedAt: time.Now(), TTL: time.Minute, PublicKey: rp}); err == nil {
		t.Fatal("signed an RSA key")
	}
	if _, err := Sign(ca, Params{Serial: 1, KeyID: "k", Principals: []string{"p"}, SourceAddress: "not-an-ip", ApprovedAt: time.Now(), TTL: time.Minute, PublicKey: edp}); err == nil {
		t.Fatal("signed without a valid source address")
	}
}

func TestKnownHostsLine(t *testing.T) {
	hk := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGilJAtWZP1K8q90h5+KBdPRC0+wBFVVtHkOZQLmI9jB"
	if got := KnownHostsLine("db-1", "192.0.2.61", 22, hk); got != "db-1,192.0.2.61 "+hk {
		t.Fatal(got)
	}
	if got := KnownHostsLine("forgejo", "192.0.2.50", 2222, hk); got != "[forgejo]:2222,[192.0.2.50]:2222 "+hk {
		t.Fatal(got)
	}
	if KnownHostsLine("x", "y", 22, "") != "" {
		t.Fatal("line without host key")
	}
}
