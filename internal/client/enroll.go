package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

var hostNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// EnrollOptions are the flags of `aqmas enroll`.
type EnrollOptions struct {
	OwnerDevice bool
	Name        string
	Server      string // empty: the server in the existing config; required on a first enrollment
	CAPin       string // "sha256:<hex>"; empty: existing config pin, else TOFU
	Force       bool   // replace an existing client certificate
	Note        string
	// SSHHostKeyGlob lists the host's SSH public host keys to report (fingerprints only).
	SSHHostKeyGlob string
}

// Enroll runs `aqmas enroll`.
func (e *Env) Enroll(ctx context.Context, o EnrollOptions) error {
	if !hostNameRE.MatchString(o.Name) {
		return &UsageError{Msg: fmt.Sprintf("--name %q: use a lowercase host name (letters, digits, '-')", o.Name)}
	}
	old, err := LoadConfig(e.Paths)
	if err != nil && !errors.Is(err, ErrNotEnrolled) {
		return err
	}
	if old != nil && old.ClientCert != "" && !o.Force {
		if _, statErr := os.Stat(expandHome(old.ClientCert)); statErr == nil {
			return &UsageError{Msg: fmt.Sprintf("already enrolled as %q (%s); pass --force to request a replacement (the owner must approve it)", old.HostName, old.ClientCert)}
		}
	}
	server := o.Server
	if server == "" {
		if old != nil && old.Server != "" {
			server = old.Server
		} else {
			return &UsageError{Msg: "--server is required (the bastion's agent API, e.g. https://192.0.2.10:8443)"}
		}
	}
	if _, _, err := serverHostPort(server); err != nil {
		return &UsageError{Msg: err.Error()}
	}

	// Server trust: explicit pin, else the pin already in config for the same server, else
	// trust on first use, which needs a person at a terminal to confirm the fingerprint.
	trust := &Trust{}
	switch {
	case o.CAPin != "":
		pin, err := ParsePin(o.CAPin)
		if err != nil {
			return &UsageError{Msg: "--ca-pin: " + err.Error()}
		}
		trust.Pin = pin
	case old != nil && old.Server == server && (old.ServerCA != "" || old.ServerCASHA256 != ""):
		t, err := LoadTrust(old)
		if err != nil {
			return err
		}
		trust = t
	default:
		if !e.StdinIsTTY {
			return &UsageError{Msg: "no --ca-pin given and stdin is not a terminal: refusing trust on first use. Pass --ca-pin sha256:<hex> (the server CA fingerprint from the bastion)"}
		}
		chain, err := ProbeChain(ctx, server)
		if err != nil {
			return err
		}
		cand := TOFUCandidate(chain)
		ok, err := ConfirmTOFU(ctx, e.Stdin, e.Stderr, server, chain, cand)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("server CA not confirmed; nothing changed")
		}
		trust.Pin = CertPin(cand)
	}

	c, err := NewAPIClient(server, trust, nil, e.now)
	if err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: o.Name},
	}, key)
	if err != nil {
		return err
	}
	note := o.Note
	if note == "" {
		h, _ := os.Hostname()
		note = fmt.Sprintf("aqmas enroll by %s on %s", e.User, h)
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	pollToken := base64.RawURLEncoding.EncodeToString(tok)
	req := &api.EnrollRequest{
		PollToken:              pollToken,
		Hostname:               o.Name,
		CSRPEM:                 string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		SSHHostKeyFingerprints: hostKeyFingerprints(o.SSHHostKeyGlob),
		Note:                   truncateBytes(note, api.MaxReasonBytes),
	}
	if o.OwnerDevice {
		req.Class = api.ClassOwner
	}
	created, err := c.Enroll(ctx, req)
	if err != nil {
		return err
	}
	if !safeID(created.ID) {
		return fmt.Errorf("server returned an invalid enrollment id %q", sanitize(created.ID))
	}
	e.logf("enrollment %s (Ref %s) for host %q sent to %s", created.ID, RefCode(created.ID), o.Name, sanitize(server))
	e.logf("client key: %s (the approval card shows it as \"Client key\")", csrFingerprint(&key.PublicKey))
	class := req.Class
	if class == "" {
		class = api.ClassAgent
	}
	e.logf("enrollment class: %s", class)
	e.logf("server CA pinned: %s", FormatPin(trust.Pin))
	e.logf("approve at: %s", sanitize(created.ApproveURL))
	e.logf("waiting for approval (Ctrl-C to stop waiting)...")

	st, err := e.waitEnrollment(ctx, c, created, pollToken)
	if err != nil {
		if errors.Is(err, ErrCancelled) {
			e.logf("stopped waiting; enrollment %s stays pending on the server until it expires", created.ID)
		}
		return err
	}
	if st.ClientCertPEM == "" {
		return fmt.Errorf("enrollment %s is approved but the server returned no certificate (it is only returned once); re-run with --force", created.ID)
	}
	cert, err := parseSingleCertPEM([]byte(strings.TrimSpace(st.ClientCertPEM) + "\n"))
	if err != nil {
		return fmt.Errorf("client certificate from server: %w", err)
	}
	if !publicKeysEqual(cert.PublicKey, &key.PublicKey) {
		return errors.New("client certificate from server is not for the key this host generated")
	}
	if cert.Subject.CommonName != o.Name {
		return fmt.Errorf("client certificate is for %q, not %q", sanitize(cert.Subject.CommonName), o.Name)
	}
	var clientCAPEM []byte
	if st.CACertPEM != "" {
		ca, err := parseSingleCertPEM([]byte(strings.TrimSpace(st.CACertPEM) + "\n"))
		if err != nil {
			return fmt.Errorf("client CA from server: %w", err)
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			return fmt.Errorf("client certificate is not signed by the client CA the server sent: %w", err)
		}
		clientCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	}

	anchor := trust.CA
	if anchor == nil {
		anchor = trust.Matched()
	}
	if anchor == nil {
		return errors.New("internal error: no verified server CA to save")
	}

	if err := ensurePrivateDir(e.Paths.ConfigDir); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	dir := e.Paths.ConfigDir
	cfg := &Config{
		Server:         server,
		ServerCA:       filepath.Join(dir, "server-ca.pem"),
		ServerCASHA256: FormatPin(CertPin(anchor)),
		HostName:       o.Name,
		ClientCert:     filepath.Join(dir, "client.crt"),
		ClientKey:      filepath.Join(dir, "client.key"),
	}
	if old != nil {
		cfg.DefaultTTL = old.DefaultTTL
	}
	writes := []struct {
		path string
		data []byte
	}{
		{cfg.ServerCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})},
		{cfg.ClientKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{cfg.ClientCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})},
	}
	if clientCAPEM != nil {
		cfg.ClientCA = filepath.Join(dir, "client-ca.pem")
		writes = append(writes, struct {
			path string
			data []byte
		}{cfg.ClientCA, clientCAPEM})
	}
	for _, w := range writes {
		if err := writeFileAtomic(w.path, w.data, 0o600); err != nil {
			return err
		}
	}
	if err := SaveConfig(e.Paths, cfg); err != nil {
		return err
	}
	e.logf("enrolled as %q; client certificate valid until %s; config %s",
		o.Name, cert.NotAfter.UTC().Format(time.RFC3339), e.Paths.ConfigFile())
	return nil
}

// csrFingerprint matches the server's CSR key fingerprint (SHA256:<hex> of the PKIX key).
func csrFingerprint(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "?"
	}
	h := sha256.Sum256(der)
	return "SHA256:" + hex.EncodeToString(h[:])
}

func (e *Env) waitEnrollment(ctx context.Context, c *APIClient, created *api.EnrollResponse, pollToken string) (*api.EnrollStatus, error) {
	pollAfter := created.PollAfterMS
	lockNotice := false
	failures := 0
	for {
		start := time.Now()
		st, err := c.EnrollStatus(ctx, created.ID, pollToken, 25*time.Second)
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.HTTPStatus == 423 && ae.Code == "locked" {
				if !lockNotice {
					e.logf("waiting for owner unlock")
					lockNotice = true
				}
				if err = sleepCtx(ctx, 2*time.Second); err != nil {
					return nil, err
				}
				continue
			}
			var ue *UnreachableError
			if errors.As(err, &ue) && failures < 5 {
				failures++
				if err := sleepCtx(ctx, time.Duration(failures)*2*time.Second); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		failures = 0
		switch st.Status {
		case api.StatusApproved:
			return st, nil
		case api.StatusDenied, api.StatusExpired, api.StatusRevoked:
			return nil, &DecisionError{Status: st.Status, What: "enrollment " + created.ID}
		case api.StatusPending:
		default:
			return nil, fmt.Errorf("enrollment %s: unexpected status %q", created.ID, sanitize(st.Status))
		}
		if err := sleepCtx(ctx, e.pollDelay(pollAfter, time.Since(start))); err != nil {
			return nil, err
		}
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ae, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ae.Equal(b)
}

// hostKeyFingerprints returns SHA256 fingerprints of the host's SSH public host keys, so the
// owner can match the enrollment against the host (best effort, never fatal).
func hostKeyFingerprints(glob string) []string {
	if glob == "" {
		glob = "/etc/ssh/ssh_host_*_key.pub"
	}
	files, _ := filepath.Glob(glob)
	var out []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			continue
		}
		out = append(out, ssh.FingerprintSHA256(pk))
	}
	return out
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// safeID accepts the ULID-like ids the server issues; ids end up in URLs and file names.
func safeID(id string) bool { return idRE.MatchString(id) }
