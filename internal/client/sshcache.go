package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// MinRemaining is how much validity a cached certificate needs to be reused.
const MinRemaining = 2 * time.Minute

// CertClockSkew is how far a certificate's start time may lie in this host's future.
const CertClockSkew = 5 * time.Minute

// File names inside a per-target cache directory <cache>/<user>@<host>/.
const (
	keyFile        = "id_ed25519"
	certFile       = "id_ed25519-cert.pub"
	knownHostsFile = "known_hosts"
	grantFile      = "grant.json"
	lockFile       = ".lock"
	// currentLink points at the newest grant directory g-<request id>. Each grant gets its own
	// directory and the link is swapped atomically, so an ssh started from an older grant
	// never sees a key from one grant next to a certificate from another.
	currentLink = "current"
)

var grantDirRE = regexp.MustCompile(`^g-[A-Za-z0-9_-]{1,64}$`)

var (
	loginUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	dnsNameRE   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	// safePathRE: paths handed to ssh -i / -o must survive ssh's own option parsing, which
	// splits on whitespace, honours quotes and expands %tokens and ~.
	safePathRE = regexp.MustCompile(`^/[A-Za-z0-9/._@+-]*$`)
)

// Target is a parsed `[user@]host`.
type Target struct {
	User string
	Host string
}

func (t Target) String() string { return t.User + "@" + t.Host }

// ParseTarget parses `[user@]host` with defaultUser for a missing user.
func ParseTarget(s, defaultUser string) (Target, error) {
	user, host, ok := strings.Cut(s, "@")
	if !ok {
		user, host = defaultUser, s
	}
	t := Target{User: user, Host: host}
	if !loginUserRE.MatchString(t.User) {
		return t, &UsageError{Msg: fmt.Sprintf("invalid login user %q", t.User)}
	}
	if !hostNameRE.MatchString(t.Host) {
		return t, &UsageError{Msg: fmt.Sprintf("invalid target host %q: use the fleet host name aqmasd knows (e.g. db-1)", t.Host)}
	}
	return t, nil
}

// StoredGrant is grant.json in the per-target cache directory.
type StoredGrant struct {
	RequestID     string    `json:"request_id"`
	GrantID       string    `json:"grant_id"`
	TargetHost    string    `json:"target_host"`
	LoginUser     string    `json:"login_user"`
	TargetAddress string    `json:"target_address"`
	TargetPort    int       `json:"target_port"`
	NotAfter      time.Time `json:"not_after"`
	KnownHosts    bool      `json:"known_hosts"` // a pinned known_hosts file was written
}

// Prepared is a usable key + certificate for one target.
type Prepared struct {
	Dir            string
	KeyPath        string
	CertPath       string
	KnownHostsPath string // empty: no pinned host key, ssh's normal known_hosts files apply
	Grant          StoredGrant
	ValidBefore    time.Time
	Reused         bool
}

// targetDir returns (and creates, 0700) the cache directory for t.
func (e *Env) targetDir(t Target) (string, error) {
	if err := ensurePrivateDir(e.Paths.CacheDir); err != nil {
		return "", err
	}
	dir := filepath.Join(e.Paths.CacheDir, t.String())
	if err := ensurePrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// CertValidity checks an OpenSSH user certificate (authorized_keys format) for key pub and
// returns its expiry. It checks type, key binding and time window; it cannot check the CA
// signature because the client is not told the CA key.
func CertValidity(certText []byte, pub ssh.PublicKey, now time.Time) (*ssh.Certificate, error) {
	pk, _, _, rest, err := ssh.ParseAuthorizedKey(certText)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("certificate: more than one line")
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("certificate: not an OpenSSH certificate")
	}
	if cert.CertType != ssh.UserCert {
		return nil, errors.New("certificate: not a user certificate")
	}
	if pub != nil && !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		return nil, errors.New("certificate: not issued for this key")
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return nil, errors.New("certificate: no expiry (refusing an unbounded certificate)")
	}
	// Tolerate this host's clock running a little behind the bastion's: the target's sshd
	// checks the start time again anyway.
	unix := now.Add(CertClockSkew).Unix()
	if unix < 0 || uint64(unix) < cert.ValidAfter {
		return nil, fmt.Errorf("certificate: not valid before %s", certTime(cert.ValidAfter).Format(time.RFC3339))
	}
	if uint64(now.Unix()) >= cert.ValidBefore {
		return nil, fmt.Errorf("certificate: expired at %s", certTime(cert.ValidBefore).Format(time.RFC3339))
	}
	return cert, nil
}

func certTime(t uint64) time.Time {
	if t > uint64(1<<62) {
		return time.Unix(1<<62, 0).UTC()
	}
	return time.Unix(int64(t), 0).UTC()
}

// loadCached returns the cached credentials for t if they are valid for at least MinRemaining.
func (e *Env) loadCached(tdir string, t Target) (*Prepared, error) {
	link, err := os.Readlink(filepath.Join(tdir, currentLink))
	if err != nil {
		return nil, err
	}
	if !grantDirRE.MatchString(link) {
		return nil, fmt.Errorf("%s/%s points somewhere unexpected", tdir, currentLink)
	}
	dir := filepath.Join(tdir, link)
	if err := checkPrivatePath(dir, true); err != nil {
		return nil, err
	}
	gdata, err := os.ReadFile(filepath.Join(dir, grantFile))
	if err != nil {
		return nil, err
	}
	var g StoredGrant
	if err := json.Unmarshal(gdata, &g); err != nil {
		return nil, fmt.Errorf("grant.json: %w", err)
	}
	if g.TargetHost != t.Host || g.LoginUser != t.User {
		return nil, errors.New("grant.json is for another target")
	}
	if err := validateEndpoint(g.TargetAddress, g.TargetPort); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, keyFile)
	if err := checkSecretFile(keyPath); err != nil {
		return nil, err
	}
	kdata, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(kdata)
	if err != nil {
		return nil, fmt.Errorf("cached key: %w", err)
	}
	cdata, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, err
	}
	cert, err := CertValidity(cdata, signer.PublicKey(), e.now())
	if err != nil {
		return nil, err
	}
	vb := certTime(cert.ValidBefore)
	if vb.Sub(e.now()) < MinRemaining {
		return nil, fmt.Errorf("certificate expires at %s, less than %s left", vb.Format(time.RFC3339), MinRemaining)
	}
	p := &Prepared{
		Dir: dir, KeyPath: keyPath, CertPath: filepath.Join(dir, certFile),
		Grant: g, ValidBefore: vb, Reused: true,
	}
	if g.KnownHosts {
		p.KnownHostsPath = filepath.Join(dir, knownHostsFile)
		if _, err := os.Stat(p.KnownHostsPath); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// storeGrant validates an approved grant against what was asked for, writes key, cert,
// known_hosts and grant.json (all 0600) into a new directory tdir/g-<request id> (0700) and
// then points tdir/current at it.
func (e *Env) storeGrant(tdir string, t Target, requestID string, priv ed25519.PrivateKey, g *api.Grant) (*Prepared, error) {
	if g == nil || g.SSH == nil {
		return nil, errors.New("approved, but the server sent no SSH grant")
	}
	sg := g.SSH
	if sg.TargetHost != t.Host || sg.LoginUser != t.User {
		return nil, fmt.Errorf("server granted %q@%q, not the requested %s; refusing", sanitize(sg.LoginUser), sanitize(sg.TargetHost), t)
	}
	if err := validateEndpoint(sg.TargetAddress, sg.TargetPort); err != nil {
		return nil, err
	}
	if g.ID != "" && !safeID(g.ID) {
		return nil, fmt.Errorf("server returned an invalid grant id %q", sanitize(g.ID))
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	cert, err := CertValidity([]byte(sg.Certificate), sshPub, e.now())
	if err != nil {
		return nil, fmt.Errorf("server sent an unusable certificate: %w", err)
	}
	var known []byte
	if sg.KnownHostsLine != "" {
		known, err = KnownHostsFor(sg.KnownHostsLine, sg.TargetAddress, sg.TargetPort, t.Host)
		if err != nil {
			return nil, err
		}
	}
	block, err := ssh.MarshalPrivateKey(priv, "aqmas "+t.String())
	if err != nil {
		return nil, err
	}
	stored := StoredGrant{
		RequestID: requestID, GrantID: g.ID,
		TargetHost: sg.TargetHost, LoginUser: sg.LoginUser,
		TargetAddress: sg.TargetAddress, TargetPort: sg.TargetPort,
		NotAfter: certTime(cert.ValidBefore), KnownHosts: known != nil,
	}
	gjson, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return nil, err
	}
	if !safeID(requestID) {
		return nil, fmt.Errorf("invalid request id %q", sanitize(requestID))
	}
	gname := "g-" + requestID
	dir := filepath.Join(tdir, gname)
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	certLine := append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(cert)), '\n')
	files := []struct {
		name string
		data []byte
	}{
		{keyFile, pem.EncodeToMemory(block)},
		{certFile, certLine},
	}
	if known != nil {
		files = append(files, struct {
			name string
			data []byte
		}{knownHostsFile, known})
	}
	files = append(files, struct {
		name string
		data []byte
	}{grantFile, append(gjson, '\n')})
	for _, f := range files {
		if err := writeFileAtomic(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			os.RemoveAll(dir)
			return nil, err
		}
	}
	tmp := filepath.Join(tdir, fmt.Sprintf(".%s.tmp-%d", currentLink, os.Getpid()))
	os.Remove(tmp)
	if err := os.Symlink(gname, tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(tdir, currentLink)); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	e.pruneGrants(tdir, gname)
	p := &Prepared{
		Dir: dir, KeyPath: filepath.Join(dir, keyFile), CertPath: filepath.Join(dir, certFile),
		Grant: stored, ValidBefore: certTime(cert.ValidBefore),
	}
	if known != nil {
		p.KnownHostsPath = filepath.Join(dir, knownHostsFile)
	}
	return p, nil
}

// pruneGrants removes grant directories other than keep whose certificate has expired (a
// running ssh has read its key and certificate long before that).
func (e *Env) pruneGrants(tdir, keep string) {
	ents, err := os.ReadDir(tdir)
	if err != nil {
		return
	}
	for _, ent := range ents {
		if !ent.IsDir() || ent.Name() == keep || !grantDirRE.MatchString(ent.Name()) {
			continue
		}
		dir := filepath.Join(tdir, ent.Name())
		var g StoredGrant
		data, err := os.ReadFile(filepath.Join(dir, grantFile))
		if err == nil && json.Unmarshal(data, &g) == nil && g.NotAfter.After(e.now()) {
			continue
		}
		if err != nil {
			if fi, ferr := ent.Info(); ferr == nil && e.now().Sub(fi.ModTime()) < time.Hour {
				continue // possibly being written by another process; keep for now
			}
		}
		os.RemoveAll(dir)
	}
}

// validateEndpoint checks a server-provided address and port before they reach ssh's argv.
func validateEndpoint(addr string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("server sent an invalid target port %d", port)
	}
	if net.ParseIP(addr) != nil && !strings.Contains(addr, "%") {
		return nil
	}
	if len(addr) <= 253 && dnsNameRE.MatchString(addr) {
		return nil
	}
	return fmt.Errorf("server sent an invalid target address %q", sanitize(addr))
}

// HostKeyAlias is the known_hosts name aqmas records for a target, used by the ssh-config
// snippet (where the address ssh connects to comes from the user's own config).
func HostKeyAlias(host string) string { return "aqmas." + host }

// KnownHostsFor turns the server's known_hosts line into a file aqmas controls: it parses the
// line (exactly one key, optional @cert-authority marker, never @revoked) and rewrites the
// host patterns to what ssh will look up for this address/port plus the aqmas alias, so the
// server's pattern text never reaches the file.
func KnownHostsFor(line, addr string, port int, host string) ([]byte, error) {
	line = strings.TrimRight(line, "\n")
	if strings.ContainsAny(line, "\r\n\x00") {
		return nil, errors.New("server sent a multi-line known_hosts entry; refusing")
	}
	marker, _, key, _, rest, err := ssh.ParseKnownHosts([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("server sent an unreadable known_hosts line: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("server sent more than one known_hosts entry; refusing")
	}
	switch marker {
	case "":
	case "cert-authority":
		marker = "@cert-authority "
	default:
		return nil, fmt.Errorf("known_hosts marker @%s is not accepted", sanitize(marker))
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, errors.New("known_hosts key is a certificate; refusing")
	}
	// ssh looks up the bare host for port 22 and "[host]:port" otherwise.
	pattern := addr
	if port != 22 {
		pattern = "[" + addr + "]:" + strconv.Itoa(port)
	}
	out := marker + pattern + "," + HostKeyAlias(host) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + "\n"
	return []byte(out), nil
}

// lockDir takes an exclusive flock on dir/.lock, polling so Ctrl-C still works. It serialises
// "check the cache, else request and store" between aqmas processes; processes already using
// a grant are protected by the per-grant directories, not by this lock.
func (e *Env) lockDir(ctxDone <-chan struct{}, dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	warned := false
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		if !warned {
			e.logf("another aqmas process is requesting the same access; waiting for it")
			warned = true
		}
		select {
		case <-ctxDone:
			f.Close()
			return nil, ErrCancelled
		case <-time.After(250 * time.Millisecond):
		}
	}
}
