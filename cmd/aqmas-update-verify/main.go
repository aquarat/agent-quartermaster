// Installed once by the owner, never replaced by the self-updater. Treat the spool
// as hostile and the passkey pin, release config and installed metadata as root inputs.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/go-webauthn/webauthn/protocol"
	"golang.org/x/sys/unix"
)

type approval struct {
	Canonical string
	Assertion json.RawMessage
}
type keyPin struct {
	ID        []byte
	PublicKey []byte
}

func verify(req approval, origin string, pins []keyPin, now time.Time) (canon.Signed, error) {
	sg, e := canon.Parse(req.Canonical)
	if e != nil {
		return sg, e
	}
	if sg.Object != "update" || sg.Action.Action != "approve" || now.Before(sg.IssuedAt) || now.Sub(sg.IssuedAt) > 2*time.Minute {
		return sg, errors.New("not a fresh update approval")
	}
	nonce, e := base64.RawURLEncoding.DecodeString(sg.Nonce)
	if e != nil || len(nonce) != 32 {
		return sg, errors.New("invalid nonce")
	}
	a, e := protocol.ParseCredentialRequestResponseBytes(req.Assertion)
	if e != nil {
		return sg, e
	}
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return sg, errors.New("invalid RP origin")
	}
	for _, k := range pins {
		if bytes.Equal(a.RawID, k.ID) {
			e = a.Verify(base64.RawURLEncoding.EncodeToString(canon.Challenge(req.Canonical)), u.Hostname(), "", []string{origin}, nil, nil, protocol.TopOriginExplicitVerificationMode, false, true, true, k.PublicKey, protocol.SignaturePolicy{ECDSAEncoding: protocol.ECDSASignatureEncodingDER})
			return sg, e
		}
	}
	return sg, errors.New("credential not pinned for root updates")
}
func readJSON(path string, obj any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, obj)
}
func consume(path string) (approval, error) {
	var req approval
	f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		_ = os.Remove(path)
		return req, e
	}
	defer f.Close()
	if e = os.Remove(path); e != nil {
		return req, e
	}
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() {
		return req, errors.New("request is not a regular file")
	}
	b, e := release.ReadLimit(f, 64<<10)
	if e != nil {
		return req, e
	}
	e = json.Unmarshal(b, &req)
	return req, e
}
func run() error {
	path := config.DefaultPath
	if len(os.Args) == 5 && os.Args[1] == "bootstrap" {
		path = os.Args[4]
	}
	cfg, e := config.Load(path)
	if e != nil {
		return e
	}
	var m release.Metadata
	var signed release.Sums
	if (len(os.Args) == 4 || len(os.Args) == 5) && os.Args[1] == "bootstrap" {
		m.Version, m.Commit = os.Args[2], os.Args[3]
	} else if len(os.Args) == 1 {
		if cfg.Updates.Cache() != "/var/lib/aqmas-releases" || cfg.Updates.Spool() != "/var/spool/aqmas-update" || os.Geteuid() != 0 {
			return errors.New("updater requires root and the unit's fixed cache/spool paths")
		}
		req, e := consume(filepath.Join(cfg.Updates.Spool(), "approved"))
		if e != nil {
			return e
		}
		var pins []keyPin
		if e = readJSON("/etc/aqmas/update-passkeys.json", &pins); e != nil {
			return e
		}
		sg, e := verify(req, cfg.PublicBaseURL, pins, time.Now())
		if e != nil {
			return e
		}
		var current release.Metadata
		if e = readJSON(filepath.Join(cfg.Updates.Cache(), "latest.json"), &current); e != nil {
			return e
		}
		if !current.Valid() || sg.FromCommit != current.Commit || sg.FromVersion != current.Version {
			return errors.New("stale installed version")
		}
		signed = sg.Sums()
		m.Version, m.Commit = sg.ToVersion, sg.ToCommit
		used := filepath.Join("/var/lib/aqmas-updater", hex.EncodeToString(canon.Challenge(req.Canonical)))
		f, e := os.OpenFile(used, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return fmt.Errorf("cannot consume approval: %w", e)
		}
		if e = f.Close(); e != nil {
			return e
		}
	} else {
		return errors.New("usage: aqmas-update-verify [bootstrap VERSION COMMIT [CONFIG]]")
	}
	if !release.ValidCommit(m.Commit) || !release.ValidVersion(m.Version) {
		return errors.New("invalid build identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if m.Forgejo, e = cfg.Updates.Forgejo.Hashes(ctx, m.Version, false); e != nil {
		return fmt.Errorf("Forgejo: %w", e)
	}
	if m.GitHub, e = cfg.Updates.GitHub.Hashes(ctx, m.Version, true); e != nil {
		return fmt.Errorf("GitHub: %w", e)
	}
	if !m.Valid() || signed != nil && !signed.Agrees(m.Forgejo) {
		return errors.New("independent release hashes or approval disagree")
	}
	return json.NewEncoder(os.Stdout).Encode(m)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
