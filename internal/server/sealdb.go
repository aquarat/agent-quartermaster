package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Seal format 2 runtime (docs/BUCKETS.md). There is no global unlock: after a
// start nothing is open; an approval tap opens exactly the buckets its signed
// card lists and the pool keeps each only as long as its holds say.

// sealActiveDDL is the root-pinned activation marker, shared by format 1
// (schema 8) and format 2 (schema 9; inventory '{}').
const sealActiveDDL = `CREATE TABLE IF NOT EXISTS seal_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1), manifest TEXT NOT NULL, inventory BLOB NOT NULL, canonical TEXT NOT NULL, assertion BLOB NOT NULL) STRICT;`

// Seal modes, as GET /api/ui/seal/status reports them.
const (
	modeBuckets   = "buckets"            // format 2, serving
	modeMigration = "migration-required" // schema-8 format-1 store under this binary
	modeSetup     = "setup"              // seal-import or bucket-migrate staging (STAGE-AGENT)
)

// Bucket refs (buckets.ref): the installation-wide CAs use caBucketRef; a
// Cloudflare proxy parent, an env set and a signer use their credential set ID.
const caBucketRef = "installation"

type sealRuntime struct {
	mode         string
	installation seal.ID
	recipient    string
	opens        *seal.OpenAttempts // Epoch() is the boot epoch of every v3 canonical
	pool         *bucketPool
	taps         tapRegistry
	windows      windowPool
	vault        vaultPool
	capabilities capabilityStages
	scopeMu      sync.Mutex // serialises scope creation, passkey wraps and rekey
	stop         chan struct{}
	once         sync.Once
	stage        *sealStage // STAGE-AGENT: seal-import / bucket-migrate staging
}

// BucketManifest is the root-pinned format-2 activation manifest
// (seal_active.manifest; its SHA-256 is config seal.manifest_sha256). The
// scopes and buckets are those at activation: both change later (new
// organisations, new sets, rekey), so boot checks only the fixed fields.
type BucketManifest struct {
	Format       int              `json:"seal_format"`
	Installation seal.ID          `json:"installation"`
	Recipient    string           `json:"offline_recipient"`
	SSHCA        string           `json:"ssh_ca"`
	InternalCA   string           `json:"internal_ca"`
	Config       string           `json:"public_config_digest"`
	Scopes       []ManifestScope  `json:"scopes"`
	Buckets      []ManifestBucket `json:"buckets"`
	Passkeys     []ManifestWrap   `json:"passkeys,omitempty"`
	ApproveOnly  []string         `json:"approve_only,omitempty"`
}
type ManifestScope struct {
	Scope  string `json:"scope"`
	Public string `json:"public_key"`
}
type ManifestBucket struct {
	ID     string `json:"id"`
	Scope  string `json:"scope"`
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Public string `json:"public_key"`
}
type ManifestWrap struct {
	Credential string `json:"credential_id"`
	Scope      string `json:"scope"`
	Salt       string `json:"salt"`
	WrapSHA256 string `json:"wrap_sha256"`
}

func migrationErr() *apiErr {
	return &apiErr{423, "locked", "migration required: this store is still sealed in format 1; move it to per-credential buckets in Admin → Setup"}
}

// bucketsReady is nil when buckets can be used at all (format 2 serving).
func (s *Server) bucketsReady() error {
	switch {
	case s.seal == nil:
		return errNotFound()
	case s.seal.mode == modeMigration:
		return migrationErr()
	case s.seal.mode != modeBuckets:
		return errConflict("staging in progress")
	}
	return nil
}
func (s *Server) sealServing() bool { return s.seal != nil && s.seal.mode == modeBuckets }

// setupSealedNotices points approval notices at the topic in notice_channel:
// readable with every bucket closed (docs/BUCKETS.md §9).
func (s *Server) setupSealedNotices() error {
	if s.seal.mode != modeBuckets {
		return nil
	}
	topic, err := s.store.Q().NoticeTopic(context.Background())
	if err != nil {
		return err
	}
	s.notify.TopicURL = topic
	return nil
}

// publishLockStatus tells the separate lock-alert service that this process
// started with everything closed. Format 2 never publishes "unlocked".
func (s *Server) publishLockStatus(state string) {
	dir := os.Getenv("RUNTIME_DIRECTORY")
	if dir == "" {
		return
	}
	epoch := s.seal.opens.Epoch()
	f, err := os.CreateTemp(dir, ".status-*")
	if err == nil {
		defer os.Remove(f.Name())
		if _, err = fmt.Fprintf(f, "%s %s\n", state, encodeID(epoch[:])); err == nil {
			err = f.Chmod(0644)
		}
		ce := f.Close()
		if err == nil {
			err = ce
		}
		if err == nil {
			err = os.Rename(f.Name(), filepath.Join(dir, "seal-status"))
		}
	}
	if err != nil {
		s.log.Warn("could not publish local lock status")
	}
}

// sealBoot decides the seal mode from the pin, the schema and the activation
// marker before anything else is loaded: "" (unsealed), modeBuckets,
// modeMigration or modeSetup.
func sealBoot(cfg *config.Config, st *store.Store, setup bool) (string, error) {
	var v, active, wraps, buckets int
	db := st.DB()
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return "", err
	}
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name='seal_active'`).Scan(&active); err != nil {
		return "", err
	}
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name='seal_wraps'`).Scan(&wraps); err != nil {
		return "", err
	}
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name='bucket_scopes'`).Scan(&buckets); err != nil {
		return "", err
	}
	pinned := cfg.Seal.Required && len(cfg.Seal.Manifest) == 64 && cfg.Ntfy.TopicURL == ""
	switch {
	case setup && cfg.Seal.Required && v >= 6 && v <= 7 && active+wraps+buckets == 0:
		return modeSetup, nil
	case !setup && pinned && v == store.SchemaBuckets && active == 1 && buckets == 1 && wraps == 0:
		return modeBuckets, nil
	case !setup && pinned && v == 8 && active == 1 && wraps == 1 && buckets == 0:
		return modeMigration, nil
	case !setup && !cfg.Seal.Required && v <= 7 && active+wraps+buckets == 0:
		return "", nil
	}
	return "", errors.New("seal pin, schema and activation marker disagree; supervised maintenance required")
}

func (s *Server) retiredSources() error {
	// Refuse to call an installation sealed while retired files or imported
	// systemd credential copies remain. Never open a private CA to check this.
	paths := []string{filepath.Join(CADir(s.cfg.DataDir), pki.ClientCAKeyFile), filepath.Join(CADir(s.cfg.DataDir), pki.SSHCAKeyFile)}
	cf := s.cfg.Cloudflare
	paths = append(paths, cf.ProxyTokenFile, cf.MinterTokenFile)
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		for _, name := range []string{cf.ProxyTokenCredential, cf.MinterTokenCredential} {
			if name != "" {
				paths = append(paths, filepath.Join(dir, name))
			}
		}
	}
	for _, p := range paths {
		if p != "" {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				return errors.New("retired plaintext source still present or cannot be checked; finish supervised cleanup")
			}
		}
	}
	return nil
}

func (s *Server) pinnedManifest() (string, error) {
	var m string
	if err := s.store.DB().QueryRow(`SELECT manifest FROM seal_active WHERE singleton=1 AND length(manifest)<=1048576`).Scan(&m); err != nil {
		return "", err
	}
	if seal.Digest([]byte(m)) != s.cfg.Seal.Manifest {
		return "", errors.New("seal: public activation pin mismatch")
	}
	return m, nil
}

func newSealRuntime(s *Server, mode string, installation seal.ID) *sealRuntime {
	z := &sealRuntime{mode: mode, installation: installation, recipient: s.cfg.Seal.Recipient, opens: seal.NewOpenAttempts(s.now), pool: newBucketPool(s.now), stop: make(chan struct{})}
	z.pool.onChange = func() { s.bcast.notify() }
	return z
}

// loadSeal starts a pinned format-2 store, or a format-1 store in
// migration-required mode (sign-in, queueing, deny/revoke and Setup only).
func (s *Server) loadSeal(mode string) error {
	if err := s.retiredSources(); err != nil {
		return err
	}
	text, err := s.pinnedManifest()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if mode == modeMigration {
		var m seal.Manifest
		if json.Unmarshal([]byte(text), &m) != nil || m.Format != 1 || m.Recipient != s.cfg.Seal.Recipient || m.SSHCA != s.sshPin() || m.InternalCA != s.pki.CAPin() || m.Installation == (seal.ID{}) {
			return errors.New("seal: public activation pin mismatch")
		}
		s.seal = newSealRuntime(s, modeMigration, m.Installation)
		// v0.4.1 created these; IF NOT EXISTS leaves its tables as they are.
		for _, init := range []func(context.Context) error{s.store.InitWindows, s.store.InitEnv, s.store.InitVault} {
			if err := init(ctx); err != nil {
				return err
			}
		}
		s.log.Warn("format-1 sealed store: migration required; only sign-in, queueing, deny/revoke and Setup are served")
		return nil
	}
	var m BucketManifest
	if json.Unmarshal([]byte(text), &m) != nil || m.Format != 2 || m.Installation == (seal.ID{}) || m.Recipient != s.cfg.Seal.Recipient || m.SSHCA != s.sshPin() || m.InternalCA != s.pki.CAPin() || m.Config != s.profileRevision {
		return errors.New("seal: public activation pin mismatch")
	}
	// Freed pages must not keep old wraps (§7). The signer-key trigger of
	// format 1 also froze payload and wrap, which rekey re-encrypts.
	if _, err = s.store.DB().ExecContext(ctx, `PRAGMA secure_delete=ON;`+store.BucketDDL+`DROP TRIGGER IF EXISTS signer_key_immutable;`); err != nil {
		return err
	}
	s.seal = newSealRuntime(s, modeBuckets, m.Installation)
	if err = s.store.InitWindows(ctx); err != nil {
		return err
	}
	if err = s.store.InitEnv(ctx); err != nil {
		return err
	}
	return s.store.InitVault(ctx)
}

func (s *Server) stopSealed() { s.seal.once.Do(func() { close(s.seal.stop); s.bcast.notify() }) }

func encodeID(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func strictB64(s string, max int) ([]byte, error) {
	if len(s) > 2*max {
		return nil, errBad("invalid base64url")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > max || encodeID(b) != s {
		return nil, errBad("invalid base64url")
	}
	return b, nil
}
func sha256Bytes(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
func sha256Hex(b []byte) string   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// writeExclusive never overwrites an old operator artifact. No secret may
// be passed here: only sealed recovery bundles and public transition pins.
func writeExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	return err
}

// errStage marks what the staging build stage still has to provide.
func errStage(what string) error {
	return fmt.Errorf("%s is not implemented in this build stage", what)
}

// STAGE-AGENT: seal-import and bucket-migrate staging (docs/BUCKETS.md §8,
// contract "Stage"). The format-1 staging (one MK, one wrap) was removed.
type sealStage struct{}

// STAGE-AGENT: build the format-2 stage (scope keys, buckets, records,
// recovery wraps in memory) from the plaintext sources or the format-1 store.
func (s *Server) newStage() error { return errStage("seal-import staging") }

// RecoveryDrill was the format-1 offline drill over an inventory bundle.
// STAGE-AGENT: replace with `aqmasd seal-drill BACKUP.db RECIPIENT` (§10).
func RecoveryDrill(b []byte, digest, recipient string, identity []byte) (string, error) {
	return "", errStage("the offline recovery drill")
}
