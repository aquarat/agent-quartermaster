package server

import (
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/notify"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

const sealDDL = `CREATE TABLE seal_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1), manifest TEXT NOT NULL, inventory BLOB NOT NULL, canonical TEXT NOT NULL, assertion BLOB NOT NULL) STRICT;
CREATE TABLE seal_wraps(passkey INTEGER PRIMARY KEY REFERENCES passkeys(id) ON DELETE CASCADE, salt BLOB NOT NULL UNIQUE CHECK(length(salt)=32), wrap BLOB NOT NULL CHECK(length(wrap)=73), generation INTEGER NOT NULL, tested_at INTEGER NOT NULL) STRICT;
CREATE TRIGGER seal_keep_unlock BEFORE DELETE ON passkeys WHEN EXISTS(SELECT 1 FROM seal_wraps WHERE passkey=OLD.id) AND (SELECT count(*) FROM seal_wraps)<=1 BEGIN SELECT RAISE(ABORT,'last tested unlock credential'); END;`

type sealRuntime struct {
	windows      windowPool
	capabilities capabilityStages
	delayed      atomic.Int64
	inv          seal.Inventory
	gate         *seal.Gate
	attempts     *seal.Attempts
	stop         chan struct{}
	once         sync.Once
	stage        *sealStage
}

func (s *Server) setupSealedNotices(client *http.Client) {
	if _, err := s.seal.inv.Record("ntfy-topic"); err != nil {
		return
	}
	slots := make(chan struct{}, 4)
	s.notify.Dispatch = func(title, text, clickURL string) {
		if s.isLocked() {
			s.seal.delayed.CompareAndSwap(0, s.now().UnixMilli())
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			s.log.Warn("notification queue full")
			return
		}
		go func() {
			defer func() { <-slots }()
			_ = s.withLease(context.Background(), func(ctx context.Context) error {
				topic, err := s.secret(ctx, "ntfy-topic")
				if err != nil {
					return err
				}
				defer clear(topic)
				n := notify.Notifier{TopicURL: string(topic), Client: client, Log: s.log}
				n.Publish(ctx, title, text, clickURL)
				return nil
			})
		}()
	}
}
func (s *Server) afterUnlock() {
	if at := s.seal.delayed.Swap(0); at > 0 {
		s.notify.Send("aqmas: delayed notifications", "Activity while locked since "+time.UnixMilli(at).UTC().Format(time.RFC3339)+"; review the queue and original activity times.", s.cfg.PublicBaseURL+"/")
	}
	s.publishLockStatus("unlocked")
}
func (s *Server) publishLockStatus(state string) {
	dir := os.Getenv("RUNTIME_DIRECTORY")
	if dir == "" {
		return
	}
	epoch := s.seal.attempts.Epoch()
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

func sealBoot(cfg *config.Config, st *store.Store, setup bool) (sealed bool, err error) {
	var v, n int
	if err = st.DB().QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return
	}
	if err = st.DB().QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name IN ('seal_active','seal_wraps')`).Scan(&n); err != nil {
		return
	}
	switch {
	case setup && cfg.Seal.Required && v >= 6 && v <= 7 && n == 0:
		return false, nil
	case !setup && cfg.Seal.Required && len(cfg.Seal.Manifest) == 64 && v == 8 && n == 2 && cfg.Ntfy.TopicURL == "":
		return true, nil
	case !setup && !cfg.Seal.Required && v <= 7 && n == 0:
		return false, nil
	}
	return false, errors.New("seal pin, schema and activation marker disagree; supervised maintenance required")
}

func (s *Server) loadSeal() error {
	// Refuse to call an installation sealed while retired files or imported
	// systemd credential copies remain. Never open a private CA to check this.
	paths := []string{filepath.Join(CADir(s.cfg.DataDir), pki.ClientCAKeyFile), filepath.Join(CADir(s.cfg.DataDir), pki.SSHCAKeyFile)}
	cf := s.cfg.Cloudflare
	{
		paths = append(paths, cf.ProxyTokenFile, cf.MinterTokenFile)
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			for _, name := range []string{cf.ProxyTokenCredential, cf.MinterTokenCredential} {
				if name != "" {
					paths = append(paths, filepath.Join(dir, name))
				}
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
	var mText string
	var b []byte
	if err := s.store.DB().QueryRow(`SELECT manifest, inventory FROM seal_active WHERE singleton=1 AND length(manifest)<=32768 AND length(inventory)<=524288`).Scan(&mText, &b); err != nil {
		return err
	}
	var m seal.Manifest
	var i seal.Inventory
	if seal.Digest([]byte(mText)) != s.cfg.Seal.Manifest || json.Unmarshal([]byte(mText), &m) != nil || m.Format != 1 || m.InventoryDigest != seal.Digest(b) || json.Unmarshal(b, &i) != nil || m.Generation != i.Generation || m.Recipient != s.cfg.Seal.Recipient || i.Recipient != m.Recipient || i.SSHCA != s.sshPin() || i.InternalCA != s.pki.CAPin() || i.ConfigHash != s.profileRevision {
		return errors.New("seal: public activation pin mismatch")
	}
	g, err := seal.NewGate(i.Generation, i.Check)
	if err != nil {
		return err
	}
	s.seal = &sealRuntime{inv: i, gate: g, attempts: seal.NewAttempts(s.now), stop: make(chan struct{})}
	if err = s.store.InitWindows(context.Background()); err != nil {
		return err
	}
	return s.store.InitEnv(context.Background())
}
func (s *Server) isLocked() bool {
	if s.seal == nil {
		return false
	}
	if s.seal.stage != nil {
		return true
	}
	ok, _ := s.seal.gate.Status()
	return !ok
}
func (s *Server) stopSealed() { s.seal.once.Do(func() { close(s.seal.stop); s.bcast.notify() }) }

type leaseKey struct{}

// All secret-backed operations use a lease from the outer handler; a
// long-poll obtains it only AFTER waiting. Re-entering never extends a lease.
func (s *Server) withLease(ctx context.Context, op func(context.Context) error) error {
	if s.seal == nil {
		return op(ctx)
	}
	if s.seal.stage != nil {
		return lockedErr()
	}
	return s.seal.gate.WithKey(ctx, func(ctx context.Context, mk *seal.Key) error { return op(context.WithValue(ctx, leaseKey{}, mk)) })
}
func lockedErr() *apiErr {
	return &apiErr{423, "locked", "waiting for owner unlock; retry within the original deadline"}
}
func (s *Server) secret(ctx context.Context, role string) ([]byte, error) {
	k, _ := ctx.Value(leaseKey{}).(*seal.Key)
	if k == nil || ctx.Err() != nil {
		return nil, lockedErr()
	}
	r, err := s.seal.inv.Record(role)
	if err == nil {
		var b []byte
		b, err = r.Decrypt(s.seal.inv.Generation, k, r.Envelope)
		if err == nil {
			return b, nil
		}
	}
	s.stopSealed()
	return nil, errors.New("sealed record failed authentication; broker restarting locked")
}

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
func (s *Server) loadWrap(ctx context.Context, pk *storedPasskey) (seal.WrappedCredential, error) {
	w := seal.WrappedCredential{Credential: seal.Credential{Generation: s.seal.inv.Generation, RPID: s.rpID, RawID: pk.CredentialID}, Passkey: pk.ID}
	var salt []byte
	err := s.store.DB().QueryRowContext(ctx, `SELECT salt,wrap FROM seal_wraps WHERE passkey=? AND generation=?`, pk.ID, w.Version).Scan(&salt, &w.Wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return w, errNotFound()
	}
	if err != nil {
		return w, err
	}
	if len(salt) != 32 {
		return w, errors.New("invalid seal salt")
	}
	copy(w.Salt[:], salt)
	w.Tested = true
	return w, nil
}

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

type sealStage struct {
	mu            sync.Mutex
	mk            *seal.Key
	dir           string
	session       string
	wrap          seal.WrappedCredential
	registration  string
	salts         map[int64]seal.ID
	activated     bool
	expectedProof [32]byte
	drill         hpke.PrivateKey // receives the recovery identity for the on-box drill
	drilled       bool
}

func (s *Server) newStage() error {
	if s.cfg.Seal.Manifest != "" {
		return errors.New("begin staging with an empty manifest pin")
	}
	g := seal.Generation{Installation: seal.RandomID(), Version: 1}
	mk, err := seal.RandomKey()
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			mk.Destroy()
		}
	}()
	i := seal.Inventory{Generation: g, Recipient: s.cfg.Seal.Recipient, ConfigHash: s.profileRevision, SSHCA: s.sshPin(), InternalCA: s.pki.CAPin()}
	if i.Check, err = g.CheckRecord(mk); err != nil {
		return err
	}
	if i.Recovery, err = g.RecoveryPacket(i.Recipient, mk); err != nil {
		return err
	}
	if err = s.importSources(func(o seal.Object, b []byte) error { o.Blob = seal.RandomID(); return i.Add(mk, o, b) }); err != nil {
		return err
	}
	proof, err := i.DrillProof(mk)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(s.cfg.DataDir, "seal-stage-")
	if err != nil {
		return err
	}
	b, err := json.Marshal(i)
	if err != nil {
		return err
	}
	if err = writeExclusive(filepath.Join(dir, "inventory.json"), b); err != nil {
		return err
	}
	drill, err := maint.NewKey()
	if err != nil {
		return err
	}
	s.seal = &sealRuntime{inv: i, attempts: seal.NewAttempts(s.now), stop: make(chan struct{}), stage: &sealStage{mk: mk, dir: dir, expectedProof: sha256.Sum256([]byte(proof)), drill: drill}}
	s.log.Info("sealed import fenced; compare bundle digest and recipient off-host and perform offline drill", "directory", dir, "inventory_sha256", seal.Digest(b), "installation", encodeID(g.Installation[:]), "recipient", i.Recipient)
	success = true
	return nil
}

func (s *Server) importSources(visit func(seal.Object, []byte) error) error {
	for _, it := range []struct{ role, file string }{{"ssh-ca", pki.SSHCAKeyFile}, {"internal-ca", pki.ClientCAKeyFile}} {
		b, err := readSecretFile(filepath.Join(CADir(s.cfg.DataDir), it.file), true)
		if err != nil {
			return err
		}
		err = s.pki.CheckPrivate(it.role, b)
		if err == nil {
			err = visit(seal.Object{Role: it.role, Global: it.role, Revision: 1}, b)
		}
		clear(b)
		if err != nil {
			return err
		}
	}
	if v := s.cfg.Ntfy.TopicURL; v != "" {
		b := []byte(v)
		err := visit(seal.Object{Role: "ntfy-topic", Global: "approval-notices", Revision: 1}, b)
		clear(b)
		if err != nil {
			return err
		}
	}
	cf := s.cfg.Cloudflare
	if cf.Enabled {
		var proxyHash [32]byte
		for _, parent := range []struct{ role, kind, cred, file string }{{"cf-proxy", "cloudflare-proxy", cf.ProxyTokenCredential, cf.ProxyTokenFile}, {"cf-minter", "cloudflare-mint", cf.MinterTokenCredential, cf.MinterTokenFile}} {
			if parent.cred == "" && parent.file == "" {
				continue
			}
			o := seal.Object{Role: parent.role, Revision: 1, Issuer: cf.APIBase, Account: cf.AccountID, ParentVersion: 1}
			if o.Issuer == "" {
				o.Issuer = "https://api.cloudflare.com/client/v4"
			}
			if err := s.store.DB().QueryRow(`SELECT c.org_id,v.id,t.id FROM personal_cutover c JOIN services v ON v.org_id=c.org_id JOIN credential_sets t ON t.service_id=v.id WHERE t.kind=? AND v.slug='dns-cdn'`, parent.kind).Scan(&o.Org, &o.Service, &o.Set); err != nil {
				return err
			}
			tok, err := loadParentToken(parent.role, parent.cred, parent.file)
			if err != nil {
				return err
			}
			b := []byte(tok)
			digest := sha256.Sum256(b)
			if parent.role == "cf-proxy" {
				proxyHash = digest
			} else if digest == proxyHash {
				clear(b)
				return errors.New("proxy and minter must have distinct parent credentials")
			}
			err = visit(o, b)
			clear(b)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// RecoveryDrill is local-only: authenticate the separately recorded bundle
// digest before attempting decryption. Its output only acknowledges the drill.
func RecoveryDrill(b []byte, digest, recipient string, identity []byte) (string, error) {
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != digest {
		return "", errors.New("recovery bundle digest differs from owner record")
	}
	var inv seal.Inventory
	if json.Unmarshal(b, &inv) != nil || inv.Recipient != recipient {
		return "", fmt.Errorf("invalid recovery context")
	}
	return inv.OfflineProof(identity)
}
