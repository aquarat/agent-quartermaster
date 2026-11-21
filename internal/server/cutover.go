package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
)

// Maintenance is an exclusive daemon mode, not a second process racing the
// live daemon. Both listeners must bind before a recovery point is taken.
type cutoverReview struct {
	Plan   string `json:"plan"`
	Digest string `json:"recovery_sha256"`
	path   string
	ID     string `json:"id"`
}

func (s *Server) lockService() (*os.File, error) {
	f, err := os.Open(s.cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another broker holds the data directory; stop and drain it first")
	}
	var v int
	if err := s.store.DB().QueryRow("PRAGMA user_version").Scan(&v); err != nil || v < 5 || v > 7 || (v >= 6) != s.store.Q().Scoped() {
		f.Close()
		return nil, errors.New("database changed during startup; restart the broker")
	}
	return f, nil
}

func (s *Server) sshPin() string { return ssh.FingerprintSHA256(s.pki.SSHSigner.PublicKey()) }
func (s *Server) verifyPersonalConfig() error {
	if !s.store.Q().Scoped() {
		return nil
	}
	if s.maintenance {
		return errors.New("personal cutover already activated")
	}
	hash, err := organisations.ConfigFingerprint(s.cfg, s.ownerID, s.sshPin(), s.pki.CAPin())
	if err != nil {
		return err
	}
	var pin string
	if err = s.store.DB().QueryRow(`SELECT config_sha256 FROM personal_cutover WHERE singleton=1`).Scan(&pin); err != nil {
		return err
	}
	if hash != pin {
		return errors.New("signed personal catalogue differs from configuration or CA; restore reviewed configuration before serving")
	}
	s.profileRevision = hash
	return nil
}

func (s *Server) prepareRecovery(ctx context.Context) error {
	path, digest, err := organisations.RecoveryPoint(ctx, s.store.DB(), s.cfg.DataDir)
	if err != nil {
		return err
	}
	p, err := organisations.InspectBackup(ctx, path, s.cfg, s.sshPin(), s.pki.CAPin(), s.now())
	if err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	s.cutover = &cutoverReview{string(b), digest, path, p.Organisation.ID}
	s.log.Info("personal cutover: fleet fenced; keep recovery point with matching binary and config", "backup", path, "sha256", digest)
	return nil
}

func (s *Server) migrationPreview(w http.ResponseWriter, r *http.Request, _ string) {
	if !s.maintenance || s.cutover == nil {
		writeJSON(w, 200, nil)
		return
	}
	writeJSON(w, 200, s.cutover)
}
func (s *Server) migrationAction(id string, in api.ChallengeRequest) (canon.Action, error) {
	var a canon.Action
	if !s.maintenance || s.cutover == nil || s.cutover.ID != id {
		return a, errNotFound()
	}
	if in.Action != "activate" || in.Nickname != "" || in.TTLSeconds != 0 || in.StandingHours != 0 {
		return a, errBad("expected activate")
	}
	return canon.Action{Object: canon.Migration, Action: "activate", ID: id, Plan: s.cutover.Plan, RecoveryHash: s.cutover.Digest}, nil
}

func (s *Server) activate(ctx context.Context, sess string, pk int64, sg canon.Signed) error {
	a := sg.Action
	if !s.maintenance || s.cutover == nil || a.Object != canon.Migration || a.Action != "activate" || sg.V != 2 || a.ID != s.cutover.ID || a.Plan != s.cutover.Plan || a.RecoveryHash != s.cutover.Digest {
		return errConflict("cutover review changed")
	}
	f, err := os.Open(s.cutover.path)
	if err != nil {
		return errConflict("missing recovery point")
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != a.RecoveryHash {
		return errConflict("recovery point changed")
	}
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	var ok int
	// Pre-cutover there is precisely one WebAuthn principal. Its session key
	// and actual assertion key must both still exist, inside this transaction.
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM web_sessions w JOIN passkeys login ON login.id=w.passkey_id JOIN passkeys signing ON signing.id=? WHERE w.hash=? AND w.expires_at>?`, pk, sess, now.UnixMilli()).Scan(&ok)
	if err != nil {
		return errConflict("owner session or signing credential changed")
	}
	if err = organisations.Backfill(ctx, tx, s.cfg, s.sshPin(), s.pki.CAPin(), now, a.Plan); err != nil {
		return errConflict("inventory or cutover state changed; restart the supervised review")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit(at,actor,action,object,detail) VALUES(?,'owner','migration_activate',?,?)`, now.UnixMilli(), "organisation:"+a.ID, fmt.Sprintf("personal; signer=%d nonce=%s config and inventory in personal_cutover; recovery=%s", pk, sg.Nonce, a.RecoveryHash)); err != nil {
		return err
	}
	return tx.Commit()
}
