package server

import "strings"

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/webui"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

const recoveryEffects = "Replace all owner login keys and wraps. End every session, pending request, grant, standing rule and host admission; require new host enrollment. Preserve audit and SSH serials. Issued certificates, copied values and upstream children are not recalled."

type recoveryFlow struct {
	dir                        string
	stopped                    bool
	mu                         sync.Mutex
	s                          *Server
	mk                         *seal.Key
	ticket, session, reg, name string
	sd                         *webauthn.SessionData
	cred                       *webauthn.Credential
	salt                       seal.ID
	wrap                       []byte
	canonical                  string
	expires                    time.Time
	done                       chan struct{}
}

// Recover never opens either production listener. The operator must stop the
// service, verify the backup inventory/serial high-water mark independently,
// and expose only this private socket to the owner's trusted RP path.
func (s *Server) Recover(ctx context.Context, dir string, input io.Reader) error {
	if !s.recovery || s.seal == nil {
		return errors.New("isolated sealed maintenance required")
	}
	lock, err := s.lockService()
	if err != nil {
		return err
	}
	defer lock.Close()
	k, err := s.seal.inv.Receive(input)
	if err != nil {
		return errors.New("invalid recovery key or damaged inventory")
	}
	defer k.Destroy()
	if err = s.verifyEnvInventory(ctx, k); err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	defer os.Remove(dir)
	socket := filepath.Join(dir, "broker.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	f := &recoveryFlow{s: s, mk: k, ticket: ids.Secret(32), reg: ids.Secret(32), salt: seal.RandomID(), expires: s.now().Add(10 * time.Minute), done: make(chan struct{})}
	f.dir = dir
	ticketPath := filepath.Join(dir, "ticket")
	if err = writeExclusive(ticketPath, []byte(f.ticket)); err != nil {
		return err
	}
	defer os.Remove(ticketPath)
	mux := http.NewServeMux()
	mux.Handle("/", webui.RecoveryHandler())
	mux.Handle("POST /recovery/{step}", s.apiGuard(http.HandlerFunc(f.serve)))
	httpd := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	}), ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 32 << 10}
	ended := make(chan error, 1)
	go func() { ended <- httpd.Serve(ln) }()
	defer func() { httpd.Close(); f.mu.Lock(); f.stopped = true; f.mu.Unlock() }()
	timer := time.NewTimer(10 * time.Minute)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("recovery expired")
	case err := <-ended:
		return err
	case <-f.done:
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpd.Shutdown(stop)
	}
}

func (s *Server) verifyEnvInventory(ctx context.Context, k *seal.Key) error {
	ctx = context.WithValue(ctx, leaseKey{}, k)
	db := s.store.DB()
	rows, err := db.QueryContext(ctx, `SELECT o.id,v.id,s.id,s.revision,r.blob,r.payload,r.wrap,r.names FROM credential_sets s JOIN services v ON v.id=s.service_id JOIN organisations o ON o.id=v.org_id LEFT JOIN env_revisions r ON r.set_id=s.id AND r.revision=s.revision WHERE s.kind='env-set' AND s.revision>0`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var b envset.Binding
		var r store.CipherRecord
		var names string
		if err = rows.Scan(&b.Org, &b.Service, &b.Set, &b.Revision, &r.Blob, &r.Payload, &r.Wrap, &names); err != nil {
			return err
		}
		var entries []envset.Entry
		if _, err = s.envCipher(ctx, b, "", r, &entries, false); err != nil || json.Unmarshal([]byte(names), &b.Names) != nil || envset.Validate(entries) != nil || !slices.Equal(envset.Names(entries), b.Names) {
			return errors.New("backup contains a missing or damaged live env revision")
		}
	}
	return rows.Err()
}

func (f *recoveryFlow) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		http.Error(w, "recovery ended", 410)
		return
	}
	s := f.s
	step := r.PathValue("step")
	if !s.now().Before(f.expires) {
		s.writeErr(w, r, errExpired("recovery expired"))
		return
	}
	key := r.Header.Get("X-Aqmas-Recovery")
	if key == "" || step == "begin" && subtle.ConstantTimeCompare([]byte(key), []byte(f.ticket)) != 1 || step != "begin" && subtle.ConstantTimeCompare([]byte(key), []byte(f.session)) != 1 {
		s.writeErr(w, r, errForbidden("invalid recovery ticket"))
		return
	}
	out, err := f.step(r, step)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, out)
	if step == "replace" {
		f.session = ""
		close(f.done)
	}
}
func (f *recoveryFlow) selection() map[string]any {
	stage := "-create"
	if f.wrap != nil {
		stage = "-test"
	}
	z := f.s.seal
	return map[string]any{"action": "wrap-enroll", "registration_id": f.reg + stage, "installation": z.inv.Installation, "mk_version": z.inv.Version, "epoch": z.attempts.Epoch(), "credential_id": encodeID(f.cred.ID), "prf_salt": f.salt, "rp_id": f.s.rpID}
}
func (f *recoveryFlow) step(r *http.Request, step string) (any, error) {
	s := f.s
	ctx := r.Context()
	z := s.seal
	switch step {
	case "begin":
		f.ticket = ""
		var in struct{ Name string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		name, err := normalizeNickname(in.Name)
		if err != nil {
			return nil, err
		}
		o, err := s.loadOwner(ctx)
		if err != nil {
			return nil, err
		}
		var excl []protocol.CredentialDescriptor
		for _, old := range o.creds {
			excl = append(excl, old.Descriptor())
		}
		cc, sd, err := s.wa.BeginRegistration(o, webauthn.WithExclusions(excl), webauthn.WithExtensions(webauthn.WithExtensionCredProps(), webauthn.WithExtensionPRFSupport()))
		if err != nil {
			return nil, err
		}
		f.name, f.sd, f.session = name, sd, ids.Secret(32)
		return map[string]any{"public_key": cc.Response, "session": f.session, "registration_id": f.reg, "installation": z.inv.Installation, "epoch": z.attempts.Epoch(), "mk_version": z.inv.Version}, nil
	case "create":
		if f.sd == nil {
			return nil, errConflict("registration unavailable")
		}
		sd := f.sd
		f.sd = nil
		var in struct{ Credential json.RawMessage }
		if decode(r, &in) != nil || !publicExtensionsOnly(in.Credential, true) {
			return nil, errBad("invalid registration")
		}
		pr, err := protocol.ParseCredentialCreationResponseBytes(in.Credential)
		if err != nil {
			return nil, errBad("invalid attestation")
		}
		o, err := s.loadOwner(ctx)
		if err != nil {
			return nil, err
		}
		cred, err := s.wa.CreateCredential(o, *sd, pr)
		if err != nil || !cred.Flags.UserVerified {
			return nil, errForbidden("invalid recovery credential")
		}
		for _, old := range o.creds {
			if bytes.Equal(old.ID, cred.ID) {
				return nil, errConflict("replacement must be a new credential")
			}
		}
		f.cred = cred
		return f.selection(), nil
	case "evaluate":
		if f.cred == nil || f.canonical != "" {
			return nil, errConflict("no staged credential")
		}
		c := seal.Credential{Generation: z.inv.Generation, RPID: s.rpID, RawID: f.cred.ID, Salt: f.salt}
		b, err := z.attempts.Begin(f.session, "wrap-enroll", f.selection()["registration_id"].(string), c)
		if err != nil {
			return nil, errConflict("evaluation unavailable")
		}
		ch, _ := strictB64(b.Challenge, 32)
		opts, err := s.requestOptions(f.owner(), ch)
		opts.Extensions = protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: protocol.PRFValues{First: f.salt[:]}}}
		return map[string]any{"attempt_id": b.ID, "canonical": b.Canonical, "publicKey": opts}, err
	case "finish":
		if f.cred == nil || f.canonical != "" {
			return nil, errConflict("no staged credential")
		}
		var in sealPacket
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		enc, _ := strictB64(in.Enc, 65)
		ct, _ := strictB64(in.CT, maxBody)
		var result any
		err := z.attempts.FinishBound(f.session, "wrap-enroll", in.ID, enc, ct, func(c seal.Credential, reg string, d [32]byte, b []byte, kek *seal.Key) error {
			if reg != f.selection()["registration_id"] || !bytes.Equal(c.RawID, f.cred.ID) {
				return errConflict("wrong test step")
			}
			if err := f.verify(b, d[:], protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: protocol.PRFValues{First: f.salt[:]}}}); err != nil {
				return err
			}
			if f.wrap == nil {
				var err error
				f.wrap, err = c.Wrap(kek, f.mk)
				result = f.selection()
				return err
			}
			k, err := c.Unwrap(kek, f.wrap, z.inv.Check)
			if err != nil {
				return err
			}
			k.Destroy()
			m := s.reviewFields("recovery", "replace", f.reg)
			m["backup_sha256"] = s.cfg.Seal.RecoveryBackupSHA256
			m["serial_high_water"] = fmt.Sprint(*s.cfg.Seal.RecoverySerial)
			m["credential_id"], m["nickname"], m["effects"], m["manifest_sha256"], m["mk_version"] = encodeID(f.cred.ID), f.name, recoveryEffects, s.cfg.Seal.Manifest, z.inv.Version
			old, err := s.loadOwner(ctx)
			if err != nil {
				return err
			}
			list := []string{}
			for _, v := range old.creds {
				list = append(list, encodeID(v.ID))
			}
			m["retire_credentials"] = strings.Join(list, ",")
			f.canonical, err = reviewJSON(m)
			if err != nil {
				return err
			}
			opts, err := s.requestOptions(f.owner(), canon.Challenge(f.canonical))
			result = map[string]any{"canonical": f.canonical, "public_key": opts}
			return err
		})
		if err != nil {
			return nil, errForbidden("invalid recovery wrap evaluation")
		}
		return result, nil
	case "replace":
		if f.canonical == "" {
			return nil, errConflict("two tested evaluations required")
		}
		text := f.canonical
		f.canonical = ""
		var in struct{ Assertion json.RawMessage }
		if decode(r, &in) != nil {
			return nil, errBad("bad assertion")
		}
		if err := f.verify(in.Assertion, canon.Challenge(text), protocol.AuthenticationExtensions{}); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, f.commit(ctx, text, in.Assertion)
	default:
		return nil, errNotFound()
	}
}
func (f *recoveryFlow) owner() *owner {
	return &owner{id: f.s.ownerID, name: f.s.cfg.OwnerName, creds: []webauthn.Credential{*f.cred}}
}
func (f *recoveryFlow) verify(b, digest []byte, ext protocol.AuthenticationExtensions) error {
	if !publicExtensionsOnly(b, false) {
		return errForbidden("unexpected extension")
	}
	pr, err := protocol.ParseCredentialRequestResponseBytes(b)
	if err != nil {
		return errBad("invalid assertion")
	}
	s := f.s
	cred, err := s.wa.ValidateLogin(f.owner(), webauthn.SessionData{Challenge: encodeID(digest), RelyingPartyID: s.rpID, Origin: s.cfg.PublicBaseURL, UserID: s.ownerID, AllowedCredentialIDs: [][]byte{f.cred.ID}, UserVerification: protocol.VerificationRequired, Extensions: ext.Session()}, pr)
	if err != nil || !cred.Flags.UserPresent || !cred.Flags.UserVerified || cred.Authenticator.CloneWarning {
		return errForbidden("replacement assertion rejected")
	}
	f.cred = cred
	return nil
}
func (f *recoveryFlow) commit(ctx context.Context, text string, assertion []byte) error {
	s := f.s
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	var prior string
	if err = tx.QueryRowContext(ctx, `SELECT manifest FROM seal_active WHERE singleton=1`).Scan(&prior); err != nil || seal.Digest([]byte(prior)) != s.cfg.Seal.Manifest {
		return errors.New("recovery pin changed")
	}
	var manifest map[string]json.RawMessage
	if err = json.Unmarshal([]byte(prior), &manifest); err != nil {
		return err
	}
	manifest["recovery_transition"], _ = json.Marshal(seal.Digest([]byte(text)))
	next, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err = writeExclusive(filepath.Join(f.dir, "replacement-manifest.json"), next); err != nil {
		return err
	}
	var seq int64
	if err = tx.QueryRowContext(ctx, `SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name='grants'),0),coalesce((SELECT max(serial) FROM grants),0))`).Scan(&seq); err != nil || seq > *s.cfg.Seal.RecoverySerial {
		return errors.New("operator serial record below restored allocator; reestablish high-water mark")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sqlite_sequence WHERE name='grants'`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sqlite_sequence(name,seq) VALUES('grants',?)`, *s.cfg.Seal.RecoverySerial); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE seal_active SET manifest=?,canonical=?,assertion=? WHERE singleton=1`, string(next), text, assertion); err != nil {
		return err
	}
	cj, err := json.Marshal(f.cred)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO passkeys(credential_id,credential_json,name,created_at) VALUES(?,?,?,?)`, f.cred.ID, string(cj), f.name, now)
	if err != nil {
		return err
	}
	row, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO seal_wraps VALUES(?,?,?,?,?)`, row, f.salt[:], f.wrap, s.seal.inv.Version, now); err != nil {
		return err
	}
	for _, stmt := range []string{`DELETE FROM web_sessions`, `DELETE FROM challenges`, `DELETE FROM enroll_codes`, `DELETE FROM env_drafts`, `UPDATE requests SET status=CASE WHEN status='approved' THEN 'revoked' ELSE 'expired' END WHERE status IN ('approved','pending')`, `UPDATE enrollments SET status='expired' WHERE status='pending'`, `UPDATE env_releases SET status=CASE WHEN status='approved' THEN 'revoked' ELSE 'expired' END WHERE status IN ('approved','pending')`} {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, table := range []string{"hosts", "grants", "standing"} {
		if _, err = tx.ExecContext(ctx, `UPDATE `+table+` SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM passkeys WHERE id!=?`, row); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit(at,actor,action,object,detail) VALUES(?,'owner','recovery_replace','seal',?)`, now, fmt.Sprintf("%s assertion=%s", text, assertion)); err != nil {
		return err
	}
	return tx.Commit()
}
