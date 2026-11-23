package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/webui"
)

const recoveryEffects = "Replace all owner login keys and wraps. End every session, pending request, grant, standing rule and host admission; require new host enrollment. Preserve audit and SSH serials. Issued certificates, copied values and upstream children are not recalled."

// recoveryScope is one scope key recovered from its recovery wrap, and the
// replacement passkey's wrap of it once made.
type recoveryScope struct {
	name   string
	pub    []byte
	key    *seal.Key
	salt   seal.ID
	wrap   []byte
	tested bool
}

type recoveryFlow struct {
	dir                        string
	stopped                    bool
	mu                         sync.Mutex
	s                          *Server
	scopes                     []*recoveryScope
	ticket, session, reg, name string
	sd                         *webauthn.SessionData
	cred                       *webauthn.Credential
	tap                        *tapOpen
	tapText                    string
	canonical                  string
	expires                    time.Time
	done                       chan struct{}
}

func (f *recoveryFlow) wipe() {
	for _, sc := range f.scopes {
		sc.key.Destroy()
		sc.key = nil
	}
}

// Recover is `aqmasd seal-recover DIRECTORY <identity.txt` (docs/BUCKETS.md
// §10). It never opens a production listener. The identity on input opens
// every scope key from its recovery wrap, and every bucket and record is
// authenticated, before the private socket opens; the replacement passkey
// then receives wraps of every scope key (create and test taps) and the old
// passkeys are retired in one transaction.
func (s *Server) Recover(ctx context.Context, dir string, input io.Reader) error {
	if !s.recovery || s.seal == nil || s.seal.mode != modeBuckets {
		return errors.New("isolated sealed maintenance required")
	}
	lock, err := s.lockService()
	if err != nil {
		return err
	}
	defer lock.Close()
	text, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(text) > 4096 {
		clear(text)
		return errors.New("invalid identity input")
	}
	id, err := seal.ParseIdentity(text)
	clear(text)
	if err != nil {
		return errors.New("invalid recovery identity")
	}
	f := &recoveryFlow{s: s, dir: dir, ticket: ids.Secret(32), reg: ids.Secret(32), expires: s.now().Add(10 * time.Minute), done: make(chan struct{})}
	defer f.wipe()
	q := s.store.Q()
	rows, err := q.Scopes(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("the store has no scope keys")
	}
	buckets := 0
	for _, x := range rows {
		k, err := seal.Scope{Installation: s.seal.installation, Name: x.Scope, Public: x.Public}.Recover(id, s.seal.recipient, x.Recovery)
		if err != nil {
			return errors.New("this is not the recovery key of this installation")
		}
		f.scopes = append(f.scopes, &recoveryScope{name: x.Scope, pub: x.Public, key: k})
		n, err := s.drillScope(ctx, q, x, k)
		if err != nil {
			return errors.New("backup contains a missing or damaged bucket or record")
		}
		buckets += n
	}
	s.log.Info("every scope key, bucket and record opened from the recovery key", "scopes", len(f.scopes), "buckets", buckets)
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
	defer func() { httpd.Close(); f.mu.Lock(); f.stopped = true; f.wipe(); f.mu.Unlock() }()
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

func (f *recoveryFlow) scopeNames() []string {
	out := []string{}
	for _, sc := range f.scopes {
		out = append(out, sc.name)
	}
	return out
}

// next picks the scopes of the next tap: up to two without a wrap (purpose
// "enrol"), then up to two untested ("test"). Empty when all are tested.
func (f *recoveryFlow) next() (string, []*recoveryScope) {
	var out []*recoveryScope
	for _, sc := range f.scopes {
		if sc.wrap == nil && len(out) < 2 {
			out = append(out, sc)
		}
	}
	if len(out) > 0 {
		return "enrol", out
	}
	for _, sc := range f.scopes {
		if !sc.tested && len(out) < 2 {
			out = append(out, sc)
		}
	}
	if len(out) > 0 {
		return "test", out
	}
	return "", nil
}

// Steps (POST /recovery/{step}, header X-Aqmas-Recovery: the ticket for
// "begin", then the session it returns):
//
//	begin {name} → {public_key, session, registration_id, installation, epoch, scopes}
//	create {credential} → {credential_id, scopes}
//	evaluate {} → {canonical, public_key, open:{descriptor}}  (scope-enrol, purpose enrol|test)
//	finish {assertion, open} → {next:"evaluate"} | {next:"replace", canonical, public_key}
//	replace {assertion} → {ok}
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
		return map[string]any{"public_key": cc.Response, "session": f.session, "registration_id": f.reg, "installation": z.installation, "epoch": z.opens.Epoch(), "scopes": f.scopeNames()}, nil
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
		return map[string]any{"credential_id": encodeID(cred.ID), "scopes": f.scopeNames()}, nil
	case "evaluate":
		if f.cred == nil || f.canonical != "" {
			return nil, errConflict("no staged credential")
		}
		purpose, list := f.next()
		if purpose == "" {
			return nil, errConflict("every scope is already tested")
		}
		var names []string
		var salts []seal.ID
		for _, sc := range list {
			names = append(names, sc.name)
			if purpose == "enrol" {
				salts = append(salts, seal.RandomID())
			} else {
				salts = append(salts, sc.salt)
			}
		}
		m := s.reviewFields("recovery-enrol", purpose, f.reg)
		m["credential_id"], m["nickname"], m["scopes"] = encodeID(f.cred.ID), f.name, names
		text, err := reviewJSON(m)
		if err != nil {
			return nil, err
		}
		opts, t, err := s.enrolTap(f.session, purpose, text, *f.cred, names, salts)
		if err != nil {
			return nil, err
		}
		f.tap, f.tapText = t, text
		return api.ChallengeResponse{Canonical: text, PublicKey: opts, Open: t.offer()}, nil
	case "finish":
		t, text := f.tap, f.tapText
		f.tap, f.tapText = nil, ""
		if f.cred == nil || f.canonical != "" || t == nil || !s.now().Before(t.expires) {
			return nil, errConflict("no tap to finish; evaluate again")
		}
		var in struct {
			Assertion json.RawMessage `json:"assertion"`
			Open      *api.OpenPacket `json:"open"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if err := f.verify(in.Assertion, seal.OpenChallenge([]byte(text), []byte(t.descriptor)), t.ext); err != nil {
			return nil, err
		}
		keks, err := s.enrolKEKs(t, f.session, text, in.Open)
		if err != nil {
			return nil, err
		}
		defer destroyKeys(keks)
		for i, name := range t.scopes {
			var sc *recoveryScope
			for _, x := range f.scopes {
				if x.name == name {
					sc = x
				}
			}
			ps := seal.PasskeyScope{Installation: z.installation, RPID: s.rpID, RawID: f.cred.ID, Scope: name, Salt: t.salts[i]}
			if t.purpose == "enrol" {
				w, err := ps.Wrap(keks[i], sc.key, sc.pub)
				if err != nil {
					return nil, errConflict("could not wrap a scope key")
				}
				sc.salt, sc.wrap = t.salts[i], w
				continue
			}
			k, err := ps.Unwrap(keks[i], sc.wrap, sc.pub)
			if err != nil {
				return nil, errForbidden("the replacement passkey's key for " + name + " did not open")
			}
			k.Destroy()
			sc.tested = true
		}
		if purpose, _ := f.next(); purpose != "" {
			return map[string]any{"next": "evaluate"}, nil
		}
		m := s.reviewFields("recovery", "replace", f.reg)
		m["backup_sha256"] = s.cfg.Seal.RecoveryBackupSHA256
		m["serial_high_water"] = fmt.Sprint(*s.cfg.Seal.RecoverySerial)
		m["credential_id"], m["nickname"], m["effects"], m["manifest_sha256"], m["scopes"] = encodeID(f.cred.ID), f.name, recoveryEffects, s.cfg.Seal.Manifest, f.scopeNames()
		old, err := s.loadOwner(ctx)
		if err != nil {
			return nil, err
		}
		list := []string{}
		for _, v := range old.creds {
			list = append(list, encodeID(v.ID))
		}
		m["retire_credentials"] = strings.Join(list, ",")
		if f.canonical, err = reviewJSON(m); err != nil {
			return nil, err
		}
		opts, err := s.requestOptions(f.owner(), canon.Challenge(f.canonical))
		if err != nil {
			return nil, err
		}
		return map[string]any{"next": "replace", "canonical": f.canonical, "public_key": opts}, nil
	case "replace":
		if f.canonical == "" {
			return nil, errConflict("every scope must be wrapped and tested first")
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
	for _, sc := range f.scopes {
		if sc.wrap == nil || !sc.tested {
			return errors.New("a scope key is not wrapped and tested")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO scope_wraps(passkey,scope,salt,wrap,created,tested_at) VALUES(?,?,?,?,?,?)`, row, sc.name, sc.salt[:], sc.wrap, now, now); err != nil {
			return err
		}
	}
	for _, stmt := range []string{`DELETE FROM web_sessions`, `DELETE FROM challenges`, `DELETE FROM enroll_codes`, `DELETE FROM env_drafts`, `UPDATE requests SET status=CASE WHEN status='approved' THEN 'revoked' ELSE 'expired' END WHERE status IN ('approved','pending')`, `UPDATE enrollments SET status='expired' WHERE status='pending'`, `UPDATE env_releases SET status=CASE WHEN status='approved' THEN 'revoked' ELSE 'expired' END WHERE status IN ('approved','pending')`, `UPDATE sign_requests SET status=CASE WHEN status='approved' THEN 'revoked' ELSE 'expired' END WHERE status IN ('approved','pending')`} {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, table := range []string{"hosts", "grants", "standing"} {
		if _, err = tx.ExecContext(ctx, `UPDATE `+table+` SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
			return err
		}
	}
	// The old passkeys' scope wraps go with them (ON DELETE CASCADE).
	if _, err = tx.ExecContext(ctx, `DELETE FROM passkeys WHERE id!=?`, row); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit(at,actor,action,object,detail) VALUES(?,'owner','recovery_replace','seal',?)`, now, fmt.Sprintf("%s assertion=%s", text, assertion)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	_ = s.store.CheckpointWAL(ctx)
	return nil
}
