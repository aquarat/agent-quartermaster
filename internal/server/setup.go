package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Settings → Setup (docs/SETUP.md). aqmasd never performs a setup task: it describes them,
// has the owner sign one, and hands the signed request to the root runner through the
// spool. The runner verifies everything again and trusts nothing written here.

// SetupFacts is the broker's read-only view for the runner (`aqmasd setup-facts`).
func SetupFacts(dataDir string) (maint.Facts, error) {
	f := maint.Facts{Version: release.Version, Commit: release.Commit}
	db, err := sql.Open("sqlite", "file:"+DBPath(dataDir)+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		return f, err
	}
	defer db.Close()
	if err = db.QueryRow(`PRAGMA user_version`).Scan(&f.Schema); err != nil {
		return f, err
	}
	rows, err := db.Query(`SELECT credential_json FROM passkeys ORDER BY id LIMIT 64`)
	if err != nil {
		return f, err
	}
	defer rows.Close()
	for rows.Next() {
		var text string
		var c webauthn.Credential
		if err = rows.Scan(&text); err != nil {
			return f, err
		}
		if json.Unmarshal([]byte(text), &c) != nil {
			return f, errors.New("invalid passkey record")
		}
		f.Passkeys = append(f.Passkeys, struct {
			ID        []byte `json:"id"`
			PublicKey []byte `json:"publicKey"`
		}{c.ID, c.PublicKey})
	}
	if err = rows.Err(); err != nil {
		return f, err
	}
	if f.Schema == 8 || f.Schema == store.SchemaBuckets {
		// The manifest and the owner's signed activation, for root to verify against its pins.
		var m string
		var assertion []byte
		if err = db.QueryRow(`SELECT manifest, canonical, assertion FROM seal_active WHERE singleton=1 AND length(manifest)<=1048576 AND length(canonical)<=65536 AND length(assertion)<=16384`).Scan(&m, &f.Activation, &assertion); err != nil {
			return f, err
		}
		sum := sha256.Sum256([]byte(m))
		f.Manifest = hex.EncodeToString(sum[:])
		if json.Valid(assertion) {
			f.ActivationProof = assertion
		}
	}
	return f, nil
}

type setupPasskey struct {
	ID      string `json:"id"`         // passkeyID, as elsewhere in the UI
	Cred    string `json:"credential"` // credential ID, base64url
	KeyHash string `json:"key_sha256"`
	Name    string `json:"name"`
	Pinned  bool   `json:"pinned"`
	Current bool   `json:"current"`
}

type setupTask struct {
	maint.Spec
	State      string            `json:"state"` // available | blocked | idle | running | waiting | done | failed
	Blocked    string            `json:"blocked_by,omitempty"`
	Rerunnable bool              `json:"rerunnable,omitempty"`
	Last       *maint.TaskStatus `json:"last,omitempty"`
}

type setupView struct {
	Mode      string            `json:"mode"` // serve | cutover | seal-setup | bucket-migrate
	Installed bool              `json:"runner_installed"`
	Version   string            `json:"runner_version,omitempty"`
	SecretKey string            `json:"secrets_key,omitempty"`
	DeployKey string            `json:"deploy_key,omitempty"`
	Passkeys  []setupPasskey    `json:"passkeys"`
	Current   *maint.TaskStatus `json:"current,omitempty"`
	Refused   *maint.Refusal    `json:"refused,omitempty"`
	Tasks     []setupTask       `json:"tasks"`
	Updates   setupSources      `json:"update_sources"`
}

// setupSources says where releases come from. Repo, GitHubAPI and SecondAPI are the sources
// "Enable self-update" will accept (fixed at the machine; maint.EffectiveSources) and
// Origin where they were decided. Active names what this broker compares right now.
type setupSources struct {
	Repo      string `json:"repo"`
	GitHubAPI string `json:"github_api"`
	SecondAPI string `json:"second_api"` // "" = GitHub only
	Origin    string `json:"origin"`     // pinned | config | default
	// Compared lists the published sources by name: "GitHub", "second source (HOST)".
	Compared []string `json:"compared"`
	// Active is the same list for the configuration the broker is running with; empty while
	// self-update is not enabled.
	Active []string `json:"active"`
	Note   string   `json:"note,omitempty"`
}

func (s *Server) setupSources(pinned *maint.Sources) setupSources {
	u := s.cfg.Updates
	eff, origin := maint.EffectiveSources(pinned, u)
	v := setupSources{Repo: eff.Repo, GitHubAPI: eff.GitHubAPI, SecondAPI: eff.SecondAPI, Origin: origin, Active: []string{},
		Compared: release.Sources{Second: release.Source{API: eff.SecondAPI}}.Names()}
	if u.Repo != "" {
		v.Active = u.Sources().Names()
	}
	switch {
	case u.SecondIgnored():
		v.Note = "The configuration names a token for a second release source but not its address, so no second source is used: releases are compared with GitHub only. To use one, add api = \"https://HOST/api/v1/repos/OWNER/NAME\" under [updates.second] in the configuration and restart the broker."
		if eff.SecondAPI != "" {
			// The pin made at the machine still names it: the task writes it back.
			v.Note += " Running “Enable self-update” again does the same: the sources fixed for it include a second source."
		}
	case u.Repo != "" && !u.Sources().HasSecond() && eff.SecondAPI == "":
		v.Note = "No second release source is configured: releases are compared with GitHub and this machine's own rebuild."
	case u.Repo != "" && (u.Second.API != eff.SecondAPI || u.Repo != eff.Repo):
		v.Note = "The sources fixed for this task differ from the ones the broker is using now; running the task applies them."
	}
	return v
}

func (s *Server) setupRoutes(m *http.ServeMux) {
	m.Handle("GET /api/ui/setup", s.requireSession(s.setupStatus))
	m.Handle("GET /api/ui/setup/cutover/preview", s.requireSession(s.setupCutoverPreview))
	m.Handle("POST /api/ui/setup/cancel", s.requireSession(s.setupCancel))
	m.Handle("POST /api/ui/setup/host-key", s.requireSession(s.setupHostKey))
	m.Handle("POST /api/ui/setup/{id}/challenge", s.requireSession(s.setupChallenge))
	m.Handle("POST /api/ui/setup/{id}/run", s.requireSession(s.setupRun))
}

func (s *Server) runnerStatus() (maint.Status, bool) {
	path := maint.StatusPath(s.cfg.Updates.Cache())
	if _, err := os.Stat(path); err != nil {
		return maint.Status{Tasks: map[string]*maint.TaskStatus{}}, false
	}
	st := maint.ReadStatus(path)
	return st, st.Runner.SecretsKey != ""
}

func (s *Server) updatesReady() bool {
	if s.cfg.Updates.Repo == "" {
		return false
	}
	var m release.Metadata
	b, err := os.ReadFile(filepath.Join(s.cfg.Updates.Cache(), "latest.json"))
	return err == nil && json.Unmarshal(b, &m) == nil && m.Valid()
}

func (s *Server) setupView(ctx context.Context, sess string) (setupView, error) {
	st, installed := s.runnerStatus()
	v := setupView{Mode: "serve", Installed: installed, Version: st.Runner.Version, SecretKey: st.Runner.SecretsKey, DeployKey: st.Runner.DeployKey,
		Current: st.Current, Refused: st.Refused, Passkeys: []setupPasskey{}, Updates: s.setupSources(st.Runner.Sources)}
	if s.maintenance {
		v.Mode = "cutover"
	} else if s.bucketMigrate {
		v.Mode = "bucket-migrate"
	} else if s.sealSetup {
		v.Mode = "seal-setup"
	}
	q := s.store.Q()
	keys, err := loadPasskeys(ctx, q)
	if err != nil {
		return v, err
	}
	login, _ := q.SessionPasskeyID(ctx, sess)
	unpinned := 0
	for _, k := range keys {
		sum := sha256.Sum256(k.cred.PublicKey)
		cred := base64.RawURLEncoding.EncodeToString(k.CredentialID)
		p := setupPasskey{ID: k.id, Cred: cred, KeyHash: hex.EncodeToString(sum[:]), Name: k.Name, Pinned: slices.Contains(st.Runner.Pins, cred), Current: k.ID == login}
		if !p.Pinned {
			unpinned++
		}
		v.Passkeys = append(v.Passkeys, p)
	}
	scoped := q.Scoped()
	sealed := s.seal != nil && !s.sealSetup || s.bucketMigrate
	migration := s.seal != nil && s.seal.mode == modeMigration
	s.updates.RLock()
	candidate := s.updates.view.Error == "" && s.updates.view.Candidate.Valid()
	s.updates.RUnlock()
	for _, spec := range maint.Specs {
		t := setupTask{Spec: spec, State: "available", Last: st.Tasks[spec.ID]}
		switch spec.ID {
		case maint.TaskCutover:
			if scoped {
				t.State = "done"
			}
		case maint.TaskSeal:
			if sealed {
				t.State = "done"
			} else if !scoped {
				t.State, t.Blocked = "blocked", "Switch to organisations first."
			}
		case maint.TaskBuckets:
			switch {
			case s.sealServing():
				t.State = "done"
			case migration || s.bucketMigrate:
			case s.seal == nil && !s.sealSetup:
				t.State, t.Blocked = "blocked", "Not needed: sealing this store creates per-credential buckets directly."
			default:
				t.State, t.Blocked = "blocked", "Only a store sealed by aqmas 0.4.1 needs this."
			}
		case maint.TaskUpdates:
			t.Rerunnable = true
			if s.updatesReady() {
				t.State = "done"
			}
		case maint.TaskPins:
			t.Rerunnable = true
			if unpinned == 0 && len(st.Runner.Pins) == len(keys) {
				t.State = "done"
			}
		case maint.TaskUpgrade:
			if !s.updatesReady() {
				t.State, t.Blocked = "blocked", "Enable self-update first."
			} else if !candidate {
				t.State = "idle"
			}
		case maint.TaskBastionAccess:
			t.Rerunnable = true
			if s.cfg.Bastion.Enabled() {
				t.State = "done"
			}
		case maint.TaskBastionRemove, maint.TaskBastionAllow:
			t.Rerunnable = true
			if !s.cfg.Bastion.Enabled() {
				t.State, t.Blocked, t.Rerunnable = "blocked", "Access to the bastion is not installed.", false
			}
		case maint.TaskOSUpdate, maint.TaskReboot, maint.TaskRestartTunnel, maint.TaskRestartBroker, maint.TaskDiskUsage, maint.TaskJournalVacuum:
			t.Rerunnable = true
		}
		if t.State == "available" && t.Last != nil && t.Last.State == "failed" {
			t.State = "failed"
		}
		if t.State == "available" || t.State == "failed" || t.State == "done" && t.Rerunnable {
			switch {
			case !installed:
				t.State, t.Blocked = "blocked", "The maintenance runner is not installed on this machine yet."
			case v.Mode != "serve" || st.Current != nil:
				if t.State != "done" {
					t.State, t.Blocked = "blocked", "Another task is in progress."
				}
			}
		}
		if st.Current != nil && st.Current.Task == spec.ID {
			t.State, t.Blocked, t.Last = st.Current.State, "", st.Current
		}
		v.Tasks = append(v.Tasks, t)
	}
	return v, nil
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request, sess string) {
	v, err := s.setupView(r.Context(), sess)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

// setupCutoverPreview shows the plan the cutover would propose now, from a consistent
// snapshot. The plan that is finally signed is built again inside the fenced review.
func (s *Server) setupCutoverPreview(w http.ResponseWriter, r *http.Request, _ string) {
	if s.maintenance || s.sealSetup || s.store.Q().Scoped() {
		s.writeErr(w, r, errConflict("no cutover to preview"))
		return
	}
	ctx := r.Context()
	path, _, err := organisations.RecoveryPoint(ctx, s.store.DB(), s.cfg.DataDir)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	defer os.RemoveAll(filepath.Dir(path))
	p, err := organisations.InspectBackup(ctx, path, s.cfg, s.sshPin(), s.pki.CAPin(), s.now())
	if err != nil {
		s.writeErr(w, r, errConflict("the cutover plan cannot be built: "+err.Error()))
		return
	}
	b, err := json.Marshal(p)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"id": p.Organisation.ID, "plan": string(b)})
}

// setupCancel asks a waiting task to give up. It is deliberately unsigned: cancelling only
// ever returns to the state before the task, and the runner ignores it at any other time.
func (s *Server) setupCancel(w http.ResponseWriter, r *http.Request, _ string) {
	st, ok := s.runnerStatus()
	if !ok || st.Current == nil || st.Current.State != "waiting" {
		s.writeErr(w, r, errConflict("no task is waiting"))
		return
	}
	f, err := os.OpenFile(maint.CancelPath(s.cfg.Updates.Spool()), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	f.Close()
	_ = s.store.Q().Audit(r.Context(), s.now(), "owner", "setup_cancel", "setup:"+st.Current.Task, "")
	writeJSON(w, 200, api.OK{OK: true})
}

// setupHostKey fetches the forge's SSH host keys for the owner to compare and sign. The
// lines only take effect as part of the signed enable-updates parameters.
func (s *Server) setupHostKey(w http.ResponseWriter, r *http.Request, _ string) {
	var in struct {
		Repo string `json:"repo"`
	}
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	host := maint.KnownHost(in.Repo)
	if host == "" {
		s.writeErr(w, r, errBad("repo must look like ssh://git@forge.example.com/owner/name.git"))
		return
	}
	name, port := host, "22"
	if strings.HasPrefix(host, "[") {
		name, port, _ = strings.Cut(strings.TrimPrefix(host, "["), "]:")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-keyscan", "-T", "8", "-t", "ed25519,ecdsa,rsa", "-p", port, "--", name)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/nonexistent"}
	out, err := cmd.Output()
	if err != nil || len(out) > 16<<10 {
		s.writeErr(w, r, errConflict("could not reach the forge's SSH port from the broker"))
		return
	}
	type key struct {
		Line        string `json:"line"`
		Fingerprint string `json:"fingerprint"`
	}
	keys := []key{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Keep only lines the signed parameters would accept.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := maint.UpdatesParams{Repo: in.Repo, GitHubAPI: "https://x/x", KnownHosts: []string{line}}
		if _, err := maint.Canonical(maint.TaskUpdates, p); err != nil {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.Fields(line)[2])
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		keys = append(keys, key{line, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])})
	}
	slices.SortFunc(keys, func(a, b key) int { return strings.Compare(a.Line, b.Line) })
	if len(keys) == 0 || len(keys) > 4 {
		s.writeErr(w, r, errConflict("the forge returned no usable host key"))
		return
	}
	writeJSON(w, 200, map[string]any{"host": host, "keys": keys})
}

type setupChallengeRequest struct {
	Params      json.RawMessage `json:"params"`
	SecretsHash string          `json:"secrets_sha256"`
}

// setupParams decodes the browser's parameters into the task's typed schema and returns
// their canonical text. Anything outside the schema is refused here and again by the runner.
func (s *Server) setupParams(ctx context.Context, task string, raw json.RawMessage) (string, any, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	strict := func(dst any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(dst); err != nil || d.More() {
			return errBad("invalid task parameters")
		}
		return nil
	}
	var v any
	var err error
	switch task {
	case maint.TaskCutover:
		var p maint.CutoverParams
		err, v = strict(&p), p
	case maint.TaskSeal:
		var p maint.SealParams
		err, v = strict(&p), p
	case maint.TaskBuckets:
		var p maint.BucketsParams
		err, v = strict(&p), p
	case maint.TaskUpdates:
		var p maint.UpdatesParams
		err = strict(&p)
		slices.Sort(p.KnownHosts)
		if p.KnownHosts == nil {
			p.KnownHosts = []string{}
		}
		// Say so now if the runner would refuse these sources (it decides; this is courtesy).
		st, _ := s.runnerStatus()
		if want, _ := maint.EffectiveSources(st.Runner.Sources, s.cfg.Updates); err == nil && (p.Repo != want.Repo || p.GitHubAPI != want.GitHubAPI || p.SecondAPI != want.SecondAPI) {
			return "", nil, errConflict("the release sources are fixed on this machine; to change them edit the [updates] table of its configuration or run `sudo aqmasd maint-init --repo … [--second-api …]` there")
		}
		v = p
	case maint.TaskPins:
		var p maint.PinsParams
		if err = strict(&p); err == nil {
			keys, e := loadPasskeys(ctx, s.store.Q())
			if e != nil {
				return "", nil, e
			}
			for _, pin := range p.Pins {
				ok := false
				for _, k := range keys {
					sum := sha256.Sum256(k.cred.PublicKey)
					ok = ok || base64.RawURLEncoding.EncodeToString(k.CredentialID) == pin.ID && hex.EncodeToString(sum[:]) == pin.KeyHash
				}
				if !ok {
					return "", nil, errConflict("a listed passkey is not registered")
				}
			}
		}
		v = p
	default:
		// The bastion and routine tasks: typed, strict, validated by Canonical below.
		if v, err = maint.Decode(task, raw); err != nil {
			if _, known := maint.Lookup(task); !known {
				return "", nil, errNotFound()
			}
			return "", nil, errBad(err.Error())
		}
	}
	if err != nil {
		return "", nil, err
	}
	text, err := maint.Canonical(task, v)
	if err != nil {
		return "", nil, errBad(err.Error())
	}
	return text, v, nil
}

func (s *Server) setupRunnable(ctx context.Context, sess, task string) error {
	v, err := s.setupView(ctx, sess)
	if err != nil {
		return err
	}
	for _, t := range v.Tasks {
		if t.ID != task {
			continue
		}
		if t.State == "available" || t.State == "failed" || t.State == "done" && t.Rerunnable && v.Current == nil && v.Mode == "serve" && v.Installed {
			return nil
		}
		if t.Blocked != "" {
			return errConflict(t.Blocked)
		}
		return errConflict("this task cannot run now (" + t.State + ")")
	}
	return errNotFound()
}

func (s *Server) setupChallenge(w http.ResponseWriter, r *http.Request, sess string) {
	ctx := r.Context()
	task := r.PathValue("id")
	if task == maint.TaskUpgrade {
		s.writeErr(w, r, errBad("approve upgrades through /api/ui/updates"))
		return
	}
	var in setupChallengeRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := s.setupRunnable(ctx, sess, task); err != nil {
		s.writeErr(w, r, err)
		return
	}
	params, typed, err := s.setupParams(ctx, task, in.Params)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if (len(maint.SecretNames(task, typed)) != 0) != (in.SecretsHash != "") {
		s.writeErr(w, r, errBad("secrets do not match the chosen options"))
		return
	}
	a := canon.Action{Object: canon.ObjectSetup, Action: canon.ActionRun, ID: task, Params: params, SecretsHash: in.SecretsHash}
	now := s.now()
	text, err := canon.Build(a, canon.NewNonce(), now)
	if err != nil {
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	o, err := s.loadOwner(ctx)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	opts, err := s.requestOptions(o, canon.Challenge(text))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	c := &store.Challenge{ID: ids.New(), Purpose: "action", ObjectType: canon.ObjectSetup, ObjectID: task, Canonical: text,
		SessionHash: sess, CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL)}
	if err := s.store.Q().InsertChallenge(ctx, c); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, api.ChallengeResponse{ChallengeID: c.ID, Canonical: text, PublicKey: opts})
}

type setupRunRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"`
	Secrets     string          `json:"secrets"`
	// Request names the agent's queued maintenance request this run answers ("" when the
	// owner started the task from the page).
	Request string `json:"request,omitempty"`
}

func (s *Server) setupRun(w http.ResponseWriter, r *http.Request, sess string) {
	ctx := r.Context()
	task := r.PathValue("id")
	var in setupRunRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	sg, pkID, settle, err := s.verifyAction(ctx, sess, canon.ObjectSetup, task, in.ChallengeID, in.Assertion, nil)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	settle(false)
	if err = s.setupRunnable(ctx, sess, task); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if hash, err := maint.PacketHash(in.Secrets); err != nil || hash != sg.SecretsHash {
		s.writeErr(w, r, errBad("secrets do not match the signed request"))
		return
	}
	text, err := canon.Build(sg.Action, sg.Nonce, sg.IssuedAt)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var answered []func(*store.Q) error
	if in.Request != "" {
		digest := hex.EncodeToString(canon.Challenge(text))[:16]
		answered = append(answered, func(q *store.Q) error {
			return approveSetupRequest(ctx, q, in.Request, task, sg.Params, digest, s.now())
		})
	}
	if err = s.spool(r, sess, pkID, "setup_run", "setup:"+task, maint.Request{Canonical: text, Assertion: in.Assertion, Secrets: in.Secrets}, answered...); err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	title, _ := maint.Lookup(task)
	s.notify.Send("aqmas: setup task approved", title.Title, s.cfg.PublicBaseURL)
	writeJSON(w, 200, api.OK{OK: true})
}

// pinnedFor reports whether the signing passkey is one the root runner will accept, so the
// owner hears about an unpinned key here instead of from a silent refusal.
func (s *Server) pinnedFor(ctx context.Context, pkID int64) error {
	st, ok := s.runnerStatus()
	if !ok {
		return errConflict("the maintenance runner is not installed on this machine yet")
	}
	keys, err := loadPasskeys(ctx, s.store.Q())
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.ID == pkID && slices.Contains(st.Runner.Pins, base64.RawURLEncoding.EncodeToString(k.CredentialID)) {
			return nil
		}
	}
	return errConflict("this passkey is not pinned for maintenance: sign with a pinned passkey, then run “Sync maintenance passkeys”")
}

// spool hands one signed request to the root runner. The audit row and the request appear
// together or not at all; only the canonical text is audited (secrets stay sealed).
func (s *Server) spool(r *http.Request, sess string, pkID int64, action, object string, req maint.Request, also ...func(*store.Q) error) error {
	ctx := r.Context()
	if err := s.pinnedFor(ctx, pkID); err != nil {
		return err
	}
	dir := s.cfg.Updates.Spool()
	target := maint.RequestPath(dir)
	if st, err := os.Lstat(target); err == nil && s.now().Sub(st.ModTime()) > 2*maint.MaxAge {
		_ = os.Remove(target) // an expired request nobody picked up
	}
	f, err := os.CreateTemp(dir, ".approval-")
	if err != nil {
		return errConflict("the maintenance spool is not writable; is the runner installed?")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = json.NewEncoder(f).Encode(req); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(q *store.Q) error {
		if s.seal != nil {
			if err := s.sealOwner(ctx, q, sess, pkID); err != nil {
				return err
			}
		}
		if err := q.Audit(ctx, s.now(), "owner", action, object, fmt.Sprintf("passkey=%d %s", pkID, req.Canonical)); err != nil {
			return err
		}
		for _, fn := range also {
			if err := fn(q); err != nil {
				return err
			}
		}
		if err := os.Link(f.Name(), target); err != nil {
			return errConflict("another maintenance request is already queued")
		}
		return nil
	})
}
