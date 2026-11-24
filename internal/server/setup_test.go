package server

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
)

// installRunner writes the status a real `aqmasd maint-init` would publish, pinning every
// registered passkey, and returns those pins and the runner's secrets key.
func (e *env) installRunner() ([]maint.KeyPin, string) {
	e.t.Helper()
	if e.cfg.Updates.CacheDir == "" {
		e.cfg.Updates.CacheDir, e.cfg.Updates.SpoolDir = e.t.TempDir(), e.t.TempDir()
	}
	keys, err := loadPasskeys(e.t.Context(), e.s.store.Q())
	if err != nil {
		e.t.Fatal(err)
	}
	k, err := maint.NewKey()
	if err != nil {
		e.t.Fatal(err)
	}
	st := maint.Status{Tasks: map[string]*maint.TaskStatus{}}
	st.Runner.SecretsKey = maint.PublicKey(k)
	st.Runner.Sources = e.sources
	var pins []maint.KeyPin
	for _, p := range keys {
		pins = append(pins, maint.KeyPin{ID: p.CredentialID, PublicKey: p.cred.PublicKey})
		st.Runner.Pins = append(st.Runner.Pins, base64.RawURLEncoding.EncodeToString(p.CredentialID))
	}
	b, _ := json.Marshal(st)
	if err = os.WriteFile(maint.StatusPath(e.cfg.Updates.Cache()), b, 0644); err != nil {
		e.t.Fatal(err)
	}
	priv, _ := k.Bytes()
	return pins, string(priv)
}

type setupOut struct {
	Installed bool `json:"runner_installed"`
	Tasks     []struct {
		ID, State string
		Blocked   string `json:"blocked_by"`
	}
	Passkeys []struct {
		Credential string
		KeyHash    string `json:"key_sha256"`
		Pinned     bool
	}
	SecretsKey string `json:"secrets_key"`
}

func (o setupOut) state(id string) string {
	for _, t := range o.Tasks {
		if t.ID == id {
			return t.State + ":" + t.Blocked
		}
	}
	return ""
}

func TestSetupQueue(t *testing.T) {
	e := newEnv(t)
	mustStatus(t, "private", e.webDo("GET", "/api/ui/setup", nil, nil), 401)
	e.setupOwner()
	var v setupOut
	mustStatus(t, "view", e.webDo("GET", "/api/ui/setup", nil, &v), 200)
	if v.Installed || !strings.HasPrefix(v.state("cutover"), "blocked:The maintenance runner") {
		t.Fatalf("without a runner every task is blocked: %+v", v)
	}
	mustStatus(t, "no runner", e.webDo("POST", "/api/ui/setup/cutover/challenge", map[string]any{}, nil), 409)

	pins, _ := e.installRunner()
	v = setupOut{}
	mustStatus(t, "view", e.webDo("GET", "/api/ui/setup", nil, &v), 200)
	if !v.Installed || v.state("cutover") != "available:" || v.state("seal") != "blocked:Switch to organisations first." || v.state("enable-updates") != "available:" ||
		v.state("upgrade") != "blocked:Enable self-update first." || v.state("sync-passkeys") != "done:" || !v.Passkeys[0].Pinned {
		t.Fatalf("unexpected queue: %+v", v)
	}
	var plan struct{ ID, Plan string }
	mustStatus(t, "preview", e.webDo("GET", "/api/ui/setup/cutover/preview", nil, &plan), 200)
	if plan.ID == "" || !strings.Contains(plan.Plan, `"slug":"personal"`) {
		t.Fatal("no plan preview")
	}
	if left, _ := filepath.Glob(filepath.Join(e.cfg.DataDir, "pre-organisations-*")); len(left) != 0 {
		t.Fatal("preview left its snapshot behind")
	}

	// Refusals before anything is signed.
	for name, c := range map[string]struct {
		path string
		body any
		want int
	}{
		"unknown task":      {"nope", map[string]any{}, 404},
		"upgrade elsewhere": {"upgrade", map[string]any{}, 400},
		"prerequisite":      {"seal", map[string]any{"params": map[string]any{"recipient": "age1" + strings.Repeat("q", 58)}}, 409},
		"unknown key":       {"cutover", map[string]any{"params": map[string]any{"command": "id"}}, 400},
		"stray secrets":     {"cutover", map[string]any{"secrets_sha256": strings.Repeat("a", 64)}, 400},
		"unpinned sources":  {"enable-updates", map[string]any{"params": map[string]any{"repo": "ssh://git@forge.example.com/a/b.git", "github_api": "https://api.github.com/repos/a/b", "second_api": "https://forge.example.com/api/v1/repos/a/b", "known_hosts": []string{"forge.example.com ssh-ed25519 " + strings.Repeat("A", 68)}}}, 409},
		"bad repo":          {"enable-updates", map[string]any{"params": map[string]any{"repo": "ssh://git@forge.example.com/x.git; id", "github_api": "https://api.github.com/repos/a/b", "second_api": "https://forge.example.com/api/v1/repos/a/b", "known_hosts": []string{"forge.example.com ssh-ed25519 " + strings.Repeat("A", 68)}}}, 409},
		"missing secrets":   {"enable-updates", map[string]any{"params": map[string]any{"repo": "ssh://git@forge.example.com/a/b.git", "github_api": "https://api.github.com/repos/a/b", "second_api": "https://forge.example.com/api/v1/repos/a/b", "known_hosts": []string{"forge.example.com ssh-ed25519 " + strings.Repeat("A", 68)}, "github_token": true}}, 409},
		"foreign pin":       {"sync-passkeys", map[string]any{"params": map[string]any{"pins": []map[string]string{{"id": strings.Repeat("A", 22), "key_sha256": strings.Repeat("a", 64)}}}}, 409},
	} {
		mustStatus(t, name, e.webDo("POST", "/api/ui/setup/"+c.path+"/challenge", c.body, nil), c.want)
	}

	// A signed request reaches the spool exactly as the root runner will verify it.
	var cr challengeResp
	mustStatus(t, "challenge", e.webDo("POST", "/api/ui/setup/cutover/challenge", map[string]any{}, &cr), 200)
	sg, err := canon.Parse(cr.Canonical)
	if err != nil || sg.Object != "setup" || sg.Action.Action != "run" || sg.ID != "cutover" || sg.Params != "{}" || sg.SecretsHash != "" {
		t.Fatalf("canonical %s: %v", cr.Canonical, err)
	}
	as, err := e.auth.AssertOptions(cr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	run := map[string]any{"challenge_id": cr.ChallengeID, "assertion": as}
	mustStatus(t, "wrong task", e.webDo("POST", "/api/ui/setup/seal/run", run, nil), 400)
	mustStatus(t, "challenge", e.webDo("POST", "/api/ui/setup/cutover/challenge", map[string]any{}, &cr), 200)
	as, _ = e.auth.AssertOptions(cr.PublicKey)
	run = map[string]any{"challenge_id": cr.ChallengeID, "assertion": as}
	mustStatus(t, "queued", e.webDo("POST", "/api/ui/setup/cutover/run", run, nil), 200)
	mustStatus(t, "single use", e.webDo("POST", "/api/ui/setup/cutover/run", run, nil), 409)
	b, err := os.ReadFile(maint.RequestPath(e.cfg.Updates.Spool()))
	if err != nil {
		t.Fatal(err)
	}
	var req maint.Request
	if json.Unmarshal(b, &req) != nil || req.Canonical != cr.Canonical {
		t.Fatal("spool does not carry the signed text")
	}
	got, err := maint.Verify(req, e.cfg.PublicBaseURL, pins, e.clock.Now())
	if err != nil || got.Task != maint.TaskCutover {
		t.Fatalf("runner would refuse the queued request: %v", err)
	}
	// A second request cannot overwrite a queued one.
	mustStatus(t, "challenge", e.webDo("POST", "/api/ui/setup/cutover/challenge", map[string]any{}, &cr), 200)
	as, _ = e.auth.AssertOptions(cr.PublicKey)
	mustStatus(t, "busy spool", e.webDo("POST", "/api/ui/setup/cutover/run", map[string]any{"challenge_id": cr.ChallengeID, "assertion": as}, nil), 409)
	mustStatus(t, "nothing waiting", e.webDo("POST", "/api/ui/setup/cancel", map[string]any{}, nil), 409)
}

// Pasted secrets cross the broker only as a sealed packet bound by the signed text.
func TestSetupSecretsStaySealed(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	e.sources = &maint.Sources{Repo: "ssh://git@forge.example.com:2222/example/agent-quartermaster.git", SecondAPI: "https://forge.example.com/api/v1/repos/example/agent-quartermaster", GitHubAPI: "https://api.github.com/repos/example/agent-quartermaster"}
	pins, priv := e.installRunner()
	var v setupOut
	mustStatus(t, "view", e.webDo("GET", "/api/ui/setup", nil, &v), 200)
	const sentinel = "ghp_SENTINELsecretTOKEN0123456789"
	params := maint.UpdatesParams{Repo: "ssh://git@forge.example.com:2222/example/agent-quartermaster.git", SecondAPI: "https://forge.example.com/api/v1/repos/example/agent-quartermaster",
		GitHubAPI: "https://api.github.com/repos/example/agent-quartermaster", KnownHosts: []string{"[forge.example.com]:2222 ssh-ed25519 " + strings.Repeat("A", 68)}, GitHubToken: true}
	packet, err := maint.SealPacket(v.SecretsKey, maint.SecretsInfo(maint.TaskUpdates), []byte(`{"github_token":"`+sentinel+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := maint.PacketHash(packet)
	var cr challengeResp
	mustStatus(t, "challenge", e.webDo("POST", "/api/ui/setup/enable-updates/challenge", map[string]any{"params": params, "secrets_sha256": hash}, &cr), 200)
	as, _ := e.auth.AssertOptions(cr.PublicKey)
	other, _ := maint.SealPacket(v.SecretsKey, maint.SecretsInfo(maint.TaskUpdates), []byte(`{"github_token":"another-token-value"}`))
	mustStatus(t, "swapped secrets", e.webDo("POST", "/api/ui/setup/enable-updates/run", map[string]any{"challenge_id": cr.ChallengeID, "assertion": as, "secrets": other}, nil), 400)
	mustStatus(t, "challenge", e.webDo("POST", "/api/ui/setup/enable-updates/challenge", map[string]any{"params": params, "secrets_sha256": hash}, &cr), 200)
	as, _ = e.auth.AssertOptions(cr.PublicKey)
	mustStatus(t, "queued", e.webDo("POST", "/api/ui/setup/enable-updates/run", map[string]any{"challenge_id": cr.ChallengeID, "assertion": as, "secrets": packet}, nil), 200)

	spool, _ := os.ReadFile(maint.RequestPath(e.cfg.Updates.Spool()))
	var audit string
	rows, err := e.s.store.DB().Query(`SELECT detail FROM audit`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		_ = rows.Scan(&d)
		audit += d + "\n"
	}
	if strings.Contains(string(spool), sentinel) || strings.Contains(audit, sentinel) || !strings.Contains(audit, hash) {
		t.Fatal("secret left its packet, or the audit does not bind it")
	}
	var req maint.Request
	_ = json.Unmarshal(spool, &req)
	got, err := maint.Verify(req, e.cfg.PublicBaseURL, pins, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	k, _ := maint.LoadKey([]byte(priv))
	secrets, err := maint.OpenSecrets(k, got.Task, got.Params, req.Secrets)
	if err != nil || secrets["github_token"] != sentinel {
		t.Fatalf("runner cannot open the packet: %v", err)
	}
}

// An unpinned passkey hears about it at once, for setup tasks and upgrades alike.
func TestSetupNeedsPinnedPasskey(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	e.installRunner()
	st := maint.ReadStatus(maint.StatusPath(e.cfg.Updates.Cache()))
	st.Runner.Pins = []string{"c29tZW9uZS1lbHNl"}
	b, _ := json.Marshal(st)
	_ = os.WriteFile(maint.StatusPath(e.cfg.Updates.Cache()), b, 0644)
	var cr challengeResp
	mustStatus(t, "challenge", e.webDo("POST", "/api/ui/setup/cutover/challenge", map[string]any{}, &cr), 200)
	as, _ := e.auth.AssertOptions(cr.PublicKey)
	mustStatus(t, "unpinned", e.webDo("POST", "/api/ui/setup/cutover/run", map[string]any{"challenge_id": cr.ChallengeID, "assertion": as}, nil), 409)
	if _, err := os.Stat(maint.RequestPath(e.cfg.Updates.Spool())); err == nil {
		t.Fatal("an unpinned approval reached the spool")
	}
}

// The upgrade task only reads "idle" (shown as "Up to date") after a check that succeeded and
// found nothing newer. A failed check, or none yet, says so instead.
func TestSetupUpgradeCheckFailed(t *testing.T) {
	e := newEnv(t)
	e.cfg.Updates.Repo = "https://forge.example.com/example/aqmas.git"
	e.cfg.Updates.SpoolDir, e.cfg.Updates.CacheDir = t.TempDir(), t.TempDir()
	e.setupOwner()
	e.installRunner()
	sums := release.Sums{}
	for _, a := range release.Assets {
		sums[a] = strings.Repeat("a", 64)
	}
	b, err := json.Marshal(release.Metadata{Version: "1.0.0", Commit: strings.Repeat("1", 40), GitHub: sums})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.cfg.Updates.Cache(), "latest.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if !e.s.updatesReady() {
		t.Fatal("fixture: self-update should read as enabled")
	}
	state := func(v updateView) string {
		e.s.updates.Lock()
		e.s.updates.view = v
		e.s.updates.Unlock()
		var out setupOut
		mustStatus(t, "view", e.webDo("GET", "/api/ui/setup", nil, &out), 200)
		return out.state("upgrade")
	}
	if got := state(updateView{}); !strings.HasPrefix(got, "blocked:The first check") {
		t.Fatalf("before the first check: %q", got)
	}
	got := state(updateView{checked: true, Error: "git fetch failed"})
	if !strings.HasPrefix(got, "blocked:The check for a new release failed: git fetch failed") {
		t.Fatalf("after a failed check: %q", got)
	}
	// In a setup or maintenance mode the poller is not running: say that, not "not finished yet".
	e.s.maintenance = true
	if got := state(updateView{}); !strings.Contains(got, "Releases are not checked while the broker is in a setup or maintenance mode") {
		t.Fatalf("no poller: %q", got)
	}
	e.s.maintenance = false
	if got := state(updateView{checked: true}); got != "idle:" {
		t.Fatalf("after a clean check with nothing newer: %q", got)
	}
}
