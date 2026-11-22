package maint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
)

const origin = "https://approvals.example.com"

// Secrets that must never appear in anything the runner publishes or journals.
const (
	secretTopic = "https://ntfy.example.com/SENTINELtopic0123456789"
	secretToken = "tk_SENTINELpublishTOKEN0123456789"
	secretForge = "fj_SENTINELforgejoTOKEN0123456789"
	secretHub   = "ghp_SENTINELgithubTOKEN0123456789"
	legacyTopic = "https://ntfy.example.com/SENTINELlegacyAPPROVALS"
)

// lab is a whole bastion under a temp dir: a stand-in broker (health endpoint, facts file,
// start/stop hook) and the real runner in its test layout.
type lab struct {
	t      *testing.T
	dir    string
	l      Layout
	auth   *vauth.Authenticator
	facts  Facts
	health *httptest.Server
	forge  *httptest.Server
	sums   release.Sums
}

func cose(a *vauth.Authenticator) []byte {
	x, y := a.Key.X.FillBytes(make([]byte, 32)), a.Key.Y.FillBytes(make([]byte, 32))
	b, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		panic(err)
	}
	return b
}

func newAuth() *vauth.Authenticator {
	a := vauth.New(origin)
	u, _ := url.Parse(origin)
	a.RPID = u.Hostname()
	return a
}

func (b *lab) path(p ...string) string { return filepath.Join(append([]string{b.dir}, p...)...) }

func (b *lab) write(mode os.FileMode, content string, p ...string) {
	b.t.Helper()
	if err := os.MkdirAll(filepath.Dir(b.path(p...)), 0700); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(b.path(p...), []byte(content), mode); err != nil {
		b.t.Fatal(err)
	}
}

func (b *lab) read(p ...string) string {
	x, _ := os.ReadFile(b.path(p...))
	return string(x)
}

func (b *lab) setFacts(schema int, manifest string) {
	b.facts.Schema, b.facts.Manifest = schema, manifest
	x, _ := json.Marshal(b.facts)
	b.write(0600, string(x), "facts.json.tmp")
	if err := os.Rename(b.path("facts.json.tmp"), b.path("facts.json")); err != nil {
		b.t.Fatal(err)
	}
}

func newLab(t *testing.T) *lab {
	t.Helper()
	b := &lab{t: t, dir: t.TempDir(), auth: newAuth()}
	b.health = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(b.path("unhealthy")); err == nil {
			http.Error(w, "no", 503)
			return
		}
		io.WriteString(w, "ok\n")
	}))
	t.Cleanup(b.health.Close)
	// The stand-in broker binary prints the facts file; the hook plays systemd.
	b.write(0755, "#!/bin/sh\ncat '"+b.path("facts.json")+"'\n", "aqmasd")
	b.write(0755, `#!/bin/sh
d='`+b.dir+`'
echo "$*" >> "$d/hook.log"
case $1 in
stop) rm -f "$d/active" ;;
start) [ -e "$d/refuse-once-$2" ] && { rm "$d/refuse-once-$2"; exit 1; }
  [ -e "$d/refuse-migrated" ] && grep -q MIGRATED "$d/data/aqmas.db" && exit 1
  echo "$2" > "$d/active" ;;
active) [ -e "$d/active" ] ;;
upgrade) [ -e "$d/upgrade-fails" ] && { echo 'Update refused or build failed; see the journal.' > "$CACHE/status"; exit 1; }
  cp "$2" "$d/installed-metadata.json"; echo "Installed and health-checked." > "$CACHE/status" ;;
esac
`, "hook")
	var err error
	if b.l, err = TestLayout(b.dir, b.path("aqmasd"), b.path("hook")); err != nil {
		t.Fatal(err)
	}
	b.facts.Version, b.facts.Commit = "0.3.0", strings.Repeat("c", 40)
	b.facts.Passkeys = append(b.facts.Passkeys, struct {
		ID        []byte `json:"id"`
		PublicKey []byte `json:"publicKey"`
	}{b.auth.CredID, cose(b.auth)})
	b.setFacts(5, "")
	for _, d := range []string{"etc", "systemd/aqmasd.service.d", "data/ca"} {
		if err := os.MkdirAll(b.path(d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	b.write(0600, "PRIVATE SSH CA", "data", "ca", "ssh_user_ca")
	b.write(0600, "PRIVATE CLIENT CA", "data", "ca", "client_ca.key")
	b.write(0644, "public", "data", "ca", "ssh_user_ca.pub")
	b.write(0600, "db", "data", "aqmas.db")
	b.write(0600, "cf parent", "etc", "cf-proxy-token")
	b.write(0600, "cf minter", "etc", "cf-minter-token")
	b.write(0644, "[Service]\nExecStart=/usr/local/bin/aqmasd serve\n", "systemd", "aqmasd.service")
	b.write(0644, "[Service]\nLoadCredential=cf-proxy-token:"+b.path("etc", "cf-proxy-token")+"\nLoadCredential=other:/etc/other\n", "systemd", "aqmasd.service.d", "cloudflare.conf")
	b.write(0640, `# owner's notes stay
listen_web      = "`+strings.TrimPrefix(b.health.URL, "http://")+`"
data_dir        = "`+b.path("data")+`"
public_base_url = "`+origin+`"

[ntfy]
topic_url = "`+legacyTopic+`"   # approvals

[updates]
cache_dir = "`+b.l.Cache+`"
spool_dir = "`+b.l.Spool+`"

[cloudflare]
enabled = true
account_id = "0123456789abcdef0123456789abcdef"
proxy_token_credential = "cf-proxy-token"
minter_token_file = "`+b.path("etc", "cf-minter-token")+`"
protected_access_hostnames = ["id.example.com"]
traefik_origin = "https://192.0.2.50:9443"
[[cloudflare.zones]]
name = "example.com"
id = "abcdef0123456789abcdef0123456789"

[[targets]]
name = "db-1"
address = "192.0.2.61"
port = 22
users = ["alice"]
`, "etc", "config.toml")
	b.write(0600, "active", "active")
	_ = os.WriteFile(b.path("active"), []byte("serve\n"), 0600)
	if err := Init(context.Background(), b.l, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	return b
}

func (b *lab) runner() *Runner {
	b.t.Helper()
	r, err := New(b.l, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.t.Fatal(err)
	}
	return r
}

// sign builds a spool request for a setup task exactly as aqmasd would.
func (b *lab) sign(task string, params any, secrets map[string]string) Request {
	b.t.Helper()
	text, err := Canonical(task, params)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.signRaw(task, text, secrets)
}

func (b *lab) signRaw(task, params string, secrets map[string]string) Request {
	b.t.Helper()
	a := canon.Action{Object: canon.ObjectSetup, Action: canon.ActionRun, ID: task, Params: params}
	var packet string
	if secrets != nil {
		plain, _ := json.Marshal(secrets)
		st := ReadStatus(b.l.status())
		var err error
		if packet, err = SealPacket(st.Runner.SecretsKey, SecretsInfo(task), plain); err != nil {
			b.t.Fatal(err)
		}
		a.SecretsHash, _ = PacketHash(packet)
	}
	text, err := canon.Build(a, canon.NewNonce(), time.Now())
	if err != nil {
		b.t.Fatal(err)
	}
	return Request{Canonical: text, Assertion: b.auth.Assert(canon.Challenge(text)), Secrets: packet}
}

func (b *lab) queue(req Request) {
	b.t.Helper()
	x, _ := json.Marshal(req)
	if err := os.MkdirAll(b.l.Spool, 0700); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(b.l.request(), x, 0600); err != nil {
		b.t.Fatal(err)
	}
}

// when waits for the hook to start the broker in mode, then plays the owner.
func (b *lab) when(mode string, owner func()) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 400; i++ {
			if strings.TrimSpace(b.read("active")) == mode {
				owner()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return done
}

func (b *lab) last(task string) *TaskStatus {
	b.t.Helper()
	st := ReadStatus(b.l.status())
	if st.Current != nil {
		b.t.Fatalf("task still current: %+v", st.Current)
	}
	if st.Tasks[task] == nil {
		b.t.Fatalf("no status for %s (refused: %+v)", task, st.Refused)
	}
	return st.Tasks[task]
}

// noSecrets fails if a sentinel reached any file outside the places secrets belong.
func (b *lab) noSecrets(allowed ...string) {
	b.t.Helper()
	_ = filepath.WalkDir(b.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		for _, ok := range allowed {
			if strings.HasPrefix(p, b.path(ok)) {
				return nil
			}
		}
		x, _ := os.ReadFile(p)
		for _, s := range []string{"SENTINELtopic", secretToken, secretForge, secretHub} {
			if strings.Contains(string(x), s) {
				b.t.Errorf("secret %q leaked into %s", s[:12], strings.TrimPrefix(p, b.dir))
			}
		}
		return nil
	})
}

func TestCutover(t *testing.T) {
	b := newLab(t)
	b.queue(b.sign(TaskCutover, CutoverParams{}, nil))
	owner := b.when("organisations-cutover", func() { b.setFacts(6, "") })
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-owner
	s := b.last(TaskCutover)
	if s.State != "done" || strings.TrimSpace(b.read("active")) != "serve" {
		t.Fatalf("%+v", s)
	}
	if got := strings.Join(strings.Fields(strings.ReplaceAll(b.read("hook.log"), "active\n", "")), " "); got != "stop start organisations-cutover stop start serve" {
		t.Fatal("unexpected service sequence: " + got)
	}
	if _, err := os.Stat(filepath.Join(s.Result["backup"], "state", "ca", "ssh_user_ca")); err != nil {
		t.Fatal("backup is incomplete")
	}
	if _, err := os.Stat(b.l.journal()); err == nil {
		t.Fatal("journal left behind")
	}
	// The same task refuses once the prerequisite is gone, and the same approval never runs twice.
	b.queue(b.sign(TaskCutover, CutoverParams{}, nil))
	if err := b.runner().Run(context.Background()); err == nil || b.last(TaskCutover).State != "failed" {
		t.Fatal("cutover ran on an activated broker")
	}
}

func TestCutoverCancelTimeoutAndUnhealthy(t *testing.T) {
	b := newLab(t)
	b.queue(b.sign(TaskCutover, CutoverParams{}, nil))
	owner := b.when("organisations-cutover", func() { _ = os.WriteFile(b.l.cancel(), nil, 0600) })
	if err := b.runner().Run(context.Background()); err == nil {
		t.Fatal("cancelled task reported success")
	}
	<-owner
	if s := b.last(TaskCutover); s.State != "failed" || !strings.Contains(s.Message, "cancelled") || strings.TrimSpace(b.read("active")) != "serve" {
		t.Fatalf("%+v", s)
	}

	b.queue(b.sign(TaskCutover, CutoverParams{}, nil))
	r := b.runner()
	r.CutoverWait = 300 * time.Millisecond
	if err := r.Run(context.Background()); err == nil || !strings.Contains(b.last(TaskCutover).Message, "not completed in time") {
		t.Fatal("no timeout")
	}
	if strings.TrimSpace(b.read("active")) != "serve" {
		t.Fatal("broker not returned to service")
	}

	// Activated, but the broker never becomes healthy: the backup comes back.
	b.queue(b.sign(TaskCutover, CutoverParams{}, nil))
	b.write(0600, "", "refuse-migrated")
	owner = b.when("organisations-cutover", func() {
		b.write(0600, "MIGRATED", "data", "aqmas.db")
		b.setFacts(6, "")
	})
	err := b.runner().Run(context.Background())
	<-owner
	if s := b.last(TaskCutover); err == nil || !strings.Contains(s.Message, "backup was restored") || b.read("data", "aqmas.db") != "db" {
		t.Fatalf("no automatic rollback: %+v", s)
	}
}

func sealParams() SealParams {
	return SealParams{Recipient: "age1" + strings.Repeat("q", 58), PurgeBackups: true, LockAlert: true}
}

func (b *lab) activateSeal(manifest string) func() {
	return func() {
		b.write(0600, `{"inventory":true}`, "data", "seal-stage-1", "inventory.json")
		b.write(0600, `{"manifest":true}`, "data", "seal-stage-1", "manifest.json")
		b.write(0600, "proof", "data", "seal-stage-1", "recovery.proof")
		b.setFacts(8, manifest)
		_ = os.Remove(b.path("active")) // the import process exits after activation
	}
}

func TestSeal(t *testing.T) {
	b := newLab(t)
	b.setFacts(7, "")
	manifest := strings.Repeat("ab", 32)
	if err := os.MkdirAll(filepath.Join(b.l.Backups, "20260101T000000Z-old", "state", "ca"), 0700); err != nil {
		t.Fatal(err)
	}
	b.queue(b.sign(TaskSeal, sealParams(), map[string]string{"ntfy_topic_url": secretTopic, "ntfy_token": secretToken}))
	owner := b.when("seal-import", func() {
		if cfg := b.read("etc", "config.toml"); !strings.Contains(cfg, "[seal]\nrequired = true\nrecipient = \"age1") || strings.Contains(cfg, "manifest_sha256") {
			t.Error("import mode started without the staged fence")
		}
		b.activateSeal(manifest)()
	})
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatal(err, b.last(TaskSeal))
	}
	<-owner
	s := b.last(TaskSeal)
	cfg := b.read("etc", "config.toml")
	switch {
	case s.State != "done" || s.Result["manifest_sha256"] != manifest:
		t.Fatalf("%+v", s)
	case !strings.Contains(cfg, `manifest_sha256 = "`+manifest+`"`) || strings.Contains(cfg, "SENTINELlegacy") || !strings.Contains(cfg, "# owner's notes stay"):
		t.Fatal("configuration not pinned or URL not retired:\n" + cfg)
	case b.read("data", "ca", "ssh_user_ca") != "" || b.read("data", "ca", "client_ca.key") != "" || b.read("etc", "cf-proxy-token") != "" || b.read("etc", "cf-minter-token") != "":
		t.Fatal("plaintext sources survive")
	case b.read("data", "ca", "ssh_user_ca.pub") != "public":
		t.Fatal("public CA removed")
	case strings.Contains(b.read("systemd", "aqmasd.service.d", "cloudflare.conf"), "cf-proxy-token") || !strings.Contains(b.read("systemd", "aqmasd.service.d", "cloudflare.conf"), "LoadCredential=other:"):
		t.Fatal("LoadCredential lines not retired precisely")
	case strings.TrimSpace(b.read("active")) != "serve":
		t.Fatal("sealed broker not started")
	case strings.TrimSpace(b.read("alert", "topic-url")) != secretTopic || strings.TrimSpace(b.read("alert", "publish-token")) != secretToken:
		t.Fatal("lock-alert credentials not stored")
	}
	left, _ := os.ReadDir(b.l.Backups)
	if len(left) != 1 || !strings.HasPrefix(left[0].Name(), "sealed-") || b.read("backups", left[0].Name(), "inventory.json") == "" {
		t.Fatalf("backups not purged down to the recovery bundle: %v", left)
	}
	if stages, _ := filepath.Glob(b.path("data", "seal-stage-*")); len(stages) != 0 {
		t.Fatal("staging directory left")
	}
	for _, f := range []string{"topic-url", "publish-token"} {
		if st, _ := os.Stat(b.path("alert", f)); st.Mode().Perm() != 0600 {
			t.Fatal("alert credential mode")
		}
	}
	b.noSecrets("alert")
}

func TestSealCancelRestoresEverything(t *testing.T) {
	b := newLab(t)
	b.setFacts(6, "")
	before := b.read("etc", "config.toml")
	b.queue(b.sign(TaskSeal, sealParams(), map[string]string{"ntfy_topic_url": secretTopic, "ntfy_token": secretToken}))
	owner := b.when("seal-import", func() {
		b.write(0600, "{}", "data", "seal-stage-1", "inventory.json")
		_ = os.WriteFile(b.l.cancel(), nil, 0600)
	})
	if err := b.runner().Run(context.Background()); err == nil {
		t.Fatal("cancelled seal reported success")
	}
	<-owner
	s := b.last(TaskSeal)
	if s.State != "failed" || b.read("etc", "config.toml") != before || b.read("data", "ca", "ssh_user_ca") == "" || b.read("alert", "publish-token") != "" || strings.TrimSpace(b.read("active")) != "serve" {
		t.Fatalf("not fully reverted: %+v", s)
	}
	if stages, _ := filepath.Glob(b.path("data", "seal-stage-*")); len(stages) != 0 {
		t.Fatal("staging directory left")
	}
	// Prerequisite: sealing a legacy broker is refused before anything is touched.
	b.setFacts(5, "")
	log := b.read("hook.log")
	b.queue(b.sign(TaskSeal, sealParams(), map[string]string{"ntfy_topic_url": secretTopic, "ntfy_token": secretToken}))
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskSeal).Message, "organisations first") || b.read("hook.log") != log {
		t.Fatal("prerequisite not enforced")
	}
	b.noSecrets()
}

// A crash or reboot mid-task: before activation everything is put back, after it the runner
// only moves forward.
func TestSealRecovery(t *testing.T) {
	for _, activated := range []bool{false, true} {
		b := newLab(t)
		b.setFacts(7, "")
		before := b.read("etc", "config.toml")
		r := b.runner()
		r.st = ReadStatus(b.l.status())
		dir, err := r.backup(context.Background(), "seal")
		if err != nil {
			t.Fatal(err)
		}
		staged, _ := addSeal(r.raw, sealParams().Recipient)
		_ = os.WriteFile(b.l.Config, staged, 0640)
		_ = r.writeJournal(journal{Task: TaskSeal, Backup: dir, Purge: true})
		_ = os.Remove(b.path("active"))
		manifest := strings.Repeat("cd", 32)
		if activated {
			b.activateSeal(manifest)()
		}
		err = b.runner().Run(context.Background())
		s := b.last(TaskSeal)
		cfg := b.read("etc", "config.toml")
		if activated {
			if err != nil || s.State != "done" || !strings.Contains(cfg, manifest) || b.read("data", "ca", "ssh_user_ca") != "" {
				t.Fatalf("did not finish forward: %v %+v", err, s)
			}
		} else if err == nil || s.State != "failed" || cfg != before || b.read("data", "ca", "ssh_user_ca") == "" {
			t.Fatalf("did not revert: %v %+v", err, s)
		}
		if _, err := os.Stat(b.l.journal()); err == nil || strings.TrimSpace(b.read("active")) != "serve" {
			t.Fatal("journal left or broker down")
		}
	}
}

// releases serves both release APIs (Forgejo and GitHub shapes) for the lab's versions.
func (b *lab) releases(versions ...string) {
	assets := map[string][]byte{}
	b.sums = release.Sums{}
	for _, name := range release.Assets {
		body := []byte("binary " + name)
		if name == release.Daemon {
			body, _ = os.ReadFile(b.l.Bin)
		}
		sum := sha256.Sum256(body)
		assets[name], b.sums[name] = body, hex.EncodeToString(sum[:])
	}
	assets["SHA256SUMS"] = []byte(b.sums.Text())
	names := []string{"SHA256SUMS", "aqmas-darwin-arm64", "aqmas-linux-amd64", "aqmas-linux-arm64"}
	b.forge = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := map[string]string{"/api/v1/repos/example/aqmas": secretForge, "/gh/repos/example/aqmas": secretHub}
		for prefix, token := range want {
			if strings.HasPrefix(r.URL.Path, prefix) && r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "token", 401)
				return
			}
		}
		for _, v := range versions {
			if strings.HasSuffix(r.URL.Path, "/releases/tags/v"+v) {
				var list []map[string]any
				for i, n := range names {
					list = append(list, map[string]any{"name": n, "id": i + 1, "uuid": fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v" + v, "assets": list})
				return
			}
		}
		for i, n := range names {
			if strings.HasSuffix(r.URL.Path, fmt.Sprintf("/releases/assets/%d", i+1)) || strings.HasSuffix(r.URL.Path, fmt.Sprintf("/attachments/00000000-0000-0000-0000-%012d", i+1)) {
				_, _ = w.Write(assets[n])
				return
			}
		}
		http.NotFound(w, r)
	}))
	b.t.Cleanup(b.forge.Close)
}

func (b *lab) updatesParams() UpdatesParams {
	return UpdatesParams{Repo: "ssh://git@forge.example.com:2222/example/aqmas.git", ForgejoAPI: b.forge.URL + "/api/v1/repos/example/aqmas", GitHubAPI: b.forge.URL + "/gh/repos/example/aqmas",
		KnownHosts: []string{"[forge.example.com]:2222 ssh-ed25519 " + strings.Repeat("A", 68)}, ForgejoToken: true, GitHubToken: true}
}

func TestEnableUpdatesAndUpgrade(t *testing.T) {
	b := newLab(t)
	b.releases("0.3.0", "0.3.1")
	before := b.read("etc", "config.toml")
	tokens := map[string]string{"forgejo_token": secretForge, "github_token": secretHub}

	// The restart fails: the previous configuration comes back.
	b.write(0600, "", "refuse-once-serve")
	b.queue(b.sign(TaskUpdates, b.updatesParams(), tokens))
	if err := b.runner().Run(context.Background()); err == nil || b.read("etc", "config.toml") != before {
		t.Fatalf("no rollback of the configuration: %+v", b.last(TaskUpdates))
	}

	// A broker that is not the published binary is refused before the configuration changes.
	b.queue(b.sign(TaskUpdates, b.updatesParams(), tokens))
	b.write(0755, b.read("aqmasd")+"# changed\n", "aqmasd")
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpdates).Message, "not the published") || b.read("etc", "config.toml") != before {
		t.Fatalf("unpublished binary accepted: %+v", b.last(TaskUpdates))
	}
	b.releases("0.3.0", "0.3.1")

	b.queue(b.sign(TaskUpdates, b.updatesParams(), tokens))
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatal(err, b.last(TaskUpdates))
	}
	cfg := b.read("etc", "config.toml")
	s := b.last(TaskUpdates)
	switch {
	case s.State != "done" || !strings.HasPrefix(s.Result["deploy_key"], "ssh-ed25519 "):
		t.Fatalf("%+v", s)
	case !strings.Contains(cfg, `repo = "ssh://git@forge.example.com:2222/example/aqmas.git"`) || !strings.Contains(cfg, `cache_dir = "`+b.l.Cache+`"`) || !strings.Contains(cfg, "# owner's notes stay"):
		t.Fatal("configuration:\n" + cfg)
	case strings.TrimSpace(b.read("etc", "forgejo-read-token")) != secretForge || strings.TrimSpace(b.read("etc", "github-read-token")) != secretHub:
		t.Fatal("tokens not stored")
	case !strings.Contains(b.read("known_hosts"), "[forge.example.com]:2222 ssh-ed25519 "):
		t.Fatal("host key not trusted")
	case b.read("releases", "0.3.0", "aqmas-linux-amd64") != "binary aqmas-linux-amd64" || !strings.Contains(b.read("releases", "latest.json"), `"version":"0.3.0"`):
		t.Fatal("release cache not seeded")
	}
	b.noSecrets("etc/forgejo-read-token", "etc/github-read-token")

	// Upgrade: an "update" approval bound to the installed identity and all four digests.
	update := func(from string, sums release.Sums) Request {
		to := strings.Repeat("d", 40)
		a := canon.Action{Object: "update", Action: "approve", ID: to, Update: canon.Update{FromVersion: from, FromCommit: b.facts.Commit, ToVersion: "0.3.1", ToCommit: to,
			DaemonHash: sums[release.Daemon], LinuxARM: sums["aqmas-linux-arm64"], LinuxAMD: sums["aqmas-linux-amd64"], DarwinARM: sums["aqmas-darwin-arm64"]}}
		text, err := canon.Build(a, canon.NewNonce(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return Request{Canonical: text, Assertion: b.auth.Assert(canon.Challenge(text))}
	}
	wrong := release.Sums{}
	for k := range b.sums {
		wrong[k] = strings.Repeat("e", 64)
	}
	for name, req := range map[string]Request{"other digests": update("0.3.0", wrong), "other installed version": update("0.2.9", b.sums)} {
		b.queue(req)
		if err := b.runner().Run(context.Background()); err == nil || b.read("installed-metadata.json") != "" {
			t.Fatal("upgrade accepted with " + name)
		}
	}
	b.queue(update("0.3.0", b.sums))
	if err := b.runner().Run(context.Background()); err != nil || !strings.Contains(b.read("installed-metadata.json"), `"version":"0.3.1"`) {
		t.Fatalf("upgrade: %v %+v", err, b.last(TaskUpgrade))
	}
	b.write(0600, "", "upgrade-fails")
	b.queue(update("0.3.0", b.sums))
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(b.last(TaskUpgrade).Message, "refused or build failed") {
		t.Fatal("installer failure not reported")
	}
}

func TestSyncPins(t *testing.T) {
	b := newLab(t)
	second := newAuth()
	b.facts.Passkeys = append(b.facts.Passkeys, struct {
		ID        []byte `json:"id"`
		PublicKey []byte `json:"publicKey"`
	}{second.CredID, cose(second)})
	b.setFacts(5, "")
	pin := func(a *vauth.Authenticator) Pin {
		sum := sha256.Sum256(cose(a))
		return Pin{ID: base64.RawURLEncoding.EncodeToString(a.CredID), KeyHash: hex.EncodeToString(sum[:])}
	}
	first := b.auth
	// The new key cannot pin itself.
	b.auth = second
	b.queue(b.sign(TaskPins, PinsParams{Pins: []Pin{pin(second)}}, nil))
	if err := b.runner().Run(context.Background()); err == nil || len(ReadStatus(b.l.status()).Runner.Pins) != 1 {
		t.Fatal("unpinned key replaced the pins")
	}
	b.auth = first
	// A signed list whose key digest is not the broker's record is refused.
	forged := pin(second)
	forged.KeyHash = strings.Repeat("0", 64)
	b.queue(b.sign(TaskPins, PinsParams{Pins: []Pin{pin(first), forged}}, nil))
	if err := b.runner().Run(context.Background()); err == nil {
		t.Fatal("pinned a key that does not match its signed digest")
	}
	b.queue(b.sign(TaskPins, PinsParams{Pins: []Pin{pin(second)}}, nil))
	if err := b.runner().Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pins := ReadStatus(b.l.status()).Runner.Pins; len(pins) != 1 || pins[0] != pin(second).ID {
		t.Fatalf("pins: %v", pins)
	}
	// From now on only the second key is accepted.
	b.queue(b.sign(TaskPins, PinsParams{Pins: []Pin{pin(first)}}, nil))
	if err := b.runner().Run(context.Background()); err == nil {
		t.Fatal("removed key still accepted")
	}
}

// Every way a spool request can be wrong is refused before any task starts.
func TestRefusals(t *testing.T) {
	b := newLab(t)
	b.setFacts(7, "")
	good := b.sign(TaskSeal, sealParams(), map[string]string{"ntfy_topic_url": secretTopic, "ntfy_token": secretToken})
	sealed := func(m map[string]string) string {
		plain, _ := json.Marshal(m)
		p, _ := SealPacket(ReadStatus(b.l.status()).Runner.SecretsKey, SecretsInfo(TaskSeal), plain)
		return p
	}
	resign := func(a canon.Action, at time.Time) Request {
		text, err := canon.Build(a, canon.NewNonce(), at)
		if err != nil {
			t.Fatal(err)
		}
		return Request{Canonical: text, Assertion: b.auth.Assert(canon.Challenge(text))}
	}
	setup := func(task, params string) canon.Action {
		return canon.Action{Object: canon.ObjectSetup, Action: canon.ActionRun, ID: task, Params: params}
	}
	cases := map[string]Request{}
	// Tampering with what was signed.
	for _, change := range [][2]string{{`"id":"seal"`, `"id":"cutover"`}, {`\"purge_backups\":true`, `\"purge_backups\":false`}, {`age1qq`, `age1pq`}, {`"object":"setup"`, `"object":"update"`}} {
		c := good
		c.Canonical = strings.Replace(good.Canonical, change[0], change[1], 1)
		if c.Canonical == good.Canonical {
			t.Fatal("test does not change " + change[0])
		}
		cases["tampered "+change[0]] = c
	}
	swapped := good
	swapped.Secrets = sealed(map[string]string{"ntfy_topic_url": "https://ntfy.example.com/attacker", "ntfy_token": "attackertoken"})
	cases["other secrets under the same signature"] = swapped
	none := good
	none.Secrets = ""
	cases["secrets removed"] = none
	// Correctly signed requests the allowlist or the schema must still refuse.
	cases["task not compiled in"] = resign(setup("shell", "{}"), time.Now())
	cases["upgrade through setup"] = resign(setup(TaskUpgrade, "{}"), time.Now())
	cases["unknown parameter"] = resign(setup(TaskCutover, `{"exec":"id"}`), time.Now())
	cases["non-canonical parameters"] = resign(setup(TaskSeal, `{"purge_backups":true,"recipient":"`+sealParams().Recipient+`","lock_alert":false}`), time.Now())
	cases["recipient injection"] = resign(setup(TaskSeal, `{"recipient":"age1\"\nrequired = false\n#","purge_backups":true,"lock_alert":false}`), time.Now())
	cases["repo injection"] = resign(setup(TaskUpdates, `{"repo":"ssh://git@forge.example.com/a/b.git\"\n[cloudflare]","forgejo_api":"https://forge.example.com/api/v1/repos/a/b","github_api":"https://api.github.com/repos/a/b","known_hosts":["forge.example.com ssh-ed25519 `+strings.Repeat("A", 68)+`"],"forgejo_token":false,"github_token":false}`), time.Now())
	cases["host key for another host"] = resign(setup(TaskUpdates, `{"repo":"ssh://git@forge.example.com/a/b.git","forgejo_api":"https://forge.example.com/api/v1/repos/a/b","github_api":"https://api.github.com/repos/a/b","known_hosts":["* ssh-ed25519 `+strings.Repeat("A", 68)+`"],"forgejo_token":false,"github_token":false}`), time.Now())
	cases["another object"] = resign(canon.Action{Object: canon.ObjectPasskey, Action: canon.ActionAdd, ID: "new"}, time.Now())
	cases["stale"] = resign(setup(TaskCutover, "{}"), time.Now().Add(-3*time.Minute))
	cases["from the future"] = resign(setup(TaskCutover, "{}"), time.Now().Add(time.Minute))
	stranger := newAuth()
	text, _ := canon.Build(setup(TaskCutover, "{}"), canon.NewNonce(), time.Now())
	cases["unpinned passkey"] = Request{Canonical: text, Assertion: stranger.Assert(canon.Challenge(text))}
	cases["no user verification"] = Request{Canonical: text, Assertion: b.auth.AssertWith(canon.Challenge(text), vauth.AssertOpts{Flags: vauth.FlagUP})}
	elsewhere := vauth.New("https://evil.example.com")
	elsewhere.Key, elsewhere.CredID, elsewhere.RPID = b.auth.Key, b.auth.CredID, b.auth.RPID
	cases["another origin"] = Request{Canonical: text, Assertion: elsewhere.Assert(canon.Challenge(text))}
	need := resign(setup(TaskSeal, `{"recipient":"`+sealParams().Recipient+`","purge_backups":true,"lock_alert":true}`), time.Now())
	cases["declared secrets missing"] = need

	log := b.read("hook.log")
	cfg := b.read("etc", "config.toml")
	for name, req := range cases {
		b.queue(req)
		if err := b.runner().Run(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
		st := ReadStatus(b.l.status())
		if st.Refused == nil || st.Tasks[TaskSeal] != nil || st.Tasks[TaskCutover] != nil || st.Tasks[TaskUpdates] != nil {
			t.Errorf("%s: a task started: %+v", name, st)
		}
		if _, err := os.Lstat(b.l.request()); err == nil {
			t.Errorf("%s: request left in the spool", name)
		}
	}
	if b.read("hook.log") != log || b.read("etc", "config.toml") != cfg {
		t.Fatal("a refused request touched the broker")
	}

	// Not a regular file: a link planted in the spool is never followed.
	b.write(0600, `{"canonical":"x"}`, "elsewhere")
	if err := os.Symlink(b.path("elsewhere"), b.l.request()); err != nil {
		t.Fatal(err)
	}
	if err := b.runner().Run(context.Background()); err == nil || b.read("elsewhere") == "" {
		t.Fatal("followed a link in the spool")
	}

	// Replay: the identical approval is accepted once.
	b.setFacts(5, "")
	once := b.sign(TaskCutover, CutoverParams{}, nil)
	b.queue(once)
	owner := b.when("organisations-cutover", func() { _ = os.WriteFile(b.l.cancel(), nil, 0600) })
	_ = b.runner().Run(context.Background())
	<-owner
	log = b.read("hook.log")
	b.queue(once)
	if err := b.runner().Run(context.Background()); err == nil || !strings.Contains(ReadStatus(b.l.status()).Refused.Reason, "already used") || b.read("hook.log") != log {
		t.Fatal("replayed approval ran again")
	}
	b.noSecrets()
}

func TestParamsCanonical(t *testing.T) {
	for task, v := range map[string]any{TaskCutover: CutoverParams{}, TaskSeal: sealParams(),
		TaskUpdates: UpdatesParams{Repo: "ssh://git@forge.example.com/a/b.git", ForgejoAPI: "https://forge.example.com/api/v1/repos/a/b", GitHubAPI: "https://api.github.com/repos/a/b", KnownHosts: []string{"forge.example.com ssh-ed25519 " + strings.Repeat("A", 68)}},
		TaskPins:    PinsParams{Pins: []Pin{{ID: strings.Repeat("A", 43), KeyHash: strings.Repeat("a", 64)}}}} {
		text, err := Canonical(task, v)
		if err != nil {
			t.Fatal(task, err)
		}
		got, err := Parse(task, text)
		if err != nil || fmt.Sprint(got) != fmt.Sprint(v) {
			t.Fatal(task, err, got)
		}
		if _, err = Parse(task, " "+text); err == nil {
			t.Fatal(task, "accepted whitespace")
		}
		if _, err = Parse(task, strings.TrimSuffix(text, "}")+`,"x":1}`); err == nil && text != "{}" {
			t.Fatal(task, "accepted an extra key")
		}
		for other := range map[string]bool{TaskCutover: true, TaskSeal: true, TaskUpdates: true, TaskPins: true} {
			if _, err = Parse(other, text); err == nil && other != task {
				t.Fatalf("%s parameters accepted for %s", task, other)
			}
		}
	}
	if _, err := Parse(TaskCutover, `{"x":1}`); err == nil {
		t.Fatal("cutover takes no parameters")
	}
	if _, err := Canonical(TaskSeal, CutoverParams{}); err == nil {
		t.Fatal("parameters of another task accepted")
	}
	if got, _ := Canonical(TaskSeal, sealParams()); got != `{"recipient":"age1`+strings.Repeat("q", 58)+`","purge_backups":true,"lock_alert":true}` {
		t.Fatal("field order is part of the wire contract: " + got)
	}
}

func TestConfigEdits(t *testing.T) {
	example, err := os.ReadFile("../../deploy/bastion/config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(strings.Replace(string(example), `topic_url = ""`, `topic_url = "https://ntfy.example.com/abc"`, 1))
	recipient := sealParams().Recipient
	staged, err := addSeal(raw, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = addSeal(staged, recipient); err == nil {
		t.Fatal("second [seal] section")
	}
	pinned, err := pinSeal(staged, strings.Repeat("a", 64))
	if err != nil || strings.Contains(string(pinned), "ntfy.example.com/abc") || !strings.HasPrefix(string(pinned), string(example[:200])) {
		t.Fatal("pin: ", err)
	}
	if _, err = pinSeal(pinned, strings.Repeat("b", 64)); err == nil {
		t.Fatal("re-pinned an activation")
	}
	// Layouts the text edit cannot prove are refused, not guessed at.
	odd := strings.Replace(string(raw), "[ntfy]", "[ntfy] # x\ntopic_url = '''https://ntfy.example.com/abc'''\n[ntfy2]", 1)
	if s, err := addSeal([]byte(odd), recipient); err == nil {
		if _, err = pinSeal(s, strings.Repeat("a", 64)); err == nil {
			t.Fatal("edited a layout it cannot prove")
		}
	}
}
