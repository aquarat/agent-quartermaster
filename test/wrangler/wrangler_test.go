// Package wrangler runs the real wrangler CLI through `aqmas cf env` against a stand-in for
// aqmasd's proxy (fakecf.StandIn, mTLS) and the in-memory fake Cloudflare API (fakecf). Run it
// with test/wrangler/run.sh, which installs wrangler with bun into a temp dir and sets
// WRANGLER_BIN; without WRANGLER_BIN the test is skipped.
//
// Nothing reaches the network: HOME and XDG_CONFIG_HOME are temp dirs (no OAuth config),
// WRANGLER_SEND_METRICS=false, and HTTP(S)_PROXY point at a local recorder that refuses (and
// records) every request not sent to the shim (NO_PROXY=127.0.0.1,localhost).
package wrangler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/testutil/fakecf"
)

const (
	account   = "4c2e6b0f1a3d5e7f9a1b3c5d7e9f0a2b"
	zoneID    = "5d1e0a6c2b4f8e9d7c3a1b5f9e8d7c6b"
	zoneName  = "example.com"
	dbID      = "7f3e2d1c-0b9a-4876-9543-210fedcba987"
	dbName    = "aqmas-test-db"
	script    = "aqmas-wrangler-test"
	project   = "aqmas-pages-test"
	parentTok = "fake-parent-token-for-wrangler-test"
)

// Grants the stand-in aqmasd reports as active for the host (proxy mode).
var grants = []api.GrantSummary{
	{ID: "GWORKERS0001", Kind: api.KindCloudflare, Status: api.StatusApproved, Scope: api.CFScopeWorkersDeploy, ScopeParams: "script=" + script, Mode: api.CFModeProxy},
	{ID: "GPAGES000001", Kind: api.KindCloudflare, Status: api.StatusApproved, Scope: api.CFScopePages, ScopeParams: "project=" + project, Mode: api.CFModeProxy},
	{ID: "GD1000000001", Kind: api.KindCloudflare, Status: api.StatusApproved, Scope: api.CFScopeD1, ScopeParams: "access=migrate;db=" + dbName, Mode: api.CFModeProxy},
}

type pki struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stand-in CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{caCert: c, caKey: key}
}

func (p *pki) leaf(t *testing.T, cn string, eku x509.ExtKeyUsage, ip net.IP) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// recorder is the HTTP(S)_PROXY every non-shim request goes to: it records and refuses.
type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Method+" "+req.Host+req.URL.Path)
	r.mu.Unlock()
	http.Error(w, "network access refused by the aqmas wrangler test", http.StatusForbidden)
}

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.seen
	r.seen = nil
	return s
}

func TestWranglerThroughShim(t *testing.T) {
	wrangler := os.Getenv("WRANGLER_BIN")
	if wrangler == "" {
		t.Skip("WRANGLER_BIN not set (run test/wrangler/run.sh)")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	root := t.TempDir()
	_, thisFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	// Fake Cloudflare.
	fk, err := fakecf.New(fakecf.Options{Tokens: []string{parentTok}, AccountID: account, Zones: []fakecf.Named{{Name: zoneName, ID: zoneID}},
		D1: []fakecf.Named{{Name: dbName, ID: dbID}}, PagesProjects: []string{project}})
	if err != nil {
		t.Fatal(err)
	}
	cfSrv := httptest.NewServer(fk)
	defer cfSrv.Close()

	// Stand-in aqmasd: mTLS agent API with /v1/grants, /v1/cf/catalogue and the proxy.
	p := newPKI(t)
	srvCert, srvKey := p.leaf(t, "aqmasd", x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1"))
	cliCert, cliKey := p.leaf(t, "wranglerhost", x509.ExtKeyUsageClientAuth, nil)
	standIn := &fakecf.StandIn{Upstream: cfSrv.URL, ParentToken: parentTok, AccountID: account,
		Allow: func(r *http.Request, method, cfPath string, offered []string) (string, string) {
			for _, id := range offered {
				for _, g := range grants {
					if g.ID == id {
						return id, ""
					}
				}
			}
			return "", "cf.workers.deploy script=" + script
		}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/grants", func(w http.ResponseWriter, r *http.Request) {
		gs := append([]api.GrantSummary(nil), grants...)
		for i := range gs {
			gs[i].NotBefore, gs[i].NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
		}
		json.NewEncoder(w).Encode(api.GrantList{Grants: gs})
	})
	mux.HandleFunc("GET /v1/cf/catalogue", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.CFCatalogue{AccountID: account, Zones: []api.CFNamedID{{Name: zoneName, ID: zoneID}},
			D1Databases: []api.CFNamedID{{Name: dbName, ID: dbID}}, Scopes: []api.CFScopeInfo{}})
	})
	mux.Handle("/cf/client/v4/", standIn)
	agent := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "wranglerhost" {
			http.Error(w, `{"error":"unauthenticated"}`, 401)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	agent.Config.ErrorLog = log.New(io.Discard, "", 0)
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	agent.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw, p.caCert.Raw}, PrivateKey: srvKey}}}
	agent.StartTLS()
	defer agent.Close()

	// aqmas config (as `aqmas enroll` writes it).
	cfgDir := filepath.Join(root, "aqmas-config")
	cacheDir := filepath.Join(root, "aqmas-cache")
	os.MkdirAll(cfgDir, 0o700)
	os.MkdirAll(cacheDir, 0o700)
	writePEM(t, filepath.Join(cfgDir, "server-ca.pem"), "CERTIFICATE", p.caCert.Raw)
	writePEM(t, filepath.Join(cfgDir, "client.crt"), "CERTIFICATE", cliCert.Raw)
	kder, _ := x509.MarshalPKCS8PrivateKey(cliKey)
	writePEM(t, filepath.Join(cfgDir, "client.key"), "PRIVATE KEY", kder)
	pin := sha256.Sum256(p.caCert.Raw)
	cfg := fmt.Sprintf("server = %q\nserver_ca = %q\nserver_ca_sha256 = %q\nhost_name = \"wranglerhost\"\nclient_cert = %q\nclient_key = %q\n",
		agent.URL, filepath.Join(cfgDir, "server-ca.pem"), "sha256:"+hex.EncodeToString(pin[:]), filepath.Join(cfgDir, "client.crt"), filepath.Join(cfgDir, "client.key"))
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// The aqmas binary.
	aqmas := filepath.Join(root, "aqmas")
	build := exec.Command("go", "build", "-o", aqmas, "./cmd/aqmas")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aqmas: %v\n%s", err, out)
	}

	// Network guard.
	rec := &recorder{}
	guard := httptest.NewServer(rec)
	defer guard.Close()

	// The project: a Worker with static assets, a cron trigger and a D1 binding with a migration;
	// a separate directory for Pages.
	proj := filepath.Join(root, "proj")
	files := map[string]string{
		"wrangler.toml": fmt.Sprintf(`name = %q
main = "src/index.js"
compatibility_date = "2025-01-01"
workers_dev = true

[assets]
directory = "./public"

[triggers]
crons = ["*/15 * * * *"]

[[d1_databases]]
binding = "DB"
database_name = %q
database_id = %q
migrations_dir = "migrations"
`, script, dbName, dbID),
		"src/index.js":              "export default {\n  async fetch(req, env) { return new Response('hello'); },\n  async scheduled(ev, env, ctx) {},\n};\n",
		"public/index.html":         "<!doctype html><title>aqmas</title><p>hello</p>\n",
		"public/style.css":          "p { color: teal; }\n",
		"public/app.js":             "console.log('aqmas');\n",
		"migrations/0001_init.sql":  "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);\n",
		"migrations/0002_index.sql": "CREATE INDEX notes_body ON notes(body);\nINSERT INTO notes (body) VALUES ('a;b');\n",
		"pages/index.html":          "<!doctype html><title>pages</title><p>pages</p>\n",
		// The same D1 database bound by name only: wrangler looks the uuid up by name.
		"nameonly/wrangler.toml": fmt.Sprintf("name = %q\nmain = \"../src/index.js\"\ncompatibility_date = \"2025-01-01\"\n\n[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = %q\n", script, dbName),
		"pages/about.html":       "<!doctype html><title>about</title>\n",
	}
	for name, content := range files {
		path := filepath.Join(proj, name)
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(root, "home")
	os.MkdirAll(filepath.Join(home, "xdg"), 0o700)
	baseEnv := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "xdg"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		"AQMAS_CONFIG_DIR=" + cfgDir,
		"AQMAS_CACHE_DIR=" + cacheDir,
		"WRANGLER_SEND_METRICS=false",
		"WRANGLER_SEND_ERROR_REPORTS=false",
		"DO_NOT_TRACK=1",
		"CI=1",
		"FORCE_COLOR=0",
		"WRANGLER_LOG=debug",
		"WRANGLER_LOG_SANITIZE=true",
		"HTTPS_PROXY=" + guard.URL, "HTTP_PROXY=" + guard.URL, "https_proxy=" + guard.URL, "http_proxy=" + guard.URL,
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
		"CLOUDFLARE_API_KEY=must-be-removed", "CLOUDFLARE_EMAIL=must-be-removed@example.com",
	}

	type step struct {
		name   string
		args   []string
		stdin  string
		check  func(out string) error
		before func()
	}
	contains := func(s ...string) func(string) error {
		return func(out string) error {
			for _, w := range s {
				if !strings.Contains(out, w) {
					return fmt.Errorf("output lacks %q", w)
				}
			}
			return nil
		}
	}
	steps := []step{
		{"whoami", []string{"whoami"}, "", contains(account), nil},
		{"deploy", []string{"deploy"}, "", contains("Uploaded "+script, "*/15 * * * *"), nil},
		{"versions upload", []string{"versions", "upload"}, "", contains("Worker Version ID"), nil},
		{"secret put", []string{"secret", "put", "MY_SECRET"}, "s3cret-value\n", contains("Success"), nil},
		{"d1 execute", []string{"d1", "execute", dbName, "--remote", "--command", "SELECT 1"}, "", contains(`"1": 1`), nil},
		{"d1 migrations apply", []string{"d1", "migrations", "apply", dbName, "--remote"}, "", contains("0001_init.sql", "0002_index.sql"), nil},
		{"pages deploy", []string{"pages", "deploy", "pages", "--project-name", project, "--branch", "main", "--commit-dirty=true"}, "", contains("Deployment complete"), nil},
		{"d1 execute (binding by name only)", []string{"d1", "execute", "DB", "--remote", "--config", "nameonly/wrangler.toml", "--command", "SELECT count(*) AS n FROM notes"}, "", contains(`"n": 1`), nil},
		// Cloudflare can ask wrangler (by a claim in the upload JWT) to upload each asset in its own
		// request, POST .../workers/assets/upload/{hash}; deploy once more in that mode.
		{"deploy (single-asset uploads)", []string{"deploy"}, "", contains("Uploaded " + script), func() {
			fk.SetSingleAssetUploads(true)
			os.WriteFile(filepath.Join(proj, "public", "new.txt"), []byte("new asset\n"), 0o644)
			os.WriteFile(filepath.Join(proj, "public", "style.css"), []byte("p { color: navy; }\n"), 0o644)
		}},
	}
	type observed struct {
		step  string
		lines []string
	}
	var obs []observed
	npmChecks := map[string]bool{}
	var report strings.Builder
	failed := false
	for _, s := range steps {
		if s.before != nil {
			s.before()
		}
		fk.ClearRequests()
		before := len(standIn.Calls())
		args := append([]string{"cf", "env", "--", node, wrangler}, s.args...)
		cmd := exec.Command(aqmas, args...)
		cmd.Dir = proj
		cmd.Env = baseEnv
		cmd.Stdin = strings.NewReader(s.stdin)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err = <-done:
		case <-ctx.Done():
			cmd.Process.Kill()
			err = <-done
		}
		cancel()
		text := out.String()
		logPath := filepath.Join(root, strings.ReplaceAll(s.name, " ", "-")+".log")
		os.WriteFile(logPath, out.Bytes(), 0o600)
		if os.Getenv("WRANGLER_LOG_DIR") != "" {
			os.WriteFile(filepath.Join(os.Getenv("WRANGLER_LOG_DIR"), filepath.Base(logPath)), out.Bytes(), 0o600)
		}
		outside := rec.take()
		var problems []string
		if err != nil {
			problems = append(problems, "exit: "+err.Error())
		} else if cerr := s.check(text); cerr != nil {
			problems = append(problems, cerr.Error())
		}
		var refusedOK []string
		for _, o := range outside {
			// wrangler's npm update check (no switch turns it off); not a Cloudflare call.
			if o == "CONNECT registry.npmjs.org:443" {
				refusedOK = append(refusedOK, o)
				continue
			}
			problems = append(problems, fmt.Sprintf("request outside the shim: %q", o))
		}
		if len(refusedOK) > 0 {
			npmChecks[s.name] = true
		}
		if strings.Contains(text, parentTok) {
			problems = append(problems, "parent token appeared in wrangler's output")
		}
		calls := standIn.Calls()[before:]
		reqs := fk.Requests()
		var lines []string
		seen := map[string]bool{}
		for _, r := range reqs {
			l := r.Method + " " + normalise(strings.TrimPrefix(r.Path, fakecf.Prefix)) + normaliseQuery(r.Query)
			switch r.Credential {
			case "upload-jwt":
				l += "    [upload JWT]"
			case "parent":
			default:
				l += "    [credential: " + r.Credential + "]"
				problems = append(problems, fmt.Sprintf("%s %s reached Cloudflare with credential %s", r.Method, r.Path, r.Credential))
			}
			if r.Status >= 400 {
				l += fmt.Sprintf("    (fake answered %d)", r.Status)
			}
			if !seen[l] {
				seen[l] = true
				lines = append(lines, l)
			}
		}
		for _, c := range calls {
			if c.Refused != "" {
				problems = append(problems, fmt.Sprintf("proxy refused %s %s: %s", c.Method, c.Path, c.Refused))
			}
			if c.GrantUsed == "" && c.Refused == "" {
				problems = append(problems, fmt.Sprintf("%s %s without a grant", c.Method, c.Path))
			}
			if c.Path == "/user/tokens/verify" || c.Path == "/user" || c.Path == "/memberships" || c.Path == "/accounts" {
				l := c.Method + " " + c.Path + "    [synthetic, answered by aqmasd]"
				if !seen[l] {
					seen[l] = true
					lines = append(lines, l)
				}
			}
		}
		sort.Strings(lines)
		obs = append(obs, observed{s.name, lines})
		status := "ok"
		if len(problems) > 0 {
			status = "FAIL: " + strings.Join(problems, "; ")
			failed = true
			t.Errorf("wrangler %s: %s\n--- output (%s) ---\n%s", s.name, status, logPath, tail(text, 60))
		}
		fmt.Fprintf(&report, "wrangler %-22s %s\n", s.name, status)
	}
	if v := standIn.Violations(); len(v) > 0 {
		t.Errorf("proxy contract violations by the shim: %q", v)
		failed = true
	}
	t.Logf("\n%s", report.String())

	// observed-paths.txt
	version := "unknown"
	if out, err := exec.Command(node, wrangler, "--version").Output(); err == nil {
		version = strings.TrimSpace(lastLine(string(out)))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Cloudflare API calls wrangler %s makes through `aqmas cf env` (test/wrangler, %s).\n", version, time.Now().UTC().Format("2006-01-02"))
	b.WriteString("# Paths are below /client/v4, normalised: {acct} account id, {zone} zone id, {db} D1 uuid,\n")
	b.WriteString("# {db-name} D1 database NAME (wrangler looks a name-only binding up by name in the path),\n")
	b.WriteString("# {script} Worker name, {project} Pages project, {id} uuid/version/deployment id, {hash} asset hash.\n")
	b.WriteString("# \"(fake answered 404)\": wrangler probes for objects that do not exist yet; the proxy must allow the call.\n")
	b.WriteString("# [upload JWT] = the call carried the upload JWT as its credential (JWT passthrough);\n")
	b.WriteString("# [synthetic] = answered by aqmasd itself (CLOUDFLARE.md 3.2), never reaches Cloudflare.\n")
	if len(npmChecks) > 0 {
		b.WriteString("# Outside the shim: only wrangler's npm update check (CONNECT registry.npmjs.org:443), refused by\n")
		b.WriteString("# the test's HTTPS_PROXY guard; no Cloudflare host was contacted except through the shim.\n")
	}
	b.WriteString("# Status per command:\n")
	for _, l := range strings.Split(strings.TrimSpace(report.String()), "\n") {
		b.WriteString("#   " + l + "\n")
	}
	for _, o := range obs {
		fmt.Fprintf(&b, "\n[wrangler %s]\n", o.step)
		for _, l := range o.lines {
			b.WriteString(l + "\n")
		}
	}
	outPath := os.Getenv("OBSERVED_PATHS")
	if outPath == "" {
		outPath = filepath.Join(filepath.Dir(thisFile), "observed-paths.txt")
	}
	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("observed paths written to %s", outPath)
	if failed {
		t.Logf("logs kept in %s", root)
	}
}

var (
	uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func normalise(p string) string {
	seg := strings.Split(p, "/")
	for i, s := range seg {
		switch {
		case s == account:
			seg[i] = "{acct}"
		case s == zoneID:
			seg[i] = "{zone}"
		case s == dbID:
			seg[i] = "{db}"
		case s == dbName:
			seg[i] = "{db-name}"
		case s == script:
			seg[i] = "{script}"
		case s == project:
			seg[i] = "{project}"
		case uuidRE.MatchString(s):
			seg[i] = "{id}"
		case hashRE.MatchString(s):
			seg[i] = "{hash}"
		}
	}
	return strings.Join(seg, "/")
}

func normaliseQuery(q string) string {
	if q == "" {
		return ""
	}
	parts := strings.Split(q, "&")
	for i, kv := range parts {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			if n := normalise(v); n != v {
				v = n
			}
			parts[i] = k + "=" + v
		}
	}
	return "?" + strings.Join(parts, "&")
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func lastLine(s string) string {
	var last string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			last = t
		}
	}
	return last
}
