package client

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/release"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// Whose enrolment a root `aqmas upgrade` uses: the invoking user's, and only when the
// directory is that user's own.
func TestSudoInvokerResolution(t *testing.T) {
	me := os.Geteuid()
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "aqmas")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := lookupHome
	t.Cleanup(func() { lookupHome = old })
	known := func(uid int) (string, string, error) { return "alice", home, nil }
	unknown := func(int) (string, string, error) { return "", "", errors.New("no such user") }
	sudo := func(uid int, extra map[string]string) func(string) string {
		m := map[string]string{"SUDO_UID": strconv.Itoa(uid), "SUDO_GID": "100", "SUDO_USER": "alice", "HOME": "/root"}
		for k, v := range extra {
			m[k] = v
		}
		return envOf(m)
	}

	lookupHome = known
	// Not root, a root login, sudo by root itself: no invoker, nothing changes.
	for name, c := range map[string]struct {
		env  func(string) string
		euid int
	}{
		"not root":          {sudo(me, nil), 1000},
		"root login":        {envOf(map[string]string{"HOME": "/root"}), 0},
		"sudo run by root":  {envOf(map[string]string{"SUDO_UID": "0", "SUDO_GID": "0"}), 0},
		"garbage SUDO_UID":  {envOf(map[string]string{"SUDO_UID": "alice", "SUDO_GID": "100"}), 0},
		"negative SUDO_UID": {envOf(map[string]string{"SUDO_UID": "-1", "SUDO_GID": "100"}), 0},
	} {
		if inv, err := sudoInvoker(c.env, c.euid); inv != nil || err != nil {
			t.Fatalf("%s: %+v %v", name, inv, err)
		}
	}

	// The usual case: HOME was reset to root's, the account database gives the user's home.
	inv, err := sudoInvoker(sudo(me, nil), 0)
	if err != nil || inv == nil || inv.UID != me || inv.GID != 100 || inv.Name != "alice" || inv.Home != home ||
		inv.ConfigDir != cfgDir || inv.CacheDir != filepath.Join(home, ".cache", "aqmas") || inv.Paths().ConfigDir != cfgDir {
		t.Fatalf("resolved %+v %v", inv, err)
	}
	// Someone else's directory is refused, not skipped: uid me+1 "ran sudo", the directory is mine.
	if inv, err := sudoInvoker(sudo(me+1, nil), 0); inv != nil || err == nil || !strings.Contains(err.Error(), "is not owned by alice") {
		t.Fatalf("foreign owner: %+v %v", inv, err)
	}
	// No SUDO_GID: refused.
	if _, err := sudoInvoker(envOf(map[string]string{"SUDO_UID": strconv.Itoa(me)}), 0); err == nil {
		t.Fatal("missing SUDO_GID accepted")
	}
	// A symlink in place of the directory is refused.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(cfgDir, link); err != nil {
		t.Fatal(err)
	}
	if inv, err := sudoInvoker(sudo(me, map[string]string{"AQMAS_CONFIG_DIR": link}), 0); inv != nil || err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlinked config directory: %+v %v", inv, err)
	}
	// An explicit AQMAS_CONFIG_DIR is used as given (and checked the same way).
	other := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if inv, err := sudoInvoker(sudo(me, map[string]string{"AQMAS_CONFIG_DIR": other}), 0); err != nil || inv == nil || inv.ConfigDir != other {
		t.Fatalf("explicit directory: %+v %v", inv, err)
	}

	// No account database entry: sudo's HOME counts only when it is that user's directory.
	lookupHome = unknown
	if inv, err := sudoInvoker(sudo(me, map[string]string{"HOME": home}), 0); err != nil || inv == nil || inv.Home != home || inv.Name != "alice" {
		t.Fatalf("HOME fallback: %+v %v", inv, err)
	}
	if inv, err := sudoInvoker(sudo(me+1, map[string]string{"HOME": home}), 0); inv != nil || err == nil || !strings.Contains(err.Error(), "cannot find the home directory") {
		t.Fatalf("HOME of another user: %+v %v", inv, err)
	}

	// The invoking user is not enrolled: root's own enrolment, as before.
	// Its paths come from root's account entry, never from a HOME that sudo kept (macOS,
	// sudo -E, env_keep), which would lead straight back to the user's directory.
	rootHome := t.TempDir()
	lookupHome = func(uid int) (string, string, error) {
		if uid == 0 {
			return "root", rootHome, nil
		}
		return "alice", t.TempDir(), nil
	}
	inv, rootOwn, err := SudoInvoker(sudo(me, map[string]string{"HOME": home}), 0)
	if inv != nil || !rootOwn || err != nil {
		t.Fatalf("not enrolled: %+v %v %v", inv, rootOwn, err)
	}
	if p := RootPaths(); p.ConfigDir != filepath.Join(rootHome, ".config", "aqmas") || p.CacheDir != filepath.Join(rootHome, ".cache", "aqmas") || strings.HasPrefix(p.ConfigDir, home) {
		t.Fatalf("root's own paths: %+v", p)
	}
	// Not through sudo at all, or a refusal: no fallback is signalled.
	if inv, rootOwn, err := SudoInvoker(envOf(map[string]string{"HOME": "/root"}), 0); inv != nil || rootOwn || err != nil {
		t.Fatalf("root login: %+v %v %v", inv, rootOwn, err)
	}
	lookupHome = known
	if _, rootOwn, err := SudoInvoker(sudo(me+1, nil), 0); rootOwn || err == nil {
		t.Fatalf("foreign owner must be an error, not a fallback: %v %v", rootOwn, err)
	}
	// No account entry for root: the platform's usual root home.
	lookupHome = unknown
	if p := RootPaths(); p.ConfigDir != "/root/.config/aqmas" && p.ConfigDir != "/var/root/.config/aqmas" {
		t.Fatalf("default root paths: %+v", p)
	}
}

// The root leg of `sudo aqmas upgrade` with a stand-in for taking root back: it happens exactly
// once, only after the release was verified against GitHub and the download was requested,
// and never for --check or a refused upgrade.
func TestUpgradeElevatesOnceAndLate(t *testing.T) {
	const binary = "new executable"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(binary)))
	sums := release.Sums{}
	for _, a := range release.Assets {
		sums[a] = digest
	}
	var events []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(release.Metadata{Version: "0.2.0", Commit: strings.Repeat("b", 40), GitHub: sums})
	})
	mux.HandleFunc("GET /v1/releases/0.2.0/{asset}", func(w http.ResponseWriter, r *http.Request) {
		events = append(events, "download")
		fmt.Fprint(w, binary)
	})
	bastion := httptest.NewServer(mux)
	defer bastion.Close()
	api := &APIClient{base: bastion.URL, http: bastion.Client(), maxRsp: 4096}
	old := installCheck
	t.Cleanup(func() { installCheck = old })
	installCheck = func(string) error { events = append(events, "install-check"); return nil }
	for _, tc := range []struct {
		name, sums, expect string
		check, ok          bool
		want               string
	}{
		{"installs", sums.Text(), digest, false, true, "install-check github download elevate"},
		{"check only", sums.Text(), "", true, true, "github"},
		{"GitHub disagrees", strings.Replace(sums.Text(), digest, strings.Repeat("a", 64), 1), digest, false, false, "install-check github"},
		{"wrong expected digest", sums.Text(), strings.Repeat("a", 64), false, false, "install-check github"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events = nil
			gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/releases/tags/v0.2.0":
					events = append(events, "github")
					fmt.Fprint(w, `{"tag_name":"v0.2.0","assets":[{"name":"SHA256SUMS","id":1}]}`)
				case "/releases/assets/1":
					fmt.Fprint(w, tc.sums)
				default:
					http.NotFound(w, r)
				}
			}))
			defer gh.Close()
			p := filepath.Join(t.TempDir(), "aqmas")
			if err := os.WriteFile(p, []byte("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			var log strings.Builder
			env := Env{Stderr: &log, Environ: func() []string { return nil }}
			env.Elevate = func() error {
				// Root is taken back while the installed executable is still the old one.
				if b, _ := os.ReadFile(p); string(b) != "old" {
					t.Error("elevated after the executable was replaced")
				}
				events = append(events, "elevate")
				return nil
			}
			err := env.upgrade(t.Context(), api, release.Source{API: gh.URL}, p, "0.1.9", tc.check, !tc.check, false, tc.expect, false)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v\n%s", err, log.String())
			}
			if got := strings.Join(events, " "); got != tc.want {
				t.Fatalf("order: %q, want %q", got, tc.want)
			}
			after, _ := os.ReadFile(p)
			if installed := string(after) == binary; installed != (tc.want == "install-check github download elevate") {
				t.Fatalf("installed=%v", installed)
			}
		})
	}
	// Taking root back fails: nothing is installed.
	events = nil
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/tags/v0.2.0" {
			fmt.Fprint(w, `{"tag_name":"v0.2.0","assets":[{"name":"SHA256SUMS","id":1}]}`)
			return
		}
		fmt.Fprint(w, sums.Text())
	}))
	defer gh.Close()
	p := filepath.Join(t.TempDir(), "aqmas")
	if err := os.WriteFile(p, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := Env{Stderr: &strings.Builder{}, Environ: func() []string { return nil }, Elevate: func() error { return errors.New("no root") }}
	if err := env.upgrade(t.Context(), api, release.Source{API: gh.URL}, p, "0.1.9", false, true, false, digest, false); err == nil || !strings.Contains(err.Error(), "no root") {
		t.Fatalf("failed elevation: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatal("installed without root")
	}
}

// A Debian-style root:staff 2775 directory is refused with the reason and the alternative.
func TestRootControlledSaysWhy(t *testing.T) {
	dir := t.TempDir() // owned by the test's user
	err := rootControlled(dir)
	if os.Geteuid() != 0 {
		if err == nil || !strings.Contains(err.Error(), "is not owned by root") {
			t.Fatalf("user-owned directory: %v", err)
		}
		return
	}
	if err := os.Chmod(dir, 0o2775); err != nil {
		t.Fatal(err)
	}
	if err = rootControlled(dir); err == nil || !strings.Contains(err.Error(), "is writable by") || !strings.Contains(err.Error(), "~/.local/bin") {
		t.Fatalf("group-writable directory: %v", err)
	}
}

// An install directory this user cannot write stops the upgrade before GitHub is asked and
// before the executable is downloaded, with the one way forward.
func TestUpgradeSystemInstallFailsEarly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	sums := release.Sums{}
	for _, a := range release.Assets {
		sums[a] = strings.Repeat("a", 64)
	}
	var assets, github int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(release.Metadata{Version: "0.2.0", Commit: strings.Repeat("b", 40), GitHub: sums})
	})
	mux.HandleFunc("GET /v1/releases/0.2.0/{asset}", func(w http.ResponseWriter, r *http.Request) { assets++ })
	bastion := httptest.NewServer(mux)
	defer bastion.Close()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { github++; http.NotFound(w, r) }))
	defer gh.Close()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "aqmas")
	if err := os.WriteFile(p, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	var log strings.Builder
	env := Env{StdinIsTTY: true, Stdin: strings.NewReader("y\n"), Stderr: &log, Environ: func() []string { return nil }, User: "alice"}
	api := &APIClient{base: bastion.URL, http: bastion.Client(), maxRsp: 4096}
	err := env.upgrade(t.Context(), api, release.Source{API: gh.URL}, p, "0.1.9", false, false, false, "", true)
	if err == nil || !strings.Contains(err.Error(), "system-wide install") || !strings.Contains(err.Error(), "sudo "+p+" upgrade") || !strings.Contains(err.Error(), "nothing was downloaded") {
		t.Fatalf("error: %v", err)
	}
	if assets != 0 || github != 0 {
		t.Fatalf("asked for %d assets and GitHub %d times before refusing", assets, github)
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatal("executable changed")
	}
	// --check never installs, so it is not refused for the directory.
	if err := env.upgrade(t.Context(), api, release.Source{API: gh.URL}, p, "0.1.9", true, false, false, "", true); err == nil || strings.Contains(err.Error(), "system-wide") {
		t.Fatalf("--check: %v", err)
	}
}

// With root given up, taking it back and what the process may touch in between: run only as
// root under sudo (`sudo ./client.test -test.run TestSudoDropAndElevate`), skipped otherwise.
func TestSudoDropAndElevate(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SUDO_UID") == "" || os.Getenv("SUDO_UID") == "0" {
		t.Skip("needs root through sudo")
	}
	uid, _ := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
	rootOnly := filepath.Join(t.TempDir(), "root-only")
	if err := os.WriteFile(rootOnly, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := &Invoker{UID: uid, GID: gid, Name: "invoker", Home: "/nonexistent"}
	elevate, err := inv.Drop()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		t.Fatalf("after Drop: euid %d egid %d", os.Geteuid(), os.Getegid())
	}
	if gs, _ := os.Getgroups(); len(gs) != 1 || gs[0] != gid {
		t.Fatalf("supplementary groups after Drop: %v", gs)
	}
	if _, err := os.ReadFile(rootOnly); err == nil {
		t.Fatal("read a root-only file after giving up root")
	}
	if err := elevate(); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Fatal("root not restored")
	}
	if _, err := os.ReadFile(rootOnly); err != nil {
		t.Fatal(err)
	}
}
