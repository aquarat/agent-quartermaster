package client

import (
	"encoding/json"
	"errors"
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
		if inv, err := SudoInvoker(c.env, c.euid); inv != nil || err != nil {
			t.Fatalf("%s: %+v %v", name, inv, err)
		}
	}

	// The usual case: HOME was reset to root's, the account database gives the user's home.
	inv, err := SudoInvoker(sudo(me, nil), 0)
	if err != nil || inv == nil || inv.UID != me || inv.GID != 100 || inv.Name != "alice" || inv.Home != home ||
		inv.ConfigDir != cfgDir || inv.CacheDir != filepath.Join(home, ".cache", "aqmas") || inv.Paths().ConfigDir != cfgDir {
		t.Fatalf("resolved %+v %v", inv, err)
	}
	// Someone else's directory is refused, not skipped: uid me+1 "ran sudo", the directory is mine.
	if inv, err := SudoInvoker(sudo(me+1, nil), 0); inv != nil || err == nil || !strings.Contains(err.Error(), "is not owned by alice") {
		t.Fatalf("foreign owner: %+v %v", inv, err)
	}
	// No SUDO_GID: refused.
	if _, err := SudoInvoker(envOf(map[string]string{"SUDO_UID": strconv.Itoa(me)}), 0); err == nil {
		t.Fatal("missing SUDO_GID accepted")
	}
	// A symlink in place of the directory is refused.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(cfgDir, link); err != nil {
		t.Fatal(err)
	}
	if inv, err := SudoInvoker(sudo(me, map[string]string{"AQMAS_CONFIG_DIR": link}), 0); inv != nil || err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlinked config directory: %+v %v", inv, err)
	}
	// An explicit AQMAS_CONFIG_DIR is used as given (and checked the same way).
	other := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if inv, err := SudoInvoker(sudo(me, map[string]string{"AQMAS_CONFIG_DIR": other}), 0); err != nil || inv == nil || inv.ConfigDir != other {
		t.Fatalf("explicit directory: %+v %v", inv, err)
	}

	// No account database entry: sudo's HOME counts only when it is that user's directory.
	lookupHome = unknown
	if inv, err := SudoInvoker(sudo(me, map[string]string{"HOME": home}), 0); err != nil || inv == nil || inv.Home != home || inv.Name != "alice" {
		t.Fatalf("HOME fallback: %+v %v", inv, err)
	}
	if inv, err := SudoInvoker(sudo(me+1, map[string]string{"HOME": home}), 0); inv != nil || err == nil || !strings.Contains(err.Error(), "cannot find the home directory") {
		t.Fatalf("HOME of another user: %+v %v", inv, err)
	}

	// The invoking user is not enrolled: root's own enrolment, as before.
	lookupHome = func(int) (string, string, error) { return "alice", t.TempDir(), nil }
	if inv, err := SudoInvoker(sudo(me, nil), 0); inv != nil || err != nil {
		t.Fatalf("not enrolled: %+v %v", inv, err)
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
