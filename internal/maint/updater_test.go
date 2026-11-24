package maint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/release"
)

// The installer's check of the rebuilt binaries (the check-assets block of updater.sh), run
// on its own with the sandbox replaced by env: SHA256SUMS.extra cannot be dropped from the
// approved metadata of a release that builds one, and must match the rebuilt tree's own.
func TestUpdaterChecksExtraSums(t *testing.T) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	begin, end := strings.Index(updaterScript, "# BEGIN check-assets"), strings.Index(updaterScript, "# END check-assets")
	if begin < 0 || end < begin {
		t.Fatal("check-assets markers missing from updater.sh")
	}
	block := updaterScript[begin:end]
	hash := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	run := func(t *testing.T, withExtraFile bool, extra map[string]string, builtExtra string) (string, error) {
		dir := t.TempDir()
		dist, out := filepath.Join(dir, "dist"), filepath.Join(dir, "out")
		for _, d := range []string{dist, out} {
			if err := os.Mkdir(d, 0700); err != nil {
				t.Fatal(err)
			}
		}
		gh := map[string]string{}
		for _, a := range append(release.Assets[:], release.DarwinAMD) {
			body := []byte("built " + a)
			if err := os.WriteFile(filepath.Join(dist, a), body, 0644); err != nil {
				t.Fatal(err)
			}
			if a != release.DarwinAMD {
				gh[a] = hash(body)
			}
		}
		if withExtraFile {
			if builtExtra == "" {
				builtExtra = release.Sums{release.DarwinAMD: hash([]byte("built " + release.DarwinAMD))}.ExtraText()
			}
			if err := os.WriteFile(filepath.Join(dist, release.ExtraSums), []byte(builtExtra), 0644); err != nil {
				t.Fatal(err)
			}
		}
		meta := map[string]any{"version": "0.9.3", "github": gh}
		if extra != nil {
			meta["extra"] = extra
		}
		b, _ := json.Marshal(meta)
		if err := os.WriteFile(filepath.Join(out, "metadata"), b, 0600); err != nil {
			t.Fatal(err)
		}
		prelude := "set -euo pipefail\nout=" + out + "\ndist=" + dist + "\nv=0.9.3\nbox=(env)\nstatus() { :; }\n"
		c := exec.Command("bash", "-c", prelude+block)
		o, err := c.CombinedOutput()
		return string(o), err
	}
	good := map[string]string{release.DarwinAMD: hash([]byte("built " + release.DarwinAMD))}

	if o, err := run(t, true, good, ""); err != nil {
		t.Fatalf("approved extra refused: %v %s", err, o)
	}
	if o, err := run(t, false, nil, ""); err != nil {
		t.Fatalf("a release without SHA256SUMS.extra (before 0.9.3) refused: %v %s", err, o)
	}
	if o, err := run(t, true, nil, ""); err == nil || !strings.Contains(o, "no extra digests") {
		t.Fatalf("metadata stripped of extra accepted: %v %s", err, o)
	}
	if o, err := run(t, true, map[string]string{release.DarwinAMD: strings.Repeat("0", 64)}, ""); err == nil {
		t.Fatalf("a different extra digest accepted: %s", o)
	}
	other := strings.Repeat("1", 64) + "  " + release.DarwinAMD + "\n"
	if o, err := run(t, true, good, other); err == nil || !strings.Contains(o, "differs from the approved") {
		t.Fatalf("a rebuilt SHA256SUMS.extra that differs accepted: %v %s", err, o)
	}
}
