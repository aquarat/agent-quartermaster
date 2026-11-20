package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/release"
)

func TestUpgradeVerifiesBeforeReplacing(t *testing.T) {
	const binary = "new executable"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(binary)))
	sums := release.Sums{}
	for _, a := range release.Assets {
		sums[a] = digest
	}
	m := release.Metadata{Version: "0.2.0", Commit: strings.Repeat("b", 40), Forgejo: sums, GitHub: sums}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/releases/latest", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(m) })
	mux.HandleFunc("GET /v1/releases/0.2.0/{asset}", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, binary) })
	bastion := httptest.NewServer(mux)
	defer bastion.Close()
	api := &APIClient{base: bastion.URL, http: bastion.Client(), maxRsp: 4096}
	for _, tc := range []struct {
		name, sums, reply, expect string
		yes, agent, ok            bool
	}{{"mismatch", strings.Replace(sums.Text(), digest, strings.Repeat("a", 64), 1), "y\n", "", false, false, false}, {"broken manifest", "bad", "y\n", "", false, false, false}, {"declined", sums.Text(), "n\n", "", false, false, false}, {"agent", sums.Text(), "y\n", "", false, true, false}, {"wrong pin", sums.Text(), "", strings.Repeat("a", 64), true, false, false}, {"confirmed", sums.Text(), "y\n", "", false, false, true}, {"expected", sums.Text(), "", digest, true, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/releases/tags/v0.2.0":
					fmt.Fprint(w, `{"tag_name":"v0.2.0","assets":[{"name":"SHA256SUMS","id":1}]}`)
				case "/releases/assets/1":
					fmt.Fprint(w, tc.sums)
				default:
					http.NotFound(w, r)
				}
			}))
			defer gh.Close()
			p := filepath.Join(t.TempDir(), "aqmas")
			if e := os.WriteFile(p, []byte("old"), 0755); e != nil {
				t.Fatal(e)
			}
			var log bytes.Buffer
			env := Env{StdinIsTTY: true, Stdin: strings.NewReader(tc.reply), Stderr: &log, Environ: func() []string {
				if tc.agent {
					return []string{"OPENCODE_X=1"}
				}
				return nil
			}}
			err := env.upgrade(t.Context(), api, release.Source{API: gh.URL}, p, "0.1.9", false, tc.yes, true, tc.expect, true)
			if (err == nil) != tc.ok {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(p)
			backup, be := os.ReadFile(p + ".prev")
			if tc.ok {
				if string(after) != binary || string(backup) != "old" || !strings.Contains(log.String(), digest) {
					t.Fatal("bad replacement")
				}
			} else if string(after) != "old" || !os.IsNotExist(be) {
				t.Fatal("changed executable after refusal")
			}
		})
	}
}
func TestReplaceRejectsBadBytes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "aqmas")
	os.WriteFile(p, []byte("keep"), 0755)
	fi, _ := os.Stat(p)
	if err := replaceBinary(p, fi, strings.NewReader("bad"), strings.Repeat("0", 64), func() bool { t.Fatal("prompted for invalid bytes"); return false }); err == nil {
		t.Fatal("accepted bad bytes")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "keep" {
		t.Fatal("damaged old binary")
	}
}

func TestPackageManagerChangedInstall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aqmas")
	os.WriteFile(path, []byte("original"), 0755)
	original, _ := os.Stat(path)
	newer := filepath.Join(dir, "replacement")
	os.WriteFile(newer, []byte("external"), 0755)
	err := replaceBinary(path, original, strings.NewReader("candidate"), fmt.Sprintf("%x", sha256.Sum256([]byte("candidate"))), func() bool {
		if err := os.Rename(newer, path); err != nil {
			t.Fatal(err)
		}
		return true
	})
	b, _ := os.ReadFile(path)
	if err == nil || string(b) != "external" {
		t.Fatal("overwrote concurrent update")
	}
	if _, err = os.Stat(path + ".prev"); !os.IsNotExist(err) {
		t.Fatal("changed backup")
	}
}
