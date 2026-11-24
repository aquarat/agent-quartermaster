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

// A macOS x86-64 CLI takes its digest from the record's "extra" member and checks it against
// GitHub's SHA256SUMS.extra as well as SHA256SUMS.
func TestUpgradeDarwinAMD64UsesExtraSums(t *testing.T) {
	const binary = "new darwin amd64 executable"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(binary)))
	sums := release.Sums{}
	for _, a := range release.Assets {
		sums[a] = strings.Repeat("1", 64)
	}
	extra := release.Sums{release.DarwinAMD: digest}
	for _, tc := range []struct {
		name          string
		record, ghExt release.Sums // the bastion's "extra", GitHub's SHA256SUMS.extra (nil: none published)
		errHas        string
	}{
		{"agree", extra, extra, ""},
		{"GitHub differs", extra, release.Sums{release.DarwinAMD: strings.Repeat("2", 64)}, "SHA256SUMS.extra disagree"},
		{"GitHub has none", extra, nil, "SHA256SUMS.extra disagree"},
		{"bastion has no record yet", nil, extra, "SHA256SUMS.extra disagree"},
		{"neither", nil, nil, "no verified record of aqmas-darwin-amd64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := release.Metadata{Version: "0.2.0", Commit: strings.Repeat("b", 40), GitHub: sums, Extra: tc.record}
			mux := http.NewServeMux()
			mux.HandleFunc("GET /v1/releases/latest", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(m) })
			var asked string
			mux.HandleFunc("GET /v1/releases/0.2.0/{asset}", func(w http.ResponseWriter, r *http.Request) { asked = r.PathValue("asset"); fmt.Fprint(w, binary) })
			bastion := httptest.NewServer(mux)
			defer bastion.Close()
			gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/releases/tags/v0.2.0":
					assets := `{"name":"SHA256SUMS","id":1}`
					if tc.ghExt != nil {
						assets += `,{"name":"SHA256SUMS.extra","id":2}`
					}
					fmt.Fprintf(w, `{"tag_name":"v0.2.0","assets":[%s]}`, assets)
				case "/releases/assets/1":
					fmt.Fprint(w, sums.Text())
				case "/releases/assets/2":
					fmt.Fprint(w, tc.ghExt.ExtraText())
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
			env := Env{StdinIsTTY: true, Stdin: strings.NewReader(""), Stderr: &log, Environ: func() []string { return nil }, goos: "darwin", goarch: "amd64"}
			api := &APIClient{base: bastion.URL, http: bastion.Client(), maxRsp: 4096}
			err := env.upgrade(t.Context(), api, release.Source{API: gh.URL}, p, "0.1.9", false, true, false, digest, true)
			after, _ := os.ReadFile(p)
			if tc.errHas == "" {
				if err != nil || string(after) != binary || asked != release.DarwinAMD || !strings.Contains(log.String(), digest) {
					t.Fatalf("err=%v asked=%q after=%q log=%s", err, asked, after, &log)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.errHas) || string(after) != "old" {
				t.Fatalf("want %q, got %v (executable %q)", tc.errHas, err, after)
			}
		})
	}
}
