package release

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateAttachmentTokenBoundary(t *testing.T) {
	sums := Sums{}
	for _, a := range Assets {
		sums[a] = strings.Repeat("0", 64)
	}
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("token reached storage")
		}
		fmt.Fprint(w, sums.Text())
	}))
	defer storage.Close()
	const id = "00000000-0000-0000-0000-000000000001"
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture" {
			http.Error(w, "denied", 401)
			return
		}
		switch r.URL.Path {
		case "/api/v1/repos/example/aqmas/releases/tags/v1.0.0":
			fmt.Fprintf(w, `{"tag_name":"v1.0.0","assets":[{"name":"SHA256SUMS","id":1,"uuid":%q,"browser_download_url":"https://example.com/untrusted"}]}`, id)
		case "/attachments/" + id:
			http.Redirect(w, r, storage.URL, 302)
		default:
			t.Error("unexpected path", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer forge.Close()
	source := Source{API: forge.URL + "/api/v1/repos/example/aqmas"}
	if _, e := source.Hashes(t.Context(), "1.0.0", false); e == nil {
		t.Fatal("missing credential accepted")
	}
	source.TokenFile = filepath.Join(t.TempDir(), "token")
	os.WriteFile(source.TokenFile, []byte("fixture"), 0600)
	got, e := source.Hashes(t.Context(), "1.0.0", false)
	if e != nil || !sums.Agrees(got) {
		t.Fatal(e)
	}
}
