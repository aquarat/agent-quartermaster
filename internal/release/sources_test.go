package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSums(c string) Sums {
	s := Sums{}
	for _, a := range Assets {
		s[a] = strings.Repeat(c, 64)
	}
	return s
}

// fakeSource serves one release in GitHub's API shape or in the Forgejo/Gitea shape.
func fakeSource(t *testing.T, github bool, sums func() string) *httptest.Server {
	t.Helper()
	const id = "00000000-0000-0000-0000-000000000001"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/tags/v1.0.0"):
			fmt.Fprintf(w, `{"tag_name":"v1.0.0","assets":[{"name":"SHA256SUMS","id":1,"uuid":%q}]}`, id)
		case github && strings.HasSuffix(r.URL.Path, "/releases/assets/1"), !github && r.URL.Path == "/attachments/"+id:
			fmt.Fprint(w, sums())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSourcesFill(t *testing.T) {
	good, other := testSums("a"), testSums("a")
	other[Daemon] = strings.Repeat("b", 64)
	second := good
	gh := fakeSource(t, true, func() string { return good.Text() })
	forge := fakeSource(t, false, func() string { return second.Text() })

	only := Sources{GitHub: Source{API: gh.URL + "/repos/example/aqmas"}}
	m := Metadata{Version: "1.0.0", Commit: strings.Repeat("c", 40)}
	if e := only.Fill(t.Context(), &m); e != nil || !m.Valid() || m.Second != nil || m.Compared() != 1 || strings.Join(only.Names(), ",") != "GitHub" {
		t.Fatalf("GitHub only: %v %+v", e, m)
	}

	both := Sources{GitHub: only.GitHub, Second: Source{API: forge.URL + "/api/v1/repos/example/aqmas"}}
	host := strings.TrimPrefix(forge.URL, "http://")
	if e := both.Fill(t.Context(), &m); e != nil || !m.Valid() || m.Compared() != 2 || both.Names()[1] != "second source ("+host+")" {
		t.Fatalf("two agreeing sources: %v %+v", e, m)
	}
	second = other
	if e := both.Fill(t.Context(), &m); e == nil || !strings.Contains(e.Error(), "disagree") {
		t.Fatalf("disagreeing second source accepted: %v", e)
	}
	second = good
	// Unreachable (a closed port): there is no fallback to GitHub alone.
	forge.Close()
	if e := both.Fill(t.Context(), &m); e == nil || !errors.Is(e, ErrOffline) || !strings.Contains(e.Error(), "second source (") {
		t.Fatalf("unreachable second source: %v", e)
	}
	// A second source without an address is not a source; asking it directly is an error.
	if _, e := (Source{}).Hashes(t.Context(), "1.0.0", false); e == nil || !strings.Contains(e.Error(), "no second release source") {
		t.Fatalf("an unconfigured second source answered: %v", e)
	}
}

func TestMetadataRecords(t *testing.T) {
	s := testSums("a")
	commit := strings.Repeat("c", 40)
	text := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	one, two := Metadata{Version: "1.0.0", Commit: commit, GitHub: s}, Metadata{Version: "1.0.0", Commit: commit, GitHub: s, Second: maps.Clone(s)}
	if got := text(one); strings.Contains(got, "second") || strings.Contains(got, "forgejo") || !strings.Contains(got, `"sources":1`) {
		t.Fatal(got)
	}
	for _, m := range []Metadata{one, two} {
		var back Metadata
		if e := json.Unmarshal([]byte(text(m)), &back); e != nil || !back.Valid() || back.Compared() != m.Compared() {
			t.Fatalf("round trip of %d sources: %v %+v", m.Compared(), e, back)
		}
		// What a 0.8.1 CLI is sent: it reads "forgejo" and "github" and needs them equal.
		wire, _ := m.LegacyJSON()
		var old struct {
			Version, Commit string
			Forgejo, GitHub Sums
		}
		if e := json.Unmarshal(wire, &old); e != nil || old.Version != "1.0.0" || !old.Forgejo.Agrees(old.GitHub) {
			t.Fatalf("a 0.8.1 reader refuses %s", wire)
		}
		// A current reader is not misled by the duplicate into counting a second source.
		if e := json.Unmarshal(wire, &back); e != nil || !back.Valid() || back.Compared() != m.Compared() {
			t.Fatalf("current reader of the legacy wire form: %v %+v", e, back)
		}
	}
	// A record written by 0.8.1 (latest.json, the rollback journal, an old bastion's reply).
	var legacy Metadata
	if e := json.Unmarshal([]byte(`{"version":"1.0.0","commit":"`+commit+`","forgejo":`+text(s)+`,"github":`+text(s)+`}`), &legacy); e != nil || !legacy.Valid() || legacy.Compared() != 2 {
		t.Fatalf("legacy record: %v %+v", e, legacy)
	}
	other := maps.Clone(s)
	other[Daemon] = strings.Repeat("b", 64)
	for name, bad := range map[string]string{
		"legacy disagreement": `{"version":"1.0.0","commit":"` + commit + `","forgejo":` + text(other) + `,"github":` + text(s) + `}`,
		"second disagreement": text(Metadata{Version: "1.0.0", Commit: commit, GitHub: s, Second: other}),
		"no github":           `{"version":"1.0.0","commit":"` + commit + `","second":` + text(s) + `,"sources":2}`,
	} {
		var m Metadata
		if e := json.Unmarshal([]byte(bad), &m); e == nil && m.Valid() {
			t.Errorf("%s accepted", name)
		}
	}
	for name, bad := range map[string]string{
		"counts a missing source": `{"version":"1.0.0","commit":"` + commit + `","github":` + text(s) + `,"sources":2}`,
		"hides a source":          `{"version":"1.0.0","commit":"` + commit + `","github":` + text(s) + `,"second":` + text(s) + `,"sources":1}`,
	} {
		var m Metadata
		if e := json.Unmarshal([]byte(bad), &m); e == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestAddressShapes(t *testing.T) {
	for _, ok := range []string{"https://api.github.com/repos/a/b", "https://forge.example.com/api/v1/repos/a/b", "https://forge.example.com:8443/api/v1/repos/a/b", "http://127.0.0.1:9/x"} {
		if !ValidAPI(ok) {
			t.Errorf("refused %s", ok)
		}
	}
	for _, bad := range []string{"", "http://forge.example.com/api/v1/repos/a/b", "https://user:pw@forge.example.com/api/v1/repos/a/b", "https://token@forge.example.com/api/v1/repos/a/b",
		"https://forge.example.com/api/v1/repos/a/b?x=1", "https://forge.example.com/api/v1/repos/a/b#x", "https://forge.example.com/api/v1/repos/../b", "https://forge.example.com", "ftp://forge.example.com/a",
		"https://forge.example.com/" + strings.Repeat("a", 512), "https://forge.example.com/a b"} {
		if ValidAPI(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	for repo, want := range map[string]string{
		"https://github.com/a/b.git": "https", "ssh://git@forge.example.com:2222/a/b.git": "ssh", "http://127.0.0.1:8080/a/b.git": "http",
		"http://github.com/a/b.git": "", "https://user:pw@github.com/a/b.git": "", "https://token@github.com/a/b.git": "", "ssh://git:pw@forge.example.com/a/b.git": "",
		"https://github.com/a/b": "", "git://github.com/a/b.git": "", "file:///srv/a.git": "", "https://github.com/a/../b.git": "", "ext::sh -c id.git": "", "https://github.com/" + strings.Repeat("a", 300) + ".git": "",
	} {
		if got := GitProtocol(repo); got != want {
			t.Errorf("%s: %q, want %q", repo, got, want)
		}
	}
	for api, want := range map[string]string{"": GitHubRepo, GitHubAPI: GitHubRepo, "https://api.github.com/repos/example/fork": "https://github.com/example/fork.git", "https://ghe.example.com/api/v3/repos/a/b": GitHubRepo} {
		if got := RepoFor(api); got != want {
			t.Errorf("RepoFor(%q) = %q", api, got)
		}
	}
	if GitProtocol(GitHubRepo) != "https" || !ValidAPI(GitHubAPI) {
		t.Fatal("the compiled defaults are not acceptable sources")
	}
}

// The second release source of the first installation is private: its host name, and that
// installation's domain, may not appear anywhere in the tree. (`make check-private` asks
// git the same question; this walk also covers files that are not committed yet.)
func TestNoPrivateHostInTree(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("not in a source tree")
	}
	private := []byte("example" + ".invalid")
	skip := map[string]bool{".git": true, "node_modules": true, "dist": true, "bin": true}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if info, e := d.Info(); e != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return nil
		}
		b, e := os.ReadFile(path)
		if e == nil && strings.Contains(strings.ToLower(string(b)), string(private)) {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s names the private host", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
