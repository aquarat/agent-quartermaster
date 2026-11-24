package release

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fakeExtraSource serves any release version with SHA256SUMS and, when extra() is not "", a
// SHA256SUMS.extra, in GitHub's API shape or the Forgejo/Gitea one.
func fakeExtraSource(t *testing.T, github bool, sums, extra func() string) *httptest.Server {
	t.Helper()
	const id1, id2 = "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/releases/tags/v"):
			_, tag, _ := strings.Cut(r.URL.Path, "/releases/tags/")
			assets := fmt.Sprintf(`{"name":"SHA256SUMS","id":1,"uuid":%q}`, id1)
			if extra() != "" {
				assets += fmt.Sprintf(`,{"name":%q,"id":2,"uuid":%q}`, ExtraSums, id2)
			}
			fmt.Fprintf(w, `{"tag_name":%q,"assets":[%s]}`, tag, assets)
		case github && strings.HasSuffix(r.URL.Path, "/releases/assets/1"), !github && r.URL.Path == "/attachments/"+id1:
			fmt.Fprint(w, sums())
		case github && strings.HasSuffix(r.URL.Path, "/releases/assets/2"), !github && r.URL.Path == "/attachments/"+id2:
			fmt.Fprint(w, extra())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testExtra(c string) Sums { return Sums{DarwinAMD: strings.Repeat(c, 64)} }

func TestExtraManifest(t *testing.T) {
	e := testExtra("a")
	text := e.ExtraText()
	if text != strings.Repeat("a", 64)+"  aqmas-darwin-amd64\n" {
		t.Fatalf("%q", text)
	}
	if got, err := ParseExtra([]byte(text)); err != nil || len(got) != 1 || got[DarwinAMD] != strings.Repeat("a", 64) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", text + text, strings.Replace(text, "  ", " *", 1), strings.ToUpper(text), testSums("a").Text(), text + testSums("a").Text()} {
		if _, err := ParseExtra([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// SHA256SUMS itself never gains the line: the strict parser (that of 0.9.0-0.9.2, which
	// is still Parse) refuses it, so a manifest with it would stop every older broker.
	if _, err := Parse([]byte(testSums("a").Text() + text)); err == nil {
		t.Fatal("Parse accepted a fifth SHA256SUMS line")
	}
}

// The release build writes SHA256SUMS with exactly the four names Parse (unchanged since
// 0.9.0) accepts, and every later build into SHA256SUMS.extra.
func TestMakefileManifests(t *testing.T) {
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	names := func(file string) []string {
		m := regexp.MustCompile(`(?m)^\tcd dist && sha256sum ([a-z0-9 -]+) > ` + regexp.QuoteMeta(file) + `$`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("no sha256sum line for %s", file)
		}
		return strings.Fields(string(m[1]))
	}
	if got := names("SHA256SUMS"); !slices.Equal(got, Assets[:]) {
		t.Fatalf("SHA256SUMS lists %v, want %v", got, Assets)
	}
	if got := names(ExtraSums); !slices.Equal(got, ExtraAssets[:]) {
		t.Fatalf("%s lists %v, want %v", ExtraSums, got, ExtraAssets)
	}
	for _, a := range CLIAssets {
		if !strings.Contains(string(b), "-o bin/"+a+" ./cmd/aqmas") {
			t.Fatalf("make build does not build %s", a)
		}
	}
}

func TestSourcesFillExtra(t *testing.T) {
	good := testSums("a")
	ghExtra, secondExtra := testExtra("e").ExtraText(), testExtra("e").ExtraText()
	gh := fakeExtraSource(t, true, func() string { return good.Text() }, func() string { return ghExtra })
	forge := fakeExtraSource(t, false, func() string { return good.Text() }, func() string { return secondExtra })
	only := Sources{GitHub: Source{API: gh.URL + "/repos/example/aqmas"}}
	both := Sources{GitHub: only.GitHub, Second: Source{API: forge.URL + "/api/v1/repos/example/aqmas"}}
	m := Metadata{Version: "1.0.0", Commit: strings.Repeat("c", 40)}

	if err := only.Fill(t.Context(), &m); err != nil || !m.Valid() || m.Hash(DarwinAMD) != strings.Repeat("e", 64) || m.Hash("aqmas-linux-arm64") != strings.Repeat("a", 64) {
		t.Fatalf("GitHub only: %v %+v", err, m)
	}
	if err := both.Fill(t.Context(), &m); err != nil || !m.Valid() || m.Compared() != 2 || m.Hash(DarwinAMD) == "" {
		t.Fatalf("two agreeing sources: %v %+v", err, m)
	}
	// A release before 0.9.3 has no such file at any source: no extra hashes.
	ghExtra, secondExtra = "", ""
	for _, v := range []string{"0.9.2", "0.8.10"} {
		old := Metadata{Version: v, Commit: m.Commit}
		if err := both.Fill(t.Context(), &old); err != nil || !old.Valid() || old.Extra != nil || old.Hash(DarwinAMD) != "" {
			t.Fatalf("%s without SHA256SUMS.extra: %v %+v", v, err, old)
		}
	}
	// From 0.9.3 on the file is required: stripping it is refused, not read as "no extras".
	for _, v := range []string{"0.9.3", "0.10.0", "1.0.0"} {
		if !NeedsExtra(v) {
			t.Fatalf("NeedsExtra(%s) = false", v)
		}
		stripped := Metadata{Version: v, Commit: m.Commit}
		if err := both.Fill(t.Context(), &stripped); err == nil || !strings.Contains(err.Error(), "has no SHA256SUMS.extra") {
			t.Fatalf("%s without SHA256SUMS.extra accepted: %v", v, err)
		}
	}
	// One source has it and the other not, or they differ: a disagreement.
	for _, c := range [][2]string{{testExtra("e").ExtraText(), ""}, {"", testExtra("e").ExtraText()}, {testExtra("e").ExtraText(), testExtra("f").ExtraText()}} {
		ghExtra, secondExtra = c[0], c[1]
		if err := both.Fill(t.Context(), &m); err == nil || !strings.Contains(err.Error(), "disagree") && !strings.Contains(err.Error(), "GitHub: release 1.0.0 has no") {
			t.Fatalf("%q vs %q accepted: %v", c[0], c[1], err)
		}
	}
	// A malformed file is an error, not an absent one.
	ghExtra = good.Text()
	if err := only.Fill(t.Context(), &m); err == nil {
		t.Fatal("malformed SHA256SUMS.extra accepted")
	}
}

func TestMetadataExtraRecord(t *testing.T) {
	commit := strings.Repeat("c", 40)
	m := Metadata{Version: "1.0.0", Commit: commit, GitHub: testSums("a"), Extra: testExtra("e")}
	for _, wire := range func() [][]byte { a, _ := json.Marshal(m); b, _ := m.LegacyJSON(); return [][]byte{a, b} }() {
		var back Metadata
		if err := json.Unmarshal(wire, &back); err != nil || !back.Valid() || back.Hash(DarwinAMD) != strings.Repeat("e", 64) {
			t.Fatalf("round trip %s: %v %+v", wire, err, back)
		}
		// A 0.9.2 reader knows only github/second: the GitHub manifest it checks is unchanged.
		var old struct{ GitHub Sums }
		if err := json.Unmarshal(wire, &old); err != nil || !old.GitHub.Valid() {
			t.Fatalf("old reader: %s", wire)
		}
	}
	for _, bad := range []Sums{{}, {DarwinAMD: "x"}, {DarwinAMD: strings.Repeat("e", 64), "aqmas-linux-arm64": strings.Repeat("e", 64)}} {
		if (Metadata{Version: "1.0.0", Commit: commit, GitHub: testSums("a"), Extra: bad}).Valid() {
			t.Fatalf("invalid extra %v accepted", bad)
		}
	}
}
