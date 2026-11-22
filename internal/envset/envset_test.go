package envset

import (
	"bytes"
	"slices"
	"testing"
)

func TestDraftCommitmentPinsExactEdit(t *testing.T) {
	b := Binding{Org: "org", Service: "svc", Set: "set", Revision: 3}
	e := Edit{Op: "import", Salt: bytes.Repeat([]byte{1}, 32), Entries: []Entry{{"APP_TOKEN", "a=b"}, {"APP_URL", "https://example.invalid"}}}
	want, err := e.Commit(b)
	if err != nil {
		t.Fatal(err)
	}
	e.Entries[0], e.Entries[1] = e.Entries[1], e.Entries[0]
	if v, _ := e.Commit(b); v != want {
		t.Fatal("order changed commitment")
	}
	for _, f := range []func(*Edit, *Binding){func(x *Edit, _ *Binding) { x.Salt[0] ^= 1 }, func(x *Edit, _ *Binding) { x.Entries[0].Value += "x" }, func(_ *Edit, x *Binding) { x.Set += "x" }, func(_ *Edit, x *Binding) { x.Revision++ }} {
		x, y := e, b
		x.Salt = slices.Clone(e.Salt)
		x.Entries = slices.Clone(e.Entries)
		f(&x, &y)
		if v, _ := x.Commit(y); v == want {
			t.Fatal("unbound edit")
		}
	}
	ops, _ := e.Changes([]string{"OLD_TOKEN", "APP_URL"})
	if ops != "APP_TOKEN:add,APP_URL:replace,OLD_TOKEN:remove" {
		t.Fatal(ops)
	}
}
func TestLiteralRefusalsDoNotEcho(t *testing.T) {
	for _, s := range []string{"PATH=sentinel", "APP_TOKEN='sentinel", "APP_TOKEN=\"sentinel\\x\"", "APP_TOKEN='sentinel' trailing", "APP_TOKEN=\"sentinel${HOME}\\", "APP_TOKEN=$(sentinel)", "APP_TOKEN=sentinel\nAPP_TOKEN=sentinel"} {
		if _, err := ParseFile([]byte(s)); err == nil || bytes.Contains([]byte(err.Error()), []byte("sentinel")) {
			t.Fatal("bad literal handling")
		}
	}
	for _, k := range []string{"LD_PRELOAD", "DYLD_LIBRARY_PATH", "BASH_ENV", "PROMPT_COMMAND", "AQMAS_CONFIG_DIR", "GIT_CONFIG_KEY", "ZDOTDIR"} {
		if SafeName(k) {
			t.Fatalf("unsafe key %s", k)
		}
	}
}

func TestMergeEditAndQuotedDotenv(t *testing.T) {
	b := Binding{Org: "org", Service: "svc", Set: "set", Revision: 3}
	pem := "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"
	e := Edit{Op: "merge", Salt: bytes.Repeat([]byte{2}, 32), Entries: []Entry{{"APP_KEY", pem}}, Remove: []string{"OLD_TOKEN"}}
	want, err := e.Commit(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []func(*Edit){func(x *Edit) { x.Remove = nil }, func(x *Edit) { x.Remove = []string{"OLD_KEY"} }, func(x *Edit) { x.Entries = []Entry{{"APP_KEY", pem + "x"}} }, func(x *Edit) { x.Op = "import"; x.Remove = nil }} {
		x := e
		f(&x)
		if v, _ := x.Commit(b); v == want {
			t.Fatal("unbound merge")
		}
	}
	for _, x := range []Edit{{Op: "merge", Salt: e.Salt}, {Op: "merge", Salt: e.Salt, Entries: e.Entries, Remove: []string{"APP_KEY"}}, {Op: "merge", Salt: e.Salt, Remove: []string{"A_KEY", "A_KEY"}}, {Op: "put", Salt: e.Salt, Entries: e.Entries, Remove: []string{"OLD_TOKEN"}}} {
		if _, err := x.Commit(b); err == nil {
			t.Fatal("invalid merge accepted")
		}
	}
	ops, err := e.Changes([]string{"OLD_TOKEN", "KEEP_TOKEN"})
	if err != nil || ops != "APP_KEY:add,OLD_TOKEN:remove" {
		t.Fatal(ops, err)
	}
	if _, err = e.Changes([]string{"KEEP_TOKEN"}); err == nil {
		t.Fatal("removed a missing key")
	}
	got, err := e.Apply([]Entry{{"KEEP_TOKEN", "k"}, {"OLD_TOKEN", "o"}})
	if err != nil || !slices.Equal(got, []Entry{{"APP_KEY", pem}, {"KEEP_TOKEN", "k"}}) {
		t.Fatal(got, err)
	}
	file := "# comment\r\nAPP_URL=https://example.com/a\r\n\nAPP_KEY=\"-----BEGIN PRIVATE KEY-----\nAAAA\\nBBBB\n-----END PRIVATE KEY-----\n\"  \nAPP_SECRET='it''s'\n"
	if _, err := ParseFile([]byte(file)); err == nil {
		t.Fatal("text after a closing quote accepted")
	}
	file = "# comment\r\nAPP_URL=https://example.com/a\r\n\nAPP_KEY=\"-----BEGIN PRIVATE KEY-----\nAAAA\\nBBBB\n-----END PRIVATE KEY-----\n\"  \nAPP_SECRET='a \"$HOME\" \\n\nb'\nAPP_TOKEN=\"q\\\"\\\\\\t\"\nAPP_ID="
	entries, err := ParseFile([]byte(file))
	want2 := []Entry{{"APP_URL", "https://example.com/a"}, {"APP_KEY", pem}, {"APP_SECRET", "a \"$HOME\" \\n\nb"}, {"APP_TOKEN", "q\"\\\t"}, {"APP_ID", ""}}
	if err != nil || !slices.Equal(entries, want2) {
		t.Fatalf("%q %v", entries, err)
	}
	if _, err := FileBytes(entries[1:2]); err == nil || !bytes.Contains([]byte(err.Error()), []byte("multi-line")) || bytes.Contains([]byte(err.Error()), []byte("AAAA")) {
		t.Fatal("file mode accepted or echoed a multi-line value")
	}
	if out, err := FileBytes(entries[:1]); err != nil || string(out) != "APP_URL=https://example.com/a\n" {
		t.Fatal("portable value refused")
	}
}
