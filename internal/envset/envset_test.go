package envset

import (
	"bytes"
	"slices"
	"testing"
)

func TestDraftCommitmentPinsExactEdit(t *testing.T) {
	b := Binding{Org: "org", Service: "svc", Set: "set", Revision: 3}
	e := Edit{"import", bytes.Repeat([]byte{1}, 32), []Entry{{"APP_TOKEN", "a=b"}, {"APP_URL", "https://example.invalid"}}}
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
	for _, s := range []string{"PATH=sentinel", "APP_TOKEN='sentinel'", "APP_TOKEN=$(sentinel)", "APP_TOKEN=sentinel\nAPP_TOKEN=sentinel"} {
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
