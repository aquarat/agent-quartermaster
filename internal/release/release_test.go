package release

import (
	"maps"
	"strings"
	"testing"
)

func TestClosedManifest(t *testing.T) {
	s := Sums{}
	for _, a := range Assets {
		s[a] = strings.Repeat("a", 64)
	}
	text := s.Text()
	got, e := Parse([]byte(text))
	if e != nil || !got.Agrees(s) {
		t.Fatal(got, e)
	}
	other := maps.Clone(s)
	other[Daemon] = strings.Repeat("b", 64)
	if s.Agrees(other) {
		t.Fatal("daemon mismatch ignored")
	}
	for _, bad := range []string{"", text + text, strings.Replace(text, Daemon, "../"+Daemon, 1), strings.Replace(text, "  ", " *", 1), strings.ToUpper(text), text[:len(text)/2], text + "\n"} {
		if _, e := Parse([]byte(bad)); e == nil {
			t.Fatal("accepted malformed manifest")
		}
	}
}
func TestReleaseOrder(t *testing.T) {
	for _, p := range [][2]string{{"0.10.3", "0.9.12"}, {"100000000000000000000.0.0", "99.99.99"}} {
		if !Newer(p[0], p[1]) || Newer(p[1], p[0]) {
			t.Fatal(p)
		}
	}
	for _, v := range []string{"v1.1.2", "../1.1.2", "1.01.2", "1.1.2\n", "1.1.2-alpha", "-1.0.0"} {
		if ValidVersion(v) {
			t.Fatal(v)
		}
	}
}
