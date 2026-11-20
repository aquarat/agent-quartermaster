package nickname

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"  Work Key ":            "Work Key",
		"Work\u00a0Key":          "Work Key",
		"Work \u2003\u3000  Key": "Work Key",
		"Caf\u00e9":              "Caf\u00e9", // precomposed \u00e9
		"Phone <img src=x>":      "Phone <img src=x>",
		"\U0001f511 keyring":     "\U0001f511 keyring",
	} {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", " \u00a0 ", "a\u202eb", "zero\u200bwidth", "tab\tname", "Cafe\u0301", "key\ufe0f", "\x00", strings.Repeat("x", 65), "a\u2028b", "bad\xffutf8"} {
		if got, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) accepted as %q", bad, got)
		}
	}
	if !Same("Bitwarden", "BITWARDEN") || Same("Bitwarden", "Bitwarden 2") {
		t.Fatal("Same")
	}
}

func TestUnique(t *testing.T) {
	used := map[string]bool{"bitwarden": true, "bitwarden 2": true}
	taken := func(c string) bool { return used[strings.ToLower(c)] }
	if got := Unique("Bitwarden", taken); got != "Bitwarden 3" {
		t.Fatal(got)
	}
	if got := Unique("Fresh", taken); got != "Fresh" {
		t.Fatal(got)
	}
	long := strings.Repeat("\u00e9", 32) // 64 bytes
	used[strings.ToLower(long)] = true
	if got := Unique(long, taken); len(got) > MaxBytes || !strings.HasSuffix(got, " 2") {
		t.Fatalf("%q (%d bytes)", got, len(got))
	}
}
