package release

import "testing"

func TestDownloadBase(t *testing.T) {
	for _, tc := range [][3]string{
		{"", "1.2.3", "https://github.com/aquarat/agent-quartermaster/releases/download/v1.2.3"},
		{"https://api.github.com/repos/example/fork/", "0.10.0", "https://github.com/example/fork/releases/download/v0.10.0"},
		{"https://git.example.com/api/v3/repos/example/fork", "1.2.3", ""},
		{"https://api.github.com/repos/example/fork/extra", "1.2.3", ""},
		{"", "dev", ""},
		{"", "1.2.3/../x", ""},
	} {
		if got := DownloadBase(tc[0], tc[1]); got != tc[2] {
			t.Errorf("DownloadBase(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}
