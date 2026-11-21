package secretfile

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSource(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "key")
	if err := os.WriteFile(p, []byte("value"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p, false, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p, false, 4); err == nil {
		t.Fatal("oversize")
	}
	for _, mk := range []func(string) error{func(f string) error { return os.Symlink(p, f) }, func(f string) error { return os.Link(p, f) }, func(f string) error { return unix.Mkfifo(f, 0600) }} {
		f := filepath.Join(d, "substitute")
		if err := mk(f); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(f, false, 10); err == nil {
			t.Fatal("accepted substitution")
		}
		os.Remove(f)
	}
	dirlink := filepath.Join(d, "dir")
	if err := os.Symlink(d, dirlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(filepath.Join(dirlink, "key"), false, 10); err == nil {
		t.Fatal("followed directory link")
	}
}
