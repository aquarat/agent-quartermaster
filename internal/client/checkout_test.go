//go:build linux

package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefuseSymlinkAndPersistentStorage(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if d, err := trustedDir(link, true); err == nil {
		d.Close()
		t.Fatal("followed symlink directory")
	}
	t.Setenv("XDG_RUNTIME_DIR", link)
	if d, err := ramRoot(); err == nil {
		d.Close()
		t.Fatal("unverified runtime")
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)
	d, err := trustedDir(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if verifyRAM(d) != nil {
		if d, err := ramRoot(); err == nil {
			d.Close()
			t.Fatal("accepted persistent storage")
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeOurLink(d, ".env", "wrong"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".env")); string(b) != "keep" {
		t.Fatal("deleted replacement")
	}
}
