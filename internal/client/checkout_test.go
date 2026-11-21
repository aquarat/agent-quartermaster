//go:build linux

package client

import (
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestShellSkipsAllExportsOnLocalAttributeCollision(t *testing.T) {
	values := []envset.Entry{{Name: "APP_FIRST", Value: "a'b\nvalue"}, {Name: "APP_SECOND", Value: "37"}}
	script := shellExports(values)
	for _, attr := range []string{"declare -i APP_SECOND", "declare -n APP_SECOND=target", "readonly APP_SECOND=original"} {
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", attr+"\n"+script+"\n[[ ! -v APP_FIRST && ! -v target ]]")
		if err := cmd.Run(); err != nil {
			t.Fatalf("unsafe partial export: %s", attr)
		}
	}
	if err := exec.Command("bash", "--noprofile", "--norc", "-c", script+"\n[[ $APP_FIRST == $'a\\'b\\nvalue' && $APP_SECOND == 37 ]]").Run(); err != nil {
		t.Fatal("literal quoting failed")
	}
}

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
