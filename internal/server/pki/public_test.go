package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSealedPublicPKI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	orig, err := Load(dir, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{SSHCAKeyFile, ClientCAKeyFile} {
		if err = os.Remove(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := LoadPublic(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.SSHCAPublicLine() != orig.SSHCAPublicLine() || p.CAPin() != orig.CAPin() || p.CAKey != nil || p.SSHSigner != nil || p.ServerCert.PrivateKey != nil {
		t.Fatal("metadata loader returned incorrect trust or read a key")
	}
	if err = p.LoadLeaf(nil); err != nil {
		t.Fatal(err)
	}
	if err = p.LoadLeaf([]string{"other.example"}); err == nil {
		t.Fatal("wrong SAN")
	}
	if err = os.Remove(filepath.Join(dir, ServerKeyFile)); err != nil {
		t.Fatal(err)
	}
	if err = p.LoadLeaf(nil); err == nil {
		t.Fatal("lost leaf silently replaced")
	}
}
