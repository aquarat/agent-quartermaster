package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// A multi-line value with every character a shell cares about survives
// `eval "$(aqmas cos ...)"` byte for byte, and nothing in it is executed.
func TestShellExportsCarryMultiLineValues(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	value := "-----BEGIN KEY-----\nline 'two' \"three\"\n$(touch " + marker + ") `touch " + marker + "` \\ ; touch " + marker + "\n'; touch " + marker + " #\n-----END KEY-----\n"
	script := shellExports([]envset.Entry{{Name: "APP_KEY", Value: value}, {Name: "APP_TOKEN", Value: "plain"}})
	cmd := exec.Command(bash, "--noprofile", "--norc", "-c", `eval "$1"; printf %s "$APP_KEY"; printf %s "$APP_TOKEN" >&2`, "sh", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatal(err, errOut.String())
	}
	if out.String() != value || errOut.String() != "plain" {
		t.Fatalf("value changed in the shell: %q", out.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("part of a value was executed")
	}
	if _, err := envset.FileBytes([]envset.Entry{{Name: "APP_KEY", Value: value}}); err == nil || strings.Contains(err.Error(), "BEGIN") {
		t.Fatal("file mode accepted or echoed a multi-line value")
	}
}

func TestSignInputsAreHashedLocally(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte{7}, 200000)
	small := []byte("manifest head")
	requireWrite := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bigPath, smallPath := requireWrite("image.bin", big), requireWrite("manifest.bin", small)
	sum := sha256.Sum256(big)
	e := &Env{Stdin: bytes.NewReader(small)}
	digest, _ := signer.Lookup("ed25519-sha256")
	pure, _ := signer.Lookup("ed25519")
	ph, _ := signer.Lookup("ed25519ph")
	got, err := e.signTargets(digest, SignOptions{Files: []string{bigPath, "-"}})
	if err != nil || len(got) != 2 || got[0].item.Name != "image.bin" || got[0].item.Size != 200000 || got[0].item.SHA256 != hex.EncodeToString(sum[:]) || got[0].item.Message != nil || got[0].out != bigPath+".sig" || got[1].item.Name != "stdin" || got[1].out != "" {
		t.Fatalf("digest scheme targets: %+v %v", got, err)
	}
	if got, err = e.signTargets(pure, SignOptions{Files: []string{smallPath}}); err != nil || !bytes.Equal(got[0].item.Message, small) {
		t.Fatal("pure scheme must carry a small artifact", err)
	}
	if _, err = e.signTargets(pure, SignOptions{Files: []string{bigPath}}); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Fatal("pure scheme accepted a large artifact")
	}
	if got, err = e.signTargets(ph, SignOptions{Files: []string{bigPath}}); err != nil || len(got[0].item.SHA512) != 128 {
		t.Fatal("ed25519ph needs the SHA-512", err)
	}
	if got, err = e.signTargets(digest, SignOptions{Digest: "sha256:" + strings.ToUpper(hex.EncodeToString(sum[:])), Out: "x.sig"}); err != nil || got[0].item.Size != -1 || got[0].item.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("--digest", err)
	}
	for _, o := range []SignOptions{{}, {Digest: "sha256:abcd"}, {Digest: "sha512:" + strings.Repeat("a", 128)}, {Digest: "sha256:" + hex.EncodeToString(sum[:]), Files: []string{bigPath}}, {Files: []string{bigPath, smallPath}, Out: "one.sig"}, {Files: []string{bigPath, bigPath}}, {Files: []string{dir}}, {Files: []string{filepath.Join(dir, "missing")}}} {
		if _, err := e.signTargets(digest, o); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	if _, err = e.signTargets(pure, SignOptions{Digest: "sha256:" + hex.EncodeToString(sum[:])}); err == nil {
		t.Fatal("--digest with a scheme that signs the message")
	}
	// Output: raw to a new file, never over an existing one, never raw to a terminal.
	var stdout bytes.Buffer
	e = &Env{Stdout: &stdout, StdoutIsTTY: true}
	sig := []byte{0, 1, 2, 0xff}
	out := filepath.Join(dir, "a.sig")
	if err = e.writeSignature(out, "", false, sig); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); !bytes.Equal(b, sig) {
		t.Fatal("raw signature file")
	}
	if e.writeSignature(out, "", false, sig) == nil {
		t.Fatal("overwrote a signature")
	}
	if err = e.writeSignature(out, "base64", true, sig); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "AAEC/w==\n" {
		t.Fatal("base64 signature file")
	}
	if e.writeSignature("", "raw", false, sig) == nil {
		t.Fatal("raw bytes to a terminal")
	}
	if err = e.writeSignature("", "", false, sig); err != nil || stdout.String() != "000102ff\n" {
		t.Fatal("hex to stdout", err)
	}
}
