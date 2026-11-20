package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestRealSSHD runs an unprivileged sshd that trusts the fake server's SSH CA, then runs the
// real ssh client with the argv from BuildSSHArgv. It checks the whole chain: certificate
// format, principals file, source-address, the rewritten known_hosts file and the options.
func TestRealSSHD(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
			if _, err := os.Stat(p); err == nil {
				sshd = p
			}
		}
	}
	sshBin, err2 := exec.LookPath("ssh")
	keygen, err3 := exec.LookPath("ssh-keygen")
	if sshd == "" || err2 != nil || err3 != nil {
		t.Skip("sshd/ssh/ssh-keygen not installed")
	}
	me := currentUser()

	f := newFakeServer(t)
	dir := t.TempDir()
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "hostkey")).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	hostPub, _ := os.ReadFile(filepath.Join(dir, "hostkey.pub"))
	f.knownHostsLine = "testhost " + strings.TrimSpace(string(hostPub))
	os.WriteFile(filepath.Join(dir, "ca.pub"), ssh.MarshalAuthorizedKey(f.sshCA.PublicKey()), 0o644)
	os.MkdirAll(filepath.Join(dir, "principals"), 0o755)
	os.WriteFile(filepath.Join(dir, "principals", me), []byte(me+"@testhost\n"), 0o644)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %[2]s/hostkey
PidFile %[2]s/sshd.pid
TrustedUserCAKeys %[2]s/ca.pub
AuthorizedPrincipalsFile %[2]s/principals/%%u
AuthorizedKeysFile none
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
`, port, dir)
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(cfg), 0o600)
	sshdLog := &lockedBuffer{}
	cmd := exec.Command(sshd, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	cmd.Stdout, cmd.Stderr = sshdLog, sshdLog
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sshd: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	up := false
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			c.Close()
			up = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !up {
		t.Skipf("unprivileged sshd did not start: %s", sshdLog.String())
	}

	f.targetAddress = "127.0.0.1"
	f.targetPort = port
	e := newTestEnv(t)
	e.User = me
	enroll(t, f, e)
	p, err := e.EnsureSSHCert(context.Background(), SSHOptions{Target: Target{User: me, Host: "testhost"}, Why: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	argv, err := BuildSSHArgv(p, []string{"echo", "aqmas-e2e-ok"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := exec.CommandContext(ctx, sshBin, argv[1:]...)
	run.Env = append(os.Environ(), "SSH_AUTH_SOCK=/nonexistent")
	out, err := run.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "aqmas-e2e-ok") {
		t.Fatalf("ssh %q: %v\n%s\nsshd log:\n%s", argv, err, out, sshdLog.String())
	}
	if !strings.Contains(sshdLog.String(), "Accepted certificate ID \"aqmas:GREQ0001") {
		t.Errorf("sshd did not log a certificate login:\n%s", sshdLog.String())
	}

	// A host key that does not match the pinned one is refused (StrictHostKeyChecking=yes).
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _ := ssh.NewPublicKey(wrongPub)
	kh, _ := os.ReadFile(p.KnownHostsPath)
	patterns := strings.SplitN(string(kh), " ", 2)[0]
	os.WriteFile(p.KnownHostsPath, append([]byte(patterns+" "), ssh.MarshalAuthorizedKey(wrong)...), 0o600)
	run = exec.CommandContext(ctx, sshBin, argv[1:]...)
	run.Env = append(os.Environ(), "SSH_AUTH_SOCK=/nonexistent")
	if out, err := run.CombinedOutput(); err == nil || !strings.Contains(string(out), "HOST IDENTIFICATION HAS CHANGED") {
		t.Fatalf("login with a wrong pinned host key: err=%v\n%s", err, out)
	}
}

// lockedBuffer is written by the sshd output goroutine and read by the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
