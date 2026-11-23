// Package hosts holds the fleet-host sshd trust files; this test exercises
// install-host-trust.sh against a temporary --root so it never touches /etc.
package hosts

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testPolicy is the site policy the fixture installs at <root>/etc/aqmas/host-trust.conf.
const testPolicy = `# test policy
refuse bastion
refuse 192.0.2.60   # the bastion's address
needs-approval web-1
needs-approval hub-1
`

type fixture struct {
	t      *testing.T
	root   string
	caKey  string
	sshd   string
	sshLog string
}

func newFixture(t *testing.T, hostname string) *fixture {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "etc/ssh/sshd_config.d"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "home/alice/.ssh"), 0o700))
	must(os.WriteFile(filepath.Join(root, "etc/ssh/sshd_config"), []byte(
		"# test sshd_config\nInclude /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n#AuthorizedPrincipalsFile none\nMatch User backup\n  ForceCommand /bin/false\n"), 0o600))
	must(os.WriteFile(filepath.Join(root, "etc/ssh/sshd_config.d/50-redhat.conf"), []byte("SyslogFacility AUTHPRIV\n"), 0o600))
	must(os.WriteFile(filepath.Join(root, "etc/hostname"), []byte(hostname+"\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "home/alice/.ssh/authorized_keys"), []byte("ssh-rsa AAAAB3Nza owner\n"), 0o600))
	must(os.MkdirAll(filepath.Join(root, "etc/aqmas"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc/aqmas/host-trust.conf"), []byte(testPolicy), 0o644))

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	ca := filepath.Join(t.TempDir(), "aqmas_user_ca.pub")
	must(os.WriteFile(ca, []byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))+" aqmas-user-ca\n"), 0o644))

	// A fake sshd: logs its args, fails -t when FAKE_SSHD_FAIL is set, prints -T output.
	bin := t.TempDir()
	logf := filepath.Join(bin, "sshd.log")
	sshd := filepath.Join(bin, "sshd")
	must(os.WriteFile(sshd, []byte(`#!/usr/bin/env bash
echo "$*" >>"`+logf+`"
if [[ $1 == -t && -n ${FAKE_SSHD_FAIL:-} ]]; then echo "fake sshd: bad config" >&2; exit 255; fi
if [[ $1 == -T ]]; then
  if [[ -n ${FAKE_SSHD_OTHER:-} ]]; then echo "trustedusercakeys /etc/ssh/other.pub"; else echo "trustedusercakeys /etc/ssh/aqmas_user_ca.pub"; fi
  echo "authorizedprincipalsfile /etc/ssh/aqmas_principals/%u"
  # Like sshd: the Match block of the inspect drop-in applies to its user only.
  conf=$(dirname "$3")/sshd_config.d/90-aqmas-inspect.conf
  user=${5#user=}; user=${user%%,*}
  if [[ -f $conf && -z ${FAKE_SSHD_NOMATCH:-} ]] && grep -qx "Match User $user" "$conf"; then
    grep -E '^    ' "$conf" | sed 's/^ *//' | awk '{k=tolower($1); $1=""; sub(/^ /,""); print k" "$0}'
  else
    echo "forcecommand none"; echo "disableforwarding no"; echo "permittty yes"
  fi
fi
exit 0
`), 0o755))
	return &fixture{t: t, root: root, caKey: ca, sshd: sshd, sshLog: logf}
}

func (f *fixture) run(env []string, args ...string) (string, error) {
	f.t.Helper()
	cmd := exec.Command("bash", append([]string{"install-host-trust.sh", "--root", f.root}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Env = append(cmd.Env, "SYSTEMCTL=/bin/false", "SUDO_USER=alice")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *fixture) path(p string) string { return filepath.Join(f.root, p) }

func (f *fixture) exists(p string) bool {
	_, err := os.Stat(f.path(p))
	return err == nil
}

// snapshot returns every file under root with its content, to prove a dry run changes nothing.
func (f *fixture) snapshot() map[string]string {
	m := map[string]string{}
	filepath.Walk(f.root, func(p string, fi os.FileInfo, err error) error {
		if err == nil {
			data, _ := os.ReadFile(p)
			m[p] = fi.Mode().String() + "|" + string(data)
		}
		return nil
	})
	return m
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestDryRunChangesNothing(t *testing.T) {
	f := newFixture(t, "db-1")
	before := f.snapshot()
	raw, _ := os.ReadFile(f.caKey)
	pk, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.run(nil, "--name", "db-1", "--ca-key", f.caKey, "--ca-fingerprint", ssh.FingerprintSHA256(pk))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"create     /etc/ssh/aqmas_user_ca.pub", "create     /etc/ssh/sshd_config.d/10-aqmas.conf",
		"create     /etc/ssh/aqmas_principals/alice", "dry run: nothing changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !equalMaps(before, f.snapshot()) {
		t.Error("dry run changed files")
	}
}

func TestApplyIdempotentAndUninstall(t *testing.T) {
	f := newFixture(t, "db-1")
	ak, _ := os.ReadFile(f.path("home/alice/.ssh/authorized_keys"))
	out, err := f.run(nil, "--name", "db-1", "--ca-key", f.caKey, "--sshd", f.sshd, "--apply")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ca, _ := os.ReadFile(f.caKey)
	for p, want := range map[string]string{
		"etc/ssh/aqmas_user_ca.pub":           strings.TrimSpace(string(ca)) + "\n",
		"etc/ssh/aqmas_principals/alice":      "alice@db-1\n",
		"etc/ssh/sshd_config.d/10-aqmas.conf": mustRead(t, "10-aqmas.conf"),
	} {
		got, err := os.ReadFile(f.path(p))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q (%v), want %q", p, got, err, want)
		}
		if fi, _ := os.Stat(f.path(p)); fi == nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode not 0644", p)
		}
	}
	if fi, _ := os.Stat(f.path("etc/ssh/aqmas_principals")); fi == nil || fi.Mode().Perm() != 0o755 {
		t.Error("principals dir mode")
	}
	log, _ := os.ReadFile(f.sshLog)
	if !strings.Contains(string(log), "-t -f "+f.root+"/etc/ssh/sshd_config") || !strings.Contains(string(log), "-T -f") {
		t.Errorf("sshd -t/-T not run: %s", log)
	}
	if !strings.Contains(out, "skip       reload sshd (--root)") {
		t.Errorf("reload not skipped under --root:\n%s", out)
	}
	if b, _ := filepath.Glob(f.path("var/backups/aqmas-host-trust/*/MANIFEST")); len(b) != 1 {
		t.Errorf("backups: %v", b)
	}

	// Second run: nothing to change.
	out, err = f.run(nil, "--name", "db-1", "--ca-key", f.caKey, "--sshd", f.sshd, "--apply")
	if err != nil || !strings.Contains(out, "nothing to change") {
		t.Fatalf("second apply: %v\n%s", err, out)
	}
	// A different name replaces the principals file, with a backup.
	out, err = f.run(nil, "--name", "db-2", "--ca-key", f.caKey, "--sshd", f.sshd, "--apply")
	if err != nil || !strings.Contains(out, "replace    /etc/ssh/aqmas_principals/alice") {
		t.Fatalf("rename: %v\n%s", err, out)
	}

	// Uninstall refuses a principals file that does not match --name.
	if out, err := f.run(nil, "--uninstall", "--name", "db-1", "--apply", "--sshd", f.sshd); err == nil {
		t.Fatalf("uninstall with wrong name succeeded:\n%s", out)
	}
	// Uninstall dry run, then apply.
	before := f.snapshot()
	out, err = f.run(nil, "--uninstall", "--name", "db-2")
	if err != nil || !strings.Contains(out, "remove     /etc/ssh/sshd_config.d/10-aqmas.conf") || !equalMaps(before, f.snapshot()) {
		t.Fatalf("uninstall dry run: %v\n%s", err, out)
	}
	out, err = f.run(nil, "--uninstall", "--name", "db-2", "--apply", "--sshd", f.sshd)
	if err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	for _, p := range []string{"etc/ssh/aqmas_user_ca.pub", "etc/ssh/aqmas_principals", "etc/ssh/sshd_config.d/10-aqmas.conf"} {
		if f.exists(p) {
			t.Errorf("%s still exists", p)
		}
	}
	if !f.exists("etc/ssh/sshd_config.d/50-redhat.conf") {
		t.Error("uninstall removed an unrelated drop-in")
	}
	if ak2, _ := os.ReadFile(f.path("home/alice/.ssh/authorized_keys")); string(ak2) != string(ak) {
		t.Error("authorized_keys changed")
	}
}

func TestFailedValidationRestores(t *testing.T) {
	f := newFixture(t, "db-1")
	before := f.snapshot()
	out, err := f.run([]string{"FAKE_SSHD_FAIL=1"}, "--name", "db-1", "--ca-key", f.caKey, "--sshd", f.sshd, "--apply")
	if err == nil || !strings.Contains(out, "restored the previous files") {
		t.Fatalf("expected failure:\n%s", out)
	}
	after := f.snapshot()
	for k := range after {
		if k == f.path("var") || strings.HasPrefix(k, f.path("var")+"/") {
			delete(after, k) // the backup itself stays
		}
	}
	if !equalMaps(before, after) {
		t.Error("files not restored after failed sshd -t")
	}

	// sshd -T showing another CA (an earlier setting wins) also rolls back.
	f = newFixture(t, "db-1")
	out, err = f.run([]string{"FAKE_SSHD_OTHER=1"}, "--name", "db-1", "--ca-key", f.caKey, "--sshd", f.sshd, "--apply")
	if err == nil || f.exists("etc/ssh/sshd_config.d/10-aqmas.conf") {
		t.Fatalf("expected rollback on sshd -T mismatch:\n%s", out)
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
		args     []string
		setup    func(f *fixture)
		want     string
	}{
		{"web-1 by hostname", "web-1", []string{"--name", "web-1"}, nil, "owner's go-ahead"},
		{"web-1 by name", "other", []string{"--name", "web-1"}, nil, "owner's go-ahead"},
		{"hub", "hub-1", []string{"--name", "hub-1"}, nil, "owner's go-ahead"},
		{"bastion", "bastion", []string{"--name", "bastion", "--i-have-owner-approval"}, nil, "policy refuses"},
		{"bastion hostname", "bastion", []string{"--name", "x", "--i-have-owner-approval"}, nil, "policy refuses"},
		{"root principals", "db-1", []string{"--name", "db-1", "--user", "root"}, nil, "root"},
		{"bad name", "db-1", []string{"--name", "db 1"}, nil, "plain lowercase"},
		{"no name", "db-1", nil, nil, "--name is required"},
		{"conflict", "db-1", []string{"--name", "db-1"}, func(f *fixture) {
			os.WriteFile(f.path("etc/ssh/sshd_config.d/05-ca.conf"), []byte("TrustedUserCAKeys /etc/ssh/other.pub\n"), 0o600)
		}, "already sets"},
		{"no include", "db-1", []string{"--name", "db-1"}, func(f *fixture) {
			os.WriteFile(f.path("etc/ssh/sshd_config"), []byte("PasswordAuthentication no\n"), 0o600)
		}, "no 'Include"},
		{"include after match", "db-1", []string{"--name", "db-1"}, func(f *fixture) {
			os.WriteFile(f.path("etc/ssh/sshd_config"), []byte("Match User x\n  X11Forwarding no\nInclude /etc/ssh/sshd_config.d/*.conf\n"), 0o600)
		}, "no 'Include"},
		{"two keys", "db-1", []string{"--name", "db-1"}, func(f *fixture) {
			data, _ := os.ReadFile(f.caKey)
			os.WriteFile(f.caKey, append(data, data...), 0o644)
		}, "exactly one public key"},
		{"options prefix", "db-1", []string{"--name", "db-1"}, func(f *fixture) {
			data, _ := os.ReadFile(f.caKey)
			os.WriteFile(f.caKey, append([]byte(`command="/bin/sh" `), data...), 0o644)
		}, "not a plain ssh-ed25519 public key"},
		{"rsa ca key", "db-1", []string{"--name", "db-1"}, func(f *fixture) {
			os.WriteFile(f.caKey, []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 rsa-ca\n"), 0o644)
		}, "not a plain ssh-ed25519 public key"},
		{"wrong fingerprint", "db-1", []string{"--name", "db-1", "--ca-fingerprint", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, nil, "is not the expected"},
		{"private key", "db-1", []string{"--name", "db-1"}, func(f *fixture) {
			os.WriteFile(f.caKey, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
		}, "exactly one public key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.hostname)
			if tc.setup != nil {
				tc.setup(f)
			}
			before := f.snapshot()
			args := append([]string{"--ca-key", f.caKey, "--sshd", f.sshd, "--apply"}, tc.args...)
			out, err := f.run(nil, args...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("want refusal containing %q, got err=%v:\n%s", tc.want, err, out)
			}
			if !equalMaps(before, f.snapshot()) {
				t.Error("files changed by a refused run")
			}
		})
	}

	// With the owner's approval web-1 is allowed (dry run).
	f := newFixture(t, "web-1")
	if out, err := f.run(nil, "--name", "web-1", "--ca-key", f.caKey, "--i-have-owner-approval"); err != nil {
		t.Fatalf("approved web-1: %v\n%s", err, out)
	}
}

func TestPolicySources(t *testing.T) {
	// No policy file: nothing is refused.
	f := newFixture(t, "web-1")
	os.Remove(f.path("etc/aqmas/host-trust.conf"))
	if out, err := f.run(nil, "--name", "web-1", "--ca-key", f.caKey); err != nil {
		t.Fatalf("no policy: %v\n%s", err, out)
	}
	// Flags add to the (absent) file.
	if out, err := f.run(nil, "--name", "web-1", "--ca-key", f.caKey, "--refuse", "web-1"); err == nil || !strings.Contains(out, "policy refuses") {
		t.Fatalf("--refuse: %v\n%s", err, out)
	}
	if out, err := f.run(nil, "--name", "web-1", "--ca-key", f.caKey, "--needs-approval=web-1"); err == nil || !strings.Contains(out, "owner's go-ahead") {
		t.Fatalf("--needs-approval: %v\n%s", err, out)
	}
	// An explicit --policy must exist and parse.
	if out, err := f.run(nil, "--name", "web-1", "--ca-key", f.caKey, "--policy", f.path("nope.conf")); err == nil || !strings.Contains(out, "cannot read policy") {
		t.Fatalf("missing --policy: %v\n%s", err, out)
	}
	bad := f.path("bad.conf")
	os.WriteFile(bad, []byte("deny web-1\n"), 0o644)
	if out, err := f.run(nil, "--name", "web-1", "--ca-key", f.caKey, "--policy", bad); err == nil || !strings.Contains(out, "unknown keyword") {
		t.Fatalf("bad policy: %v\n%s", err, out)
	}
	// The example file parses and refuses its bastion.
	g := newFixture(t, "bastion")
	if out, err := g.run(nil, "--name", "x", "--ca-key", g.caKey, "--policy", "host-trust.conf.example"); err == nil || !strings.Contains(out, "policy refuses") {
		t.Fatalf("example policy: %v\n%s", err, out)
	}
	// Without --user or $SUDO_USER there is no default login user.
	cmd := exec.Command("bash", "install-host-trust.sh", "--root", f.root, "--name", "web-1", "--ca-key", f.caKey)
	cmd.Env = append(os.Environ(), "SUDO_USER=", "SYSTEMCTL=/bin/false")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "--user is required") {
		t.Fatalf("no user: %v\n%s", err, out)
	}
}

func TestApplyOnRealSystemNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	// "//" and a symlink to / are the real system too, not a test root.
	link := filepath.Join(t.TempDir(), "slash")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{nil, {"--root", "//"}, {"--root", link}} {
		args := append([]string{"install-host-trust.sh", "--name", "db-1", "--user", "alice", "--ca-key", "/nonexistent", "--apply"}, extra...)
		out, err := exec.Command("bash", args...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "needs root") {
			t.Fatalf("%v: got %v:\n%s", extra, err, out)
		}
	}
}

func TestUnexpectedFailureRestores(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newFixture(t, "db-1")
	confDir := f.path("etc/ssh/sshd_config.d")
	os.Chmod(confDir, 0o555) // the drop-in is written last: CA + principals are in place by then
	defer os.Chmod(confDir, 0o755)
	before := f.snapshot()
	out, err := f.run(nil, "--name", "db-1", "--ca-key", f.caKey, "--sshd", f.sshd, "--apply")
	if err == nil || !strings.Contains(out, "unexpected failure") || !strings.Contains(out, "restoring") {
		t.Fatalf("expected a restore:\n%s", out)
	}
	after := f.snapshot()
	for k := range after {
		if k == f.path("var") || strings.HasPrefix(k, f.path("var")+"/") {
			delete(after, k)
		}
	}
	if !equalMaps(before, after) {
		t.Errorf("not restored:\n%s", out)
	}
}

func TestScriptNeverMentionsAuthorizedKeysFiles(t *testing.T) {
	data := mustRead(t, "install-host-trust.sh")
	for i, line := range strings.Split(data, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "authorized_keys") {
			t.Errorf("line %d touches authorized_keys: %s", i+1, line)
		}
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The maintenance runner on the bastion itself: --bastion-self skips the site's refuse rules
// and installs the forced-command block for the inspect account (docs/BASTION-ACCESS.md).
func TestBastionSelf(t *testing.T) {
	f := newFixture(t, "bastion")
	self := []string{"--bastion-self", "--inspect-user", "aqmas-inspect", "--inspect-command", "/usr/local/bin/aqmasd inspect"}
	args := append(append([]string{}, self...), "--name", "bastion", "--ca-key", f.caKey, "--admin-user", "alice", "--sshd", f.sshd, "--apply")
	// Without the flag the bastion is refused, as before.
	if out, err := f.run(nil, "--name", "bastion", "--ca-key", f.caKey, "--user", "aqmas-inspect", "--sshd", f.sshd, "--apply"); err == nil || !strings.Contains(out, "refusing to run on bastion") {
		t.Fatalf("bastion not refused: %v\n%s", err, out)
	}
	// The flag alone, or half of the inspect pair, is refused.
	for _, bad := range [][]string{
		{"--bastion-self", "--name", "bastion", "--ca-key", f.caKey, "--user", "alice", "--apply"},
		{"--bastion-self", "--inspect-user", "aqmas-inspect", "--name", "bastion", "--ca-key", f.caKey, "--apply"},
		{"--inspect-command", "/usr/local/bin/aqmasd inspect", "--name", "db-1", "--ca-key", f.caKey, "--user", "alice", "--apply"},
		{"--bastion-self", "--inspect-user", "aqmas-inspect", "--inspect-command", "/bin/sh -c id;id", "--name", "bastion", "--ca-key", f.caKey, "--apply"},
		{"--bastion-self", "--inspect-user", "aqmas-inspect", "--inspect-command", "aqmasd inspect", "--name", "bastion", "--ca-key", f.caKey, "--apply"},
		{"--bastion-self", "--inspect-user", "aqmas-inspect", "--inspect-command", "/usr/../bin/sh", "--name", "bastion", "--ca-key", f.caKey, "--apply"},
		{"--bastion-self", "--inspect-user", "root", "--inspect-command", "/usr/local/bin/aqmasd inspect", "--name", "bastion", "--ca-key", f.caKey, "--apply"},
		{"--bastion-self", "--inspect-user", "aqmas-inspect", "--inspect-command", "/usr/local/bin/aqmasd inspect", "--admin-user", "aqmas-inspect", "--name", "bastion", "--ca-key", f.caKey, "--apply"},
	} {
		before := f.snapshot()
		if out, err := f.run(nil, append(bad, "--sshd", f.sshd)...); err == nil || !equalMaps(before, f.snapshot()) {
			t.Fatalf("%v accepted or changed files:\n%s", bad, out)
		}
	}
	ak, _ := os.ReadFile(f.path("home/alice/.ssh/authorized_keys"))
	out, err := f.run(nil, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := "# managed by aqmas install-host-trust.sh (bastion inspect account)\nMatch User aqmas-inspect\n    ForceCommand /usr/local/bin/aqmasd inspect\n    AuthenticationMethods publickey\n" +
		"    AuthorizedKeysFile none\n    AuthorizedKeysCommand none\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    DisableForwarding yes\n    PermitTTY no\n    PermitUserRC no\n"
	if got, _ := os.ReadFile(f.path("etc/ssh/sshd_config.d/90-aqmas-inspect.conf")); string(got) != want {
		t.Fatalf("inspect block:\n%s", got)
	}
	if got, _ := os.ReadFile(f.path("etc/ssh/aqmas_principals/aqmas-inspect")); string(got) != "aqmas-inspect@bastion\n" {
		t.Fatalf("inspect principals: %q", got)
	}
	// The admin's principals file belongs to the runner (it carries from=), not to the script.
	if f.exists("etc/ssh/aqmas_principals/alice") {
		t.Fatal("the script wrote the admin's principals file")
	}
	for _, line := range []string{"site refuse rules not applied", "confines aqmas-inspect to the forced command", "for alice: CA trusted, no forced command"} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
	log, _ := os.ReadFile(f.sshLog)
	for _, c := range []string{"user=aqmas-inspect,host=bastion", "user=alice,host=bastion"} {
		if !strings.Contains(string(log), c) {
			t.Errorf("sshd -T not asked about %s", c)
		}
	}
	// Idempotent, and the second run is a pure check.
	if out, err = f.run(nil, args...); err != nil || !strings.Contains(out, "nothing to change") {
		t.Fatalf("second run: %v\n%s", err, out)
	}
	// If sshd no longer applies the block (another Match wins, a package replaced a file),
	// the check fails: on an unchanged install nothing is touched, on a fresh one it is undone.
	if out, err = f.run([]string{"FAKE_SSHD_NOMATCH=1"}, args...); err == nil || !strings.Contains(out, "does not show the forced command") {
		t.Fatalf("lost confinement not noticed: %v\n%s", err, out)
	}
	// The runner writes the admin's file; uninstall for the inspect account leaves it alone.
	if err := os.WriteFile(f.path("etc/ssh/aqmas_principals/alice"), []byte("from=\"192.0.2.21\" alice@bastion\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err = f.run(nil, append(append([]string{}, self...), "--uninstall", "--sshd", f.sshd, "--apply")...); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	for _, p := range []string{"etc/ssh/aqmas_user_ca.pub", "etc/ssh/aqmas_principals/aqmas-inspect", "etc/ssh/sshd_config.d/10-aqmas.conf", "etc/ssh/sshd_config.d/90-aqmas-inspect.conf"} {
		if f.exists(p) {
			t.Errorf("%s left behind", p)
		}
	}
	if !f.exists("etc/ssh/aqmas_principals/alice") {
		t.Error("uninstall removed a file it did not write")
	}
	if now, _ := os.ReadFile(f.path("home/alice/.ssh/authorized_keys")); string(now) != string(ak) {
		t.Error("authorized_keys changed")
	}
}

func TestBastionSelfFreshInstallRestoresOnLostConfinement(t *testing.T) {
	f := newFixture(t, "bastion")
	before := f.snapshot()
	out, err := f.run([]string{"FAKE_SSHD_NOMATCH=1"}, "--bastion-self", "--inspect-user", "aqmas-inspect", "--inspect-command", "/usr/local/bin/aqmasd inspect",
		"--name", "bastion", "--ca-key", f.caKey, "--admin-user", "alice", "--sshd", f.sshd, "--apply")
	if err == nil || !strings.Contains(out, "restored the previous files") {
		t.Fatalf("%v\n%s", err, out)
	}
	after := f.snapshot()
	for k := range after {
		if k == f.path("var") || strings.HasPrefix(k, f.path("var")+"/") {
			delete(after, k)
		}
	}
	if !equalMaps(before, after) {
		t.Errorf("not restored:\n%s", out)
	}
}
