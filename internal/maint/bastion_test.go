package maint

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

func newKeyLine(t *testing.T) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), ssh.FingerprintSHA256(pk)
}

// bastionLab adds what the bastion and routine tasks touch: a system root with an sshd
// configuration, a host key and boot files, a real SSH CA public key, and a stand-in for
// every system tool that records its argv (sys.log) and answers from files in the lab.
type bastionLab struct {
	*lab
	caFP, hostKey string
}

const sysScript = `#!/bin/bash
d='DIR'
echo "$*" >> "$d/sys.log"
name=$1; shift
case $name in
getent) [[ -e $d/inspect-user ]] || exit 2; cat "$d/inspect-user" ;;
useradd) echo "aqmas-inspect:x:$(cat "$d/inspect-uid" 2>/dev/null || echo 990):990::/:/bin/sh" > "$d/inspect-user" ;;
usermod | passwd | loginctl) ;;
userdel) rm -f "$d/inspect-user" ;;
id) cat "$d/inspect-groups" 2>/dev/null || echo "aqmas-inspect systemd-journal" ;;
rpm) cat "$d/rpm-$(cat "$d/rpm-phase" 2>/dev/null || echo before)" ;;
systemd-run) [[ -e $d/dnf-fails ]] && exit 1
  echo after > "$d/rpm-phase"
  [[ -e $d/dnf-touches-boot ]] && echo changed >> "$d/sysroot/boot/loader/entries/default.conf"
  exit 0 ;;
systemctl) case $1 in
  show) u=${!#}; if [[ -e $d/unit-$u ]]; then echo loaded; else echo not-found; fi ;;
  is-active) [[ ! -e $d/tunnel-dead ]] ;;
  esac ;;
journalctl) [[ $1 == --disk-usage ]] && echo "Archived and active journals take up 1.2G in the file system." ;;
df) printf 'Filesystem Size Used Avail Use%% Mounted on\n/dev/a 50G 12G 38G 25%% /\n/dev/a 50G 12G 38G 25%% /var\n' ;;
sshd)
  [[ $1 == -t && -e $d/sshd-bad ]] && { echo "bad config" >&2; exit 255; }
  if [[ $1 == -T ]]; then
    echo "trustedusercakeys /etc/ssh/aqmas_user_ca.pub"
    echo "authorizedprincipalsfile /etc/ssh/aqmas_principals/%u"
    conf=$(dirname "$3")/sshd_config.d/90-aqmas-inspect.conf
    user=${5#user=}; user=${user%%,*}
    if [[ -f $conf && ! -e $d/sshd-unconfined ]] && grep -qx "Match User $user" "$conf"; then
      grep -E '^    ' "$conf" | sed 's/^ *//' | awk '{k=tolower($1); $1=""; sub(/^ /,""); print k" "$0}'
    else
      echo "forcecommand none"; echo "disableforwarding no"; echo "permittty yes"
    fi
  fi ;;
esac
exit 0
`

func newBastionLab(t *testing.T) *bastionLab {
	t.Helper()
	b := &bastionLab{lab: newLab(t)}
	ca, fp := newKeyLine(t)
	b.caFP = fp
	b.write(0644, ca+" aqmas-user-ca\n", "data", "ca", "ssh_user_ca.pub")
	hk, _ := newKeyLine(t)
	b.hostKey = hk
	b.write(0644, hk+" root@bastion\n", "sysroot", "etc", "ssh", "ssh_host_ed25519_key.pub")
	b.write(0600, "# test sshd_config\nInclude /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n", "sysroot", "etc", "ssh", "sshd_config")
	b.write(0600, "SyslogFacility AUTHPRIV\n", "sysroot", "etc", "ssh", "sshd_config.d", "50-redhat.conf")
	b.write(0600, "ssh-rsa AAAAB3Nza emergency\n", "sysroot", "home", "alice", ".ssh", "authorized_keys")
	b.write(0644, "title Linux\nlinux /vmlinuz-6.1\n", "sysroot", "boot", "loader", "entries", "default.conf")
	b.write(0644, "kernel image", "sysroot", "boot", "vmlinuz-6.1")
	for _, d := range []string{"sysroot/etc/ssh", "sysroot/etc/ssh/sshd_config.d", "sysroot/etc", "sysroot"} {
		if err := os.Chmod(b.path(d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	b.write(0755, strings.ReplaceAll(sysScript, "DIR", b.dir), "sys")
	b.write(0644, "bash\t5.2-1.fc41.aarch64\nkernel-core\t6.1.0-1.fc41.aarch64\nopenssh-server\t9.6-1.fc41.aarch64\nzlib\t1.3-1.fc41.aarch64\n", "rpm-before")
	b.write(0644, "bash\t5.2-2.fc41.aarch64\nkernel-core\t6.1.0-1.fc41.aarch64\nopenssh-server\t9.7-1.fc41.aarch64\nzlib\t1.3-1.fc41.aarch64\njq\t1.7-1.fc41.aarch64\n", "rpm-after")
	return b
}

func (b *bastionLab) access() BastionAccessParams {
	return BastionAccessParams{Name: "bastion", Address: "192.0.2.10", Port: 22, AdminUser: "alice", SSHCA: b.caFP}
}

// run queues one signed task and runs the runner once.
func (b *bastionLab) run(task string, params any) (*TaskStatus, error) {
	b.t.Helper()
	b.queue(b.sign(task, params, nil))
	err := b.runner().Run(context.Background())
	return b.last(task), err
}

func (b *bastionLab) sysLog() string { return b.read("sys.log") }

func (b *bastionLab) clearSysLog() { _ = os.Remove(b.path("sys.log")) }

func (b *bastionLab) ssh(p ...string) string {
	return b.read(append([]string{"sysroot", "etc", "ssh"}, p...)...)
}

const wantInspectBlock = "# managed by aqmas install-host-trust.sh (bastion inspect account)\nMatch User aqmas-inspect\n    ForceCommand BIN inspect\n    AuthenticationMethods publickey\n" +
	"    AuthorizedKeysFile none\n    AuthorizedKeysCommand none\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    DisableForwarding yes\n    PermitTTY no\n    PermitUserRC no\n"

func TestBastionAccessAllowAndRemove(t *testing.T) {
	b := newBastionLab(t)
	emergency := b.read("sysroot", "home", "alice", ".ssh", "authorized_keys")
	before := b.read("etc", "config.toml")
	cfgMode := mode(t, b.l.Config)

	// Nobody may be allowed before the access exists.
	if st, err := b.run(TaskBastionAllow, BastionAllowParams{Hosts: []AllowedHost{}}); err == nil || !strings.Contains(st.Message, "not installed") {
		t.Fatalf("allow without access: %v %+v", err, st)
	}

	st, err := b.run(TaskBastionAccess, b.access())
	if err != nil {
		t.Fatalf("%v: %+v", err, st)
	}
	if got := b.ssh("aqmas_user_ca.pub"); !strings.HasPrefix(got, "ssh-ed25519 ") || strings.Count(got, "\n") != 1 {
		t.Fatalf("CA file: %q", got)
	}
	if _, fp, err := oneEd25519([]byte(strings.Join(firstFields(b.ssh("aqmas_user_ca.pub"), 2), " "))); err != nil || fp != b.caFP {
		t.Fatalf("installed CA is not the signed one: %v %s", err, fp)
	}
	if got := b.ssh("aqmas_principals", "aqmas-inspect"); got != "aqmas-inspect@bastion\n" {
		t.Fatalf("inspect principals: %q", got)
	}
	if got, want := b.ssh("sshd_config.d", "90-aqmas-inspect.conf"), strings.ReplaceAll(wantInspectBlock, "BIN", b.l.Bin); got != want {
		t.Fatalf("inspect block:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(b.ssh("sshd_config.d", "10-aqmas.conf"), "TrustedUserCAKeys /etc/ssh/aqmas_user_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/aqmas_principals/%u\n") {
		t.Fatal("trust drop-in missing")
	}
	// Nobody is allowed yet: the admin has no principals file, so no root certificate works.
	if _, err := os.Stat(b.path("sysroot", "etc", "ssh", "aqmas_principals", "alice")); err == nil {
		t.Fatal("admin principals file exists with an empty allowlist")
	}
	cfg, err := config.Load(b.l.Config)
	want := config.Bastion{Name: "bastion", Address: "192.0.2.10", Port: 22, AdminUser: "alice", HostKey: b.hostKey}
	if err != nil || cfg.Bastion != want {
		t.Fatalf("config: %v %+v", err, cfg.Bastion)
	}
	text := b.read("etc", "config.toml")
	if !strings.HasPrefix(text, before) || !strings.Contains(text, "# owner's notes stay") || !strings.Contains(text, "\n[bastion]\nname = \"bastion\"\n") {
		t.Fatalf("config text:\n%s", text)
	}
	if mode(t, b.l.Config) != cfgMode {
		t.Fatal("config mode changed")
	}
	if strings.TrimSpace(b.read("active")) != "serve" || !strings.Contains(b.read("hook.log"), "stop\nstart serve\n") {
		t.Fatalf("broker not restarted: %q", b.read("hook.log"))
	}
	log := b.sysLog()
	for _, want := range []string{
		"getent passwd aqmas-inspect\n",
		"useradd --system --no-create-home --home-dir / --shell /bin/sh --groups systemd-journal aqmas-inspect\n",
		"passwd -l aqmas-inspect\n",
		"sshd -t -f " + b.path("sysroot", "etc", "ssh", "sshd_config") + "\n",
		"-C user=aqmas-inspect,host=bastion,addr=192.0.2.50\n",
		"-C user=alice,host=bastion,addr=192.0.2.50\n",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("sys log lacks %q:\n%s", want, log)
		}
	}
	if st.Result["ssh_ca"] != b.caFP || st.Result["inspect_user"] != "aqmas-inspect" || st.State != "done" {
		t.Fatalf("status: %+v", st)
	}

	// The allowlist: root's file and the from= line sshd enforces.
	hosts := []AllowedHost{{ID: "01HZZZZZZZZZZZZZZZZZZZZZZA", Name: "dev-1", Address: "192.0.2.21"}, {ID: "01HZZZZZZZZZZZZZZZZZZZZZZB", Name: "dev-2", Address: "2001:db8::22"}}
	if st, err = b.run(TaskBastionAllow, BastionAllowParams{Hosts: hosts}); err != nil {
		t.Fatalf("%v: %+v", err, st)
	}
	if got := b.ssh("aqmas_principals", "alice"); got != "from=\"192.0.2.21,2001:db8::22\" alice@bastion\n" {
		t.Fatalf("admin principals: %q", got)
	}
	if mode(t, b.path("sysroot", "etc", "ssh", "aqmas_principals", "alice")) != 0644 || mode(t, AllowPath(b.l.ConfigDir)) != 0640 {
		t.Fatal("modes of the allowlist files")
	}
	if got := ReadAllow(AllowPath(b.l.ConfigDir)); !slices.Equal(got, hosts) {
		t.Fatalf("allow file: %+v", got)
	}
	if strings.Contains(b.read("hook.log"), "stop\nstart serve\nstop") {
		t.Fatal("changing the allowlist restarted the broker")
	}
	// Running the access task again keeps the list.
	if _, err = b.run(TaskBastionAccess, b.access()); err != nil {
		t.Fatal(err)
	}
	if got := b.ssh("aqmas_principals", "alice"); !strings.HasPrefix(got, "from=\"192.0.2.21,") {
		t.Fatalf("re-run lost the allowlist: %q", got)
	}
	if n := strings.Count(b.read("etc", "config.toml"), "[bastion]"); n != 1 {
		t.Fatalf("%d [bastion] tables", n)
	}
	// An empty list removes the admin's way in.
	if _, err = b.run(TaskBastionAllow, BastionAllowParams{Hosts: []AllowedHost{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.path("sysroot", "etc", "ssh", "aqmas_principals", "alice")); err == nil || len(ReadAllow(AllowPath(b.l.ConfigDir))) != 0 {
		t.Fatal("empty allowlist left a principals file or entries")
	}
	if _, err = b.run(TaskBastionAllow, BastionAllowParams{Hosts: hosts[:1]}); err != nil {
		t.Fatal(err)
	}

	// Remove: everything the task installed goes, nothing else.
	b.clearSysLog()
	if st, err = b.run(TaskBastionRemove, BastionRemoveParams{}); err != nil {
		t.Fatalf("%v: %+v", err, st)
	}
	for _, p := range []string{"aqmas_user_ca.pub", "aqmas_principals", "sshd_config.d/10-aqmas.conf", "sshd_config.d/90-aqmas-inspect.conf"} {
		if _, err := os.Stat(b.path("sysroot", "etc", "ssh", p)); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
	if _, err := os.Stat(AllowPath(b.l.ConfigDir)); err == nil {
		t.Error("allowlist left behind")
	}
	if got := b.read("etc", "config.toml"); got != before && strings.TrimRight(got, "\n") != strings.TrimRight(before, "\n") {
		t.Fatalf("config after removal:\n%s", got)
	}
	if log := b.sysLog(); !strings.Contains(log, "loginctl terminate-user aqmas-inspect\n") || !strings.Contains(log, "userdel aqmas-inspect\n") {
		t.Fatalf("account not removed: %s", log)
	}
	if b.read("sysroot", "home", "alice", ".ssh", "authorized_keys") != emergency || b.ssh("sshd_config.d", "50-redhat.conf") == "" {
		t.Fatal("removal touched files that are not aqmas's")
	}
	b.noSecrets()
}

func TestBastionAccessRefusals(t *testing.T) {
	b := newBastionLab(t)
	before := b.read("etc", "config.toml")
	untouched := func(why string) {
		t.Helper()
		if b.read("etc", "config.toml") != before {
			t.Fatalf("%s: configuration changed", why)
		}
		for _, p := range []string{"aqmas_user_ca.pub", "aqmas_principals", "sshd_config.d/10-aqmas.conf", "sshd_config.d/90-aqmas-inspect.conf"} {
			if _, err := os.Stat(b.path("sysroot", "etc", "ssh", p)); err == nil {
				t.Fatalf("%s: %s exists", why, p)
			}
		}
	}
	// Another CA than the signed one (the broker owns that file).
	_, other := newKeyLine(t)
	p := b.access()
	p.SSHCA = other
	if st, err := b.run(TaskBastionAccess, p); err == nil || !strings.Contains(st.Message, "not the one you signed") {
		t.Fatalf("wrong CA accepted: %v %+v", err, st)
	}
	untouched("wrong CA")
	if strings.Contains(b.sysLog(), "useradd") {
		t.Fatal("account created before the CA was checked")
	}
	// A CA file that is not one plain key, or a link out of the broker's directory.
	good := b.read("data", "ca", "ssh_user_ca.pub")
	b.write(0644, good+good, "data", "ca", "ssh_user_ca.pub")
	if _, err := b.run(TaskBastionAccess, b.access()); err == nil {
		t.Fatal("two keys accepted")
	}
	b.write(0644, good, "outside.pub")
	_ = os.Remove(b.path("data", "ca", "ssh_user_ca.pub"))
	if err := os.Symlink(b.path("outside.pub"), b.path("data", "ca", "ssh_user_ca.pub")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(TaskBastionAccess, b.access()); err == nil {
		t.Fatal("followed a link out of the CA directory")
	}
	_ = os.Remove(b.path("data", "ca", "ssh_user_ca.pub"))
	b.write(0644, good, "data", "ca", "ssh_user_ca.pub")
	untouched("bad CA file")

	// A name that collides with a target is refused by the configuration rules, first.
	p = b.access()
	p.Name = "db-1"
	if st, err := b.run(TaskBastionAccess, p); err == nil || !strings.Contains(st.Message, "would not be valid") {
		t.Fatalf("colliding name accepted: %v %+v", err, st)
	}
	untouched("colliding name")
	if strings.Contains(b.sysLog(), "useradd") || strings.Contains(b.sysLog(), "sshd") {
		t.Fatal("machine touched before the configuration was proved")
	}

	// An existing account of that name that is not a confined system account.
	b.write(0644, "aqmas-inspect:x:1001:1001::/home/x:/bin/bash\n", "inspect-user")
	if st, err := b.run(TaskBastionAccess, b.access()); err == nil || !strings.Contains(st.Message, "not a system account") {
		t.Fatalf("ordinary account accepted: %v %+v", err, st)
	}
	b.write(0644, "aqmas-inspect:x:0:0::/:/bin/sh\n", "inspect-user")
	if _, err := b.run(TaskBastionAccess, b.access()); err == nil {
		t.Fatal("uid 0 accepted")
	}
	b.write(0644, "aqmas-inspect:x:990:990::/:/bin/sh\n", "inspect-user")
	b.write(0644, "aqmas-inspect systemd-journal wheel\n", "inspect-groups")
	if st, err := b.run(TaskBastionAccess, b.access()); err == nil || !strings.Contains(st.Message, "wheel") {
		t.Fatalf("account in wheel accepted: %v %+v", err, st)
	}
	untouched("bad account")
	_ = os.Remove(b.path("inspect-user"))
	_ = os.Remove(b.path("inspect-groups"))

	// sshd rejects the result: the installer restores, nothing is configured.
	b.write(0644, "", "sshd-bad")
	if _, err := b.run(TaskBastionAccess, b.access()); err == nil {
		t.Fatal("bad sshd configuration accepted")
	}
	untouched("sshd -t failed")
	_ = os.Remove(b.path("sshd-bad"))
	// sshd would not confine the inspect account (another Match wins).
	b.write(0644, "", "sshd-unconfined")
	if _, err := b.run(TaskBastionAccess, b.access()); err == nil {
		t.Fatal("unconfined inspect account accepted")
	}
	untouched("unconfined")
	_ = os.Remove(b.path("sshd-unconfined"))

	// The broker does not start on the new configuration.
	b.write(0644, "", "refuse-once-serve")
	if st, err := b.run(TaskBastionAccess, b.access()); err == nil || !strings.Contains(st.Message, "restored") {
		t.Fatalf("failed start not handled: %v %+v", err, st)
	}
	untouched("broker did not start")
	if strings.TrimSpace(b.read("active")) != "serve" {
		t.Fatal("broker left stopped")
	}
}

// In a sealed store the CA must also be the one of the manifest root pinned.
func TestBastionAccessManifestPin(t *testing.T) {
	b := newBastionLab(t)
	manifest := func(ca string) string {
		m, _ := json.Marshal(map[string]any{"seal_format": 2, "ssh_ca": ca})
		return string(m)
	}
	pinned := manifest(b.caFP)
	sum := sha256.Sum256([]byte(pinned))
	raw := b.read("etc", "config.toml")
	raw = strings.Replace(raw, "[ntfy]", "[seal]\nrequired = true\nrecipient = \""+sealParams().Recipient+"\"\nmanifest_sha256 = \""+hex.EncodeToString(sum[:])+"\"\n\n[ntfy]", 1)
	b.write(0640, raw, "etc", "config.toml")
	activation := func(m string) {
		a, _ := json.Marshal(map[string]any{"manifest": m})
		b.facts.Activation = string(a)
		b.setFacts(9, "")
	}
	// The database's manifest is not the pinned one.
	_, other := newKeyLine(t)
	activation(manifest(other))
	if st, err := b.run(TaskBastionAccess, b.access()); err == nil || !strings.Contains(st.Message, "pinned") {
		t.Fatalf("unpinned manifest accepted: %v %+v", err, st)
	}
	// No activation record at all.
	b.facts.Activation = ""
	b.setFacts(9, "")
	if _, err := b.run(TaskBastionAccess, b.access()); err == nil {
		t.Fatal("missing manifest accepted")
	}
	// The pinned manifest names another CA than the file and the signature: a swapped file
	// with a matching card is still refused.
	swapped, swappedFP := newKeyLine(t)
	b.write(0644, swapped+"\n", "data", "ca", "ssh_user_ca.pub")
	activation(pinned)
	p := b.access()
	p.SSHCA = swappedFP
	if st, err := b.run(TaskBastionAccess, p); err == nil || !strings.Contains(st.Message, "pinned activation manifest") {
		t.Fatalf("swapped CA accepted: %v %+v", err, st)
	}
	if _, err := os.Stat(b.path("sysroot", "etc", "ssh", "aqmas_user_ca.pub")); err == nil {
		t.Fatal("a CA was installed")
	}
}

func TestBastionConfigEdits(t *testing.T) {
	base := []byte("public_base_url = \"https://a.example.com\"\n\n[[targets]]\nname = \"db-1\"\naddress = \"192.0.2.61\"\nusers = [\"alice\"]\n")
	hk, _ := newKeyLine(t)
	b := config.Bastion{Name: "bastion", Address: "192.0.2.10", Port: 2222, AdminUser: "alice", HostKey: hk}
	out, err := addBastion(base, b)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil || cfg.Bastion != b || len(cfg.Targets) != 1 {
		t.Fatalf("%v %+v", err, cfg)
	}
	// Replacing keeps one table; removing restores the original text.
	b2 := b
	b2.AdminUser = "bob"
	out2, err := addBastion(out, b2)
	if err != nil || strings.Count(string(out2), "[bastion]") != 1 {
		t.Fatalf("%v\n%s", err, out2)
	}
	back, err := removeBastion(out2)
	if err != nil || strings.TrimRight(string(back), "\n") != strings.TrimRight(string(base), "\n") {
		t.Fatalf("%v\n%q", err, back)
	}
	// A table in the middle of the file is removed without touching what follows.
	mid := "public_base_url = \"https://a.example.com\"\n\n[bastion] # here\nname = \"bastion\"\naddress = \"192.0.2.10\"\nadmin_user = \"alice\"\nhost_key = \"" + hk + "\"\n\n[[targets]]\nname = \"db-1\"\naddress = \"192.0.2.61\"\nusers = [\"alice\"]\n"
	if got, err := removeBastion([]byte(mid)); err != nil || strings.Contains(string(got), "bastion") || !strings.Contains(string(got), "[[targets]]\nname = \"db-1\"") {
		t.Fatalf("%v\n%s", err, got)
	}
	// Collisions and reserved accounts never produce a configuration.
	for _, bad := range []config.Bastion{
		{Name: "db-1", Address: "192.0.2.10", Port: 22, AdminUser: "alice", HostKey: hk},
		{Name: "bastion", Address: "192.0.2.10", Port: 22, AdminUser: "root", HostKey: hk},
		{Name: "bastion", Address: "192.0.2.10", Port: 22, AdminUser: "aqmas-inspect", HostKey: hk},
		{Name: "bastion", Address: "bastion.example.com", Port: 22, AdminUser: "alice", HostKey: hk},
		{Name: "bastion", Address: "192.0.2.10", Port: 22, AdminUser: "alice", HostKey: "ssh-rsa AAAA"},
		{Name: "bastion\"\n[ntfy]\ntopic_url = \"https://evil.example.com/x", Address: "192.0.2.10", Port: 22, AdminUser: "alice", HostKey: hk},
	} {
		if out, err := addBastion(base, bad); err == nil {
			t.Errorf("accepted %+v:\n%s", bad, out)
		}
	}
	// A target that would issue the bastion's principal.
	clash := append(slices.Clone(base), []byte("\n[[targets]]\nname = \"forge\"\naddress = \"192.0.2.62\"\nusers = [\"git\"]\nprincipal = \"alice@bastion\"\n")...)
	if _, err := addBastion(clash, b); err == nil {
		t.Error("principal collision accepted")
	}
}

func TestOSUpdate(t *testing.T) {
	b := newBastionLab(t)
	st, err := b.run(TaskOSUpdate, OSUpdateParams{})
	if err != nil {
		t.Fatalf("%v: %+v", err, st)
	}
	want := "systemd-run --wait --collect --quiet --pipe --unit=aqmas-os-update --description=aqmas: system package update --property=TimeoutStartSec=5400 -- dnf -y --refresh upgrade" +
		" --exclude=kernel* --exclude=kmod-* --exclude=akmod-* --exclude=grub2* --exclude=shim* --exclude=dracut* --exclude=systemd-boot* --exclude=sdubby* --exclude=linux-firmware* --exclude=m1n1* --exclude=uboot* --exclude=asahi-*\n"
	if !strings.Contains(b.sysLog(), want) {
		t.Fatalf("dnf argv:\n%s", b.sysLog())
	}
	if !strings.Contains(b.sysLog(), "rpm -qa --qf %{NAME}\\t%{EVR}.%{ARCH}\\n\n") {
		t.Fatalf("rpm argv:\n%s", b.sysLog())
	}
	log := strings.Join(st.Log, "\n")
	for _, line := range []string{"bash 5.2-1.fc41.aarch64 → 5.2-2.fc41.aarch64", "installed jq 1.7-1.fc41.aarch64", "openssh-server 9.6-1.fc41.aarch64 → 9.7-1.fc41.aarch64"} {
		if !strings.Contains(log, line) {
			t.Errorf("summary lacks %q:\n%s", line, log)
		}
	}
	if st.Result["packages_changed"] != "3" || st.Result["boot_files_changed"] != "false" || st.Result["kernel_allowed"] != "false" || !strings.Contains(st.Message, "left alone") {
		t.Fatalf("result: %+v %q", st.Result, st.Message)
	}
	if strings.Contains(b.sysLog(), "sshd") {
		t.Fatal("sshd checked although bastion access is not installed")
	}

	// A site's own exclusions are added; a file with anything but globs is refused.
	_ = os.Remove(b.path("rpm-phase"))
	b.clearSysLog()
	b.write(0644, "# pinned here\nzfs*\nnvidia-driver\n", "etc", "os-update-exclude")
	if _, err = b.run(TaskOSUpdate, OSUpdateParams{}); err != nil || !strings.Contains(b.sysLog(), " --exclude=asahi-* --exclude=zfs* --exclude=nvidia-driver\n") {
		t.Fatalf("site exclusions: %v\n%s", err, b.sysLog())
	}
	for _, bad := range []string{"kernel*; id\n", "--installroot=/x\n", "a b\n", "$(id)\n", "ok\n../x\n"} {
		b.clearSysLog()
		b.write(0644, bad, "etc", "os-update-exclude")
		if _, err = b.run(TaskOSUpdate, OSUpdateParams{}); err == nil || strings.Contains(b.sysLog(), "systemd-run") {
			t.Fatalf("exclusion file %q accepted", bad)
		}
	}
	b.write(0666, "zfs*\n", "etc", "os-update-exclude")
	if err := os.Chmod(b.path("etc", "os-update-exclude"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = b.run(TaskOSUpdate, OSUpdateParams{}); err == nil {
		t.Fatal("world-writable exclusion file accepted")
	}
	_ = os.Remove(b.path("etc", "os-update-exclude"))

	// With the owner's permission nothing is excluded.
	_ = os.Remove(b.path("rpm-phase"))
	b.clearSysLog()
	if st, err = b.run(TaskOSUpdate, OSUpdateParams{Kernel: true}); err != nil || strings.Contains(b.sysLog(), "--exclude") || !strings.Contains(b.sysLog(), "-- dnf -y --refresh upgrade\n") {
		t.Fatalf("kernel update: %v %+v\n%s", err, st, b.sysLog())
	}

	// dnf fails: reported, with what changed before it stopped.
	b.write(0644, "", "dnf-fails")
	if st, err = b.run(TaskOSUpdate, OSUpdateParams{}); err == nil || !strings.Contains(st.Message, "dnf upgrade failed") {
		t.Fatalf("dnf failure: %v %+v", err, st)
	}
}

func TestOSUpdateKernelGuardAndRestartRefusal(t *testing.T) {
	b := newBastionLab(t)
	marker := b.path("maint", "boot-changed")
	// A kernel package changed although it was excluded.
	b.write(0644, "bash\t5.2-2.fc41.aarch64\nkernel-core\t6.2.0-1.fc41.aarch64\nopenssh-server\t9.6-1.fc41.aarch64\nzlib\t1.3-1.fc41.aarch64\n", "rpm-after")
	st, err := b.run(TaskOSUpdate, OSUpdateParams{})
	if err == nil || !strings.Contains(st.Message, "kernel-core") || st.Result["kernel_or_boot_packages_changed"] != "kernel-core" {
		t.Fatalf("kernel change not caught: %v %+v", err, st)
	}
	if !strings.Contains(strings.Join(st.Log, "\n"), "kernel-core 6.1.0-1.fc41.aarch64 → 6.2.0-1.fc41.aarch64") {
		t.Fatalf("summary: %v", st.Log)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("no marker")
	}
	// While the marker exists the machine is not restarted.
	b.clearSysLog()
	if st, err = b.run(TaskReboot, RebootParams{}); err == nil || !strings.Contains(st.Message, "Refused") || strings.Contains(b.sysLog(), "systemctl") {
		t.Fatalf("restart after an unapproved boot change: %v %+v\n%s", err, st, b.sysLog())
	}
	// The owner accepts kernel changes: the marker goes, the restart is allowed.
	_ = os.Remove(b.path("rpm-phase"))
	if _, err = b.run(TaskOSUpdate, OSUpdateParams{Kernel: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("marker survived an approved kernel update")
	}
	b.clearSysLog()
	st, err = b.run(TaskReboot, RebootParams{})
	if err != nil || st.State != "done" || !strings.Contains(st.Message, "nothing open") {
		t.Fatalf("restart: %v %+v", err, st)
	}
	if b.sysLog() != "systemctl reboot\n" {
		t.Fatalf("restart argv: %q", b.sysLog())
	}

	// The boot files changed although no excluded package did.
	_ = os.Remove(b.path("rpm-phase"))
	b.write(0644, "bash\t5.2-2.fc41.aarch64\nkernel-core\t6.1.0-1.fc41.aarch64\nopenssh-server\t9.6-1.fc41.aarch64\nzlib\t1.3-1.fc41.aarch64\n", "rpm-after")
	b.write(0644, "", "dnf-touches-boot")
	if st, err = b.run(TaskOSUpdate, OSUpdateParams{}); err == nil || !strings.Contains(st.Message, "boot files changed") || st.Result["boot_files_changed"] != "true" {
		t.Fatalf("boot change not caught: %v %+v", err, st)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("no marker after a boot file change")
	}
}

// After an update the runner checks that sshd still confines the inspect account.
func TestOSUpdateRechecksConfinement(t *testing.T) {
	b := newBastionLab(t)
	if _, err := b.run(TaskBastionAccess, b.access()); err != nil {
		t.Fatal(err)
	}
	b.clearSysLog()
	if st, err := b.run(TaskOSUpdate, OSUpdateParams{}); err != nil || !strings.Contains(b.sysLog(), "-C user=aqmas-inspect,host=bastion") {
		t.Fatalf("no re-check: %v %+v\n%s", err, st, b.sysLog())
	}
	_ = os.Remove(b.path("rpm-phase"))
	b.write(0644, "", "sshd-unconfined")
	if st, err := b.run(TaskOSUpdate, OSUpdateParams{}); err == nil || !strings.Contains(st.Message, "no longer confines") {
		t.Fatalf("lost confinement not reported: %v %+v", err, st)
	}
}

func TestRoutineTasks(t *testing.T) {
	b := newBastionLab(t)
	// The tunnel: the first installed unit of the fixed list, by LoadState only.
	if st, err := b.run(TaskRestartTunnel, RestartTunnelParams{}); err == nil || !strings.Contains(st.Message, "no cloudflared service") {
		t.Fatalf("missing tunnel: %v %+v", err, st)
	}
	b.write(0644, "", "unit-cloudflared.service")
	b.clearSysLog()
	st, err := b.run(TaskRestartTunnel, RestartTunnelParams{})
	if err != nil || st.Result["unit"] != "cloudflared.service" {
		t.Fatalf("%v %+v", err, st)
	}
	if got, want := b.sysLog(), "systemctl show --property=LoadState --value cloudflared-aqmas.service\nsystemctl show --property=LoadState --value cloudflared.service\nsystemctl restart cloudflared.service\nsystemctl is-active --quiet cloudflared.service\n"; got != want {
		t.Fatalf("tunnel argv:\n%s", got)
	}
	b.write(0644, "", "unit-cloudflared-aqmas.service")
	b.clearSysLog()
	if _, err = b.run(TaskRestartTunnel, RestartTunnelParams{}); err != nil || !strings.Contains(b.sysLog(), "systemctl restart cloudflared-aqmas.service\n") {
		t.Fatalf("preferred unit: %v\n%s", err, b.sysLog())
	}
	if strings.Contains(b.sysLog(), "status") || strings.Contains(b.sysLog(), " cat ") {
		t.Fatal("asked systemctl for something that can print the tunnel token")
	}

	// The broker.
	before := b.read("hook.log")
	if st, err = b.run(TaskRestartBroker, RestartBrokerParams{}); err != nil || !strings.HasSuffix(b.read("hook.log"), "stop\nstart serve\nactive\n") && !strings.Contains(strings.TrimPrefix(b.read("hook.log"), before), "stop\nstart serve\n") {
		t.Fatalf("broker restart: %v %+v\n%s", err, st, b.read("hook.log"))
	}

	// Disk and journal usage.
	b.clearSysLog()
	st, err = b.run(TaskDiskUsage, DiskUsageParams{})
	if err != nil || st.Result["disk /"] != "12G of 50G used (25%), 38G free" || !strings.Contains(st.Result["journal"], "1.2G") {
		t.Fatalf("%v %+v", err, st)
	}
	if got, want := b.sysLog(), "df -P -h / "+b.path("data")+" /var/log\njournalctl --disk-usage\n"; got != want {
		t.Fatalf("usage argv:\n%s", got)
	}

	// Trimming the journal: the days are a number the runner formats.
	b.clearSysLog()
	if st, err = b.run(TaskJournalVacuum, JournalVacuumParams{KeepDays: 14}); err != nil || st.Result["keep_days"] != "14" {
		t.Fatalf("%v %+v", err, st)
	}
	if log := b.sysLog(); !strings.Contains(log, "journalctl --rotate\njournalctl --vacuum-time=14d\n") {
		t.Fatalf("vacuum argv:\n%s", log)
	}
}

// Every parameter schema: one accepted encoding, nothing outside the patterns, and nothing
// that could become an option or a second word of a command line.
func TestBastionAndRoutineParams(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("A", 43)
	ok := map[string]string{
		TaskBastionAccess: `{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
		TaskBastionRemove: `{}`,
		TaskBastionAllow:  `{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"192.0.2.21"}]}`,
		TaskOSUpdate:      `{"kernel":false}`,
		TaskReboot:        `{}`,
		TaskRestartTunnel: `{}`,
		TaskRestartBroker: `{}`,
		TaskDiskUsage:     `{}`,
		TaskJournalVacuum: `{"keep_days":14}`,
	}
	for task, text := range ok {
		v, err := Parse(task, text)
		if err != nil {
			t.Errorf("%s: %s refused: %v", task, text, err)
			continue
		}
		if again, err := Canonical(task, v); err != nil || again != text {
			t.Errorf("%s: canonical %q %v", task, again, err)
		}
		if _, known := Lookup(task); !known {
			t.Errorf("%s has no description", task)
		}
		// Another task's parameters, extra keys, whitespace and trailing data are refused.
		for _, bad := range []string{strings.Replace(text, "}", `,"x":1}`, 1), " " + text, text + " ", text + "{}", strings.Replace(text, "{", `{"cmd":"id",`, 1), "null", "[]", ""} {
			if bad == text {
				continue
			}
			if _, err := Parse(task, bad); err == nil {
				t.Errorf("%s accepted %q", task, bad)
			}
		}
	}
	if _, err := Parse(TaskBastionAllow, `{"hosts":[]}`); err != nil {
		t.Errorf("empty allowlist refused: %v", err)
	}
	bad := map[string][]string{
		TaskBastionAccess: {
			`{"address":"192.0.2.10","name":"bastion","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`, // key order
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"alice"}`,
			`{"name":"Bastion","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"--apply","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion;id","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"bastion.example.com","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10 --root /","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.010","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"0.0.0.0","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"fe80::1%eth0","port":22,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":0,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":65536,"admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":"22","admin_user":"alice","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"root","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"aqmas","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"aqmas-inspect","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"alice --user root","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"-o","ssh_ca":"` + fp + `"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"MD5:00:11"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"` + fp + ` --apply"}`,
			`{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"` + fp + `","host_key":"ssh-ed25519 AAAA"}`,
		},
		TaskBastionAllow: {
			`{}`, `{"hosts":null}`,
			`{"hosts":[{"id":"x","name":"dev-1","address":"192.0.2.21"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"*"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"192.0.2.0/24"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"192.0.2.21,*"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"192.0.2.21\" root@bastion"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"!192.0.2.21"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev 1","address":"192.0.2.21"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA/../x","name":"dev-1","address":"192.0.2.21"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZB","name":"dev-2","address":"192.0.2.22"},{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"192.0.2.21"}]}`,
			`{"hosts":[{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"192.0.2.21"},{"id":"01HZZZZZZZZZZZZZZZZZZZZZZA","name":"dev-1","address":"192.0.2.21"}]}`,
			`{"hosts":[{"name":"dev-1","id":"01HZZZZZZZZZZZZZZZZZZZZZZA","address":"192.0.2.21"}]}`,
		},
		TaskOSUpdate:      {`{}`, `{"kernel":"true"}`, `{"kernel":1}`, `{"kernel":true,"exclude":"x"}`, `{"kernel":false,"args":["--installroot=/x"]}`},
		TaskJournalVacuum: {`{}`, `{"keep_days":0}`, `{"keep_days":366}`, `{"keep_days":-1}`, `{"keep_days":"14"}`, `{"keep_days":14.5}`, `{"keep_days":1e2}`, `{"keep_days":014}`, `{"keep_days":14,"unit":"s"}`},
		TaskReboot:        {`{"force":true}`, `{"when":"now"}`},
		TaskRestartTunnel: {`{"unit":"sshd.service"}`},
		TaskRestartBroker: {`{"mode":"seal-import"}`},
		TaskDiskUsage:     {`{"path":"/var/lib/aqmas"}`},
		TaskBastionRemove: {`{"keep_user":true}`},
	}
	for task, list := range bad {
		for _, text := range list {
			if v, err := Parse(task, text); err == nil {
				t.Errorf("%s accepted %s as %+v", task, text, v)
			}
		}
	}
	// Decode takes any key order (a browser's) and still refuses unknown keys; values are
	// judged by Canonical.
	v, err := Decode(TaskBastionAccess, []byte(`{"ssh_ca":"`+fp+`","port":22,"admin_user":"alice","address":"192.0.2.10","name":"bastion"}`))
	if err != nil {
		t.Fatal(err)
	}
	if text, err := Canonical(TaskBastionAccess, v); err != nil || text != ok[TaskBastionAccess] {
		t.Fatalf("%q %v", text, err)
	}
	if _, err := Decode(TaskOSUpdate, []byte(`{"kernel":true,"x":1}`)); err == nil {
		t.Fatal("unknown key decoded")
	}
	if _, err := Decode(TaskSeal, []byte(`{}`)); err == nil {
		t.Fatal("Decode is only for the bastion and routine tasks")
	}
	if _, err := Canonical(TaskOSUpdate, JournalVacuumParams{KeepDays: 3}); err == nil {
		t.Fatal("parameters of another task accepted")
	}
}

func TestAgentAllowed(t *testing.T) {
	for _, c := range []struct {
		task   string
		params any
		ok     bool
	}{
		{TaskOSUpdate, OSUpdateParams{}, true},
		{TaskOSUpdate, OSUpdateParams{Kernel: true}, false},
		{TaskJournalVacuum, JournalVacuumParams{KeepDays: 7}, true},
		{TaskJournalVacuum, JournalVacuumParams{KeepDays: 6}, false},
		{TaskReboot, RebootParams{}, true},
		{TaskRestartTunnel, RestartTunnelParams{}, true},
		{TaskRestartBroker, RestartBrokerParams{}, true},
		{TaskDiskUsage, DiskUsageParams{}, true},
		{TaskBastionAccess, BastionAccessParams{}, false},
		{TaskBastionRemove, BastionRemoveParams{}, false},
		{TaskBastionAllow, BastionAllowParams{Hosts: []AllowedHost{}}, false},
		{TaskPins, PinsParams{}, false},
		{TaskSeal, SealParams{}, false},
		{TaskUpdates, UpdatesParams{}, false},
		{TaskCutover, CutoverParams{}, false},
		{TaskUpgrade, nil, false},
		{"shell", nil, false},
	} {
		if err := AgentAllowed(c.task, c.params); (err == nil) != c.ok {
			t.Errorf("%s %+v: %v", c.task, c.params, err)
		}
	}
}

// Verify accepts each new task only as a signed, fresh, canonical request by a pinned key.
func TestVerifyNewTasks(t *testing.T) {
	b := newBastionLab(t)
	pins, err := b.runner().readPins()
	if err != nil {
		t.Fatal(err)
	}
	for task, params := range map[string]any{
		TaskBastionAccess: b.access(), TaskBastionRemove: BastionRemoveParams{}, TaskBastionAllow: BastionAllowParams{Hosts: []AllowedHost{}},
		TaskOSUpdate: OSUpdateParams{Kernel: true}, TaskReboot: RebootParams{}, TaskRestartTunnel: RestartTunnelParams{},
		TaskRestartBroker: RestartBrokerParams{}, TaskDiskUsage: DiskUsageParams{}, TaskJournalVacuum: JournalVacuumParams{KeepDays: 30},
	} {
		req := b.sign(task, params, nil)
		v, err := Verify(req, origin, pins, b.runner().now())
		if err != nil || v.Task != task || v.Params != nil && !sameParams(v.Params, params) {
			t.Errorf("%s: %v %+v", task, err, v.Params)
		}
		// Another key's signature, or the signature moved to other parameters, is refused.
		other := newAuth()
		forged := req
		forged.Assertion = other.Assert(sha256Of(req.Canonical))
		if _, err := Verify(forged, origin, pins, b.runner().now()); err == nil {
			t.Errorf("%s: unpinned signature accepted", task)
		}
		if _, err := Verify(req, "https://other.example.com", pins, b.runner().now()); err == nil {
			t.Errorf("%s: other origin accepted", task)
		}
	}
	for _, task := range []string{"shell", "bastion-root", "os-update ", "../reboot", "dnf"} {
		req := b.signRaw(task, "{}", nil)
		if _, err := Verify(req, origin, pins, b.runner().now()); err == nil {
			t.Errorf("unknown task %q accepted", task)
		}
	}
	// A request that is not on the allowlist never reaches a command.
	b.clearSysLog()
	b.queue(b.signRaw("shell", "{}", nil))
	if err := b.runner().Run(context.Background()); err == nil || b.sysLog() != "" {
		t.Fatalf("unknown task ran something: %v %q", err, b.sysLog())
	}
	// A signed vacuum whose text was altered after signing does not run.
	req := b.sign(TaskJournalVacuum, JournalVacuumParams{KeepDays: 30}, nil)
	req.Canonical = strings.Replace(req.Canonical, `\"keep_days\":30`, `\"keep_days\":1`, 1)
	b.queue(req)
	if err := b.runner().Run(context.Background()); err == nil || strings.Contains(b.sysLog(), "vacuum") {
		t.Fatalf("altered request ran: %v %q", err, b.sysLog())
	}
}

func sameParams(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func sha256Of(text string) []byte {
	h := sha256.Sum256([]byte(text))
	return h[:]
}

func TestBootFingerprint(t *testing.T) {
	b := newBastionLab(t)
	one, err := b.l.bootFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if two, _ := b.l.bootFingerprint(); two != one {
		t.Fatal("fingerprint is not stable")
	}
	b.write(0644, "another kernel", "sysroot", "boot", "vmlinuz-6.2")
	added, _ := b.l.bootFingerprint()
	if added == one {
		t.Fatal("a new file under /boot went unnoticed")
	}
	// No /boot at all is a fingerprint too, not an error.
	if err := os.RemoveAll(b.path("sysroot", "boot")); err != nil {
		t.Fatal(err)
	}
	if none, err := b.l.bootFingerprint(); err != nil || none == added {
		t.Fatalf("%v", err)
	}
	if got := filepath.Base(b.l.bootMarker()); got != "boot-changed" {
		t.Fatal(got)
	}
}
