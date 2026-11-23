package inspect

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPlanAccepts(t *testing.T) {
	cases := map[string][][]string{
		"logs aqmasd":                     {{"journalctl", "--no-pager", "--output=short-iso", "--since=-60min", "--lines=500", "--unit=aqmasd.service"}},
		"logs  maint since=2d lines=50":   {{"journalctl", "--no-pager", "--output=short-iso", "--since=-2880min", "--lines=50", "--unit=aqmas-maint.service", "--unit=aqmas-maint.path"}},
		"logs kernel lines=5000 since=5m": {{"journalctl", "--no-pager", "--output=short-iso", "--since=-5min", "--lines=5000", "--dmesg"}},
		"status sshd":                     {{"systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp,NRestarts", "sshd.service", "ssh.service"}},
		"failed":                          {{"systemctl", "list-units", "--failed", "--no-pager", "--no-legend"}},
		"disk":                            {{"df", "-P", "-h", "/", "/var", "/var/log"}, {"journalctl", "--no-pager", "--disk-usage"}},
		"version":                         {{"uname", "-srm"}, {"uptime"}},
	}
	for req, want := range cases {
		got, err := Plan(req)
		if err != nil || len(got) != len(want) {
			t.Fatalf("%q: %v %v", req, got, err)
		}
		for i, c := range got {
			if !slices.Equal(append([]string{c.Name}, c.Args...), want[i]) {
				t.Errorf("%q: argv %v, want %v", req, append([]string{c.Name}, c.Args...), want[i])
			}
		}
	}
	for _, req := range []string{"", "  ", "help"} {
		if got, err := Plan(req); got != nil || err != nil {
			t.Errorf("%q should print the help: %v %v", req, got, err)
		}
	}
	// Every word of a status over all units comes from the table, and no form of the
	// request asks systemctl for anything that prints a command line.
	all, err := Plan("status")
	if err != nil || len(all) != 1 || len(all[0].Args) < 10 {
		t.Fatal(all, err)
	}
	for _, a := range all[0].Args {
		if a == "status" || strings.Contains(a, "Exec") && !strings.Contains(a, "ExecMainStatus") || strings.Contains(a, "Environment") {
			t.Fatalf("status must not expose command lines or environments: %v", all[0].Args)
		}
	}
}

// Nothing from a request may reach a command line except a table key and re-formatted numbers.
func TestPlanRefuses(t *testing.T) {
	for _, req := range []string{
		"sh", "bash -c id", "logs", "logs aqmasd.service", "logs ../aqmasd", "logs -u", "logs --file=/var/lib/aqmas/aqmas.db",
		"logs aqmasd --file=/etc/shadow", "logs aqmasd -D /var/lib/aqmas", "logs aqmasd since=1h since=2h", "logs aqmasd since=0h",
		"logs aqmasd since=31d", "logs aqmasd since=1w", "logs aqmasd since=-1h", "logs aqmasd lines=0", "logs aqmasd lines=5001",
		"logs aqmasd lines=99999", "logs aqmasd lines=1 since=1h extra", "logs aqmasd output=json", "logs aqmasd;id", "logs aqmasd|cat",
		"logs aqmasd $(id)", "logs aqmasd `id`", "logs aqmasd\nstatus", "logs aqmasd\x00", "logs 'aqmasd'", "logs aqmasd > /tmp/x",
		"status aqmasd sshd", "status --all", "status user@1000", "failed x", "disk /etc", "version -a", "help me", "scp -t /tmp",
		"internal-sftp", "/usr/libexec/openssh/sftp-server", "logs " + strings.Repeat("a", 200), "LOGS aqmasd", "logs AQMASD",
		"logs aqmasd since=1H", "logs aqmasd since=١h", "systemctl restart aqmasd", "journalctl -u aqmasd", "env", "cat /etc/aqmas/config.toml",
	} {
		if got, err := Plan(req); err != ErrUsage || got != nil {
			t.Errorf("%q was accepted: %v %v", req, got, err)
		}
	}
}

func TestUnitTable(t *testing.T) {
	want := []string{"aqmasd", "cloudflared", "firewall", "lock-alert", "maint", "sshd", "kernel"}
	if got := UnitNames(); !slices.Equal(got, want) {
		t.Fatalf("units %v, want %v", got, want)
	}
	for k, units := range Units {
		for _, u := range units {
			if !strings.HasSuffix(u, ".service") && !strings.HasSuffix(u, ".path") || strings.ContainsAny(u, " /@*") {
				t.Errorf("%s: unexpected unit %q", k, u)
			}
		}
	}
}

// Run executes only the planned argv from binDir, with a clean environment.
func TestRun(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	script := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >>" + log + "\nenv | sort >>" + log + "\necho out-$(basename \"$0\")\n"
	for _, name := range []string{"journalctl", "systemctl", "df", "uname", "uptime"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AQMAS_SECRET_SENTINEL", "must-not-leak")
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), "logs aqmasd lines=3", dir, "1.2.3", &out, &errOut); code != 0 || !strings.Contains(out.String(), "out-journalctl") {
		t.Fatal(code, out.String(), errOut.String())
	}
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), "journalctl --no-pager --output=short-iso --since=-60min --lines=3 --unit=aqmasd.service\n") || strings.Contains(string(b), "SENTINEL") {
		t.Fatalf("log: %s", b)
	}
	out.Reset()
	if code := Run(context.Background(), "version", dir, "1.2.3", &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "aqmasd 1.2.3\n") {
		t.Fatal(code, out.String())
	}
	out.Reset()
	errOut.Reset()
	os.Remove(log)
	if code := Run(context.Background(), "logs aqmasd; cat /etc/shadow", dir, "1.2.3", &out, &errOut); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "not an inspect command") {
		t.Fatal(code, out.String(), errOut.String())
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("a refused request ran a command")
	}
	out.Reset()
	if code := Run(context.Background(), "", dir, "1.2.3", &out, &errOut); code != 0 || !strings.Contains(out.String(), "units: aqmasd") {
		t.Fatal(code, out.String())
	}
}
