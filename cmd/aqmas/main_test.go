package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseFlags(t *testing.T) {
	spec := map[string]bool{"ttl": true, "why": true, "fresh": false}
	f, err := parseFlags([]string{"--ttl", "10m", "db-1", "--why=check disk", "--fresh", "--", "df", "-h", "--why"}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if f.str["ttl"] != "10m" || f.str["why"] != "check disk" || !f.bool["fresh"] {
		t.Errorf("flags %+v", f)
	}
	if !reflect.DeepEqual(f.pos, []string{"db-1"}) || !reflect.DeepEqual(f.cmd, []string{"df", "-h", "--why"}) {
		t.Errorf("pos %q cmd %q", f.pos, f.cmd)
	}
	for _, bad := range [][]string{{"--bogus"}, {"--ttl"}, {"--fresh=1"}, {"--why", "--", "ls"}} {
		if _, err := parseFlags(bad, spec); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if f, _ := parseFlags([]string{"db-1"}, spec); f.cmd != nil {
		t.Error("cmd should be nil without --")
	}
}

func TestParseArgsGroupsAndMulti(t *testing.T) {
	spec := map[string]int{"grant": flagMulti, "request": flagGroup, "ttl": flagValue, "why": flagValue, "raw": flagBool}
	f, err := parseArgs([]string{"--grant", "G1", "--request", "cf.dns.edit", "zone=a", "name=*.a", "--grant=G2",
		"--request", "cf.read", "--why", "deploy", "--raw", "--", "wrangler", "deploy", "--why"}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.multi["grant"], []string{"G1", "G2"}) || f.str["why"] != "deploy" || !f.bool["raw"] {
		t.Errorf("flags %+v", f)
	}
	want := []group{{"cf.dns.edit", []string{"zone=a", "name=*.a"}}, {"cf.read", nil}}
	if !reflect.DeepEqual(f.groups, want) || !reflect.DeepEqual(f.cmd, []string{"wrangler", "deploy", "--why"}) || len(f.pos) != 0 {
		t.Errorf("groups %+v cmd %q pos %q", f.groups, f.cmd, f.pos)
	}
	o, err := envOptions(f)
	if err != nil || len(o.Requests) != 2 || o.Requests[0].Params["name"] != "*.a" || len(o.Grants) != 2 {
		t.Errorf("env options %+v %v", o, err)
	}
	for _, bad := range [][]string{{"--bogus"}, {"--grant"}, {"--raw=1"}, {"--request", "--", "x"}} {
		if _, err := parseArgs(bad, spec); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A key=value word that is not after --request stays positional (cf request SCOPE k=v).
	f, _ = parseArgs([]string{"cf.dns.edit", "zone=a", "--ttl", "1h"}, spec)
	if !reflect.DeepEqual(f.pos, []string{"cf.dns.edit", "zone=a"}) || f.str["ttl"] != "1h" {
		t.Errorf("pos %q", f.pos)
	}
}

// capture runs the CLI with stdout and stderr in files.
func capture(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	// A fresh, empty configuration: nothing here may reach a real broker.
	t.Setenv("AQMAS_CONFIG_DIR", filepath.Join(dir, "config"))
	t.Setenv("AQMAS_CACHE_DIR", filepath.Join(dir, "cache"))
	oldOut, oldErr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	var err error
	if os.Stdout, err = os.Create(filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if os.Stderr, err = os.Create(filepath.Join(dir, "err")); err != nil {
		t.Fatal(err)
	}
	code = run(args)
	os.Stdout.Close()
	os.Stderr.Close()
	o, _ := os.ReadFile(filepath.Join(dir, "out"))
	e, _ := os.ReadFile(filepath.Join(dir, "err"))
	return code, string(o), string(e)
}

func TestSetUsage(t *testing.T) {
	// Help prints the set lines of the usage text, and only those.
	for _, args := range [][]string{{"set", "--help"}, {"set", "-h"}, {"set", "help"}, {"set", "import", "--help"}, {"set", "import", "help"}, {"set", "put", "a/b/c", "-h"}, {"set", "check", "--help"}} {
		code, out, errOut := capture(t, args...)
		if code != 0 || errOut != "" || !strings.HasPrefix(out, "Usage:\n  aqmas set import PATH --from FILE --why REASON") || !strings.Contains(out, "aqmas set check --from FILE [PATH]") || !strings.Contains(out, "--ticket-fd FD") || strings.Contains(out, "aqmas run") || strings.Contains(out, "aqmas cf") {
			t.Errorf("%q: exit %d\n%s%s", args, code, out, errOut)
		}
	}
	if u := setUsage(); !strings.Contains(usage, strings.TrimPrefix(u, "Usage:\n")) || strings.Count(u, "\n") < 8 {
		t.Errorf("set usage is not a part of the usage text:\n%s", u)
	}
	// A usage error names what is missing.
	for want, args := range map[string][]string{
		"set needs import, put, unset or check, then a set path": {"set"},
		`not "push"`:                         {"set", "push", "a/b/c"},
		"set import needs PATH":              {"set", "import", "--from", "x.env", "--why", "w"},
		"set import needs --from FILE":       {"set", "import", "a/b/c", "--why", "w"},
		"set import takes one PATH":          {"set", "import", "a/b/c", "x.env", "--from", "x.env", "--why", "w"},
		"set import needs --why":             {"set", "import", "a/b/c", "--from", "x.env"},
		"set put needs PATH":                 {"set", "put", "a/b/c", "--why", "w"},
		"set put needs --why":                {"set", "put", "a/b/c", "APP_KEY"},
		"not --from":                         {"set", "put", "a/b/c", "APP_KEY", "--from", "x.env", "--why", "w"},
		"set unset needs PATH":               {"set", "unset", "--why", "w"},
		"set unset takes PATH and one KEY":   {"set", "unset", "a/b/c", "APP_A", "APP_B", "--why", "w"},
		"--create goes with set import":      {"set", "unset", "a/b/c", "APP_KEY", "--why", "w", "--create"},
		"add --create":                       {"set", "import", "a/b/c", "--from", "x.env", "--why", "w", "--title", "T"},
		"not both":                           {"set", "import", "a/b/c", "--from", "x.env", "--ticket", "--ticket-fd", "3"},
		"at least 3":                         {"set", "import", "a/b/c", "--from", "x.env", "--ticket-fd", "1"},
		"leave out the ticket option":        {"set", "import", "a/b/c", "--from", "x.env", "--ticket", "--create"},
		"with a ticket the edit is reviewed": {"set", "import", "a/b/c", "--from", "x.env", "--ticket", "--why", "w"},
		"set check needs --from FILE":        {"set", "check", "a/b/c"},
		"set check takes at most one PATH":   {"set", "check", "--from", "x.env", "a/b/c", "d/e/f"},
		"it sends nothing":                   {"set", "check", "--from", "x.env", "--why", "w"},
		"takes no -- COMMAND":                {"set", "import", "a/b/c", "--from", "x.env", "--why", "w", "--", "true"},
		`unknown flag "--force"`:             {"set", "import", "a/b/c", "--from", "x.env", "--why", "w", "--force"},
	} {
		code, out, errOut := capture(t, args...)
		if code != 2 || out != "" || !strings.Contains(errOut, want) {
			t.Errorf("%q: exit %d, want %q in\n%s", args, code, want, errOut)
		}
	}
	// set check validates locally: names on stdout, problems by line on stderr, exit 1.
	file := filepath.Join(t.TempDir(), "x.env")
	if err := os.WriteFile(file, []byte("APP_TOKEN=sentinel\nbroken sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := capture(t, "set", "check", "--from", file)
	if code != 1 || out != "APP_TOKEN\n" || !strings.Contains(errOut, "line 2: ") || strings.Contains(out+errOut, "sentinel") {
		t.Errorf("check: exit %d\n%s%s", code, out, errOut)
	}
	if err := os.WriteFile(file, []byte("APP_TOKEN=sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut = capture(t, "set", "check", "--from", file); code != 0 || out != "APP_TOKEN\n" || strings.Contains(errOut, "sentinel") {
		t.Errorf("check: exit %d\n%s%s", code, out, errOut)
	}
	// A proposal reads and checks the file before it looks for an enrolment or a broker.
	if err := os.WriteFile(file, []byte("broken sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut = capture(t, "set", "import", "a/b/c", "--from", file, "--why", "w"); code != 1 || !strings.Contains(errOut, "line 1: ") || !strings.Contains(errOut, "nothing was sent") || strings.Contains(errOut, "sentinel") {
		t.Errorf("import of a bad file: exit %d\n%s", code, errOut)
	}
}
