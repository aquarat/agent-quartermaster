package main

import (
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

func TestCommandHelp(t *testing.T) {
	// Every command the dispatcher knows has its lines in the usage text, aliases included.
	for _, cmd := range []string{"guide", "mcp", "ls", "catalogue", "targets", "reap-checkouts", "run", "get", "checkout", "co",
		"checkout-shell", "cos", "signer", "sign", "ssh-agent", "ssh-key", "ci", "checkin", "cis", "checkin-shell", "upgrade",
		"update", "help", "version", "enroll", "ssh", "cert", "mosh", "bastion", "status", "list", "cf", "ssh-config", "set"} {
		text, ok := commandUsage(cmd)
		if !ok || !strings.Contains(text, "aqmas ") {
			t.Errorf("no usage lines for %q", cmd)
		}
	}
	text, _ := commandUsage("ssh")
	if !strings.Contains(text, "--level inspect|root") || !strings.Contains(text, "Log in with a short-lived certificate") || strings.Contains(text, "mosh [USER@]") {
		t.Errorf("ssh help:\n%s", text)
	}
	if text, _ := commandUsage("co"); !strings.Contains(text, "checkout|co PATH") || strings.Contains(text, "aqmas run") {
		t.Errorf("co help:\n%s", text)
	}
	if _, ok := commandUsage("bogus"); ok {
		t.Error("help for an unknown command")
	}
	for args, want := range map[string]bool{"--help": true, "x -h": true, "help": true, "x --why y": false, "x -- cmd --help": false, "x -- -h": false, "": false} {
		if got := wantsHelp(strings.Fields(args)); got != want {
			t.Errorf("wantsHelp(%q) = %v", args, got)
		}
	}
	helpCommand = "run"
	if h := usageHint(); h != " (see: aqmas run --help)" {
		t.Errorf("hint %q", h)
	}
	helpCommand = "nonsense"
	if h := usageHint(); h != " (see: aqmas help)" {
		t.Errorf("hint %q", h)
	}
}
