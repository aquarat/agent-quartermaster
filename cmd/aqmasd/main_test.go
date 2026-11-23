package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// The shipped example config parses, and its commented [cloudflare] block is valid once
// uncommented and filled with (fake) ids.
func TestExampleConfigCloudflare(t *testing.T) {
	b, err := os.ReadFile("../../deploy/bastion/config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(b)
	if err != nil {
		t.Fatalf("example config as shipped: %v", err)
	}
	if cfg.Cloudflare.Enabled {
		t.Fatal("cloudflare enabled in the example as shipped")
	}
	var out []string
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		if l == "# [cloudflare]" {
			in = true
		}
		if in && !strings.HasPrefix(l, "#") {
			in = false
		}
		if in {
			l = strings.TrimPrefix(strings.TrimPrefix(l, "#"), " ")
		}
		out = append(out, l)
	}
	text := strings.NewReplacer(
		"<32 lowercase hex>", "0123456789abcdef0123456789abcdef",
		"<32 hex zone id>", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"<tunnel uuid>", "7e570b05-0000-4000-8000-000000000000",
		"<database uuid>", "11111111-2222-4333-8444-555555555555",
		"<static home IPv4>", "203.0.113.7",
	).Replace(strings.Join(out, "\n"))
	cfg, err = config.Parse([]byte(text))
	if err != nil {
		t.Fatalf("uncommented [cloudflare] example: %v", err)
	}
	cf := cfg.Cloudflare
	if !cf.Enabled || cf.ProxyTokenCredential != "cf-proxy-token" || cf.MinterTokenCredential != "cf-minter-token" || len(cf.Zones) != 1 {
		t.Fatalf("parsed %+v", cf)
	}
	if _, err := cfscope.NewCatalogue(&cf); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile("../../deploy/bastion/aqmasd.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LoadCredential=cf-proxy-token:/etc/aqmas/cf-proxy-token", "LoadCredential=cf-minter-token:/etc/aqmas/cf-minter-token", "StateDirectory=aqmas", "ProtectSystem=strict"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("aqmasd.service lacks %q", want)
		}
	}
}

// The forced command of the bastion's inspect account: fixed tools from one directory, the
// request only from SSH_ORIGINAL_COMMAND, no configuration read.
func TestInspectCommand(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	for _, name := range []string{"journalctl", "systemctl", "df", "uname", "uptime"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho \"$(basename \"$0\") $*\" >>"+log+"\necho ran\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	inspectBin = dir
	defer func() { inspectBin = "/usr/bin" }()
	var out, errOut bytes.Buffer
	if code := inspectCommand(nil, "logs aqmasd lines=5", &out, &errOut); code != 0 || out.String() != "ran\n" {
		t.Fatal(code, out.String(), errOut.String())
	}
	b, _ := os.ReadFile(log)
	if string(b) != "journalctl --no-pager --output=short-iso --since=-60min --lines=5 --unit=aqmasd.service\n" {
		t.Fatalf("argv: %s", b)
	}
	os.Remove(log)
	out.Reset()
	// Anything outside the grammar runs nothing; a shell is never involved.
	for _, req := range []string{"sh", "logs aqmasd; id", "cat /etc/aqmas/config.toml", "logs aqmasd --file=/var/lib/aqmas/aqmas.db", "scp -t /tmp"} {
		if code := inspectCommand(nil, req, &out, &errOut); code != 2 || out.Len() != 0 {
			t.Fatalf("%q: exit %d, output %q", req, code, out.String())
		}
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("a refused request ran a command")
	}
	// Arguments on the forced command line itself are not a way to pass a request.
	for _, args := range [][]string{{"logs", "aqmasd"}, {"--bin"}, {"--bin", dir}, {"-config", "/etc/aqmas/config.toml"}} {
		if code := inspectCommand(args, "help", &out, &errOut); code != 2 {
			t.Fatalf("%v accepted", args)
		}
	}
	out.Reset()
	if code := inspectCommand(nil, "", &out, &errOut); code != 0 || !bytes.Contains(out.Bytes(), []byte("units: aqmasd")) {
		t.Fatal(code, out.String())
	}
}
