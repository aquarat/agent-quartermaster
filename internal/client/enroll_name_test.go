package client

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDefaultHostName(t *testing.T) {
	long := strings.Repeat("a", 64)
	for _, tc := range []struct {
		host, want, errHas string
	}{
		{host: "thirteenrat", want: "thirteenrat"},
		{host: "web-1.example.com", want: "web-1"},
		{host: "WEB-1", want: "web-1"},
		{host: "Foo-MacBook-Pro.local", want: "foo-macbook-pro"},
		{host: strings.Repeat("a", 63) + ".example.com", want: strings.Repeat("a", 63)},
		{host: "web_1", errHas: `"web_1"`},
		{host: "zürich", errHas: `"zürich"`},
		{host: "-web", errHas: `"-web"`},
		{host: "", errHas: `hostname ""`},
		{host: ".local", errHas: `".local"`},
		{host: long, errHas: long},
		{host: "bad\x1b[31m", errHas: `"bad?[31m"`},
	} {
		got, err := DefaultHostName(func() (string, error) { return tc.host, nil })
		if tc.errHas == "" {
			if err != nil || got != tc.want {
				t.Errorf("%q: got %q, %v; want %q", tc.host, got, err, tc.want)
			}
			continue
		}
		var ue *UsageError
		if err == nil || !errors.As(err, &ue) || !strings.Contains(err.Error(), tc.errHas) || !strings.Contains(err.Error(), "pass --name") {
			t.Errorf("%q: got %q, %v; want a usage error containing %s and the --name hint", tc.host, got, err, tc.errHas)
		}
	}
	if _, err := DefaultHostName(func() (string, error) { return "", errors.New("boom") }); err == nil || !strings.Contains(err.Error(), "pass --name") {
		t.Errorf("hostname error: %v", err)
	}
}

// Without --name the hostname is the name, and the CLI says so before it sends anything.
func TestEnrollDefaultsToHostname(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	e.Hostname = func() (string, error) { return "Agent-Host.local", nil }
	if err := e.Enroll(context.Background(), EnrollOptions{Server: f.URL(), CAPin: f.pin()}); err != nil {
		t.Fatalf("enroll: %v\nstderr: %s", err, e.stderr)
	}
	cfg, err := LoadConfig(e.Paths)
	if err != nil || cfg.HostName != "agent-host" {
		t.Fatalf("config %+v, %v", cfg, err)
	}
	msg := `aqmas: enrolling as "agent-host" (from this machine's hostname; use --name to choose another)`
	if !strings.Contains(e.stderr.String(), msg) {
		t.Fatalf("stderr lacks %q:\n%s", msg, e.stderr)
	}
	if strings.Index(e.stderr.String(), msg) > strings.Index(e.stderr.String(), "sent to") {
		t.Fatalf("name announced after the request was sent:\n%s", e.stderr)
	}

	// An explicit --name is used as given, without the hostname line.
	e2 := newTestEnv(t)
	e2.Hostname = func() (string, error) { t.Fatal("hostname read despite --name"); return "", nil }
	enroll(t, f, e2)
	if strings.Contains(e2.stderr.String(), "from this machine's hostname") {
		t.Fatalf("hostname line with --name:\n%s", e2.stderr)
	}
}

// --force on a configuration copied from another machine takes this machine's hostname,
// not the old enrolment's name, and says which enrolment it replaces.
func TestEnrollForceDefaultsToHostnameAndNamesTheOld(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e) // enrolled as "agenthost"
	e.Hostname = func() (string, error) { return "newhost", nil }
	e.stderr.Reset()
	if err := e.Enroll(context.Background(), EnrollOptions{Force: true}); err != nil {
		t.Fatalf("enroll --force: %v\nstderr: %s", err, e.stderr)
	}
	msg := `aqmas: enrolling as "newhost" (from this machine's hostname, replacing the enrolment as "agenthost"; use --name to choose another)`
	if !strings.Contains(e.stderr.String(), msg) {
		t.Fatalf("stderr lacks %q:\n%s", msg, e.stderr)
	}
	if cfg, err := LoadConfig(e.Paths); err != nil || cfg.HostName != "newhost" {
		t.Fatalf("config %+v, %v", cfg, err)
	}

	// Same name: nothing to mention.
	e.stderr.Reset()
	if err := e.Enroll(context.Background(), EnrollOptions{Force: true}); err != nil {
		t.Fatalf("enroll --force again: %v", err)
	}
	if strings.Contains(e.stderr.String(), "replacing") || !strings.Contains(e.stderr.String(), `enrolling as "newhost" (from this machine's hostname; use`) {
		t.Fatalf("stderr:\n%s", e.stderr)
	}

	// Without --force the existing enrolment still stops it.
	if err := e.Enroll(context.Background(), EnrollOptions{}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("without --force: %v", err)
	}
}
