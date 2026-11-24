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
		{host: "localhost", errHas: `"localhost" names no machine`},
		{host: "LocalHost.localdomain", errHas: `"LocalHost.localdomain" names no machine`},
		{host: "localhost-live", errHas: "names no machine"},
		{host: "localhostess", want: "localhostess"},
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
	msg := `aqmas: enrolling as "agent-host" (from this machine's hostname; use --name to choose another). If the approval card says it replaces an enrolment, approving it revokes that other machine's access`
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

// aqmasd replaces by name, so --force without --name goes ahead only when the hostname gives
// the name already enrolled here; otherwise the user chooses between the two.
func TestEnrollForceWithoutNameNeedsTheSameName(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e) // enrolled as "agenthost"
	posts := f.enrollPosts
	e.Hostname = func() (string, error) { return "newhost", nil }
	err := e.Enroll(context.Background(), EnrollOptions{Force: true})
	for _, s := range []string{`enrolled as "agenthost"`, `gives "newhost"`, "--name agenthost to replace", "--name newhost to enrol this machine as a new host", `revoke "agenthost" under Hosts`} {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Fatalf("error lacks %q: %v", s, err)
		}
	}
	if f.enrollPosts != posts {
		t.Fatal("a request was sent")
	}
	if cfg, err := LoadConfig(e.Paths); err != nil || cfg.HostName != "agenthost" {
		t.Fatalf("config changed: %+v, %v", cfg, err)
	}

	// Either explicit choice goes ahead.
	if err := e.Enroll(context.Background(), EnrollOptions{Force: true, Name: "newhost"}); err != nil {
		t.Fatalf("--force --name newhost: %v", err)
	}
	// Now the hostname gives the enrolled name: --force alone replaces it.
	e.stderr.Reset()
	if err := e.Enroll(context.Background(), EnrollOptions{Force: true}); err != nil {
		t.Fatalf("enroll --force with the same name: %v", err)
	}
	if !strings.Contains(e.stderr.String(), `enrolling as "newhost" (from this machine's hostname; use`) || !strings.Contains(e.stderr.String(), "revokes that other machine's access") {
		t.Fatalf("stderr:\n%s", e.stderr)
	}

	// Without --force the existing enrolment still stops it.
	if err := e.Enroll(context.Background(), EnrollOptions{}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("without --force: %v", err)
	}
}
