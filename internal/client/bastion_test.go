package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// fakeBastion is the agent API of docs/BASTION-ACCESS.md §4 and §7 as the CLI sees it.
type fakeBastion struct {
	off         bool // GET /v1/bastion answers 404
	rootAllowed bool
	pending     int    // pending answers before the decision
	decision    string // "" = approved
	note        string
	noCert      bool // root: approved, certificate already collected
	created     int
	reqs        map[string]*fakeBastionReq
	// the two status endpoints are counted apart: reuse must ask the bastion's
	statusPolls int

	taskPending  int
	taskDecision string // "" = approved
	taskRuns     []api.SetupRunStatus
	tasks        map[string]*fakeTask
}

type fakeBastionReq struct {
	req       api.BastionRequest
	host      string
	polls     int
	grant     *api.Grant
	cancelled bool
	revoked   bool
}

type fakeTask struct {
	req       api.SetupRequest
	polls     int
	runPolls  int
	cancelled bool
	afters    []string
}

func (f *fakeServer) bastionInfo() api.BastionInfo {
	return api.BastionInfo{Name: "bastion", Address: "192.0.2.10", Port: 22, InspectUser: "aqmas-inspect", AdminUser: "alice", RootAllowed: f.bastion.rootAllowed,
		InspectMaxSeconds: 28800, InspectDefault: 3600, RootMaxSeconds: 3600, Tasks: BastionTasks}
}

func (f *fakeServer) setupBastion(mux *http.ServeMux) {
	f.bastion.reqs, f.bastion.tasks = map[string]*fakeBastionReq{}, map[string]*fakeTask{}
	mux.HandleFunc("GET /v1/bastion", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.bastion.off {
			apiErr(w, 404, "not_found", "not found")
			return
		}
		writeJSON(w, 200, f.bastionInfo())
	})
	mux.HandleFunc("POST /v1/bastion/requests", func(w http.ResponseWriter, r *http.Request) {
		host, ok := f.host(w, r)
		if !ok {
			return
		}
		var req api.BastionRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Reason == "" {
			apiErr(w, 400, "bad_request", "bad request")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if req.Level == api.LevelRoot && !f.bastion.rootAllowed {
			apiErr(w, 403, "forbidden", "not on the allowlist")
			return
		}
		f.bastion.created++
		id := fmt.Sprintf("BAS%04d", f.bastion.created)
		f.bastion.reqs[id] = &fakeBastionReq{req: req, host: host}
		writeJSON(w, 201, api.RequestCreated{ID: id, Status: api.StatusPending, ApproveURL: "https://aqmas.example/r/" + id, PollAfterMS: 1, ExpiresAt: time.Now().Add(10 * time.Minute)})
	})
	mux.HandleFunc("GET /v1/bastion/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		host, ok := f.host(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		f.mu.Lock()
		defer f.mu.Unlock()
		b := &f.bastion
		fr, ok := b.reqs[id]
		if !ok || fr.host != host {
			apiErr(w, 404, "not_found", "no such request")
			return
		}
		fr.polls++
		b.statusPolls++
		st := api.RequestStatus{ID: id, Kind: api.KindBastion, Status: api.StatusApproved}
		switch {
		case fr.cancelled:
			st.Status = api.StatusCancelled
		case fr.revoked:
			st.Status = api.StatusRevoked
		case fr.polls <= b.pending:
			st.Status = api.StatusPending
		case b.decision != "":
			st.Status, st.DecisionNote = b.decision, b.note
		default:
			if fr.grant == nil {
				fr.grant = f.signBastion(id, fr)
			}
			g := *fr.grant
			sg := *g.SSH
			g.SSH = &sg
			if fr.req.Level == api.LevelRoot && (b.noCert || fr.polls > b.pending+1) {
				// A root certificate goes out once.
				sg.Certificate, st.DecisionNote = "", "the certificate was already collected: a root certificate is handed out once"
			}
			st.Grant = &g
		}
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("POST /v1/bastion/requests/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		fr, ok := f.bastion.reqs[r.PathValue("id")]
		if !ok {
			apiErr(w, 404, "not_found", "no such request")
			return
		}
		fr.cancelled = true
		writeJSON(w, 200, api.RequestStatus{ID: r.PathValue("id"), Kind: api.KindBastion, Status: api.StatusCancelled})
	})
	mux.HandleFunc("POST /v1/setup-requests", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		var req api.SetupRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Reason == "" {
			apiErr(w, 400, "bad_request", "bad request")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		id := fmt.Sprintf("TSK%04d", len(f.bastion.tasks)+1)
		f.bastion.tasks[id] = &fakeTask{req: req}
		writeJSON(w, 201, api.RequestCreated{ID: id, Status: api.StatusPending, ApproveURL: "https://aqmas.example/r/" + id, PollAfterMS: 1, ExpiresAt: time.Now().Add(10 * time.Minute)})
	})
	mux.HandleFunc("GET /v1/setup-requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		id := r.PathValue("id")
		f.mu.Lock()
		defer f.mu.Unlock()
		b := &f.bastion
		ft, ok := b.tasks[id]
		if !ok {
			apiErr(w, 404, "not_found", "no such request")
			return
		}
		ft.polls++
		st := api.SetupRequestStatus{ID: id, Task: ft.req.Task, Status: api.StatusApproved}
		switch {
		case ft.cancelled:
			st.Status = api.StatusCancelled
		case ft.polls <= b.taskPending:
			st.Status = api.StatusPending
		case b.taskDecision != "":
			st.Status, st.DecisionNote = b.taskDecision, "dismissed by owner"
		default:
			ft.afters = append(ft.afters, r.URL.Query().Get("after"))
			run := b.taskRuns[min(ft.runPolls, len(b.taskRuns)-1)]
			ft.runPolls++
			st.Run = &run
		}
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("POST /v1/setup-requests/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		ft, ok := f.bastion.tasks[r.PathValue("id")]
		if !ok {
			apiErr(w, 404, "not_found", "no such request")
			return
		}
		ft.cancelled = true
		writeJSON(w, 200, api.SetupRequestStatus{ID: r.PathValue("id"), Task: ft.req.Task, Status: api.StatusCancelled})
	})
}

func (f *fakeServer) signBastion(id string, fr *fakeBastionReq) *api.Grant {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fr.req.PublicKey))
	if err != nil {
		f.t.Errorf("fake bastion: bad public key: %v", err)
		return nil
	}
	info := f.bastionInfo()
	user, perms := info.InspectUser, ssh.Permissions{CriticalOptions: map[string]string{"source-address": "127.0.0.1/32", "force-command": "/usr/local/bin/aqmasd inspect"}}
	if fr.req.Level == api.LevelRoot {
		user, perms = info.AdminUser, ssh.Permissions{CriticalOptions: map[string]string{"source-address": "127.0.0.1/32"}, Extensions: map[string]string{"permit-pty": ""}}
	}
	now := time.Now()
	ttl := time.Duration(fr.req.TTLSeconds) * time.Second
	cert := &ssh.Certificate{Key: pk, Serial: 7, CertType: ssh.UserCert, KeyId: "aqmas:G" + id, ValidPrincipals: []string{user + "@" + info.Name},
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(ttl).Unix()), Permissions: perms}
	if err := cert.SignCert(rand.Reader, f.sshCA); err != nil {
		f.t.Errorf("fake bastion: sign: %v", err)
		return nil
	}
	key := strings.SplitN(f.knownHostsLine, " ", 2)[1]
	return &api.Grant{ID: "G" + id, Kind: api.KindBastion, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(ttl), SSH: &api.SSHGrant{
		Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), Principals: cert.ValidPrincipals, TargetHost: info.Name,
		TargetAddress: info.Address, TargetPort: info.Port, LoginUser: user, KnownHostsLine: info.Name + "," + info.Address + " " + key}}
}

func bastionSetup(t *testing.T) (*fakeServer, *testEnv) {
	t.Helper()
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	return f, e
}

func cacheEntries(t *testing.T, e *testEnv) []string {
	t.Helper()
	ents, err := os.ReadDir(e.Paths.CacheDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, ent := range ents {
		names = append(names, ent.Name())
	}
	return names
}

func TestBastionInspectFlow(t *testing.T) {
	f, e := bastionSetup(t)
	f.bastion.pending = 2
	ctx := context.Background()
	o := BastionOptions{Host: "bastion", Why: "why is the tunnel flapping"}
	p, err := e.EnsureBastionInspect(ctx, o)
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, e.stderr)
	}
	fr := f.bastion.reqs["BAS0001"]
	if p.Reused || fr == nil || fr.req.Level != api.LevelInspect || fr.req.TTLSeconds != 3600 || fr.req.Reason != o.Why || fr.host != "agenthost" || fr.req.Requester.User != "alice" {
		t.Fatalf("request %+v reused=%v", fr, p.Reused)
	}
	if f.created != 0 {
		t.Fatal("the generic request endpoint was used for a bastion session")
	}
	stderr := e.stderr.String()
	for _, s := range []string{"request BAS0001 (Ref AS0001): bastion inspect (bastion) for 1h0m0s by claude-code on agenthost: why is the tunnel flapping", "approve at: https://aqmas.example/r/BAS0001", "approved: grant GBAS0001"} {
		if !strings.Contains(stderr, s) {
			t.Errorf("stderr lacks %q:\n%s", s, stderr)
		}
	}
	if strings.Contains(stderr, "ROOT") {
		t.Error("an inspect session was announced as root")
	}
	dir := filepath.Join(e.Paths.CacheDir, "aqmas-inspect@bastion", "g-BAS0001")
	if p.Dir != dir || mode(t, dir) != 0o700 || mode(t, p.KeyPath) != 0o600 {
		t.Errorf("cached in %s", p.Dir)
	}
	kh, _ := os.ReadFile(p.KnownHostsPath)
	if !strings.HasPrefix(string(kh), "192.0.2.10,aqmas.bastion ssh-ed25519 ") {
		t.Errorf("known_hosts = %q", kh)
	}

	argv, err := BuildInspectArgv(p, []string{"logs", "aqmasd", "since=2h"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh", "-T", "-F", "none", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=publickey",
		"-i", filepath.Join(dir, "id_ed25519"), "-o", "CertificateFile=" + filepath.Join(dir, "id_ed25519-cert.pub"),
		"-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"), "-o", "StrictHostKeyChecking=yes",
		"-p", "22", "--", "aqmas-inspect@192.0.2.10", "logs aqmasd since=2h"}
	if !reflect.DeepEqual(argv, want) {
		t.Errorf("argv =\n%q\nwant\n%q", argv, want)
	}
	if argv, err = BuildInspectArgv(p, nil); err != nil || argv[len(argv)-1] != "help" {
		t.Errorf("no command should send help: %q %v", argv, err)
	}

	// Reuse asks the bastion's own status endpoint, never /v1/requests (where a bastion
	// request does not exist).
	before := f.bastion.statusPolls
	p2, err := e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Level: "inspect", User: "aqmas-inspect", Why: "again"})
	if err != nil || !p2.Reused || p2.KeyPath != p.KeyPath || f.bastion.created != 1 || f.bastion.statusPolls != before+1 {
		t.Fatalf("reuse: %v reused=%v created=%d polls=%d→%d", err, p2 != nil && p2.Reused, f.bastion.created, before, f.bastion.statusPolls)
	}
	for id, fr := range f.requests {
		t.Errorf("generic request %s polled %d times", id, fr.polls)
	}
	// Revoked on the server: a new request.
	f.mu.Lock()
	f.bastion.reqs["BAS0001"].revoked = true
	f.mu.Unlock()
	if p3, err := e.EnsureBastionInspect(ctx, o); err != nil || p3.Reused || f.bastion.created != 2 {
		t.Fatalf("after revoke: %v created=%d", err, f.bastion.created)
	}
	// --fresh.
	o.Fresh = true
	if _, err := e.EnsureBastionInspect(ctx, o); err != nil || f.bastion.created != 3 {
		t.Fatalf("fresh: %v created=%d", err, f.bastion.created)
	}
	// The server is down: the cached certificate is still offered, with a warning.
	f.srv.Close()
	e.stderr.Reset()
	if p4, err := e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "aqmasd is down"}); err != nil || !p4.Reused || !strings.Contains(e.stderr.String(), "cannot reach the server") {
		t.Fatalf("offline: %v\n%s", err, e.stderr)
	}
	if _, err := e.EnsureBastionInspect(ctx, o); ExitCode(err) != ExitUnreachable {
		t.Fatalf("offline --fresh: %v", err)
	}
}

func TestBastionValidation(t *testing.T) {
	f, e := bastionSetup(t)
	f.bastion.rootAllowed = true
	ctx := context.Background()
	never := func([]string) (int, error) { t.Error("ssh was run"); return 0, nil }
	usage := func(name string, err error) {
		t.Helper()
		if ExitCode(err) != ExitUsage {
			t.Errorf("%s: err=%v code=%d", name, err, ExitCode(err))
		}
	}
	_, err := e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion"})
	usage("no --why", err)
	_, err = e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "x", Level: "admin"})
	usage("unknown level", err)
	_, err = e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "x", Level: "root"})
	usage("cert for root", err)
	_, err = e.EnsureBastionInspect(ctx, BastionOptions{Host: "db-1", Why: "x", Level: "inspect"})
	usage("--level for another host", err)
	_, err = e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "x", User: "alice"})
	usage("inspect as the admin user", err)
	_, err = e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "x", TTL: 9 * time.Hour})
	usage("inspect ttl above the maximum", err)
	_, err = e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "x", TTL: time.Second})
	usage("inspect ttl below a minute", err)
	_, err = e.BastionRoot(ctx, BastionOptions{Host: "bastion", Why: "x", User: "aqmas-inspect"}, never)
	usage("root as the inspect user", err)
	_, err = e.BastionRoot(ctx, BastionOptions{Host: "bastion", Why: "x", TTL: 61 * time.Minute}, never)
	usage("root ttl above an hour", err)
	_, err = e.BastionRoot(ctx, BastionOptions{Host: "bastion"}, never)
	usage("root without --why", err)
	if f.bastion.created != 0 {
		t.Errorf("%d requests were created by invalid invocations", f.bastion.created)
	}

	// Inspect commands: only what the forced command's grammar can hold.
	for _, ok := range [][]string{{"logs", "aqmasd"}, {"logs", "kernel", "since=30m", "lines=50"}, {"status"}, {"logs aqmasd since=2h"}} {
		if _, err := InspectCommand(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"logs", "aqmasd;id"}, {"sh", "-c", "id"}, {"logs", "$(id)"}, {"logs", "a|b"}, {"cat", "/etc/shadow"}, {"logs", "aqmasd\nstatus"},
		{"logs", "aqmasd", ">", "x"}, {"logs", "'aqmasd'"}, {strings.Repeat("a", 201)}, {"logs", "ünit"}} {
		_, err := InspectCommand(bad)
		usage(fmt.Sprintf("inspect command %q", bad), err)
		if err != nil && !strings.Contains(err.Error(), "logs <unit>") {
			t.Errorf("the refusal of %q does not list the commands: %v", bad, err)
		}
	}

	// The names the CLI recognises.
	if !e.IsBastion(ctx, "bastion") || e.IsBastion(ctx, "db-1") {
		t.Error("IsBastion")
	}
	f.mu.Lock()
	f.bastion.off = true
	f.mu.Unlock()
	if e.IsBastion(ctx, "bastion") {
		t.Error("IsBastion without bastion access")
	}
	if _, err := e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "x"}); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("not installed: %v", err)
	}
	if !NotATarget(&APIError{HTTPStatus: 404, Code: "not_found"}) || !NotATarget(&APIError{HTTPStatus: 400}) || NotATarget(&APIError{HTTPStatus: 403}) || NotATarget(errors.New("x")) {
		t.Error("NotATarget")
	}
}

func TestBastionRootFlow(t *testing.T) {
	f, e := bastionSetup(t)
	f.bastion.rootAllowed = true
	f.bastion.pending = 1
	ctx := context.Background()
	var argv []string
	var tmp string
	run := func(a []string) (int, error) {
		argv = a
		// While ssh runs: one private directory with key, certificate and known_hosts.
		for _, n := range cacheEntries(t, e) {
			if strings.HasPrefix(n, ".bastion-root-") {
				tmp = filepath.Join(e.Paths.CacheDir, n)
			}
		}
		if tmp == "" || mode(t, tmp) != 0o700 {
			t.Errorf("no private temporary directory while ssh runs: %v", cacheEntries(t, e))
			return 0, nil
		}
		key, _ := os.ReadFile(filepath.Join(tmp, "g-BAS0001", keyFile))
		cert, _ := os.ReadFile(filepath.Join(tmp, "g-BAS0001", certFile))
		if !strings.Contains(string(key), "PRIVATE KEY") || !strings.HasPrefix(string(cert), "ssh-ed25519-cert-v01@openssh.com ") {
			t.Error("key or certificate missing while ssh runs")
		}
		return 7, nil
	}
	code, err := e.BastionRoot(ctx, BastionOptions{Host: "bastion", Why: "replace the tunnel credential", TTL: 20 * time.Minute}, run)
	if err != nil || code != 7 {
		t.Fatalf("root: code=%d err=%v\n%s", code, err, e.stderr)
	}
	fr := f.bastion.reqs["BAS0001"]
	if fr.req.Level != api.LevelRoot || fr.req.TTLSeconds != 1200 || fr.req.Reason != "replace the tunnel credential" {
		t.Errorf("request %+v", fr.req)
	}
	stderr := e.stderr.String()
	warn, asked := strings.Index(stderr, "This asks for ROOT on the bastion; the owner will see a red card."), strings.Index(stderr, "request BAS0001")
	if warn < 0 || asked < 0 || warn > asked || !strings.Contains(stderr, "bastion root (bastion) for 20m0s") || !strings.Contains(stderr, "is not kept") {
		t.Errorf("stderr:\n%s", stderr)
	}
	dir := filepath.Join(tmp, "g-BAS0001")
	want := []string{"ssh", "-F", "none", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=publickey",
		"-i", filepath.Join(dir, "id_ed25519"), "-o", "CertificateFile=" + filepath.Join(dir, "id_ed25519-cert.pub"),
		"-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"), "-o", "StrictHostKeyChecking=yes", "-p", "22", "--", "alice@192.0.2.10"}
	if !reflect.DeepEqual(argv, want) {
		t.Errorf("argv =\n%q\nwant\n%q", argv, want)
	}
	// Afterwards nothing is left: no temporary directory, and never a cache entry.
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temporary directory left behind: %v", err)
	}
	if got := cacheEntries(t, e); len(got) != 0 {
		t.Errorf("cache after a root session: %v", got)
	}
	if strings.Contains(stderr, "PRIVATE KEY") {
		t.Error("private key printed")
	}

	// A second run asks again (no reuse) and uses the default duration.
	if _, err := e.BastionRoot(ctx, BastionOptions{Host: "bastion", Level: "root", User: "alice", Why: "again"}, func([]string) (int, error) { return 0, nil }); err != nil || f.bastion.created != 2 {
		t.Fatalf("second root session: %v created=%d", err, f.bastion.created)
	}
	if f.bastion.reqs["BAS0002"].req.TTLSeconds != 1800 {
		t.Errorf("default root ttl = %d", f.bastion.reqs["BAS0002"].req.TTLSeconds)
	}
	// An inspect certificate in the cache is never used for root, nor replaced by it.
	if _, err := e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "logs"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.BastionRoot(ctx, BastionOptions{Host: "bastion", Why: "x"}, func(a []string) (int, error) {
		if strings.Contains(strings.Join(a, " "), "aqmas-inspect") {
			t.Errorf("root used the inspect cache: %q", a)
		}
		return 0, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := cacheEntries(t, e); !reflect.DeepEqual(got, []string{"aqmas-inspect@bastion"}) {
		t.Errorf("cache: %v", got)
	}
}

func TestBastionRootFailuresLeaveNothing(t *testing.T) {
	never := func([]string) (int, error) { panic("ssh must not run") }
	clean := func(t *testing.T, e *testEnv) {
		t.Helper()
		if got := cacheEntries(t, e); len(got) != 0 {
			t.Errorf("left behind: %v", got)
		}
	}
	t.Run("not allowed", func(t *testing.T) {
		f, e := bastionSetup(t)
		_, err := e.BastionRoot(context.Background(), BastionOptions{Host: "bastion", Why: "x"}, never)
		if err == nil || ExitCode(err) != ExitError || !strings.Contains(err.Error(), "may not ask for root") || f.bastion.created != 0 {
			t.Fatalf("err=%v created=%d", err, f.bastion.created)
		}
		if strings.Contains(e.stderr.String(), "red card") {
			t.Error("announced a red card that will never appear")
		}
		clean(t, e)
	})
	t.Run("denied", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.rootAllowed, f.bastion.decision, f.bastion.note = true, api.StatusDenied, "denied by owner"
		_, err := e.BastionRoot(context.Background(), BastionOptions{Host: "bastion", Why: "x"}, never)
		if ExitCode(err) != ExitDenied {
			t.Fatalf("err=%v", err)
		}
		clean(t, e)
	})
	t.Run("already collected", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.rootAllowed, f.bastion.noCert = true, true
		_, err := e.BastionRoot(context.Background(), BastionOptions{Host: "bastion", Why: "x"}, never)
		if err == nil || ExitCode(err) != ExitError || !strings.Contains(err.Error(), "already collected") {
			t.Fatalf("err=%v", err)
		}
		clean(t, e)
	})
	t.Run("wrong CA", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.rootAllowed = true
		_, other, _ := newEd25519(t)
		f.publishedSSHCA = other
		_, err := e.BastionRoot(context.Background(), BastionOptions{Host: "bastion", Why: "x"}, never)
		if err == nil || !strings.Contains(err.Error(), "not the server's SSH CA") {
			t.Fatalf("err=%v", err)
		}
		clean(t, e)
	})
	t.Run("ssh fails to start", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.rootAllowed = true
		_, err := e.BastionRoot(context.Background(), BastionOptions{Host: "bastion", Why: "x"}, func([]string) (int, error) { return 0, errors.New("exec: ssh not found") })
		if err == nil {
			t.Fatal("no error")
		}
		clean(t, e)
	})
	t.Run("cancelled while waiting", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.rootAllowed, f.bastion.pending = true, 1<<30
		ctx, cancel := f.waitingCtx(t)
		defer cancel()
		_, err := e.BastionRoot(ctx, BastionOptions{Host: "bastion", Why: "x"}, never)
		if ExitCode(err) != ExitCancelled {
			t.Fatalf("err=%v code=%d", err, ExitCode(err))
		}
		f.mu.Lock()
		cancelled := f.bastion.reqs["BAS0001"].cancelled
		f.mu.Unlock()
		if !cancelled || !strings.Contains(e.stderr.String(), "cancelled request BAS0001") {
			t.Errorf("not cancelled on the bastion endpoint: %s", e.stderr)
		}
		clean(t, e)
	})
	t.Run("stale directories are swept", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.rootAllowed = true
		old := filepath.Join(e.Paths.CacheDir, ".bastion-root-old")
		if err := os.MkdirAll(old, 0o700); err != nil {
			t.Fatal(err)
		}
		past := time.Now().Add(-3 * time.Hour)
		if err := os.Chtimes(old, past, past); err != nil {
			t.Fatal(err)
		}
		if _, err := e.BastionRoot(context.Background(), BastionOptions{Host: "bastion", Why: "x"}, func([]string) (int, error) { return 0, nil }); err != nil {
			t.Fatal(err)
		}
		clean(t, e)
	})
}

func newEd25519(t *testing.T) (ssh.PublicKey, ssh.Signer, error) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s.PublicKey(), s, nil
}

func TestBastionInspectCancel(t *testing.T) {
	f, e := bastionSetup(t)
	f.bastion.pending = 1 << 30
	ctx, cancel := f.waitingCtx(t)
	defer cancel()
	_, err := e.EnsureBastionInspect(ctx, BastionOptions{Host: "bastion", Why: "x"})
	if ExitCode(err) != ExitCancelled {
		t.Fatalf("err=%v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.bastion.reqs["BAS0001"].cancelled {
		t.Error("the request was not cancelled on the bastion endpoint")
	}
	for id := range f.requests {
		t.Errorf("generic request %s exists", id)
	}
}

func TestBastionTask(t *testing.T) {
	ctx := context.Background()
	t.Run("approved and done", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskPending = 2
		f.bastion.taskRuns = []api.SetupRunStatus{{State: "queued"}, {State: "running", Step: "Run dnf upgrade"}, {State: "running", Step: "Run dnf upgrade"},
			{State: "running", Step: "Compare before and after"}, {State: "done", Message: "12 packages updated.", Result: map[string]string{"packages_changed": "12", "boot_changed": "no"}}}
		if err := e.BastionTask(ctx, TaskOptions{Task: "os-update", Why: "monthly updates"}); err != nil {
			t.Fatalf("task: %v\n%s", err, e.stderr)
		}
		ft := f.bastion.tasks["TSK0001"]
		if ft.req.Task != "os-update" || string(ft.req.Params) != `{"kernel":false}` || ft.req.Reason != "monthly updates" || ft.req.Requester.User != "alice" {
			t.Errorf("request %+v", ft.req)
		}
		if e.stdout.String() != "boot_changed: no\npackages_changed: 12\n" {
			t.Errorf("stdout = %q", e.stdout)
		}
		stderr := e.stderr.String()
		for _, s := range []string{`request TSK0001 (Ref SK0001): bastion task os-update {"kernel":false} by claude-code on agenthost: monthly updates`, "approve at: https://aqmas.example/r/TSK0001",
			"approved: the bastion's maintenance runner", "queued\n", "running: Run dnf upgrade", "running: Compare before and after", "done: 12 packages updated."} {
			if !strings.Contains(stderr, s) {
				t.Errorf("stderr lacks %q:\n%s", s, stderr)
			}
		}
		if strings.Count(stderr, "running: Run dnf upgrade") != 1 {
			t.Errorf("a step was printed twice:\n%s", stderr)
		}
		if !reflect.DeepEqual(ft.afters, []string{"", "queued", "running", "running", "running"}) {
			t.Errorf("after= sequence %q", ft.afters)
		}
	})
	t.Run("params", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskRuns = []api.SetupRunStatus{{State: "done"}}
		want := map[string]string{"reboot": `{}`, "restart-cloudflared": `{}`, "restart-broker": `{}`, "disk-usage": `{}`}
		for task := range want {
			if err := e.BastionTask(ctx, TaskOptions{Task: task, Why: "x"}); err != nil {
				t.Fatalf("%s: %v", task, err)
			}
		}
		if err := e.BastionTask(ctx, TaskOptions{Task: "journal-vacuum", Why: "x"}); err != nil {
			t.Fatal(err)
		}
		if err := e.BastionTask(ctx, TaskOptions{Task: "journal-vacuum", Why: "x", KeepDays: 7}); err != nil {
			t.Fatal(err)
		}
		var vacuum []string
		for _, ft := range f.bastion.tasks {
			if ft.req.Task == "journal-vacuum" {
				vacuum = append(vacuum, string(ft.req.Params))
			} else if string(ft.req.Params) != want[ft.req.Task] {
				t.Errorf("%s params %s", ft.req.Task, ft.req.Params)
			}
		}
		if len(vacuum) != 2 || !strings.Contains(strings.Join(vacuum, " "), `{"keep_days":14}`) || !strings.Contains(strings.Join(vacuum, " "), `{"keep_days":7}`) {
			t.Errorf("journal-vacuum params %q", vacuum)
		}
		n := len(f.bastion.tasks)
		for name, o := range map[string]TaskOptions{"keep-days below the floor": {Task: "journal-vacuum", Why: "x", KeepDays: 6}, "keep-days above a year": {Task: "journal-vacuum", Why: "x", KeepDays: 366},
			"keep-days on another task": {Task: "disk-usage", Why: "x", KeepDays: 14}, "unknown task": {Task: "bastion-access", Why: "x"}, "upgrade": {Task: "upgrade", Why: "x"}, "no why": {Task: "disk-usage"}} {
			if err := e.BastionTask(ctx, o); ExitCode(err) != ExitUsage {
				t.Errorf("%s: %v", name, err)
			}
		}
		if err := e.BastionTask(ctx, TaskOptions{Task: "journal-vacuum", Why: "x", KeepDays: 6}); err == nil || !strings.Contains(err.Error(), "at least the last week") {
			t.Errorf("floor message: %v", err)
		}
		if len(f.bastion.tasks) != n {
			t.Error("an invalid task was sent")
		}
	})
	t.Run("dismissed", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskDecision = api.StatusDenied
		err := e.BastionTask(ctx, TaskOptions{Task: "disk-usage", Why: "x"})
		if ExitCode(err) != ExitDenied || e.stdout.Len() != 0 {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskDecision = api.StatusExpired
		if err := e.BastionTask(ctx, TaskOptions{Task: "disk-usage", Why: "x"}); ExitCode(err) != ExitExpired {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("failed run", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskRuns = []api.SetupRunStatus{{State: "running", Step: "Run dnf upgrade"}, {State: "failed", Message: "kernel packages changed", Result: map[string]string{"packages_changed": "3"}}}
		err := e.BastionTask(ctx, TaskOptions{Task: "os-update", Why: "x"})
		var te *TaskError
		if !errors.As(err, &te) || ExitCode(err) != ExitError || te.State != "failed" || !strings.Contains(err.Error(), "kernel packages changed") {
			t.Fatalf("err=%v", err)
		}
		if e.stdout.String() != "packages_changed: 3\n" {
			t.Errorf("stdout %q", e.stdout)
		}
	})
	t.Run("refused by the runner", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskRuns = []api.SetupRunStatus{{State: "refused", Message: "credential is not pinned for maintenance"}}
		if err := e.BastionTask(ctx, TaskOptions{Task: "disk-usage", Why: "x"}); ExitCode(err) != ExitError || !strings.Contains(err.Error(), "refused: credential is not pinned") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("cancel before the decision", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskPending = 1 << 30
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := e.BastionTask(ctx, TaskOptions{Task: "disk-usage", Why: "x"}); ExitCode(err) != ExitCancelled {
			t.Fatalf("err=%v", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.bastion.tasks["TSK0001"].cancelled {
			t.Error("not cancelled on the server")
		}
	})
	t.Run("interrupt after approval leaves the task alone", func(t *testing.T) {
		f, e := bastionSetup(t)
		f.bastion.taskRuns = []api.SetupRunStatus{{State: "running", Step: "Run dnf upgrade"}}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := e.BastionTask(ctx, TaskOptions{Task: "os-update", Why: "x"}); ExitCode(err) != ExitCancelled {
			t.Fatalf("err=%v", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.bastion.tasks["TSK0001"].cancelled || !strings.Contains(e.stderr.String(), "the task continues on the bastion") {
			t.Errorf("an approved task was cancelled, or nothing was said: %s", e.stderr)
		}
	})
}

func TestBastionShow(t *testing.T) {
	f, e := bastionSetup(t)
	ctx := context.Background()
	if err := e.BastionShow(ctx); err != nil {
		t.Fatal(err)
	}
	out := e.stdout.String()
	for _, s := range []string{"bastion      bastion (192.0.2.10 port 22)", "inspect      as aqmas-inspect", "up to 8h0m0s (default 1h0m0s)", "root         as alice: NOT allowed from this host", "tasks        os-update reboot restart-cloudflared restart-broker disk-usage journal-vacuum"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	e.stdout.Reset()
	f.mu.Lock()
	f.bastion.rootAllowed = true
	f.mu.Unlock()
	if err := e.BastionShow(ctx); err != nil || !strings.Contains(e.stdout.String(), "root         as alice: allowed from this host, up to 1h0m0s, red card every time") {
		t.Errorf("%v\n%s", err, e.stdout)
	}
	e.stdout.Reset()
	f.mu.Lock()
	f.bastion.off = true
	f.mu.Unlock()
	if err := e.BastionShow(ctx); err != nil || !strings.Contains(e.stdout.String(), "not installed") {
		t.Errorf("%v\n%s", err, e.stdout)
	}
}
