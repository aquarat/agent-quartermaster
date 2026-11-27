package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
)

// fakeProps is the broker's side of env proposals: it recomputes the
// commitment as aqmasd does and answers polls with the configured decision.
type fakeProps struct {
	decision  string // committed (default), discarded, expired, superseded, pending
	posts     []envset.ProposalRequest
	proposals map[string]*envset.Proposal
	polls     int
	cancelled []string
	gets      int // GET /v2/env/set?create=1
	// Faults: a POST answered with another commitment, polls answered 503 (that
	// many, or all with -1), a cancel that fails, and a short life.
	tamper     bool
	pollFail   int
	cancelFail bool
	ttl        time.Duration
}

// proposalBase: organisation "acme" exists with the service "billing".
func (f *fakeServer) proposalBase(host, path string) (envset.Binding, bool) {
	p := strings.Split(path, "/")
	if len(p) != 3 || p[0] != "acme" {
		return envset.Binding{}, false
	}
	f.prop.gets++
	b := envset.Binding{Path: path, Title: "Acme / " + p[1], Org: "o", PolicyRevision: 1, Generation: 1, Enrollment: "e1", Host: host, Class: "agent", Names: []string{}, Default: 600, Soft: 3600}
	if p[1] == "billing" {
		b.Service, b.ServiceRevision = "s", 1
	}
	return b, true
}

func (f *fakeServer) setupProposals(mux *http.ServeMux) {
	f.prop.proposals = map[string]*envset.Proposal{}
	mux.HandleFunc("POST /v2/env/proposals", func(w http.ResponseWriter, r *http.Request) {
		host, ok := f.host(w, r)
		if !ok {
			return
		}
		var in envset.ProposalRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			apiErr(w, 400, "bad_request", "invalid JSON body")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.prop.posts = append(f.prop.posts, in)
		var b envset.Binding
		if entries, ok := f.iface.sets[in.Path]; ok && in.Create == nil {
			b = envset.Binding{Path: in.Path, Title: in.Path, Org: "o", Service: "s", Set: "set-" + in.Path, Revision: 1, ServiceRevision: 1, PolicyRevision: 1, Generation: 1, Enrollment: "e1", Host: host, Class: "agent", Names: envset.Names(entries), Default: 600, Soft: 3600}
		} else if base, ok := f.proposalBase(host, in.Path); ok && in.Create != nil {
			b = base
			if b.Service == "" {
				b.Service = in.Create.ServiceID
			}
			b.Set, b.Title = in.Create.SetID, b.Title+" / "+in.Create.Title
		} else {
			apiErr(w, 404, api.ErrNotFound, "not found")
			return
		}
		commit, err := in.Edit.Commit(b)
		if err != nil || commit != in.Commitment {
			apiErr(w, 400, "bad_request", "invalid edit commitment")
			return
		}
		changes, _ := in.Edit.Changes(b.Names)
		id := fmt.Sprintf("PROP%04dabcdef", len(f.prop.proposals)+1)
		now := time.Now()
		p := &envset.Proposal{Binding: b, ID: id, Ref: RefCode(id), Operation: in.Edit.Op, Commitment: commit, Changes: changes, Reason: in.Reason, Peer: "127.0.0.1",
			NewService: in.Create != nil && in.Create.ServiceID != "", NewSet: in.Create != nil, Status: "pending", Created: now.UnixMilli(), Expires: now.Add(10 * time.Minute).UnixMilli()}
		if f.prop.ttl > 0 {
			p.Expires = now.Add(f.prop.ttl).UnixMilli()
		}
		f.prop.proposals[id] = p
		if f.prop.tamper {
			q := *p
			q.Commitment = strings.Repeat("0", 64)
			writeJSON(w, 200, q)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("GET /v2/env/proposals/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		p := f.prop.proposals[r.PathValue("id")]
		if p == nil {
			apiErr(w, 404, api.ErrNotFound, "not found")
			return
		}
		f.prop.polls++
		if f.prop.pollFail != 0 {
			if f.prop.pollFail > 0 {
				f.prop.pollFail--
			}
			apiErr(w, 503, "unavailable", "restarting")
			return
		}
		if p.Status == "pending" {
			switch f.prop.decision {
			case "pending":
			case "", "committed":
				p.Status, p.Result = "committed", p.Revision+1
			default:
				p.Status = f.prop.decision
			}
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("POST /v2/env/proposals/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := f.prop.proposals[r.PathValue("id")]
		if p == nil {
			apiErr(w, 404, api.ErrNotFound, "not found")
			return
		}
		if f.prop.cancelFail {
			apiErr(w, 503, "unavailable", "restarting")
			return
		}
		if p.Status != "pending" {
			apiErr(w, 409, "conflict", "proposal no longer pending")
			return
		}
		p.Status = "cancelled"
		f.prop.cancelled = append(f.prop.cancelled, p.ID)
		writeJSON(w, 200, p)
	})
}

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "import.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const propSet = "acme/billing/staging-env"

func proposalEnv(t *testing.T) (*fakeServer, *testEnv) {
	t.Helper()
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	f.iface.sets[propSet] = []envset.Entry{{Name: "APP_TOKEN", Value: "old"}, {Name: "OLD_URL", Value: "old"}}
	e.stderr.Reset()
	return f, e
}

func TestSetProposeImport(t *testing.T) {
	f, e := proposalEnv(t)
	const value = "sentinel-proposed-value-11"
	file := writeEnvFile(t, "# staging\nAPP_TOKEN="+value+"\nAPP_URL='https://example.com/x y'\n")
	p, err := e.SetPropose(context.Background(), SetOptions{Op: "import", Path: propSet, From: file, Why: "rotate the staging token"})
	if err != nil {
		t.Fatalf("propose: %v\n%s", err, e.stderr)
	}
	if p.Status != "committed" || p.Result != 2 || p.Changes != "APP_TOKEN:replace,APP_URL:add,OLD_URL:remove" {
		t.Fatalf("proposal: %+v", p)
	}
	// The terminal shows the Ref, the commitment and the changes by name; never a value.
	out := e.stderr.String()
	for _, want := range []string{"Ref " + p.Ref, "commitment " + p.Commitment, "add APP_URL", "replace APP_TOKEN", "remove OLD_URL", "replacing the whole set", "Ctrl-C withdraws", "committed: " + propSet + " is at revision 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, value) || strings.Contains(e.stdout.String(), value) || strings.Contains(out, "example.com") {
		t.Fatalf("a value was printed:\n%s", out)
	}
	if len(f.prop.posts) != 1 || f.prop.posts[0].Create != nil || f.prop.posts[0].Reason != "rotate the staging token" || len(f.prop.posts[0].Edit.Salt) != 32 || len(f.prop.cancelled) != 0 {
		t.Fatalf("posts: %+v", f.prop.posts)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.Commitment) || len(p.Ref) != 6 {
		t.Fatalf("commitment %q ref %q", p.Commitment, p.Ref)
	}
}

func TestSetProposeOutcomes(t *testing.T) {
	for decision, want := range map[string]int{"discarded": ExitDenied, "expired": ExitExpired, "superseded": ExitExpired} {
		f, e := proposalEnv(t)
		f.prop.decision = decision
		e.Stdin = strings.NewReader("new-value")
		p, err := e.SetPropose(context.Background(), SetOptions{Op: "put", Path: propSet, Key: "APP_TOKEN", Why: "rotate"})
		if got := ExitCode(err); got != want || p.Status != decision {
			t.Errorf("%s: exit %d (%v), status %s", decision, got, err, p.Status)
		}
		if strings.Contains(e.stderr.String(), "new-value") || err != nil && strings.Contains(err.Error(), "new-value") {
			t.Errorf("%s: the value was printed", decision)
		}
	}
	// Ctrl-C while waiting withdraws the proposal: exit 130.
	f, e := proposalEnv(t)
	f.prop.decision = "pending"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			time.Sleep(10 * time.Millisecond)
			f.mu.Lock()
			polled := f.prop.polls > 0
			f.mu.Unlock()
			if polled {
				cancel()
			}
		}
	}()
	_, err := e.SetPropose(ctx, SetOptions{Op: "unset", Path: propSet, Key: "OLD_URL", Why: "no longer used"})
	if ExitCode(err) != ExitCancelled {
		t.Fatalf("cancel: %v", err)
	}
	f.mu.Lock()
	cancelled := len(f.prop.cancelled)
	f.mu.Unlock()
	if cancelled != 1 {
		t.Fatalf("%d proposals withdrawn", cancelled)
	}
}

func TestSetProposeChecksBeforeSending(t *testing.T) {
	f, e := proposalEnv(t)
	sent := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.prop.posts)
	}
	// A file that would not import: every problem by line, nothing sent, no text of the file.
	file := writeEnvFile(t, "APP_TOKEN=sentinel-a\nDATABASE_HOST=sentinel-b\nAPP_URL=has space sentinel-c\n")
	_, err := e.SetPropose(context.Background(), SetOptions{Op: "import", Path: propSet, From: file, Why: "x"})
	out := e.stderr.String()
	if err == nil || ExitCode(err) != ExitError || sent() != 0 || !strings.Contains(out, "line 2: ") || strings.Contains(out, "line 1: ") || strings.Contains(out, "sentinel") || strings.Contains(out, "DATABASE") || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("bad file: %v\n%s", err, out)
	}
	// Usage mistakes.
	good := writeEnvFile(t, "APP_TOKEN=v\n")
	for name, o := range map[string]SetOptions{
		"no why":               {Op: "import", Path: propSet, From: good},
		"bad path":             {Op: "import", Path: "acme/billing", From: good, Why: "x"},
		"title without create": {Op: "import", Path: propSet, From: good, Why: "x", Title: "T"},
		"bad title":            {Op: "import", Path: propSet, From: good, Why: "x", Create: true, Title: "<b>"},
		"create with unset":    {Op: "unset", Path: propSet, Key: "APP_TOKEN", Why: "x", Create: true},
		"unsafe key":           {Op: "put", Path: propSet, Key: "LD_PRELOAD", Why: "x"},
	} {
		if _, err := e.SetPropose(context.Background(), o); ExitCode(err) != ExitUsage {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Local refusals that need the set's names.
	if _, err := e.SetPropose(context.Background(), SetOptions{Op: "unset", Path: propSet, Key: "APP_ID", Why: "x"}); err == nil || !strings.Contains(err.Error(), "no key APP_ID") {
		t.Errorf("unset of a missing key: %v", err)
	}
	// A missing set without --create: not found, with the hint; nothing created.
	if _, err := e.SetPropose(context.Background(), SetOptions{Op: "import", Path: "acme/billing/prod", From: good, Why: "x"}); err == nil || !strings.Contains(err.Error(), "--create") {
		t.Errorf("missing set: %v", err)
	}
	if sent() != 0 {
		t.Fatalf("%d proposals sent by refused commands", sent())
	}
}

func TestSetProposeCreate(t *testing.T) {
	f, e := proposalEnv(t)
	file := writeEnvFile(t, "APP_TOKEN=v\n")
	hex32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	// A new set in an existing service.
	p, err := e.SetPropose(context.Background(), SetOptions{Op: "import", Path: "acme/billing/prod", From: file, Why: "first deploy", Create: true, Title: "Production"})
	if err != nil || !p.NewSet || p.NewService || p.Service != "s" || !hex32.MatchString(p.Set) || p.Result != 1 {
		t.Fatalf("new set: %v %+v", err, p)
	}
	c := f.prop.posts[0].Create
	if c == nil || c.ServiceID != "" || c.SetID != p.Set || c.Title != "Production" || !strings.Contains(e.stderr.String(), "create set acme/billing/prod") {
		t.Fatalf("create: %+v\n%s", c, e.stderr)
	}
	// A new service too: both IDs are this host's, and distinct.
	e.Stdin = strings.NewReader("v")
	p, err = e.SetPropose(context.Background(), SetOptions{Op: "put", Path: "acme/mail/prod", Key: "APP_KEY", Why: "first deploy", Create: true})
	c = f.prop.posts[1].Create
	if err != nil || !p.NewService || !p.NewSet || !hex32.MatchString(c.ServiceID) || !hex32.MatchString(c.SetID) || c.ServiceID == c.SetID || c.Title != "" || !strings.Contains(e.stderr.String(), "create service and set acme/mail/prod") {
		t.Fatalf("new service: %v %+v", err, c)
	}
	// --create on a set that exists proposes the edit to it and creates nothing.
	p, err = e.SetPropose(context.Background(), SetOptions{Op: "import", Path: propSet, From: file, Why: "idempotent", Create: true})
	if err != nil || p.NewSet || f.prop.posts[2].Create != nil || !strings.Contains(e.stderr.String(), "exists: proposing the edit") {
		t.Fatalf("create of an existing set: %v %+v", err, p)
	}
	// An organisation this host is not in.
	if _, err = e.SetPropose(context.Background(), SetOptions{Op: "import", Path: "other/billing/prod", From: file, Why: "x", Create: true}); err == nil || len(f.prop.posts) != 3 {
		t.Fatalf("unknown organisation: %v", err)
	}
}

func TestSetCheck(t *testing.T) {
	_, e := proposalEnv(t)
	file := writeEnvFile(t, "APP_TOKEN=sentinel-a\nAPP_URL=\"sentinel\nb\"\n")
	if err := e.SetCheck(context.Background(), file, ""); err != nil || e.stdout.String() != "APP_TOKEN\nAPP_URL\n" {
		t.Fatalf("check: %v %q", err, e.stdout)
	}
	e.stdout.Reset()
	if err := e.SetCheck(context.Background(), file, propSet); err != nil || e.stdout.String() != "APP_TOKEN\nAPP_URL\nreplace APP_TOKEN\nadd APP_URL\nremove OLD_URL\n" {
		t.Fatalf("check with a path: %v %q", err, e.stdout)
	}
	e.stdout.Reset()
	if err := e.SetCheck(context.Background(), file, "acme/billing/prod"); err != nil || e.stdout.String() != "APP_TOKEN\nAPP_URL\nadd APP_TOKEN\nadd APP_URL\n" || !strings.Contains(e.stderr.String(), "--create") {
		t.Fatalf("check against a missing set: %v %q", err, e.stdout)
	}
	e.stdout.Reset()
	e.stderr.Reset()
	bad := writeEnvFile(t, "APP_TOKEN=sentinel-a\nsentinel line\nAPP_TOKEN=sentinel-again\n")
	err := e.SetCheck(context.Background(), bad, propSet)
	all := e.stdout.String() + e.stderr.String()
	if ExitCode(err) != ExitError || e.stdout.String() != "APP_TOKEN\n" || !strings.Contains(all, "line 2: ") || !strings.Contains(all, "line 3: ") || strings.Contains(all, "sentinel") {
		t.Fatalf("bad file: %v\n%s", err, all)
	}
	if ExitCode(e.SetCheck(context.Background(), file, "nope")) != ExitUsage {
		t.Fatal("bad path accepted")
	}
	// A file somebody else could have written is not read.
	loose := writeEnvFile(t, "APP_TOKEN=v\n")
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if e.SetCheck(context.Background(), loose, "") == nil {
		t.Fatal("a world-writable file was read")
	}
}

func TestMCPStoreEnv(t *testing.T) {
	f, e := proposalEnv(t)
	const value = "sentinel-mcp-store-77"
	file := writeEnvFile(t, "APP_TOKEN="+value+"\nAPP_ID=7\n")
	s := startMCP(t, e.Env)
	s.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}})
	text, isErr := s.tool("aqmas_store_env", map[string]any{"path": propSet, "file": file, "why": "rotate the staging token"})
	if isErr {
		t.Fatalf("aqmas_store_env: %s", text)
	}
	var out struct {
		Status, Ref, Path string
		Revision          int
		Changes           map[string][]string
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	if out.Status != "committed" || len(out.Ref) != 6 || out.Path != propSet || out.Revision != 2 || fmt.Sprint(out.Changes) != "map[add:[APP_ID] remove:[OLD_URL] replace:[APP_TOKEN]]" || strings.Contains(text, value) {
		t.Fatalf("result: %s", text)
	}
	// Refusals are tool errors with the CLI's exit code; nothing is sent for a bad file.
	f.mu.Lock()
	f.prop.decision = "discarded"
	f.mu.Unlock()
	if text, isErr = s.tool("aqmas_store_env", map[string]any{"path": propSet, "file": file, "why": "again"}); !isErr || !strings.Contains(text, "exit code: 3") || strings.Contains(text, value) {
		t.Fatalf("discarded: %s", text)
	}
	bad := writeEnvFile(t, "APP_TOKEN "+value+"\n")
	if text, isErr = s.tool("aqmas_store_env", map[string]any{"path": propSet, "file": bad, "why": "x"}); !isErr || !strings.Contains(text, "line 1") || strings.Contains(text, value) {
		t.Fatalf("bad file: %s", text)
	}
	for name, args := range map[string]map[string]any{
		"relative file": {"path": propSet, "file": "import.env", "why": "x"},
		"no why":        {"path": propSet, "file": file, "why": " "},
		"unknown field": {"path": propSet, "file": file, "why": "x", "value": "v"},
	} {
		if text, isErr = s.tool("aqmas_store_env", args); !isErr || !strings.Contains(text, "exit code: 2") {
			t.Errorf("%s: %s", name, text)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.prop.posts) != 2 {
		t.Fatalf("%d proposals sent", len(f.prop.posts))
	}
	var seen bytes.Buffer
	for _, p := range f.prop.proposals {
		b, _ := json.Marshal(p)
		seen.Write(b)
	}
	if strings.Contains(seen.String(), value) {
		t.Fatal("a proposal's metadata holds a value")
	}
}

// After the POST the broker holds something the owner can commit: every
// failure withdraws it or says that it may still be committed.
func TestSetProposeNeverLeavesASilentProposal(t *testing.T) {
	pending := func(f *fakeServer) (n int) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, p := range f.prop.proposals {
			if p.Status == "pending" {
				n++
			}
		}
		return n
	}
	put := func(e *testEnv) (envset.Proposal, error) {
		e.Stdin = strings.NewReader("new-value")
		return e.SetPropose(context.Background(), SetOptions{Op: "put", Path: propSet, Key: "APP_TOKEN", Why: "rotate"})
	}
	// The broker's answer is not the edit that was sent: withdrawn, exit 1, the Ref already printed.
	f, e := proposalEnv(t)
	f.prop.tamper = true
	_, err := put(e)
	if ExitCode(err) != ExitError || !strings.Contains(err.Error(), "differs from the submitted edit") || !strings.Contains(err.Error(), "was withdrawn") || pending(f) != 0 || len(f.prop.cancelled) != 1 || !strings.Contains(e.stderr.String(), "proposal Ref ") {
		t.Fatalf("tampered answer: %v\n%s", err, e.stderr)
	}
	// A broker that is briefly away is asked again.
	f, e = proposalEnv(t)
	f.prop.pollFail = 3
	p, err := put(e)
	if err != nil || p.Status != "committed" || !strings.Contains(e.stderr.String(), "still waiting for the decision") {
		t.Fatalf("transient poll failures: %v\n%s", err, e.stderr)
	}
	// Away until the proposal would have expired: withdrawn if the cancel gets through.
	f, e = proposalEnv(t)
	f.prop.pollFail, f.prop.ttl = -1, 200*time.Millisecond
	_, err = put(e)
	if ExitCode(err) != ExitUnreachable || !strings.Contains(err.Error(), "was withdrawn") || pending(f) != 0 {
		t.Fatalf("unreachable, cancel worked: %v\n%s", err, e.stderr)
	}
	// ... and when it does not, the terminal says that it may still be committed, until when, and how to check.
	f, e = proposalEnv(t)
	f.prop.pollFail, f.prop.cancelFail, f.prop.ttl = -1, true, 200*time.Millisecond
	_, err = put(e)
	out := e.stderr.String()
	if ExitCode(err) != ExitUnreachable || pending(f) != 1 || !strings.Contains(out, "may still be committed by the owner until ") || !strings.Contains(out, "check the approval page") || strings.Contains(out+err.Error(), "new-value") {
		t.Fatalf("unreachable, cancel failed: %v\n%s", err, out)
	}
	// Ctrl-C with a cancel that fails says the same; exit 130.
	f, e = proposalEnv(t)
	f.prop.decision, f.prop.cancelFail = "pending", true
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			time.Sleep(10 * time.Millisecond)
			f.mu.Lock()
			polled := f.prop.polls > 0
			f.mu.Unlock()
			if polled {
				cancel()
			}
		}
	}()
	e.Stdin = strings.NewReader("new-value")
	_, err = e.SetPropose(ctx, SetOptions{Op: "put", Path: propSet, Key: "APP_TOKEN", Why: "rotate"})
	if ExitCode(err) != ExitCancelled || !strings.Contains(e.stderr.String(), "may still be committed by the owner until ") {
		t.Fatalf("interrupted, cancel failed: %v\n%s", err, e.stderr)
	}
	// Committed while the withdraw was on its way: said so.
	f, e = proposalEnv(t)
	f.prop.decision = "pending"
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()
	go func() {
		for ctx2.Err() == nil {
			time.Sleep(10 * time.Millisecond)
			f.mu.Lock()
			if f.prop.polls > 0 {
				for _, p := range f.prop.proposals {
					p.Status, p.Result = "committed", 2
				}
				cancel2()
			}
			f.mu.Unlock()
		}
	}()
	e.Stdin = strings.NewReader("new-value")
	_, err = e.SetPropose(ctx2, SetOptions{Op: "put", Path: propSet, Key: "APP_TOKEN", Why: "rotate"})
	if ExitCode(err) != ExitCancelled || !strings.Contains(e.stderr.String(), "was COMMITTED by the owner meanwhile") {
		t.Fatalf("committed during the interrupt: %v\n%s", err, e.stderr)
	}
	// An empty value is refused here: usually an empty stdin.
	f, e = proposalEnv(t)
	e.Stdin = strings.NewReader("")
	if _, err = e.SetPropose(context.Background(), SetOptions{Op: "put", Path: propSet, Key: "APP_TOKEN", Why: "rotate"}); err == nil || !strings.Contains(err.Error(), "the value is empty: was stdin empty?") || len(f.prop.posts) != 0 {
		t.Fatalf("empty put: %v", err)
	}
}
