package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
)

// fakeIface is the fake broker's discovery answer and its env releases.
type fakeIface struct {
	catalogue *api.HostCatalogue // nil: not_admitted
	missing   bool               // an older broker: no /v2/catalogue
	sets      map[string][]envset.Entry
	decision  string // approved (default), denied, or pending (never decided)
	releases  map[string]*envset.Release
	modes     []string
	reasons   []string
}

func (f *fakeServer) setupIface(mux *http.ServeMux) {
	f.iface.sets, f.iface.releases = map[string][]envset.Entry{}, map[string]*envset.Release{}
	mux.HandleFunc("GET /v2/catalogue", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case f.iface.missing:
			apiErr(w, 404, api.ErrNotFound, "not found")
		case f.iface.catalogue == nil:
			apiErr(w, 404, api.ErrNotAdmitted, "this host is enrolled but not admitted to an organisation yet")
		default:
			writeJSON(w, 200, f.iface.catalogue)
		}
	})
	binding := func(host, path string) (envset.Binding, bool) {
		entries, ok := f.iface.sets[path]
		return envset.Binding{Path: path, Title: path, Org: "o", Service: "s", Set: "set-" + path, Revision: 1, ServiceRevision: 1, PolicyRevision: 1, Generation: 1, Enrollment: "e1", Host: host, Class: "agent", Names: envset.Names(entries), Default: 600, Soft: 3600}, ok
	}
	mux.HandleFunc("GET /v2/env/set", func(w http.ResponseWriter, r *http.Request) {
		host, ok := f.host(w, r)
		if !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		b, ok := binding(host, r.URL.Query().Get("path"))
		if !ok {
			apiErr(w, 404, api.ErrNotFound, "not found")
			return
		}
		writeJSON(w, 200, b)
	})
	mux.HandleFunc("POST /v2/env/requests", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		var in struct {
			Binding envset.Binding
			Mode    string
			Reason  string
			TTL     int `json:"ttl_seconds"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		id := fmt.Sprintf("ENV%04d", len(f.iface.releases)+1)
		rel := &envset.Release{Binding: in.Binding, ID: id, Mode: in.Mode, Peer: "127.0.0.1", Reason: in.Reason, TTL: 600, Deadline: time.Now().Add(10 * time.Minute).UnixMilli(), Status: "pending"}
		f.iface.releases[id] = rel
		f.iface.modes, f.iface.reasons = append(f.iface.modes, in.Mode), append(f.iface.reasons, in.Reason)
		writeJSON(w, 200, rel)
	})
	mux.HandleFunc("GET /v2/env/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		rel := f.iface.releases[r.PathValue("id")]
		if rel == nil {
			apiErr(w, 404, api.ErrNotFound, "not found")
			return
		}
		switch f.iface.decision {
		case "denied":
			rel.Status = "denied"
		case "pending":
		default:
			rel.Status, rel.Grant, rel.Until = "approved", "G"+rel.ID, time.Now().Add(10*time.Minute).UnixMilli()
		}
		writeJSON(w, 200, rel)
	})
	mux.HandleFunc("POST /v2/env/requests/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if rel := f.iface.releases[r.PathValue("id")]; rel != nil {
			rel.Status = "cancelled"
		}
		writeJSON(w, 200, api.OK{OK: true})
	})
	mux.HandleFunc("POST /v2/grants/{id}/collect", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		rel := f.iface.releases[strings.TrimPrefix(r.PathValue("id"), "G")]
		if rel == nil || rel.Status != "approved" || rel.Consumed {
			apiErr(w, 409, "conflict", "grant expired, revoked or already collected")
			return
		}
		rel.Consumed = true
		writeJSON(w, 200, envset.Collection{Release: *rel, Entries: f.iface.sets[rel.Path]})
	})
}

var testCatalogue = api.HostCatalogue{Discovery: true,
	Credentials: []api.HostCredential{
		{Path: "acme/infra/tailnet-api-key", Kind: "secret", Title: "Tailnet API key", Env: "TAILNET_API_KEY", Approval: "owner", Use: `aqmas run acme/infra/tailnet-api-key --why "..." -- COMMAND`},
		{Path: "acme/billing/staging-env", Kind: "env-set", Title: "Staging", Names: []string{"APP_TOKEN", "DB_URL"}, Approval: "owner", Use: `aqmas run acme/billing/staging-env --why "..." -- COMMAND`},
		{Path: "acme/releases/firmware-key", Kind: "signer", Title: "Firmware", Scheme: "ed25519", Approval: "owner", Use: `aqmas sign acme/releases/firmware-key --why "..." FILE`},
	},
	Targets: []api.HostTarget{{Name: "web-1", Path: "personal/fleet/web-1", Address: "192.0.2.61", Port: 22, Users: []string{"alice"}, Approval: "owner-or-standing", Use: `aqmas ssh alice@web-1 --why "..."`}},
}

func TestLsAndTargets(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	ctx := context.Background()

	// Not admitted anywhere: the usual plain answer.
	if err := e.Ls(ctx, false); !NotAdmitted(err) || !strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("unadmitted: %v", err)
	}
	// Admitted, listing off everywhere: said in so many words, and not an error.
	f.iface.catalogue = &api.HostCatalogue{Credentials: []api.HostCredential{}, Targets: []api.HostTarget{}}
	for name, run := range map[string]func(context.Context, bool) error{"ls": e.Ls, "targets": e.Targets} {
		e.stdout.Reset()
		if err := run(ctx, false); err != nil || !strings.Contains(e.stdout.String(), "discovery is disabled by the owner") || !strings.Contains(e.stdout.String(), "does not mean nothing exists") {
			t.Fatalf("%s with listing off: %v\n%s", name, err, e.stdout)
		}
	}
	e.stdout.Reset()
	if err := e.Ls(ctx, true); err != nil || !strings.Contains(e.stdout.String(), `"discovery": false`) {
		t.Fatalf("ls --json with listing off: %v\n%s", err, e.stdout)
	}
	// Listing on.
	cat := testCatalogue
	f.iface.catalogue = &cat
	e.stdout.Reset()
	if err := e.Ls(ctx, false); err != nil {
		t.Fatal(err)
	}
	out := e.stdout.String()
	for _, want := range []string{"PATH", "acme/infra/tailnet-api-key  secret", "$TAILNET_API_KEY", "APP_TOKEN,DB_URL", "signer", "ed25519", "1 SSH target(s): aqmas targets", "aqmas guide"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls output lacks %q:\n%s", want, out)
		}
	}
	e.stdout.Reset()
	if err := e.Targets(ctx, false); err != nil || !strings.Contains(e.stdout.String(), "web-1") || !strings.Contains(e.stdout.String(), "192.0.2.61") || !strings.Contains(e.stdout.String(), "alice") {
		t.Fatalf("targets: %v\n%s", err, e.stdout)
	}
	e.stdout.Reset()
	var parsed struct {
		Discovery bool
		Targets   []api.HostTarget
	}
	if err := e.Targets(ctx, true); err != nil || json.Unmarshal(e.stdout.Bytes(), &parsed) != nil || !parsed.Discovery || len(parsed.Targets) != 1 || parsed.Targets[0].Name != "web-1" {
		t.Fatalf("targets --json: %v\n%s", err, e.stdout)
	}
	// Server text is never passed to the terminal raw.
	cat.Credentials = []api.HostCredential{{Path: "a/b/c", Kind: "env-set", Names: []string{"X\x1b[31m_KEY"}, Use: "x"}}
	e.stdout.Reset()
	if err := e.Ls(ctx, false); err != nil || strings.Contains(e.stdout.String(), "\x1b") {
		t.Fatalf("escape sequence reached the terminal: %q", e.stdout.String())
	}
	// A broker from before 0.10.0 has no listing: said plainly.
	f.iface.missing = true
	if err := e.Ls(ctx, false); err == nil || !strings.Contains(err.Error(), "does not offer listing") {
		t.Fatalf("old broker: %v", err)
	}
}

func TestGetAndRunSecret(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	const value = "tskey-api-sentinel-0193"
	f.iface.sets["acme/infra/tailnet-api-key"] = []envset.Entry{{Name: "TAILNET_API_KEY", Value: value}}
	f.iface.sets["acme/billing/staging-env"] = []envset.Entry{{Name: "APP_TOKEN", Value: "a"}, {Name: "DB_URL", Value: "b"}}
	ctx := context.Background()

	// get: the value and a newline on stdout, nothing of it on stderr.
	if err := e.EnvDeliver(ctx, EnvOptions{Path: "acme/infra/tailnet-api-key", Mode: "get", Why: "configure the exporter"}); err != nil {
		t.Fatalf("get: %v\n%s", err, e.stderr)
	}
	if e.stdout.String() != value+"\n" || strings.Contains(e.stderr.String(), value) || f.iface.modes[0] != "get" || f.iface.reasons[0] != "configure the exporter" {
		t.Fatalf("get printed %q, stderr %q, mode %v", e.stdout, e.stderr, f.iface.modes)
	}
	if !strings.Contains(e.stderr.String(), "awaiting get release of acme/infra/tailnet-api-key") || !strings.Contains(e.stderr.String(), "Ref ") {
		t.Fatalf("no Ref line: %s", e.stderr)
	}
	// get is for one secret; --why is required off a terminal.
	for name, o := range map[string]EnvOptions{
		"an env set":  {Path: "acme/billing/staging-env", Mode: "get", Why: "x"},
		"a command":   {Path: "acme/infra/tailnet-api-key", Mode: "get", Why: "x", Command: []string{"true"}},
		"no why":      {Path: "acme/infra/tailnet-api-key", Mode: "get"},
		"env on get":  {Path: "acme/infra/tailnet-api-key", Mode: "get", Why: "x", EnvName: "TS_API_KEY"},
		"bad env":     {Path: "acme/infra/tailnet-api-key", Mode: "process", Why: "x", EnvName: "LD_PRELOAD", Command: []string{"true"}},
		"env on many": {Path: "acme/billing/staging-env", Mode: "process", Why: "x", EnvName: "TS_API_KEY", Command: []string{"true"}},
	} {
		before := len(f.iface.modes)
		var ue *UsageError
		if err := e.EnvDeliver(ctx, o); !errorsAs(err, &ue) || (name != "no why" && len(f.iface.modes) != before) {
			t.Errorf("%s: %v (requests %d -> %d)", name, err, before, len(f.iface.modes))
		}
	}
	// run with --env: the command gets the value under the chosen name only.
	var got []string
	run := func(exe string, argv, env []string) error { got = env; return nil }
	if err := e.EnvDeliver(ctx, EnvOptions{Path: "acme/infra/tailnet-api-key", Mode: "process", Why: "list devices", EnvName: "TS_API_KEY", Command: []string{"true"}, Run: run}); err != nil {
		t.Fatalf("run: %v", err)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "TS_API_KEY="+value) || strings.Contains(joined, "TAILNET_API_KEY=") {
		t.Fatalf("environment: %q", got)
	}
	// A denial is exit code 3, as everywhere.
	f.iface.decision = "denied"
	if err := e.EnvDeliver(ctx, EnvOptions{Path: "acme/infra/tailnet-api-key", Mode: "get", Why: "again"}); ExitCode(err) != ExitDenied {
		t.Fatalf("denied get: %v", err)
	}
}

// The guide is what an agent reads first: it has to name every command and every
// answer an agent will meet, and match the tools the MCP server offers.
func TestGuideContent(t *testing.T) {
	g := Guide()
	for _, want := range []string{
		"aqmas status", "aqmas ls", "aqmas targets", "aqmas ssh ", "aqmas mosh ", "aqmas cert ", "aqmas run ", "aqmas get ", "aqmas checkout ", "aqmas sign ", "aqmas signer ", "aqmas ssh-agent ", "aqmas ssh-key ", "aqmas cf ", "aqmas bastion", "aqmas guide --json", "aqmas set import ", "aqmas set check ", "--create", "replaces the whole set",
		"--why", "Ref", "passkey", "do not look for long-lived credentials", "Prefer `sign` over fetching keys", "not_admitted", "not_found", "Hosts may list what they can ask for", "| `ssh-key` |", "ssh://git@forge.example.com/", "may be handed out",
		"claude mcp add aqmas -- aqmas mcp", `"mcpServers"`, "block until the owner decides",
		"| 3 |", "| 4 |", "| 5 |", "| 130 |",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("the guide lacks %q", want)
		}
	}
	for _, name := range mcpToolNames() {
		if !strings.Contains(g, "`"+name+"`") {
			t.Errorf("the guide does not name the MCP tool %s", name)
		}
	}
	s := GuideJSON()
	names := map[string]bool{}
	for _, c := range s.Commands {
		names[c.Name] = true
		if c.Usage == "" || c.Summary == "" || !strings.HasPrefix(c.Usage, "aqmas ") || (c.Approval != "none" && c.Approval != "owner" && c.Approval != "sometimes") {
			t.Errorf("command summary: %+v", c)
		}
	}
	for _, want := range []string{"ls", "targets", "run", "get", "sign", "ssh", "ssh-agent", "ssh-key", "mcp", "guide"} {
		if !names[want] {
			t.Errorf("guide --json lacks %s", want)
		}
	}
	if b, err := json.Marshal(s); err != nil || !json.Valid(b) || s.ExitCodes["3"] == "" || s.Errors["not_admitted"] == "" {
		t.Fatalf("guide --json: %v", err)
	}
}

// mcpSession drives ServeMCP over pipes, as an MCP client does over stdio.
type mcpSession struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Reader
	done chan error
	id   int
}

func startMCP(t *testing.T, e *Env) *mcpSession {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &mcpSession{t: t, in: inW, out: bufio.NewReaderSize(outR, 1<<20), done: make(chan error, 1)}
	go func() { s.done <- e.ServeMCP(context.Background(), inR, outW); outW.Close() }()
	t.Cleanup(func() {
		inW.Close()
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
			t.Error("the MCP server did not stop when its input ended")
		}
	})
	return s
}

type mcpReply struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Error  *mcpError       `json:"error"`
	Result json.RawMessage `json:"result"`
}

func (s *mcpSession) send(line string) {
	s.t.Helper()
	if _, err := io.WriteString(s.in, line+"\n"); err != nil {
		s.t.Fatal(err)
	}
}

// read returns the next message with an id, collecting notifications on the way.
func (s *mcpSession) read(notes *[]mcpReply) mcpReply {
	s.t.Helper()
	for {
		line, err := s.out.ReadBytes('\n')
		if err != nil {
			s.t.Fatalf("MCP output ended: %v", err)
		}
		var r mcpReply
		if err := json.Unmarshal(line, &r); err != nil || !bytes.Contains(line, []byte(`"jsonrpc":"2.0"`)) {
			s.t.Fatalf("not a JSON-RPC line: %q", line)
		}
		if len(r.ID) == 0 {
			if notes != nil {
				*notes = append(*notes, r)
			}
			continue
		}
		return r
	}
}
func (s *mcpSession) request(method string, params any) mcpReply {
	s.t.Helper()
	s.id++
	p, _ := json.Marshal(params)
	s.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, s.id, method, p))
	r := s.read(nil)
	if string(r.ID) != fmt.Sprint(s.id) {
		s.t.Fatalf("answer to %s has id %s, want %d", method, r.ID, s.id)
	}
	return r
}

type toolResult struct {
	Content []struct{ Type, Text string }
	IsError bool `json:"isError"`
}

func (s *mcpSession) tool(name string, args any) (string, bool) {
	s.t.Helper()
	r := s.request("tools/call", map[string]any{"name": name, "arguments": args})
	if r.Error != nil {
		s.t.Fatalf("%s: protocol error %+v", name, r.Error)
	}
	var out toolResult
	if err := json.Unmarshal(r.Result, &out); err != nil || len(out.Content) != 1 || out.Content[0].Type != "text" {
		s.t.Fatalf("%s: result %s", name, r.Result)
	}
	return out.Content[0].Text, out.IsError
}

func TestMCPServer(t *testing.T) {
	f := newFakeServer(t)
	e := newTestEnv(t)
	enroll(t, f, e)
	const value = "tskey-api-sentinel-mcp-55"
	f.iface.sets["acme/infra/tailnet-api-key"] = []envset.Entry{{Name: "TAILNET_API_KEY", Value: value}}
	s := startMCP(t, e.Env)

	// initialize: the client's protocol version when we speak it, ours otherwise.
	r := s.request("initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools *struct{} `json:"tools"`
		}
		ServerInfo   struct{ Name, Version string }
		Instructions string
	}
	if err := json.Unmarshal(r.Result, &init); err != nil || init.ProtocolVersion != "2024-11-05" || init.Capabilities.Tools == nil || init.ServerInfo.Name != "aqmas" || !strings.Contains(init.Instructions, "aqmas_guide") {
		t.Fatalf("initialize: %s", r.Result)
	}
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if r = s.request("initialize", map[string]any{"protocolVersion": "1999-01-01"}); !strings.Contains(string(r.Result), mcpVersions[0]) {
		t.Fatalf("unknown protocol version: %s", r.Result)
	}
	if r = s.request("ping", map[string]any{}); r.Error != nil || string(r.Result) != "{}" {
		t.Fatalf("ping: %+v %s", r.Error, r.Result)
	}
	if r = s.request("resources/list", map[string]any{}); r.Error == nil || r.Error.Code != -32601 {
		t.Fatalf("unknown method: %+v", r)
	}
	s.send(`not json`)
	if r = s.read(nil); r.Error == nil || r.Error.Code != -32700 {
		t.Fatalf("garbage: %+v", r)
	}

	// tools/list: every tool has a description and an object schema; no tool hands out a value.
	r = s.request("tools/list", map[string]any{})
	var list struct {
		Tools []struct {
			Name, Description string
			InputSchema       struct {
				Type       string
				Properties map[string]json.RawMessage
				Required   []string
			} `json:"inputSchema"`
		}
	}
	if err := json.Unmarshal(r.Result, &list); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tool := range list.Tools {
		seen[tool.Name] = true
		if tool.Description == "" || tool.InputSchema.Type != "object" || tool.InputSchema.Properties == nil || tool.InputSchema.Required == nil {
			t.Errorf("tool %s: incomplete definition", tool.Name)
		}
		needsOwner := tool.Name == "aqmas_run" || tool.Name == "aqmas_sign" || tool.Name == "aqmas_ssh_exec" || tool.Name == "aqmas_with_ssh_key"
		if needsOwner != strings.Contains(tool.Description, "locks until the owner approves") {
			t.Errorf("tool %s: blocking is not stated where it applies: %s", tool.Name, tool.Description)
		}
		if needsOwner && (!strings.Contains(strings.Join(tool.InputSchema.Required, ","), "why") || tool.InputSchema.Properties["approval_timeout_seconds"] == nil) {
			t.Errorf("tool %s: why and approval_timeout_seconds", tool.Name)
		}
		if strings.HasSuffix(tool.Name, "_get") || strings.Contains(tool.Name, "reveal") || strings.Contains(tool.Name, "secret") || strings.Contains(tool.Name, "handout") || tool.Name == "aqmas_ssh_key" {
			t.Errorf("a tool that returns values: %s", tool.Name)
		}
	}
	for _, want := range []string{"aqmas_guide", "aqmas_status", "aqmas_list_credentials", "aqmas_list_targets", "aqmas_run", "aqmas_sign", "aqmas_ssh_exec", "aqmas_with_ssh_key"} {
		if !seen[want] {
			t.Errorf("tools/list lacks %s", want)
		}
	}
	if len(list.Tools) != 8 {
		t.Errorf("%d tools", len(list.Tools))
	}

	if text, isErr := s.tool("aqmas_guide", map[string]any{}); isErr || text != Guide() {
		t.Fatal("aqmas_guide is not the guide")
	}
	// Not admitted: said plainly, with what to do.
	if text, isErr := s.tool("aqmas_list_credentials", map[string]any{}); !isErr || !strings.Contains(text, "not admitted") || !strings.Contains(text, "ask the owner to admit this host") {
		t.Fatalf("unadmitted listing: %s", text)
	}
	// Listing off: a clear result, not an error.
	f.mu.Lock()
	f.iface.catalogue = &api.HostCatalogue{Credentials: []api.HostCredential{}, Targets: []api.HostTarget{}}
	f.mu.Unlock()
	for _, name := range []string{"aqmas_list_credentials", "aqmas_list_targets"} {
		if text, isErr := s.tool(name, map[string]any{}); isErr || !strings.Contains(text, "discovery is disabled by the owner") {
			t.Fatalf("%s with listing off: %v %s", name, isErr, text)
		}
	}
	if text, isErr := s.tool("aqmas_status", map[string]any{}); isErr || !strings.Contains(text, "host name    agenthost") || !strings.Contains(text, "admission    admitted") || !strings.Contains(text, "discovery    off") {
		t.Fatalf("status: %s", text)
	}
	cat := testCatalogue
	f.mu.Lock()
	f.iface.catalogue = &cat
	f.mu.Unlock()
	text, isErr := s.tool("aqmas_list_credentials", map[string]any{})
	var creds struct {
		Discovery   bool
		Credentials []api.HostCredential
	}
	if isErr || json.Unmarshal([]byte(text), &creds) != nil || !creds.Discovery || len(creds.Credentials) != 3 || creds.Credentials[0].Env != "TAILNET_API_KEY" || strings.Contains(text, "web-1") {
		t.Fatalf("credentials: %s", text)
	}
	if text, isErr = s.tool("aqmas_list_targets", map[string]any{}); isErr || !strings.Contains(text, `"name": "web-1"`) || strings.Contains(text, "tailnet") {
		t.Fatalf("targets: %s", text)
	}

	// aqmas_run: blocks for the approval, runs the command with the secret in its
	// environment, returns exit code and output; the progress token gets the Ref line.
	s.id++
	s.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"aqmas_run","_meta":{"progressToken":"p1"},"arguments":{"path":"acme/infra/tailnet-api-key","why":"count the key's characters","command":["sh","-c","printf %%s \"$TAILNET_API_KEY\" | wc -c; echo to-stderr >&2; exit 7"]}}}`, s.id))
	var notes []mcpReply
	r = s.read(&notes)
	var out toolResult
	var res runResult
	if err := json.Unmarshal(r.Result, &out); err != nil || out.IsError || json.Unmarshal([]byte(out.Content[0].Text), &res) != nil {
		t.Fatalf("aqmas_run: %s", r.Result)
	}
	if res.ExitCode != 7 || strings.TrimSpace(res.Stdout) != fmt.Sprint(len(value)) || strings.TrimSpace(res.Stderr) != "to-stderr" || !strings.Contains(res.Note, "do not repeat it") || strings.Contains(string(r.Result), value) {
		t.Fatalf("aqmas_run result: %+v", res)
	}
	progress := false
	for _, n := range notes {
		progress = progress || n.Method == "notifications/progress" && strings.Contains(string(n.Params), `"progressToken":"p1"`) && strings.Contains(string(n.Params), "Ref ")
	}
	if !progress || f.iface.reasons[len(f.iface.reasons)-1] != "count the key's characters" {
		t.Fatalf("no progress line with the Ref, or the why was not sent: %v", notes)
	}
	// Missing why, unknown argument, unknown tool.
	if text, isErr = s.tool("aqmas_run", map[string]any{"path": "acme/infra/tailnet-api-key", "command": []string{"true"}}); !isErr || !strings.Contains(text, "why") {
		t.Fatalf("run without why: %s", text)
	}
	if text, isErr = s.tool("aqmas_run", map[string]any{"path": "acme/infra/tailnet-api-key", "why": "x", "command": []string{"true"}, "print": true}); !isErr || !strings.Contains(text, "exit code: 2") {
		t.Fatalf("unknown argument: %s", text)
	}
	if r = s.request("tools/call", map[string]any{"name": "aqmas_get", "arguments": map[string]any{}}); r.Error == nil {
		t.Fatal("an unknown tool was called")
	}
	// A denial tells the agent to stop.
	f.mu.Lock()
	f.iface.decision = "denied"
	f.mu.Unlock()
	if text, isErr = s.tool("aqmas_run", map[string]any{"path": "acme/infra/tailnet-api-key", "why": "again", "command": []string{"true"}}); !isErr || !strings.Contains(text, "exit code: 3") || !strings.Contains(text, "Do not rephrase and retry") {
		t.Fatalf("denied run: %s", text)
	}
	// Nobody decides: the approval timeout withdraws the request.
	f.mu.Lock()
	f.iface.decision = "pending"
	f.mu.Unlock()
	if text, isErr = s.tool("aqmas_run", map[string]any{"path": "acme/infra/tailnet-api-key", "why": "nobody home", "command": []string{"true"}, "approval_timeout_seconds": 2}); !isErr || !strings.Contains(text, "did not decide within the approval timeout") || !strings.Contains(text, "exit code: 4") {
		t.Fatalf("approval timeout: %s", text)
	}
	f.mu.Lock()
	last := f.iface.releases[fmt.Sprintf("ENV%04d", len(f.iface.releases))]
	status := last.Status
	f.mu.Unlock()
	if status != "cancelled" {
		t.Fatalf("the timed-out request was not withdrawn: %s", status)
	}
	// A cancelled call (notifications/cancelled) ends its wait too.
	s.id++
	id := s.id
	s.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"aqmas_run","arguments":{"path":"acme/infra/tailnet-api-key","why":"to be cancelled","command":["true"]}}}`, id))
	for {
		f.mu.Lock()
		n := len(f.iface.releases)
		f.mu.Unlock()
		if n == 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.send(fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":%d}}`, id))
	if r = s.read(nil); !strings.Contains(string(r.Result), `"isError":true`) {
		t.Fatalf("cancelled call: %s", r.Result)
	}
}
