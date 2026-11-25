package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/envset"
)

// `aqmas mcp`: a Model Context Protocol server on stdin/stdout (JSON-RPC 2.0, one message
// per line). The subset written here by hand is what a tool-only server needs: initialize,
// notifications/initialized, ping, tools/list, tools/call, notifications/cancelled, and
// notifications/progress for the lines the CLI would print while it waits. Every tool does
// what the matching command does, through the same code and the same approvals. No tool
// returns a secret's value.

var mcpVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const (
	mcpMaxMessage  = 4 << 20
	mcpMaxOutput   = 64 << 10
	mcpInstruction = "aqmas brokers credentials for this host: SSH certificates, secrets and env sets, signatures. " +
		"The host holds no long-lived credentials; ask through these tools. Tools that need the owner block until the owner approves with a passkey, denies, or the approval timeout passes; give a specific, honest `why`. " +
		"Call aqmas_guide first."
)

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	call        func(ctx context.Context, e *Env, args json.RawMessage) (string, error)
}

func schema(required []string, props map[string]any) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}
func prop(kind, desc string) map[string]any { return map[string]any{"type": kind, "description": desc} }

var (
	propWhy     = prop("string", "Shown to the owner on the approval card (marked unverified) and logged. One specific, honest sentence about what you are doing and for which task. Never a secret.")
	propApprove = prop("integer", "Seconds to wait for the owner's decision before giving up and withdrawing the request (default 600, at most 3600).")
	propTimeout = prop("integer", "Seconds the command may run once started (default 300, at most 3600).")
)

const blocks = " Blocks until the owner approves with a passkey, denies, or approval_timeout_seconds passes (the request is then withdrawn). Do not call it again in a loop: each call is another notification on the owner's phone."

func mcpTools() []mcpTool {
	return []mcpTool{
		{Name: "aqmas_guide", Description: "The agent guide for the installed aqmas: what it is, how approvals work, every command with examples, exit codes and what to do on each error. Read this first.",
			InputSchema: schema(nil, map[string]any{}),
			call:        func(context.Context, *Env, json.RawMessage) (string, error) { return Guide(), nil }},
		{Name: "aqmas_status", Description: "This host's enrolment (server, host name, client certificate), whether the owner admitted it, whether listing is allowed, cached SSH certificates and active grants. Needs no approval.",
			InputSchema: schema(nil, map[string]any{}), call: mcpStatus},
		{Name: "aqmas_list_credentials", Description: "Credential sets this host may ask for: path (organisation/service/set), kind (secret, env-set, signer, cloudflare-*), key names or variable name (never values) and the command to use. Returns a clear \"discovery is disabled by the owner\" result when the owner has listing off; that does not mean nothing exists. Needs no approval.",
			InputSchema: schema(nil, map[string]any{}), call: mcpList(false)},
		{Name: "aqmas_list_targets", Description: "SSH targets this host may ask a certificate for: name, address, port, allowed login users. Returns a clear \"discovery is disabled by the owner\" result when the owner has listing off. Needs no approval.",
			InputSchema: schema(nil, map[string]any{}), call: mcpList(true)},
		{Name: "aqmas_run", Description: "Run a command on this host with a secret or env set injected into its environment (like `aqmas run PATH --why ... -- COMMAND`). The command is started directly, without a shell; for shell syntax pass [\"sh\",\"-c\",\"...\"]. Returns the exit code and the captured stdout and stderr (each truncated to 64 KiB). The secret's value is never returned by aqmas itself, but the output is returned as the command printed it: if your command prints the secret, the output contains it, so do not print it." + blocks,
			InputSchema: schema([]string{"path", "why", "command"}, map[string]any{
				"path":                     prop("string", "organisation/service/set of a secret or env set (see aqmas_list_credentials)."),
				"why":                      propWhy,
				"command":                  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "description": "The command and its arguments."},
				"env":                      prop("string", "For a secret (or a one-key set): deliver under this variable name instead of its own."),
				"cwd":                      prop("string", "Working directory for the command (default: the MCP server's)."),
				"ttl_seconds":              prop("integer", "How long the approval stays collectable (default: the organisation's)."),
				"timeout_seconds":          propTimeout,
				"approval_timeout_seconds": propApprove,
			}), call: mcpRun},
		{Name: "aqmas_sign", Description: "Have aqmas sign files or a SHA-256 digest with a signing key that never leaves it (like `aqmas sign`). Files are hashed on this host; the owner approves the names, sizes and digests. For files, FILE.sig is written next to each and the paths are reported; for a digest, the signature is returned as hex." + blocks,
			InputSchema: schema([]string{"path", "why"}, map[string]any{
				"path":                     prop("string", "organisation/service/key of a signer (see aqmas_list_credentials)."),
				"why":                      propWhy,
				"files":                    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Absolute paths of the files to sign. Give files or digest, not both."},
				"digest":                   prop("string", "sha256:HEX, for a key whose scheme signs a SHA-256 digest."),
				"force":                    prop("boolean", "Overwrite an existing FILE.sig."),
				"approval_timeout_seconds": propApprove,
			}), call: mcpSign},
		{Name: "aqmas_ssh_exec", Description: "Run one command on an SSH target with a short-lived certificate (like `aqmas ssh USER@HOST --why ... -- COMMAND`). The command line is run by the remote login shell. Returns the exit code and the captured stdout and stderr (each truncated to 64 KiB). A cached certificate that is still valid is reused without asking; otherwise this" + strings.ToLower(blocks[:2]) + blocks[2:],
			InputSchema: schema([]string{"target", "why", "command"}, map[string]any{
				"target":                   prop("string", "[USER@]HOST: a target name from aqmas_list_targets and one of its allowed users."),
				"why":                      propWhy,
				"command":                  prop("string", "The remote command line."),
				"ttl_seconds":              prop("integer", "Certificate lifetime to ask for (default 1800)."),
				"timeout_seconds":          propTimeout,
				"approval_timeout_seconds": propApprove,
			}), call: mcpSSH},
	}
}

func mcpToolNames() []string {
	var out []string
	for _, t := range mcpTools() {
		out = append(out, t.Name)
	}
	return out
}

// ---- protocol ----

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}
type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type mcpServer struct {
	env   *Env
	tools []mcpTool
	wmu   sync.Mutex
	out   io.Writer
	mu    sync.Mutex
	calls map[string]context.CancelFunc
}

func (s *mcpServer) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.out.Write(append(b, '\n'))
}
func (s *mcpServer) reply(id json.RawMessage, result any, e *mcpError) {
	m := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		m["error"] = e
	} else {
		m["result"] = result
	}
	s.send(m)
}

// mcpDrain is how long calls already running may finish after the input ended (a client
// that pipes its requests in and closes the pipe still gets its answers).
const mcpDrain = 5 * time.Second

// ServeMCP runs the MCP server until in ends or ctx is cancelled. Calls that are still
// running when the input ends get mcpDrain to finish; requests still waiting for the owner
// after that are withdrawn on the way out.
func (e *Env) ServeMCP(ctx context.Context, in io.Reader, out io.Writer) error {
	s := &mcpServer{env: e, tools: mcpTools(), out: out, calls: map[string]context.CancelFunc{}}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		idle := make(chan struct{})
		go func() { wg.Wait(); close(idle) }()
		select {
		case <-idle:
		case <-ctx.Done():
		case <-time.After(mcpDrain):
		}
		cancel()
		wg.Wait()
	}()
	lines := make(chan []byte)
	var readErr error
	go func() {
		defer close(lines)
		r := bufio.NewReaderSize(in, 64<<10)
		for {
			line, err := readLine(r, mcpMaxMessage)
			if len(bytes.TrimSpace(line)) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					readErr = err
				}
				return
			}
		}
	}()
	for {
		var line []byte
		var ok bool
		select {
		case <-ctx.Done():
			return nil
		case line, ok = <-lines:
		}
		if !ok {
			return readErr
		}
		var req mcpRequest
		if err := json.Unmarshal(line, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			if bytes.HasPrefix(bytes.TrimSpace(line), []byte("{")) && err == nil && req.Method == "" {
				continue // a response to something we never asked: ignore
			}
			s.reply(json.RawMessage("null"), nil, &mcpError{-32700, "expected one JSON-RPC 2.0 request per line"})
			continue
		}
		notification := len(req.ID) == 0 || string(req.ID) == "null"
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(req.Params, &p)
			v := mcpVersions[0]
			for _, known := range mcpVersions {
				if p.ProtocolVersion == known {
					v = known
				}
			}
			s.reply(req.ID, map[string]any{"protocolVersion": v, "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "aqmas", "version": Version}, "instructions": mcpInstruction}, nil)
		case "notifications/initialized":
		case "notifications/cancelled":
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			_ = json.Unmarshal(req.Params, &p)
			s.mu.Lock()
			if stop := s.calls[string(p.RequestID)]; stop != nil {
				stop()
			}
			s.mu.Unlock()
		case "ping":
			if !notification {
				s.reply(req.ID, map[string]any{}, nil)
			}
		case "tools/list":
			s.reply(req.ID, map[string]any{"tools": s.tools}, nil)
		case "tools/call":
			if notification {
				continue
			}
			cctx, stop := context.WithCancel(ctx)
			key := string(req.ID)
			s.mu.Lock()
			s.calls[key] = stop
			s.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					s.mu.Lock()
					delete(s.calls, key)
					s.mu.Unlock()
					stop()
				}()
				s.call(cctx, req)
			}()
		default:
			if !notification {
				s.reply(req.ID, nil, &mcpError{-32601, "method not found: " + sanitize(req.Method)})
			}
		}
	}
}

// readLine reads one line of at most max bytes; a longer one is an error.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		part, err := r.ReadSlice('\n')
		out = append(out, part...)
		if len(out) > max {
			return nil, errors.New("mcp: message too large")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return out, err
	}
}

// progressWriter forwards what the CLI prints while it waits (the Ref, "awaiting ...") as
// MCP progress notifications when the caller asked for them, and keeps it for the result.
type progressWriter struct {
	s     *mcpServer
	token json.RawMessage
	mu    sync.Mutex
	buf   bytes.Buffer
	n     int
}

func (w *progressWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() < mcpMaxOutput {
		w.buf.Write(p)
	}
	if len(w.token) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(p)), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				w.n++
				w.s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"progressToken": w.token, "progress": w.n, "message": line}})
			}
		}
	}
	return len(p), nil
}
func (w *progressWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (s *mcpServer) call(ctx context.Context, req mcpRequest) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      struct {
			ProgressToken json.RawMessage `json:"progressToken"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.reply(req.ID, nil, &mcpError{-32602, "invalid tools/call parameters"})
		return
	}
	for _, t := range s.tools {
		if t.Name != p.Name {
			continue
		}
		// Each call gets the environment of a non-interactive command: no terminal, no
		// stdin, its own output buffers. Stdout of this process carries the protocol only.
		e := *s.env
		notes := &progressWriter{s: s, token: p.Meta.ProgressToken}
		e.Stdin, e.StdinIsTTY, e.StdoutIsTTY, e.Stderr = strings.NewReader(""), false, false, notes
		e.Stdout = &bytes.Buffer{}
		if len(p.Arguments) == 0 {
			p.Arguments = json.RawMessage("{}")
		}
		text, err := t.call(ctx, &e, p.Arguments)
		if err != nil {
			text = mcpFailure(err, notes.String())
		}
		s.reply(req.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": err != nil}, nil)
		return
	}
	s.reply(req.ID, nil, &mcpError{-32602, "unknown tool: " + sanitize(p.Name)})
}

// errApprovalTimeout marks a wait that this server ended itself.
var errApprovalTimeout = errors.New("approval timeout")

// mcpFailure says what went wrong and what to do about it, as `aqmas guide` does.
func mcpFailure(err error, notes string) string {
	code := ExitCode(err)
	var b strings.Builder
	var de *DecisionError
	switch {
	case errors.Is(err, errApprovalTimeout):
		code = ExitExpired
		b.WriteString("aqmas: the owner did not decide within the approval timeout; the request was withdrawn.")
	default:
		fmt.Fprintf(&b, "aqmas: %s", sanitize(err.Error()))
	}
	fmt.Fprintf(&b, "\nexit code: %d\n", code)
	switch {
	case NotAdmitted(err):
		b.WriteString("What to do: ask the owner to admit this host to an organisation (approval page, Hosts tab), then call again.")
	case errors.As(err, &de) && de.Status == "denied", code == ExitDenied:
		b.WriteString("What to do: stop. Do not rephrase and retry; tell the owner what you wanted and why.")
	case code == ExitExpired:
		b.WriteString("What to do: the owner is probably away. Ask once more only if the task is worth another notification; otherwise report it and continue with something else.")
	case code == ExitUnreachable:
		b.WriteString("What to do: the bastion or the network is down. Do not look for another way in; report it.")
	case code == ExitUsage:
		b.WriteString("What to do: fix the arguments (aqmas_guide has examples).")
	case plainNotFound(err):
		b.WriteString("What to do: check the path or target with aqmas_list_credentials / aqmas_list_targets, or ask the owner for it. A path this host may not see and a path that does not exist look the same.")
	}
	if notes = strings.TrimSpace(notes); notes != "" {
		b.WriteString("\n\n" + notes)
	}
	return b.String()
}

func mcpArgs(raw json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return &UsageError{Msg: "invalid arguments: " + err.Error()}
	}
	return nil
}

func seconds(v, def, max int) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(min(v, max)) * time.Second
}

// approval runs fn under the approval timeout. A wait this server ended reports
// errApprovalTimeout; the flows withdraw their pending request when their context ends.
func approval(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := fn(actx)
	if err != nil && errors.Is(actx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return errApprovalTimeout
	}
	return err
}

// ---- running commands ----

type capped struct {
	buf     bytes.Buffer
	dropped int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := mcpMaxOutput - c.buf.Len(); room >= len(p) {
		c.buf.Write(p)
	} else {
		c.buf.Write(p[:max(room, 0)])
		c.dropped += len(p) - max(room, 0)
	}
	return len(p), nil
}

type runResult struct {
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated,omitempty"`
	TimedOut  bool   `json:"timed_out,omitempty"`
	Note      string `json:"note,omitempty"`
}

// runCaptured runs one command to its end (or its timeout) and returns what it printed.
func runCaptured(ctx context.Context, timeout time.Duration, exe string, argv, env []string, dir string) (runResult, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, exe)
	cmd.Args, cmd.Env, cmd.Dir = argv, env, dir
	var so, se capped
	cmd.Stdout, cmd.Stderr = &so, &se
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	res := runResult{Stdout: strings.ToValidUTF8(so.buf.String(), "�"), Stderr: strings.ToValidUTF8(se.buf.String(), "�"), Truncated: so.dropped+se.dropped > 0}
	var ee *exec.ExitError
	switch {
	case errors.Is(cctx.Err(), context.DeadlineExceeded):
		res.ExitCode, res.TimedOut = -1, true
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case err != nil:
		return res, err
	}
	return res, nil
}

func resultJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return string(b), err
}

// ---- tools ----

func mcpStatus(ctx context.Context, e *Env, _ json.RawMessage) (string, error) {
	out := e.Stdout.(*bytes.Buffer)
	if err := e.Status(ctx, ""); err != nil {
		return "", err
	}
	if strings.HasPrefix(out.String(), "not enrolled") {
		out.WriteString("This host is not enrolled. The owner runs the install-and-enroll command from the approval page's Help tab on this machine; an agent cannot enroll by itself.\n")
		return out.String(), nil
	}
	cat, err := e.Catalogue(ctx)
	switch {
	case NotAdmitted(err):
		out.WriteString("\nadmission    NOT admitted to any organisation: ask the owner to admit this host (Hosts tab)\n")
		return out.String(), nil
	case err != nil:
		fmt.Fprintf(out, "\nadmission    unknown: %s\n", sanitize(err.Error()))
	case cat.Discovery:
		fmt.Fprintf(out, "\nadmission    admitted\ndiscovery    on: %d credential set(s), %d SSH target(s) listed (aqmas_list_credentials, aqmas_list_targets)\n", len(cat.Credentials), len(cat.Targets))
	default:
		out.WriteString("\nadmission    admitted\ndiscovery    off: the owner has not turned listing on; ask the owner for paths and target names\n")
	}
	out.WriteString("\nactive grants on the server:\n")
	if err := e.List(ctx, false); err != nil {
		fmt.Fprintf(out, "unavailable: %s\n", sanitize(err.Error()))
	}
	return out.String(), nil
}

func mcpList(targets bool) func(context.Context, *Env, json.RawMessage) (string, error) {
	return func(ctx context.Context, e *Env, _ json.RawMessage) (string, error) {
		cat, err := e.Catalogue(ctx)
		if err != nil {
			return "", err
		}
		if !cat.Discovery {
			return DiscoveryOff, nil
		}
		if targets {
			return resultJSON(map[string]any{"discovery": true, "targets": cat.Targets, "note": "Use a target's name and one of its users: aqmas_ssh_exec, or aqmas ssh USER@NAME --why \"...\"."})
		}
		return resultJSON(map[string]any{"discovery": true, "credentials": cat.Credentials, "note": "Names only; values are never listed. Only organisations whose owner turned listing on appear."})
	}
}

func mcpRun(ctx context.Context, e *Env, raw json.RawMessage) (string, error) {
	var a struct {
		Path, Why, Env, Cwd string
		Command             []string
		TTL                 int `json:"ttl_seconds"`
		Timeout             int `json:"timeout_seconds"`
		Approval            int `json:"approval_timeout_seconds"`
	}
	if err := mcpArgs(raw, &a); err != nil {
		return "", err
	}
	if !envset.ValidPath(a.Path) || len(a.Command) == 0 || strings.TrimSpace(a.Why) == "" {
		return "", &UsageError{Msg: "path (organisation/service/set), why and command are required"}
	}
	if a.TTL < 0 {
		return "", &UsageError{Msg: "ttl_seconds must be positive"}
	}
	var res runResult
	err := approval(ctx, seconds(a.Approval, 600, 3600), func(actx context.Context) error {
		return e.EnvDeliver(actx, EnvOptions{Path: a.Path, Mode: "process", Why: a.Why, TTL: a.TTL, Command: a.Command, EnvName: a.Env,
			// The command runs under the call's own context, not the approval deadline.
			Run: func(exe string, argv, env []string) (err error) {
				res, err = runCaptured(ctx, seconds(a.Timeout, 300, 3600), exe, argv, env, a.Cwd)
				return err
			}})
	})
	if err != nil {
		return "", err
	}
	res.Note = "Output is returned as the command printed it. If the command printed the secret, it is in this result: do not repeat it anywhere."
	return resultJSON(res)
}

func mcpSign(ctx context.Context, e *Env, raw json.RawMessage) (string, error) {
	var a struct {
		Path, Why, Digest string
		Files             []string
		Force             bool
		Approval          int `json:"approval_timeout_seconds"`
	}
	if err := mcpArgs(raw, &a); err != nil {
		return "", err
	}
	for _, f := range a.Files {
		if f == "-" {
			return "", &UsageError{Msg: "name files; this server has no stdin to sign"}
		}
	}
	err := approval(ctx, seconds(a.Approval, 600, 3600), func(actx context.Context) error {
		return e.Sign(actx, SignOptions{Path: a.Path, Why: a.Why, Digest: a.Digest, Files: a.Files, Force: a.Force})
	})
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(e.Stdout.(*bytes.Buffer).String())
	notes := strings.TrimSpace(e.Stderr.(*progressWriter).String())
	if a.Digest != "" {
		return resultJSON(map[string]any{"signature_hex": out, "notes": notes})
	}
	sigs := make([]string, len(a.Files))
	for i, f := range a.Files {
		sigs[i] = f + ".sig"
	}
	return resultJSON(map[string]any{"signatures": sigs, "notes": notes})
}

func mcpSSH(ctx context.Context, e *Env, raw json.RawMessage) (string, error) {
	var a struct {
		Target, Why, Command string
		TTL                  int `json:"ttl_seconds"`
		Timeout              int `json:"timeout_seconds"`
		Approval             int `json:"approval_timeout_seconds"`
	}
	if err := mcpArgs(raw, &a); err != nil {
		return "", err
	}
	if strings.TrimSpace(a.Command) == "" || strings.TrimSpace(a.Why) == "" {
		return "", &UsageError{Msg: "target, why and command are required"}
	}
	t, err := ParseTarget(a.Target, e.User)
	if err != nil {
		return "", err
	}
	var p *Prepared
	err = approval(ctx, seconds(a.Approval, 600, 3600), func(actx context.Context) (err error) {
		p, err = e.EnsureSSHCert(actx, SSHOptions{Target: t, TTL: time.Duration(max(a.TTL, 0)) * time.Second, Why: a.Why})
		return err
	})
	if err != nil {
		if NotATarget(err) {
			return "", fmt.Errorf("%w (not an SSH target this host may use; the bastion itself is reached with the CLI: aqmas ssh BASTION --why ... -- INSPECT-COMMAND)", err)
		}
		return "", err
	}
	argv, err := BuildSSHArgv(p, []string{a.Command})
	if err != nil {
		return "", err
	}
	// Never a prompt: there is nobody at this server's terminal.
	argv = append([]string{argv[0], "-o", "BatchMode=yes"}, argv[1:]...)
	exe, err := exec.LookPath(argv[0])
	if err != nil {
		return "", err
	}
	res, err := runCaptured(ctx, seconds(a.Timeout, 300, 3600), exe, argv, os.Environ(), "")
	if err != nil {
		return "", err
	}
	if res.ExitCode == 255 {
		res.Note = "Exit code 255 is ssh's own: the connection or login failed (see stderr)."
	}
	return resultJSON(res)
}
