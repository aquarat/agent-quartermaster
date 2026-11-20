package client

import (
	"os"
	"os/user"
	"strings"
	"unicode/utf8"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// Requester tools (self-reported, untrusted, display only).
const (
	ToolClaudeCode = "claude-code"
	ToolOpenCode   = "opencode"
	ToolOwnerCLI   = "owner-cli"
	ToolOther      = "other"
)

// DetectTool guesses which agent (if any) runs us, from the environment.
func DetectTool(getenv func(string) string, environ []string, stdinIsTTY bool) string {
	if getenv("CLAUDECODE") == "1" {
		return ToolClaudeCode
	}
	for _, kv := range environ {
		if strings.HasPrefix(kv, "OPENCODE") {
			return ToolOpenCode
		}
	}
	if stdinIsTTY {
		return ToolOwnerCLI
	}
	return ToolOther
}

// Requester builds the self-reported requester context.
func (e *Env) Requester() api.Requester {
	var environ []string
	if e.Environ != nil {
		environ = e.Environ()
	}
	r := api.Requester{
		Tool: DetectTool(e.Getenv, environ, e.StdinIsTTY),
		PID:  e.PID,
		User: e.User,
	}
	// Claude Code exports CLAUDE_CODE_SESSION_ID; CLAUDE_SESSION_ID is what API.md names.
	for _, k := range []string{"CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID", "AQMAS_SESSION_ID"} {
		if v := e.Getenv(k); v != "" {
			r.SessionID = truncateBytes(v, api.MaxSessionIDBytes)
			break
		}
	}
	if e.Getwd != nil {
		if wd, err := e.Getwd(); err == nil {
			r.CWD = truncateBytes(wd, api.MaxCWDBytes)
		}
	}
	return r
}

// truncate caps s at n runes.
// truncateBytes cuts s to at most n bytes without splitting a UTF-8 sequence (the server's
// limits are in bytes).
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return "unknown"
}
