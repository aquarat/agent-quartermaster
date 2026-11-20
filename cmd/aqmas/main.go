// Command aqmas is the agent-quartermaster CLI: it enrolls a fleet host with aqmasd and asks
// the owner for short-lived SSH certificates (docs/API.md section 3) and Cloudflare API grants
// (section 5.6).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/aquarat/agent-quartermaster/internal/client"
)

const usage = `aqmas: request short-lived, owner-approved access through agent-quartermaster

Usage:
  aqmas enroll --name HOST [--server URL] [--ca-pin sha256:HEX] [--force]
      Enroll this host once: creates a client key, waits for the owner to approve.
      Without --ca-pin, the server CA is trusted only after you confirm its
      fingerprint at a terminal.
  aqmas ssh [USER@]HOST [--ttl 30m] [--why "..."] [--fresh] [-- COMMAND...]
      Log in with a short-lived certificate (cached and reused while >= 2 min valid).
      --why is required when stdin is not a terminal.
  aqmas cert [USER@]HOST [--ttl 30m] [--why "..."] [--fresh] [--quiet]
      Like ssh, but only make sure a certificate is cached and print its paths.
  aqmas status [REQUEST-ID]   enrollment + cached certificates, or one request
  aqmas list [--json]         this host's active grants on the server
  aqmas ssh-config [USER@]HOST...  print an opt-in ~/.ssh/config snippet (read its notes)
  aqmas cf scopes|request|api|env|curl|token|snapshot ...
      Cloudflare API access through aqmasd (aqmas cf help).
  aqmas version | help

Exit codes: 0 ok (or ssh's own), 1 error, 2 usage, 3 denied, 4 expired,
5 server unreachable / TLS failure, 130 cancelled.
Config: ~/.config/aqmas/config.toml; cache: $XDG_RUNTIME_DIR/aqmas (or ~/.cache/aqmas).
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return client.ExitUsage
	}
	env, err := client.DefaultEnv(term.IsTerminal(int(os.Stdin.Fd())))
	if err != nil {
		return fail(err)
	}
	env.StdoutIsTTY = term.IsTerminal(int(os.Stdout.Fd()))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
		return 0
	case "version", "--version":
		fmt.Printf("aqmas %s (%s %s/%s)\n", client.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "enroll":
		f, err := parseFlags(rest, map[string]bool{"name": true, "server": true, "ca-pin": true, "note": true, "force": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) > 0 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "enroll takes no positional arguments"})
		}
		if f.str["name"] == "" {
			return fail(&client.UsageError{Msg: "enroll needs --name HOST (the name aqmasd will know this host by)"})
		}
		return fail(env.Enroll(ctx, client.EnrollOptions{
			Name: f.str["name"], Server: f.str["server"], CAPin: f.str["ca-pin"],
			Note: f.str["note"], Force: f.bool["force"],
		}))
	case "ssh", "cert":
		spec := map[string]bool{"ttl": true, "why": true, "fresh": false}
		if cmd == "cert" {
			spec["quiet"] = false
		}
		f, err := parseFlags(rest, spec)
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 1 {
			return fail(&client.UsageError{Msg: fmt.Sprintf("usage: aqmas %s [USER@]HOST [flags] [-- COMMAND...] (put the remote command after --)", cmd)})
		}
		if cmd == "cert" && f.cmd != nil {
			return fail(&client.UsageError{Msg: "cert takes no command"})
		}
		target, err := client.ParseTarget(f.pos[0], env.User)
		if err != nil {
			return fail(err)
		}
		var ttl time.Duration
		if s := f.str["ttl"]; s != "" {
			if ttl, err = time.ParseDuration(s); err != nil {
				return fail(&client.UsageError{Msg: "--ttl: " + err.Error()})
			}
		}
		p, err := env.EnsureSSHCert(ctx, client.SSHOptions{Target: target, TTL: ttl, Why: f.str["why"], Fresh: f.bool["fresh"]})
		if err != nil {
			return fail(err)
		}
		if cmd == "cert" {
			if !f.bool["quiet"] {
				fmt.Printf("key          %s\ncertificate  %s\nknown_hosts  %s\naddress      %s port %d\nvalid until  %s\n",
					p.KeyPath, p.CertPath, p.KnownHostsPath, p.Grant.TargetAddress, p.Grant.TargetPort,
					p.ValidBefore.Local().Format(time.RFC3339))
			}
			return 0
		}
		argv, err := client.BuildSSHArgv(p, f.cmd)
		if err != nil {
			return fail(err)
		}
		sshPath, err := exec.LookPath("ssh")
		if err != nil {
			return fail(err)
		}
		stop()
		err = syscall.Exec(sshPath, argv, os.Environ())
		return fail(fmt.Errorf("exec %s: %w", sshPath, err))
	case "status":
		if len(rest) > 1 {
			return fail(&client.UsageError{Msg: "usage: aqmas status [REQUEST-ID]"})
		}
		id := ""
		if len(rest) == 1 {
			id = rest[0]
		}
		return fail(env.Status(ctx, id))
	case "list":
		f, err := parseFlags(rest, map[string]bool{"json": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) > 0 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas list [--json]"})
		}
		return fail(env.List(ctx, f.bool["json"]))
	case "cf":
		return runCF(ctx, env, rest)
	case "ssh-config":
		self, err := os.Executable()
		if err != nil {
			self = "aqmas"
		} else if abs, err := filepath.EvalSymlinks(self); err == nil {
			self = abs
		}
		s, err := env.SSHConfigSnippet(rest, self)
		if err != nil {
			return fail(err)
		}
		fmt.Print(s)
		return 0
	default:
		return fail(&client.UsageError{Msg: fmt.Sprintf("unknown command %q (try aqmas help)", cmd)})
	}
}

func fail(err error) int {
	if err == nil {
		return 0
	}
	code := client.ExitCode(err)
	switch {
	case errors.Is(err, client.ErrCancelled), errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "aqmas: cancelled")
	default:
		fmt.Fprintf(os.Stderr, "aqmas: %s\n", client.Sanitize(err.Error()))
	}
	return code
}

type flags struct {
	str  map[string]string
	bool map[string]bool
	pos  []string
	cmd  []string // after "--"; nil if no "--"
}

// parseFlags accepts --name VALUE, --name=VALUE and boolean --flag anywhere before "--";
// spec maps flag name to whether it takes a value.
func parseFlags(args []string, spec map[string]bool) (*flags, error) {
	f := &flags{str: map[string]string{}, bool: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			f.cmd = append([]string{}, args[i+1:]...)
			return f, nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			f.pos = append(f.pos, a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		takes, ok := spec[name]
		if !ok {
			return nil, &client.UsageError{Msg: fmt.Sprintf("unknown flag %q", a)}
		}
		if !takes {
			if hasVal {
				return nil, &client.UsageError{Msg: fmt.Sprintf("flag --%s takes no value", name)}
			}
			f.bool[name] = true
			continue
		}
		if !hasVal {
			if i+1 >= len(args) || args[i+1] == "--" {
				return nil, &client.UsageError{Msg: fmt.Sprintf("flag --%s needs a value", name)}
			}
			i++
			val = args[i]
		}
		f.str[name] = val
	}
	return f, nil
}
