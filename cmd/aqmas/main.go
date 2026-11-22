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
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/aquarat/agent-quartermaster/internal/client"
)

const usage = `aqmas: request short-lived, owner-approved access through agent-quartermaster

Usage:
  aqmas enroll --name HOST --server URL [--ca-pin sha256:HEX] [--force] [--owner-device]
      Enroll this host once: creates a client key, waits for the owner to approve.
      --server (the bastion's agent API, https://HOST:8443) is required the first time.
      Without --ca-pin, the server CA is trusted only after you confirm its
      fingerprint at a terminal.
  aqmas ssh [USER@]HOST [--ttl 30m] [--why "..."] [--fresh] [-- COMMAND...]
      Log in with a short-lived certificate (cached and reused while >= 2 min valid).
      --why is required when stdin is not a terminal.
  aqmas mosh [USER@]HOST[:PORT] [--ttl 30m] [--why "..."] [-- MOSH-OPTIONS...]
      Open mosh with the same certificate and host-key policy as ssh.
  aqmas cert [USER@]HOST [--ttl 30m] [--why "..."] [--fresh] [--quiet]
      Like ssh, but only make sure a certificate is cached and print its paths.
  aqmas status [REQUEST-ID]   enrollment + cached certificates, or one request
  aqmas list [--json]         this host's active grants on the server
  aqmas ssh-config [USER@]HOST...  print an opt-in ~/.ssh/config snippet (read its notes)
  aqmas cf scopes|request|api|env|curl|token|snapshot ...
      Cloudflare API access through aqmasd (aqmas cf help).
  aqmas set import PATH --from FILE | set put PATH KEY | set unset PATH KEY
      Enter the Admin upload ticket at the hidden prompt or via --ticket-fd FD.
  aqmas run PATH --why REASON [--ttl 10m] -- COMMAND...
  aqmas checkout|co PATH --why REASON [--file .env]; aqmas checkin|ci PATH
  aqmas checkout-shell|cos PATH --why REASON; aqmas checkin-shell|cis PATH
  aqmas sign ORG/SERVICE/KEY --why REASON [--ttl 30m [--count N]] FILE... | - | --digest sha256:HEX
      Have aqmas sign: files are hashed here, the owner approves the names, sizes
      and SHA-256 digests, the key never leaves aqmas. Writes FILE.sig (or --out,
      --format raw|hex|base64, --force); stdin and --digest print hex. --ttl asks
      for a signing grant reused by later calls; "aqmas sign PATH --end" ends it.
  aqmas signer ORG/SERVICE/KEY [--pem]   the key's scheme and public key
  aqmas version | help
  aqmas upgrade | update [--check] [--yes --expect-sha256 HEX] [--allow-single-source]

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
	if cmd != "upgrade" && cmd != "update" && term.IsTerminal(int(os.Stderr.Fd())) {
		env.UpdateNotice(ctx)
	}
	switch cmd {
	case "reap-checkouts":
		return fail(client.ReapEnv())
	case "_env-holder":
		if len(rest) != 2 {
			return 2
		}
		return fail(env.HoldEnv(ctx, rest[0], rest[1]))
	case "set":
		if len(rest) < 2 {
			return fail(&client.UsageError{Msg: "set requires import, put or unset and a qualified set path"})
		}
		op := rest[0]
		f, err := parseFlags(rest[1:], map[string]bool{"from": true, "ticket-fd": true})
		if err != nil {
			return fail(err)
		}
		if f.cmd != nil || !(op == "import" && len(f.pos) == 1 && f.str["from"] != "" || (op == "put" || op == "unset") && len(f.pos) == 2 && f.str["from"] == "") {
			return fail(&client.UsageError{Msg: "invalid set edit arguments"})
		}
		fd := -1
		if f.str["ticket-fd"] != "" {
			fd, err = strconv.Atoi(f.str["ticket-fd"])
			if err != nil || fd < 3 {
				return fail(&client.UsageError{Msg: "ticket fd must be at least 3"})
			}
		}
		key := ""
		if len(f.pos) == 2 {
			key = f.pos[1]
		}
		return fail(env.SetEdit(ctx, op, f.pos[0], key, f.str["from"], fd))
	case "run", "checkout", "co", "checkout-shell", "cos":
		f, err := parseFlags(rest, map[string]bool{"why": true, "ttl": true, "file": true})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 1 || cmd != "run" && len(f.cmd) > 0 {
			return fail(&client.UsageError{Msg: "expected qualified set path"})
		}
		mode := "process"
		if cmd == "co" || cmd == "checkout" {
			mode = "file"
			if err := client.ReapEnv(); err != nil {
				return fail(err)
			}
		} else if cmd != "run" {
			mode = "shell"
		}
		name := f.str["file"]
		if name == "" {
			name = ".env"
		} else if mode != "file" {
			return fail(&client.UsageError{Msg: "--file requires checkout"})
		}
		ttl := 0
		if f.str["ttl"] == "indefinite" {
			ttl = -1
		} else if f.str["ttl"] != "" {
			d, err := time.ParseDuration(f.str["ttl"])
			if err != nil || d <= 0 || d%time.Second != 0 {
				return fail(&client.UsageError{Msg: "invalid TTL"})
			}
			ttl = int(d / time.Second)
		}
		return fail(env.EnvUse(ctx, f.pos[0], mode, f.str["why"], name, ttl, f.cmd))
	case "signer":
		f, err := parseFlags(rest, map[string]bool{"pem": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 1 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "expected org/service/key"})
		}
		return fail(env.SignerInfo(ctx, f.pos[0], f.bool["pem"]))
	case "sign":
		f, err := parseFlags(rest, map[string]bool{"why": true, "ttl": true, "count": true, "out": true, "format": true, "digest": true, "force": false, "end": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) < 1 {
			return fail(&client.UsageError{Msg: "expected org/service/key, then the files to sign"})
		}
		o := client.SignOptions{Path: f.pos[0], Why: f.str["why"], Out: f.str["out"], Format: f.str["format"], Digest: f.str["digest"], Force: f.bool["force"], Files: append(f.pos[1:], f.cmd...)}
		if f.bool["end"] {
			if len(o.Files) > 0 || o.Digest != "" {
				return fail(&client.UsageError{Msg: "--end takes only the key path"})
			}
			return fail(env.SignEnd(ctx, o.Path))
		}
		if f.str["ttl"] != "" {
			d, err := time.ParseDuration(f.str["ttl"])
			if err != nil || d < time.Second || d%time.Second != 0 || d > 24*time.Hour {
				return fail(&client.UsageError{Msg: "--ttl is a duration up to 24h, such as 30m"})
			}
			o.TTL = int(d / time.Second)
		}
		if f.str["count"] != "" {
			if o.Count, err = strconv.Atoi(f.str["count"]); err != nil || o.Count < 1 || o.Count > 1000 {
				return fail(&client.UsageError{Msg: "--count is between 1 and 1000"})
			}
		}
		return fail(env.Sign(ctx, o))
	case "ci", "checkin", "cis", "checkin-shell":
		if len(rest) != 1 {
			return fail(&client.UsageError{Msg: "expected qualified set path"})
		}
		mode := "file"
		if cmd == "cis" || cmd == "checkin-shell" {
			mode = "shell"
		}
		return fail(env.EnvCheckin(ctx, rest[0], mode))
	case "upgrade", "update":
		f, err := parseFlags(rest, map[string]bool{"check": false, "yes": false, "expect-sha256": true, "allow-single-source": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) > 0 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "upgrade takes flags only"})
		}
		return fail(env.Upgrade(ctx, f.bool["check"], f.bool["yes"], f.bool["allow-single-source"], f.str["expect-sha256"], term.IsTerminal(int(os.Stderr.Fd()))))
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
		return 0
	case "version", "--version":
		fmt.Printf("aqmas %s (%s %s/%s)\n", client.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "enroll":
		f, err := parseFlags(rest, map[string]bool{"name": true, "server": true, "ca-pin": true, "note": true, "force": false, "owner-device": false})
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
			Note: f.str["note"], Force: f.bool["force"], OwnerDevice: f.bool["owner-device"],
		}))
	case "ssh", "cert", "mosh":
		spec := map[string]bool{"ttl": true, "why": true, "fresh": false}
		if cmd == "cert" {
			spec["quiet"] = false
			spec["canonical-only"] = false // ssh-config reads a fixed cache path
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
		if cmd == "mosh" {
			if err := client.CheckMoshArgs(f.cmd); err != nil {
				return fail(err)
			}
		}
		p, err := env.EnsureSSHCert(ctx, client.SSHOptions{Target: target, TTL: ttl, Why: f.str["why"], Fresh: f.bool["fresh"], CanonicalOnly: f.bool["canonical-only"]})
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
		build := client.BuildSSHArgv
		if cmd == "mosh" {
			build = client.BuildMoshArgv
		}
		argv, err := build(p, f.cmd)
		if err != nil {
			return fail(err)
		}
		sshPath, err := exec.LookPath(argv[0])
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
		s, err := env.SSHConfigSnippet(ctx, rest, self)
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
