// Command aqmas is the agent-quartermaster CLI: it enrolls a fleet host with aqmasd and asks
// the owner for short-lived SSH certificates (docs/API.md section 3) and Cloudflare API grants
// (section 5.6).
package main

import (
	"context"
	"encoding/json"
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

Agents: run "aqmas guide" first (how approvals work, every command with examples, what to
do on each error). "aqmas ls" and "aqmas targets" list what this host may ask for.

Usage:
  aqmas guide [--json]        the agent guide for this version (--json: command summary)
  aqmas ls|catalogue [--json] credential sets this host may ask for (names, never values)
  aqmas targets [--json]      SSH targets this host may use
      Both list only organisations whose owner turned listing on, and say so otherwise.
  aqmas mcp                   MCP server on stdin/stdout: claude mcp add aqmas -- aqmas mcp
  aqmas enroll [--name HOST] --server URL [--ca-pin sha256:HEX] [--force] [--owner-device]
      Enroll this host once: creates a client key, waits for the owner to approve.
      --name defaults to this machine's hostname (up to the first dot, lowercased).
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
  aqmas ssh BASTION --why "..." [--level inspect|root] [--ttl 30m] [-- INSPECT-COMMAND]
      The bastion itself (aqmas bastion shows its name). Level inspect (default) runs one
      read-only command: logs <unit> [since=2h] [lines=200] | status [<unit>] | failed |
      disk | version | help. Level root asks for the owner's admin account: a red card
      every time, at most one hour, only from hosts the owner allowed, and the
      certificate is used for this one ssh and never cached. --why is always required.
  aqmas bastion               what this host may ask for on the bastion
  aqmas bastion task NAME --why "..." [--keep-days N]
      Queue routine maintenance for the owner's tap and wait for the result. NAME:
      os-update | reboot | restart-cloudflared | restart-broker | disk-usage |
      journal-vacuum (--keep-days, default 14, at least 7). Kernel and boot-chain
      updates are the owner's to start on the approval page. Exit 1 if the task failed.
  aqmas status [REQUEST-ID]   enrollment + cached certificates, or one request
  aqmas list [--json]         this host's active grants on the server
  aqmas ssh-config [USER@]HOST...  print an opt-in ~/.ssh/config snippet (read its notes)
  aqmas cf scopes|request|api|env|curl|token|snapshot ...
      Cloudflare API access through aqmasd (aqmas cf help).
  aqmas set import PATH --from FILE --why REASON [--create [--title TITLE]]
  aqmas set put PATH KEY --why REASON [--create [--title TITLE]]
  aqmas set unset PATH KEY --why REASON
      Ask the owner to store values in an env set: import replaces the whole set from a
      dotenv FILE, put sets one key (value from a hidden prompt, or stdin when it is not
      a terminal), unset removes one. Prints the Ref, the commitment and the key changes
      (names only), then waits for the owner to commit or discard; Ctrl-C withdraws.
      --create also creates a missing set (and service) in an existing organisation.
      An owner device with an upload ticket from the Vault adds --ticket (hidden prompt)
      or --ticket-fd FD instead of --why: the edit is then staged for the Vault.
  aqmas set check --from FILE [PATH]
      Check FILE against the import rules, sending nothing: key names on stdout, each
      problem with its line number on stderr, never a value; exit 1 if it would not
      import. With PATH also what an import would add, replace and remove.
  aqmas run PATH --why REASON [--ttl 10m] [--env NAME] -- COMMAND...
      Run COMMAND with a secret or env set in its environment. --env renames a secret's variable.
  aqmas get PATH --why REASON [--ttl 10m]
      Print one secret's value to stdout. Prefer run: with get the value has left aqmas.
  aqmas checkout|co PATH --why REASON [--file .env]; aqmas checkin|ci PATH
  aqmas checkout-shell|cos PATH --why REASON; aqmas checkin-shell|cis PATH
  aqmas reap-checkouts        remove what a killed checkout holder left (run at login)
  aqmas sign ORG/SERVICE/KEY --why REASON [--ttl 30m [--count N]] FILE... | - | --digest sha256:HEX
      Have aqmas sign: files are hashed here, the owner approves the names, sizes
      and SHA-256 digests, the key never leaves aqmas. Writes FILE.sig (or --out,
      --format raw|hex|base64, --force); stdin and --digest print hex. --ttl asks
      for a signing grant reused by later calls; "aqmas sign PATH --end" ends it.
  aqmas signer ORG/SERVICE/KEY [--pem]   the key's scheme and public key
  aqmas ssh-agent ORG/SERVICE/KEY --why REASON [--ttl 10m] [--count N] -- COMMAND...
      Run COMMAND (git, ssh, scp, rsync -e ssh ...) with an SSH key that stays in aqmas:
      SSH_AUTH_SOCK points at a private agent socket that offers exactly that key, and
      each login is signed by aqmasd under one approved grant (default 10 minutes, 20
      logins; later calls reuse it). --socket instead of a command serves the agent and
      prints SSH_AUTH_SOCK=PATH for a script; "aqmas ssh-agent PATH --end" ends the grant.
  aqmas ssh-key ORG/SERVICE/KEY --public   the key's authorized_keys line (no approval)
  aqmas ssh-key ORG/SERVICE/KEY --why REASON [--out FILE] [--force]
      Hand the private key out as a file (0600, plus FILE.pub). Only for a key the owner
      marked "may be handed out", after a red approval card: the key has then left aqmas
      and cannot be recalled. Prefer ssh-agent.
  aqmas version | help
  aqmas upgrade | update [--check] [--yes --expect-sha256 HEX] [--allow-single-source]
      A system-wide install (e.g. /usr/local/bin/aqmas): sudo aqmas upgrade. It uses
      the enrolment of the user who ran sudo; only the replacement runs as root.

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
	helpCommand = args[0]
	if !ownHelp[args[0]] && wantsHelp(args[1:]) {
		if text, ok := commandUsage(args[0]); ok {
			fmt.Print(text)
			return 0
		}
	}
	env, err := client.DefaultEnv(term.IsTerminal(int(os.Stdin.Fd())))
	if err != nil {
		return fail(err)
	}
	env.StdoutIsTTY = term.IsTerminal(int(os.Stdout.Fd()))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := args[0], args[1:]
	if cmd != "upgrade" && cmd != "update" && cmd != "mcp" && cmd != "guide" && term.IsTerminal(int(os.Stderr.Fd())) {
		env.UpdateNotice(ctx)
	}
	switch cmd {
	case "guide":
		f, err := parseFlags(rest, map[string]bool{"json": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) > 0 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas guide [--json]"})
		}
		if f.bool["json"] {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return fail(enc.Encode(client.GuideJSON()))
		}
		fmt.Print(client.Guide())
		return 0
	case "mcp":
		if len(rest) > 0 {
			return fail(&client.UsageError{Msg: "usage: aqmas mcp (an MCP server on stdin/stdout; register with: claude mcp add aqmas -- aqmas mcp)"})
		}
		return fail(env.ServeMCP(ctx, os.Stdin, os.Stdout))
	case "ls", "catalogue", "targets":
		f, err := parseFlags(rest, map[string]bool{"json": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) > 0 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas " + cmd + " [--json]"})
		}
		if cmd == "targets" {
			return fail(env.Targets(ctx, f.bool["json"]))
		}
		return fail(env.Ls(ctx, f.bool["json"]))
	case "reap-checkouts":
		return fail(client.ReapEnv())
	case "_env-holder":
		if len(rest) != 2 {
			return 2
		}
		return fail(env.HoldEnv(ctx, rest[0], rest[1]))
	case "set":
		return runSet(ctx, env, rest)
	case "run", "get", "checkout", "co", "checkout-shell", "cos":
		f, err := parseFlags(rest, map[string]bool{"why": true, "ttl": true, "file": true, "env": true})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 1 || cmd != "run" && len(f.cmd) > 0 {
			return fail(&client.UsageError{Msg: "expected qualified set path"})
		}
		if _, given := f.str["env"]; given && (cmd != "run" || f.str["env"] == "") {
			return fail(&client.UsageError{Msg: "--env NAME renames the variable for aqmas run"})
		}
		mode := "process"
		if cmd == "get" {
			mode = "get"
		} else if cmd == "co" || cmd == "checkout" {
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
		return fail(env.EnvDeliver(ctx, client.EnvOptions{Path: f.pos[0], Mode: mode, Why: f.str["why"], File: name, TTL: ttl, Command: f.cmd, EnvName: f.str["env"]}))
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
			if err != nil || d < time.Minute || d%time.Second != 0 || d > 24*time.Hour {
				return fail(&client.UsageError{Msg: "--ttl is a duration from 1m to 24h, such as 30m"})
			}
			o.TTL = int(d / time.Second)
		}
		if f.str["count"] != "" {
			if o.Count, err = strconv.Atoi(f.str["count"]); err != nil || o.Count < 1 || o.Count > 1000 {
				return fail(&client.UsageError{Msg: "--count is between 1 and 1000"})
			}
		}
		return fail(env.Sign(ctx, o))
	case "ssh-agent":
		f, err := parseFlags(rest, map[string]bool{"why": true, "ttl": true, "count": true, "socket": false, "end": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 1 {
			return fail(&client.UsageError{Msg: "usage: aqmas ssh-agent ORG/SERVICE/KEY --why REASON [--ttl 10m] [--count N] -- COMMAND..."})
		}
		if f.bool["end"] {
			if len(f.cmd) > 0 || f.bool["socket"] {
				return fail(&client.UsageError{Msg: "--end takes only the key path"})
			}
			return fail(env.SSHAgentEnd(ctx, f.pos[0]))
		}
		o := client.SSHAgentOptions{Path: f.pos[0], Why: f.str["why"], Command: f.cmd, Socket: f.bool["socket"]}
		if f.str["ttl"] != "" {
			d, err := time.ParseDuration(f.str["ttl"])
			if err != nil || d < time.Minute || d%time.Second != 0 || d > 24*time.Hour {
				return fail(&client.UsageError{Msg: "--ttl is a duration from 1m to 24h, such as 30m"})
			}
			o.TTL = int(d / time.Second)
		}
		if f.str["count"] != "" {
			if o.Count, err = strconv.Atoi(f.str["count"]); err != nil || o.Count < 1 || o.Count > 1000 {
				return fail(&client.UsageError{Msg: "--count is between 1 and 1000"})
			}
		}
		code, err := env.SSHAgent(ctx, o)
		if err != nil {
			return fail(err)
		}
		return code
	case "ssh-key":
		f, err := parseFlags(rest, map[string]bool{"why": true, "out": true, "force": false, "public": false})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 1 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas ssh-key ORG/SERVICE/KEY --public | --why REASON [--out FILE] [--force]"})
		}
		if f.bool["public"] {
			if f.str["out"] != "" || f.bool["force"] {
				return fail(&client.UsageError{Msg: "--public prints the authorized_keys line and takes no other flag"})
			}
			return fail(env.SSHKeyPublic(ctx, f.pos[0]))
		}
		home, _ := os.UserHomeDir()
		return fail(env.SSHKeyHandout(ctx, client.SSHKeyOptions{Path: f.pos[0], Why: f.str["why"], Out: f.str["out"], Force: f.bool["force"], Home: home}))
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
		// A system-wide install is upgraded with `sudo aqmas upgrade`: it runs as the user
		// who called sudo, with that user's enrolment, until the executable is replaced.
		inv, rootOwn, err := client.SudoInvoker(os.Getenv, os.Geteuid())
		if err != nil {
			return fail(err)
		}
		if rootOwn {
			// The user who ran sudo is not enrolled: root's own enrolment, found from root's
			// account and not from a HOME that sudo may have kept.
			env.Paths = client.RootPaths()
		}
		if inv != nil {
			env.Paths = inv.Paths()
			if env.Elevate, err = inv.Drop(); err != nil {
				return fail(err)
			}
			env.User = inv.Name
			fmt.Fprintf(os.Stderr, "aqmas: started with sudo: using the enrolment of %s in %s; only replacing the executable runs as root\n", inv.Name, inv.ConfigDir)
		}
		return fail(env.Upgrade(ctx, f.bool["check"], f.bool["yes"], f.bool["allow-single-source"], f.str["expect-sha256"], term.IsTerminal(int(os.Stderr.Fd()))))
	case "help", "-h", "--help":
		if len(rest) == 1 {
			if text, ok := commandUsage(rest[0]); ok {
				fmt.Print(text)
				return 0
			}
			return fail(&client.UsageError{Msg: fmt.Sprintf("no command %q", rest[0])})
		}
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
		if name, given := f.str["name"]; given && name == "" {
			// Without --name the hostname is used; an empty --name is a mistake, not that.
			return fail(&client.UsageError{Msg: "enroll: --name is empty (leave it out to use this machine's hostname)"})
		}
		return fail(env.Enroll(ctx, client.EnrollOptions{
			Name: f.str["name"], Server: f.str["server"], CAPin: f.str["ca-pin"],
			Note: f.str["note"], Force: f.bool["force"], OwnerDevice: f.bool["owner-device"],
		}))
	case "ssh", "cert", "mosh":
		spec := map[string]bool{"ttl": true, "why": true, "fresh": false}
		if cmd != "mosh" {
			spec["level"] = true // the bastion itself (docs/BASTION-ACCESS.md)
		}
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
		bo := client.BastionOptions{Host: target.Host, Level: f.str["level"], TTL: ttl, Why: f.str["why"], Fresh: f.bool["fresh"], Command: f.cmd}
		if strings.Contains(f.pos[0], "@") {
			bo.User = target.User
		}
		if _, given := f.str["level"]; given {
			return runBastion(ctx, stop, env, cmd, bo, f.bool["quiet"])
		}
		p, err := env.EnsureSSHCert(ctx, client.SSHOptions{Target: target, TTL: ttl, Why: f.str["why"], Fresh: f.bool["fresh"], CanonicalOnly: f.bool["canonical-only"]})
		if err != nil && cmd != "mosh" && !f.bool["canonical-only"] && client.NotATarget(err) && env.IsBastion(ctx, target.Host) {
			// Not an SSH target, but the name of the bastion itself: an inspect session.
			return runBastion(ctx, stop, env, cmd, bo, f.bool["quiet"])
		}
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
	case "bastion":
		if len(rest) == 0 {
			return fail(env.BastionShow(ctx))
		}
		if rest[0] != "task" {
			return fail(&client.UsageError{Msg: "usage: aqmas bastion | aqmas bastion task NAME --why \"...\" [--keep-days N]"})
		}
		f, err := parseFlags(rest[1:], map[string]bool{"why": true, "keep-days": true})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 1 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas bastion task NAME --why \"...\" [--keep-days N]; tasks: " + strings.Join(client.BastionTasks, ", ")})
		}
		o := client.TaskOptions{Task: f.pos[0], Why: f.str["why"]}
		if s, given := f.str["keep-days"]; given {
			if o.KeepDays, err = strconv.Atoi(s); err != nil || o.KeepDays < 1 {
				return fail(&client.UsageError{Msg: "--keep-days is a number of days"})
			}
		}
		return fail(env.BastionTask(ctx, o))
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

// runBastion handles `aqmas ssh|cert` for the bastion itself. Inspect is prepared like any
// SSH grant and ssh replaces this process; root runs ssh as a child so that its key and
// certificate can be deleted when it exits.
func runBastion(ctx context.Context, stop context.CancelFunc, env *client.Env, cmd string, o client.BastionOptions, quiet bool) int {
	if o.Level == client.LevelRoot {
		if cmd != "ssh" {
			return fail(&client.UsageError{Msg: "a root session on the bastion is never cached: use aqmas ssh"})
		}
		code, err := env.BastionRoot(ctx, o, func(argv []string) (int, error) {
			stop() // from here on signals belong to ssh
			return client.RunChild(argv)
		})
		if err != nil {
			return fail(err)
		}
		return code
	}
	if cmd == "ssh" {
		// Refuse a command the bastion would refuse before asking the owner for anything.
		if _, err := client.InspectCommand(o.Command); err != nil {
			return fail(err)
		}
	}
	p, err := env.EnsureBastionInspect(ctx, o)
	if err != nil {
		return fail(err)
	}
	if cmd == "cert" {
		if !quiet {
			fmt.Printf("key          %s\ncertificate  %s\nknown_hosts  %s\naddress      %s port %d\nvalid until  %s\n",
				p.KeyPath, p.CertPath, p.KnownHostsPath, p.Grant.TargetAddress, p.Grant.TargetPort,
				p.ValidBefore.Local().Format(time.RFC3339))
		}
		return 0
	}
	argv, err := client.BuildInspectArgv(p, o.Command)
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
		hint := ""
		if u := (*client.UsageError)(nil); errors.As(err, &u) {
			hint = usageHint()
		}
		fmt.Fprintf(os.Stderr, "aqmas: %s%s\n", client.Sanitize(err.Error()), hint)
	}
	return code
}

// setUsage is the part of the usage text about `aqmas set`.
func setUsage() string {
	var b strings.Builder
	in := false
	for _, line := range strings.SplitAfter(usage, "\n") {
		if strings.HasPrefix(line, "  aqmas ") {
			in = strings.HasPrefix(line, "  aqmas set ")
		} else if !strings.HasPrefix(line, "      ") {
			in = false
		}
		if in {
			b.WriteString(line)
		}
	}
	return "Usage:\n" + b.String()
}

// runSet is `aqmas set import|put|unset|check`. Without a ticket option an
// edit is a proposal the owner commits on the approval page; --ticket and
// --ticket-fd keep the owner-device upload against a Vault ticket.
func runSet(ctx context.Context, env *client.Env, rest []string) int {
	for i, a := range rest {
		if a == "--" {
			break
		}
		if a == "--help" || a == "-h" || a == "help" && i < 2 {
			fmt.Print(setUsage())
			return 0
		}
	}
	bad := func(msg string) int {
		return fail(&client.UsageError{Msg: msg + " (aqmas set --help)"})
	}
	if len(rest) == 0 {
		return bad("set needs import, put, unset or check, then a set path")
	}
	op := rest[0]
	if op != "import" && op != "put" && op != "unset" && op != "check" {
		return bad(fmt.Sprintf("set needs import, put, unset or check, not %q", op))
	}
	f, err := parseFlags(rest[1:], map[string]bool{"from": true, "why": true, "create": false, "title": true, "ticket": false, "ticket-fd": true})
	if err != nil {
		return fail(err)
	}
	if f.cmd != nil {
		return bad("set " + op + " takes no -- COMMAND")
	}
	_, hasFrom := f.str["from"]
	_, hasWhy := f.str["why"]
	_, hasFD := f.str["ticket-fd"]
	_, hasTitle := f.str["title"]
	ticket := f.bool["ticket"] || hasFD
	if op == "check" {
		switch {
		case f.str["from"] == "":
			return bad("set check needs --from FILE")
		case len(f.pos) > 1:
			return bad("set check takes at most one PATH after --from FILE")
		case hasWhy || ticket || f.bool["create"] || hasTitle:
			return bad("set check takes only --from FILE and an optional PATH: it sends nothing")
		}
		path := ""
		if len(f.pos) == 1 {
			path = f.pos[0]
		}
		return fail(env.SetCheck(ctx, f.str["from"], path))
	}
	key := ""
	if op == "import" {
		switch {
		case len(f.pos) == 0:
			return bad("set import needs PATH (organisation/service/set)")
		case len(f.pos) > 1:
			return bad("set import takes one PATH; the file goes in --from FILE")
		case f.str["from"] == "":
			return bad("set import needs --from FILE")
		}
	} else {
		switch {
		case len(f.pos) < 2:
			return bad("set " + op + " needs PATH (organisation/service/set) and KEY")
		case len(f.pos) > 2:
			return bad("set " + op + " takes PATH and one KEY")
		case hasFrom && op == "put":
			return bad("set put reads its value from a hidden prompt or stdin, not --from (set import takes a file)")
		case hasFrom:
			return bad("set unset takes no --from")
		}
		key = f.pos[1]
	}
	if hasTitle && !f.bool["create"] {
		return bad("--title names the set that --create makes: add --create")
	}
	if f.bool["create"] && op == "unset" {
		return bad("--create goes with set import or set put")
	}
	if ticket {
		switch {
		case f.bool["ticket"] && hasFD:
			return bad("give --ticket (hidden prompt) or --ticket-fd FD, not both")
		case f.bool["create"]:
			return bad("--create proposes a new set to the owner: leave out the ticket option and give --why")
		case hasWhy:
			return bad("--why goes with a proposal; with a ticket the edit is reviewed in the Vault: leave one out")
		}
		fd := -1
		if hasFD {
			if fd, err = strconv.Atoi(f.str["ticket-fd"]); err != nil || fd < 3 {
				return bad("--ticket-fd needs a descriptor number of at least 3")
			}
		}
		return fail(env.SetEdit(ctx, op, f.pos[0], key, f.str["from"], fd))
	}
	if strings.TrimSpace(f.str["why"]) == "" {
		return bad("set " + op + " needs --why \"...\": what the values are for, shown to the owner (an owner device with a Vault upload ticket gives --ticket instead)")
	}
	_, err = env.SetPropose(ctx, client.SetOptions{Op: op, Path: f.pos[0], Key: key, From: f.str["from"], Why: f.str["why"], Create: f.bool["create"], Title: f.str["title"]})
	return fail(err)
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
