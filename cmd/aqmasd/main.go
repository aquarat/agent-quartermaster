// Command aqmasd is the agent-quartermaster credential broker server.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/inspect"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/webui"
	"golang.org/x/crypto/ssh"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: aqmasd [-config PATH] <command>

commands:
  seal-import           seal an unsealed store into per-credential buckets (started by the runner)
  bucket-migrate        move a format-1 sealed store to per-credential buckets (started by the runner)
  seal-drill BACKUP.db RECIPIENT   offline: open every scope key, bucket and record of a
                        standalone backup with the age identity on stdin; prints only counts
  seal-recover DIRECTORY    isolated recovery: the age identity on stdin opens every scope key,
                        then a private socket and ticket in DIRECTORY (which must not exist)
                        register a replacement passkey
  serve                 run the agent API and the approval web UI
  organisations-plan BACKUP   preview the personal cutover from a standalone SQLite online backup
  organisations-cutover       fence fleet access, create a recovery point and serve owner review
  passkey-enroll-code   print a one-time code (15 min, single use) to register the first passkey
  print-ssh-ca          print the SSH user CA public key (for TrustedUserCAKeys)
  print-client-ca       print the internal CA certificate (PEM; signs the agent-API server cert too)
  tls-fingerprint       print the CA pin for ` + "`aqmas enroll --ca-pin`" + ` (sha256:<hex>)
  revoke-host NAME      revoke an enrolled host's identity (client certificate) at once
  setup-facts           print the schema version and public passkey records (JSON) for the runner
  version               print the version

as root (docs/SETUP.md):
  maint-init [--repin] [--repo URL --forgejo-api URL --github-api URL]
                        install the maintenance runner: units, spool, keys and passkey pins;
                        optionally pin the release sources self-update may use
  maint-run             run one owner-approved maintenance request (started by aqmas-maint.path)

as the bastion's inspect account (docs/BASTION-ACCESS.md; sshd's forced command, never a shell):
  inspect               run the read-only command in $SSH_ORIGINAL_COMMAND (logs, status,
                        failed, disk, version, help); reads no configuration

Run every command as the aqmas user (sudo -u aqmas aqmasd ...).
`

func main() {
	syscall.Umask(0o077)
	if len(os.Args) > 1 && os.Args[1] == "inspect" {
		os.Exit(inspectCommand(os.Args[2:], os.Getenv("SSH_ORIGINAL_COMMAND"), os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && (os.Args[1] == "maint-run" || os.Args[1] == "maint-init") {
		if err := maintenance(os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "aqmasd:", err)
			os.Exit(1)
		}
		return
	}
	fs := flag.NewFlagSet("aqmasd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	protected := fs.Bool("require-root-config", false, "require a root-owned config and protected ancestor directories")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *protected {
		if err := rootPin(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "aqmasd:", err)
			os.Exit(1)
		}
	}
	needsArg := fs.Arg(0) == "revoke-host" || fs.Arg(0) == "organisations-plan" || fs.Arg(0) == "seal-recover"
	offline := fs.Arg(0) == "seal-drill"
	if !(offline && fs.NArg() == 3) && (fs.NArg() < 1 || needsArg != (fs.NArg() == 2) || fs.NArg() > 2 || offline) {
		fs.Usage()
		os.Exit(2)
	}
	if err := run(fs.Arg(0), *cfgPath, os.Stdout, fs.Args()[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, "aqmasd:", err)
		os.Exit(1)
	}
}

func run(cmd, cfgPath string, out io.Writer, args ...string) error {
	if cmd == "seal-drill" {
		if len(args) != 2 {
			return fmt.Errorf("a standalone backup and the recovery recipient required")
		}
		if err := restrictDumps(); err != nil {
			return err
		}
		id, err := readIdentity()
		defer clear(id)
		if err != nil {
			return err
		}
		// The configuration names the Cloudflare issuer and account its record is bound
		// to; offline without it that one record is reported unchecked.
		var cf *config.Cloudflare
		if cfg, err := config.Load(cfgPath); err == nil {
			cf = &cfg.Cloudflare
		}
		res, err := server.DrillBackup(args[0], args[1], id, cf)
		if err == nil {
			_, err = fmt.Fprintln(out, res)
		}
		return err
	}
	if cmd == "version" {
		ui := "embedded"
		if webui.IsFallback() {
			ui = "placeholder"
		}
		fmt.Fprintf(out, "aqmasd %s (web ui: %s)\n", version, ui)
		return nil
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := checkUser(cfg.DataDir); err != nil {
		return err
	}
	switch cmd {
	case "setup-facts":
		f, err := server.SetupFacts(cfg.DataDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(f)
	case "seal-recover":
		if len(args) != 1 || !cfg.Seal.Required {
			return fmt.Errorf("sealed recovery directory required")
		}
		if err = restrictDumps(); err != nil {
			return err
		}
		id, err := readIdentity()
		defer clear(id)
		if err != nil {
			return err
		}
		s, err := server.New(server.Options{Config: cfg, ConfigPath: cfgPath, Recovery: true})
		if err != nil {
			return err
		}
		defer s.Close()
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return s.Recover(ctx, args[0], bytes.NewReader(id))
	case "organisations-plan":
		if len(args) != 1 {
			return fmt.Errorf("organisations-plan requires a standalone SQLite backup")
		}
		sshPin, tlsPin, err := inventoryPins(server.CADir(cfg.DataDir))
		if err != nil {
			return err
		}
		plan, err := organisations.InspectBackup(context.Background(), args[0], cfg, sshPin, tlsPin, time.Now())
		if err != nil {
			return err
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	case "serve", "organisations-cutover", "seal-import", "bucket-migrate":
		if err := restrictDumps(); err != nil {
			return fmt.Errorf("disable process dumps: %w", err)
		}
		log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		srv, err := server.New(server.Options{Config: cfg, ConfigPath: cfgPath, Logger: log, Maintenance: cmd == "organisations-cutover", SealSetup: cmd == "seal-import", BucketMigrate: cmd == "bucket-migrate"})
		if err != nil {
			return err
		}
		defer srv.Close()
		if webui.IsFallback() {
			log.Warn("web UI not embedded; serving placeholder page")
		}
		log.Info("aqmasd starting", "version", version, "ssh_ca", srv.PKI().SSHCAPublicLine())
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return srv.Run(ctx)
	case "passkey-enroll-code":
		if _, err := os.Stat(server.DBPath(cfg.DataDir)); err != nil {
			return fmt.Errorf("no database at %s: start `aqmasd serve` once first", server.DBPath(cfg.DataDir))
		}
		code, err := server.NewEnrollCode(cfg.DataDir, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n\nOne-time passkey enroll code, valid 15 minutes, single use.\nOpen %s and register a passkey with it.\n", code, cfg.PublicBaseURL)
		return nil
	case "print-ssh-ca":
		p, err := pki.LoadPublic(server.CADir(cfg.DataDir))
		if err != nil {
			return err
		}
		fmt.Fprintln(out, p.SSHCAPublicLine())
		return nil
	case "revoke-host":
		if err := server.RevokeHost(cfg.DataDir, args[0], time.Now()); err != nil {
			return err
		}
		fmt.Fprintf(out, "revoked %s (restarting aqmasd is not needed)\n", args[0])
		return nil
	case "tls-fingerprint":
		p, err := pki.LoadPublic(server.CADir(cfg.DataDir))
		if err != nil {
			return err
		}
		fmt.Fprintln(out, p.CAPin())
		return nil
	case "print-client-ca":
		p, err := pki.LoadPublic(server.CADir(cfg.DataDir))
		if err != nil {
			return err
		}
		fmt.Fprint(out, string(p.CAPEM))
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// maintenance is the root side of Admin → Setup. It takes no path or command from its
// arguments: production always uses the fixed layout and the root-protected configuration.
// "--test-layout DIR HOOK" relocates everything for the interop suite and is refused for root.
func maintenance(cmd string, args []string) error {
	layout := maint.Production()
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	test := fs.Bool("test-layout", false, "DIR HOOK follow: relocate everything (never as root)")
	repin := fs.Bool("repin", false, "replace the maintenance pins with the passkeys registered now")
	var src maint.Sources
	fs.StringVar(&src.Repo, "repo", "", "pin the release repository (ssh://…)")
	fs.StringVar(&src.ForgejoAPI, "forgejo-api", "", "pin the Forgejo release API")
	fs.StringVar(&src.GitHubAPI, "github-api", "", "pin the GitHub release API")
	usage := fmt.Errorf("usage: aqmasd maint-run | aqmasd maint-init [--repin] [--repo URL --forgejo-api URL --github-api URL]")
	if err := fs.Parse(args); err != nil {
		return usage
	}
	var sources *maint.Sources
	if src != (maint.Sources{}) {
		if src.Repo == "" || src.ForgejoAPI == "" || src.GitHubAPI == "" {
			return usage
		}
		sources = &src
	}
	switch {
	case *test && fs.NArg() == 2:
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if layout, err = maint.TestLayout(fs.Arg(0), exe, fs.Arg(1)); err != nil {
			return err
		}
	case *test || fs.NArg() != 0 || cmd == "maint-run" && (*repin || sources != nil):
		return usage
	}
	if os.Geteuid() == 0 {
		if err := rootPin(layout.Config); err != nil {
			if cmd == "maint-run" {
				time.Sleep(20 * time.Second)
			}
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cmd == "maint-init" {
		return maint.Init(ctx, layout, *repin, sources, os.Stdout)
	}
	r, err := maint.New(layout, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err != nil {
		// Whatever started the runner is still there and will start it again: go slowly.
		if os.Geteuid() == 0 {
			time.Sleep(20 * time.Second)
		}
		return err
	}
	// A refused request or a failed task is reported on the Setup page; for systemd the
	// run succeeded. Only an unfinished recovery exits non-zero (and is started again).
	var reported *maint.Handled
	if err = r.Run(ctx); errors.As(err, &reported) {
		fmt.Fprintln(os.Stderr, "aqmasd:", err)
		return nil
	}
	return err
}

// readIdentity reads the age identity from a redirected stdin (never a terminal).
func readIdentity() ([]byte, error) {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice != 0 {
		return nil, fmt.Errorf("redirect the age identity on stdin")
	}
	id, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(id) > 4096 {
		clear(id)
		return nil, fmt.Errorf("invalid identity input")
	}
	return id, nil
}

// Only public CA material is needed on the machine inspecting the backup.
func inventoryPins(dir string) (string, string, error) {
	p, err := pki.LoadPublic(dir)
	if err != nil {
		return "", "", err
	}
	return ssh.FingerprintSHA256(p.SSHPublic), p.CAPin(), nil
}

// checkUser refuses to run as root when the data dir belongs to another user, so root never
// creates files the service user can't read.
func checkUser(dataDir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	st, err := os.Stat(dataDir)
	if err != nil {
		return nil // serve creates it; under systemd StateDirectory owns it
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
		return fmt.Errorf("running as root but %s belongs to uid %d: use sudo -u aqmas aqmasd ...", dataDir, sys.Uid)
	}
	return nil
}

// inspectCommand is the forced command of the bastion's read-only account. It runs before
// anything else in main: it reads no configuration (that account cannot) and takes its
// request only from SSH_ORIGINAL_COMMAND. It takes no argument at all: nothing on its command
// line can relocate the tools it runs.
// inspectBin is where the inspect command's fixed tools live. Only tests change it.
var inspectBin = "/usr/bin"

func inspectCommand(args []string, request string, out, errOut io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(errOut, "usage: aqmasd inspect   (the request is read from SSH_ORIGINAL_COMMAND)")
		return 2
	}
	bin := inspectBin
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return inspect.Run(ctx, request, bin, version, out, errOut)
}
