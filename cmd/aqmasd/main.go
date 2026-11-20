// Command aqmasd is the agent-quartermaster credential broker server.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/webui"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: aqmasd [-config PATH] <command>

commands:
  serve                 run the agent API and the approval web UI
  passkey-enroll-code   print a one-time code (15 min, single use) to register the first passkey
  print-ssh-ca          print the SSH user CA public key (for TrustedUserCAKeys)
  print-client-ca       print the internal CA certificate (PEM; signs the agent-API server cert too)
  tls-fingerprint       print the CA pin for ` + "`aqmas enroll --ca-pin`" + ` (sha256:<hex>)
  version               print the version

Run every command as the aqmas user (sudo -u aqmas aqmasd ...).
`

func main() {
	syscall.Umask(0o077)
	fs := flag.NewFlagSet("aqmasd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	if err := run(fs.Arg(0), *cfgPath, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "aqmasd:", err)
		os.Exit(1)
	}
}

func run(cmd, cfgPath string, out io.Writer) error {
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
	case "serve":
		log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		srv, err := server.New(server.Options{Config: cfg, Logger: log})
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
		p, err := pki.LoadCAs(server.CADir(cfg.DataDir))
		if err != nil {
			return err
		}
		fmt.Fprintln(out, p.SSHCAPublicLine())
		return nil
	case "tls-fingerprint":
		p, err := pki.LoadCAs(server.CADir(cfg.DataDir))
		if err != nil {
			return err
		}
		fmt.Fprintln(out, p.CAPin())
		return nil
	case "print-client-ca":
		p, err := pki.LoadCAs(server.CADir(cfg.DataDir))
		if err != nil {
			return err
		}
		fmt.Fprint(out, string(p.CAPEM))
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
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
