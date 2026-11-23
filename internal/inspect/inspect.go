// Package inspect is the forced command of the bastion's read-only account
// (docs/BASTION-ACCESS.md §8). sshd runs `aqmasd inspect` for every session of that account;
// the request arrives in SSH_ORIGINAL_COMMAND and is never given to a shell. Each command is
// a fixed argv: the only request-derived words are a key of a compiled-in table and numbers
// this package re-formats itself.
package inspect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Units maps the names a request may use to what journalctl and systemctl are asked for.
// A request never names a unit directly.
var Units = map[string][]string{
	"aqmasd":      {"aqmasd.service"},
	"maint":       {"aqmas-maint.service", "aqmas-maint.path"},
	"cloudflared": {"cloudflared-aqmas.service", "cloudflared.service"},
	"firewall":    {"aqmas-firewall.service", "nftables.service", "firewalld.service"},
	"lock-alert":  {"aqmas-lock-alert.service"},
	"sshd":        {"sshd.service", "ssh.service"},
}

const (
	// Kernel selects the kernel ring (firewall log lines land there); it is not a unit.
	Kernel       = "kernel"
	maxRequest   = 200
	defaultSince = time.Hour
	maxSince     = 30 * 24 * time.Hour
	defaultLines = 500
	maxLines     = 5000
	limit        = 30 * time.Second
)

// Help is printed for `help` and with every refusal.
const Help = `aqmas inspect: read-only view of the bastion. Commands:
  help
  logs <unit> [since=<n><m|h|d>] [lines=<n>]   default since=1h lines=500 (at most 30d, 5000)
  status [<unit>]
  failed
  disk
  version
units: %s
`

var requestRE = regexp.MustCompile(`^[A-Za-z0-9 ._=-]*$`)
var sinceRE = regexp.MustCompile(`^([1-9][0-9]{0,4})([mhd])$`)
var linesRE = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)

// Command is one fixed argv. Name is a file name in the binary directory.
type Command struct {
	Name string
	Args []string
}

// UnitNames lists the accepted unit keys, sorted, with "kernel" last.
func UnitNames() []string {
	var names []string
	for k := range Units {
		names = append(names, k)
	}
	sort.Strings(names)
	return append(names, Kernel)
}

// ErrUsage marks a request outside the grammar.
var ErrUsage = errors.New("not an inspect command")

// Plan turns a request into the commands to run. It is the whole grammar: anything else is
// ErrUsage. A nil slice with a nil error means "print the help".
func Plan(request string) ([]Command, error) {
	if len(request) > maxRequest || !requestRE.MatchString(request) {
		return nil, ErrUsage
	}
	w := strings.Fields(request)
	if len(w) == 0 || len(w) == 1 && w[0] == "help" {
		return nil, nil
	}
	switch w[0] {
	case "logs":
		if len(w) < 2 || len(w) > 4 {
			return nil, ErrUsage
		}
		since, lines := defaultSince, defaultLines
		seen := map[string]bool{}
		for _, opt := range w[2:] {
			k, v, ok := strings.Cut(opt, "=")
			if !ok || seen[k] {
				return nil, ErrUsage
			}
			seen[k] = true
			switch k {
			case "since":
				m := sinceRE.FindStringSubmatch(v)
				if m == nil {
					return nil, ErrUsage
				}
				n, _ := strconv.Atoi(m[1])
				since = time.Duration(n) * map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
				if since > maxSince {
					return nil, ErrUsage
				}
			case "lines":
				if !linesRE.MatchString(v) {
					return nil, ErrUsage
				}
				lines, _ = strconv.Atoi(v)
				if lines > maxLines {
					return nil, ErrUsage
				}
			default:
				return nil, ErrUsage
			}
		}
		args := []string{"--no-pager", "--output=short-iso", "--since=-" + strconv.Itoa(int(since/time.Minute)) + "min", "--lines=" + strconv.Itoa(lines)}
		if w[1] == Kernel {
			return []Command{{"journalctl", append(args, "--dmesg")}}, nil
		}
		units, ok := Units[w[1]]
		if !ok {
			return nil, ErrUsage
		}
		for _, u := range units {
			args = append(args, "--unit="+u)
		}
		return []Command{{"journalctl", args}}, nil
	case "status":
		if len(w) > 2 {
			return nil, ErrUsage
		}
		var units []string
		if len(w) == 2 {
			u, ok := Units[w[1]]
			if !ok {
				return nil, ErrUsage
			}
			units = u
		} else {
			for _, k := range UnitNames() {
				units = append(units, Units[k]...)
			}
		}
		// "show" with a fixed property list, never "status": a status prints each process's
		// command line, and a tunnel started with its token as an argument would leak it.
		return []Command{{"systemctl", append([]string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp,NRestarts"}, units...)}}, nil
	case "failed":
		if len(w) != 1 {
			return nil, ErrUsage
		}
		return []Command{{"systemctl", []string{"list-units", "--failed", "--no-pager", "--no-legend"}}}, nil
	case "disk":
		if len(w) != 1 {
			return nil, ErrUsage
		}
		return []Command{{"df", []string{"-P", "-h", "/", "/var", "/var/log"}}, {"journalctl", []string{"--no-pager", "--disk-usage"}}}, nil
	case "version":
		if len(w) != 1 {
			return nil, ErrUsage
		}
		return []Command{{"uname", []string{"-srm"}}, {"uptime", nil}}, nil
	}
	return nil, ErrUsage
}

// Run executes a request, writing the commands' output to out. binDir is where the fixed
// tools live ("/usr/bin" when installed). A command that exits non-zero (systemctl status of
// a stopped unit does) is not an error of the request; the last such status is returned.
func Run(ctx context.Context, request, binDir, version string, out, errOut io.Writer) int {
	cmds, err := Plan(request)
	if err != nil {
		fmt.Fprintf(errOut, "aqmas inspect: not an inspect command\n"+Help, strings.Join(UnitNames(), " "))
		return 2
	}
	if cmds == nil {
		fmt.Fprintf(out, Help, strings.Join(UnitNames(), " "))
		return 0
	}
	if len(cmds) > 0 && cmds[0].Name == "uname" {
		fmt.Fprintln(out, "aqmasd", version)
	}
	code := 0
	for _, c := range cmds {
		ctx, cancel := context.WithTimeout(ctx, limit)
		cmd := exec.CommandContext(ctx, filepath.Join(binDir, c.Name), c.Args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TZ=UTC", "HOME=/nonexistent", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
		cmd.Dir = "/"
		cmd.Stdout, cmd.Stderr = out, errOut
		cmd.WaitDelay = 5 * time.Second
		err := cmd.Run()
		cancel()
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			code = ee.ExitCode()
		case err != nil:
			fmt.Fprintf(errOut, "aqmas inspect: %s could not be run\n", c.Name)
			code = 1
		}
	}
	return code
}
