package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/aquarat/agent-quartermaster/docs"
	"github.com/aquarat/agent-quartermaster/internal/api"
)

// DiscoveryOff is what `aqmas ls`, `aqmas targets` and the MCP listing tools say when no
// organisation that admits this host lets hosts list.
const DiscoveryOff = `discovery is disabled by the owner: no organisation that admits this host has "Hosts may list what they can ask for" turned on. ` +
	`That does not mean nothing exists. Ask the owner for the path (organisation/service/set) or the target name, ` +
	`or to turn listing on (approval page: Settings, the organisation's policy).`

// Catalogue fetches what this host may ask for (GET /v2/catalogue).
func (e *Env) Catalogue(ctx context.Context) (*api.HostCatalogue, error) {
	_, c, err := e.authedClient()
	if err != nil {
		return nil, err
	}
	var out api.HostCatalogue
	if err = c.do(ctx, "GET", "/v2/catalogue", nil, &out); err != nil {
		if plainNotFound(err) {
			return nil, errors.New("this broker does not offer listing (it is older than aqmas 0.10.0, or organisations are not active there); ask the owner for the path or target name")
		}
		return nil, err
	}
	return &out, nil
}

func printJSON(e *Env, v any) error {
	enc := json.NewEncoder(e.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// holds says what a credential carries, in names only.
func holds(c api.HostCredential) string {
	switch c.Kind {
	case "secret":
		return "$" + sanitize(c.Env)
	case "signer":
		return sanitize(c.Scheme)
	case "ssh-key":
		// The public line is public: it is what goes into authorized_keys or a forge.
		if c.Handout {
			return sanitize(c.PublicKey) + " (may be handed out)"
		}
		return sanitize(c.PublicKey)
	case "env-set":
		names := make([]string, len(c.Names))
		for i, n := range c.Names {
			names[i] = sanitize(n)
		}
		return strings.Join(names, ",")
	}
	return "by scope"
}

// Ls runs `aqmas ls`: the credential sets this host may ask for.
func (e *Env) Ls(ctx context.Context, asJSON bool) error {
	cat, err := e.Catalogue(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(e, struct {
			Discovery   bool                 `json:"discovery"`
			Credentials []api.HostCredential `json:"credentials"`
		}{cat.Discovery, cat.Credentials})
	}
	if !cat.Discovery {
		fmt.Fprintln(e.Stdout, DiscoveryOff)
		return nil
	}
	if len(cat.Credentials) == 0 {
		fmt.Fprintln(e.Stdout, "no credential sets are listed for this host")
	} else {
		tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "PATH\tKIND\tHOLDS\tUSE")
		for _, c := range cat.Credentials {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", sanitize(c.Path), sanitize(c.Kind), holds(c), sanitize(c.Use))
		}
		if err = tw.Flush(); err != nil {
			return err
		}
	}
	if n := len(cat.Targets); n > 0 {
		fmt.Fprintf(e.Stdout, "\n%d SSH target(s): aqmas targets\n", n)
	}
	fmt.Fprintln(e.Stdout, "\nOnly organisations whose owner turned listing on are shown; values are never listed. How to use these: aqmas guide")
	return nil
}

// Targets runs `aqmas targets`: the SSH targets this host may ask a certificate for.
func (e *Env) Targets(ctx context.Context, asJSON bool) error {
	cat, err := e.Catalogue(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(e, struct {
			Discovery bool             `json:"discovery"`
			Targets   []api.HostTarget `json:"targets"`
		}{cat.Discovery, cat.Targets})
	}
	if !cat.Discovery {
		fmt.Fprintln(e.Stdout, DiscoveryOff)
		return nil
	}
	if len(cat.Targets) == 0 {
		fmt.Fprintln(e.Stdout, "no SSH targets are listed for this host")
		return nil
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tPORT\tUSERS\tAPPROVAL\tUSE")
	for _, t := range cat.Targets {
		users := make([]string, len(t.Users))
		for i, u := range t.Users {
			users[i] = sanitize(u)
		}
		approval := "owner tap"
		if t.Approval == "owner-or-standing" {
			approval = "owner tap, or an auto-approval"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", sanitize(t.Name), sanitize(t.Address), t.Port, strings.Join(users, ","), approval, sanitize(t.Use))
	}
	return tw.Flush()
}

// GuideCommand is one entry of `aqmas guide --json`.
type GuideCommand struct {
	Name     string `json:"name"`
	Usage    string `json:"usage"`
	Summary  string `json:"summary"`
	Approval string `json:"approval"` // none | owner | sometimes
}

// GuideSummary is `aqmas guide --json`: the commands an agent uses, in a form a program reads.
type GuideSummary struct {
	Version   string            `json:"version"`
	Rule      string            `json:"rule"`
	Commands  []GuideCommand    `json:"commands"`
	ExitCodes map[string]string `json:"exit_codes"`
	Errors    map[string]string `json:"errors"`
	MCP       map[string]any    `json:"mcp"`
	Guide     string            `json:"guide"`
}

// Guide is the agent guide (docs/AGENTS.md) of this build.
func Guide() string { return docs.AgentGuide }

// GuideJSON is the machine-readable summary of the guide.
func GuideJSON() GuideSummary {
	return GuideSummary{
		Version: Version,
		Rule:    "Agents hold no long-lived credentials: ask aqmas each time, with a specific and honest --why. Requests block until the owner approves with a passkey, denies, or nobody decides in time.",
		Commands: []GuideCommand{
			{"status", "aqmas status", "enrolment, server and cached certificates", "none"},
			{"ls", "aqmas ls [--json]", "credential sets this host may ask for: path, kind, key names (never values); empty when the owner has listing off", "none"},
			{"targets", "aqmas targets [--json]", "SSH targets this host may use: name, address, port, users", "none"},
			{"list", "aqmas list [--json]", "this host's active grants", "none"},
			{"ssh", "aqmas ssh [USER@]HOST --why TEXT [--ttl 30m] [-- COMMAND...]", "log in or run one command with a short-lived certificate (cached while valid)", "sometimes"},
			{"mosh", "aqmas mosh [USER@]HOST --why TEXT", "mosh with the same certificate", "sometimes"},
			{"cert", "aqmas cert [USER@]HOST --why TEXT", "only fetch the certificate and print its paths (rsync, scp)", "sometimes"},
			{"run", "aqmas run ORG/SERVICE/SET --why TEXT [--env NAME] [--ttl 10m] -- COMMAND...", "run a command with a secret or env set in its environment; exit status is the command's", "owner"},
			{"get", "aqmas get ORG/SERVICE/SECRET --why TEXT", "print one secret's value to stdout; prefer run", "owner"},
			{"checkout", "aqmas checkout ORG/SERVICE/SET --why TEXT [--file .env]; aqmas checkin ORG/SERVICE/SET", "a RAM-backed .env file until check-in or expiry", "owner"},
			{"set", "aqmas set import ORG/SERVICE/SET --from FILE --why TEXT [--create [--title TITLE]]; aqmas set put ORG/SERVICE/SET KEY --why TEXT [--create]; aqmas set unset ORG/SERVICE/SET KEY --why TEXT", "ask the owner to store values in an env set: import replaces the whole set from a dotenv file, put sets one key (value on stdin), unset removes one; the owner sees the key names and commits or discards; --create also makes a missing set (and service); exit 0 committed, 3 discarded, 4 expired or superseded", "owner"},
			{"set check", "aqmas set check --from FILE [ORG/SERVICE/SET]", "check a dotenv file against the import rules without sending anything: key names, problems by line number, with a path what an import would add, replace and remove; never a value", "none"},
			{"sign", "aqmas sign ORG/SERVICE/KEY --why TEXT FILE... | --digest sha256:HEX", "have aqmas sign; the key never leaves it", "owner"},
			{"signer", "aqmas signer ORG/SERVICE/KEY [--pem]", "a signing key's scheme and public key", "none"},
			{"ssh-agent", "aqmas ssh-agent ORG/SERVICE/KEY --why TEXT [--ttl 10m] [--count N] -- COMMAND...", "run git, ssh, scp or rsync with an SSH key that stays in aqmas: a private agent socket offers that one key for the command; one approval covers the logins within the grant", "sometimes"},
			{"ssh-key", "aqmas ssh-key ORG/SERVICE/KEY --public | --why TEXT [--out FILE]", "--public prints the authorized_keys line; otherwise the private key is handed out as a file, only for a key the owner allows it for; prefer ssh-agent", "owner"},
			{"cf", "aqmas cf scopes|request|api|env|curl|token|snapshot ...", "Cloudflare API through the broker's proxy, by scope (aqmas cf help)", "sometimes"},
			{"bastion", "aqmas bastion; aqmas bastion task NAME --why TEXT; aqmas ssh BASTION --why TEXT -- INSPECT-COMMAND", "read-only inspection and routine maintenance of the bastion", "owner"},
			{"guide", "aqmas guide [--json]", "this guide", "none"},
			{"mcp", "aqmas mcp", "MCP server on stdin/stdout with the same abilities", "none"},
		},
		ExitCodes: map[string]string{
			"0": "ok, or the exit status of the command that was run", "1": "error", "2": "usage",
			"3": "denied or refused: stop, do not retry, tell the owner", "4": "expired: nobody decided in time",
			"5": "server unreachable or TLS failure: report it, do not look for another way in", "130": "cancelled",
		},
		Errors: map[string]string{
			"not_admitted": "the host is enrolled but the owner has not admitted it to an organisation; ask the owner (Hosts tab)",
			"not_found":    "no such path or target for this host (a deleted item looks the same); check with aqmas ls / aqmas targets or ask the owner",
			"locked":       "the credential's bucket is closed; the owner needs one more tap, the command keeps waiting",
			"rate_limited": "too many pending requests from this host; wait for the owner",
			"forbidden":    "refused by the owner's policy (for example aqmas get turned off: use aqmas run)",
		},
		MCP: map[string]any{
			"register": "claude mcp add aqmas -- aqmas mcp",
			"config":   map[string]any{"mcpServers": map[string]any{"aqmas": map[string]any{"command": "aqmas", "args": []string{"mcp"}}}},
			"tools":    mcpToolNames(),
		},
		Guide: "aqmas guide",
	}
}
