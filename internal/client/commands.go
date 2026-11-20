package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// Status runs `aqmas status [id]`: with an id, the server's view of that request; without,
// this host's enrollment and the locally cached certificates.
func (e *Env) Status(ctx context.Context, id string) error {
	if id != "" {
		if !safeID(id) {
			return &UsageError{Msg: fmt.Sprintf("invalid request id %q", id)}
		}
		_, c, err := e.authedClient()
		if err != nil {
			return err
		}
		st, err := c.RequestStatus(ctx, id, 0)
		if err != nil {
			return err
		}
		w := e.Stdout
		fmt.Fprintf(w, "request  %s\nkind     %s\nstatus   %s\n", sanitize(st.ID), sanitize(st.Kind), sanitize(st.Status))
		if st.DecidedAt != nil {
			fmt.Fprintf(w, "decided  %s\n", st.DecidedAt.Local().Format(time.RFC3339))
		}
		if st.DecisionNote != "" {
			fmt.Fprintf(w, "note     %s\n", sanitize(st.DecisionNote))
		}
		if g := st.Grant; g != nil {
			fmt.Fprintf(w, "grant    %s valid %s .. %s\n", sanitize(g.ID),
				g.NotBefore.Local().Format(time.RFC3339), g.NotAfter.Local().Format(time.RFC3339))
			if g.SSH != nil {
				fmt.Fprintf(w, "ssh      %s@%s (%s port %d)\n", sanitize(g.SSH.LoginUser), sanitize(g.SSH.TargetHost),
					sanitize(g.SSH.TargetAddress), g.SSH.TargetPort)
			}
			if cf := g.Cloudflare; cf != nil {
				// Never the token value: a token-mode grant's value is only in the local cache.
				fmt.Fprintf(w, "scope    %s\nmode     %s\naccount  %s\n", describeCFGrant(cf.Scope, cf.ScopeParams, ""), sanitize(cf.Mode), sanitize(cf.AccountID))
				if cf.TokenID != "" {
					fmt.Fprintf(w, "token id %s (delivered: %v)\n", sanitize(cf.TokenID), cf.TokenDelivered || cf.Token != "")
				}
				if len(cf.IPCondition) > 0 {
					fmt.Fprintf(w, "token ip %s\n", sanitize(strings.Join(cf.IPCondition, ",")))
				}
				for _, p := range cf.Permissions {
					fmt.Fprintf(w, "permits  %s\n", sanitize(p))
				}
			}
		}
		return nil
	}

	w := e.Stdout
	cfg, err := LoadConfig(e.Paths)
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) {
			fmt.Fprintf(w, "not enrolled (config %s missing)\n", e.Paths.ConfigFile())
			return nil
		}
		return err
	}
	fmt.Fprintf(w, "server       %s\n", sanitize(cfg.Server))
	fmt.Fprintf(w, "server CA    %s\n", sanitize(cfg.ServerCASHA256))
	fmt.Fprintf(w, "host name    %s\n", sanitize(cfg.HostName))
	if cfg.ClientCert != "" {
		if pair, err := tls.LoadX509KeyPair(expandHome(cfg.ClientCert), expandHome(cfg.ClientKey)); err != nil {
			fmt.Fprintf(w, "client cert  unusable: %v\n", err)
		} else if pair.Leaf != nil {
			fmt.Fprintf(w, "client cert  CN=%s valid until %s\n", sanitize(pair.Leaf.Subject.CommonName), pair.Leaf.NotAfter.Local().Format(time.RFC3339))
		}
	}
	fmt.Fprintf(w, "cache        %s\n", e.Paths.CacheDir)
	entries, _ := os.ReadDir(e.Paths.CacheDir)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	n := 0
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		t, err := ParseTarget(ent.Name(), "")
		if err != nil {
			continue
		}
		if n == 0 {
			fmt.Fprintln(tw, "TARGET\tGRANT\tVALID UNTIL\tSTATE")
		}
		n++
		p, err := e.loadCached(filepath.Join(e.Paths.CacheDir, ent.Name()), t)
		if err != nil {
			fmt.Fprintf(tw, "%s\t-\t-\t%s\n", t, sanitize(err.Error()))
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\tvalid\n", t, p.Grant.GrantID, p.ValidBefore.Local().Format(time.RFC3339))
	}
	if n == 0 {
		fmt.Fprintln(tw, "no cached certificates")
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	toks, err := e.loadCFTokens()
	if err != nil {
		fmt.Fprintf(w, "cf tokens    unreadable: %s\n", sanitize(err.Error()))
		return nil
	}
	if len(toks) == 0 {
		return nil
	}
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nCF TOKEN GRANT\tSCOPE\tVALID UNTIL")
	for _, t := range toks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", sanitize(t.GrantID), describeCFGrant(t.Scope, t.ScopeParams, ""), t.NotAfter.Local().Format(time.RFC3339))
	}
	return tw.Flush()
}

// List runs `aqmas list`: this host's active grants according to the server.
func (e *Env) List(ctx context.Context, asJSON bool) error {
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	gl, err := c.ActiveGrants(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(e.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(gl)
	}
	if len(gl.Grants) == 0 {
		fmt.Fprintln(e.Stdout, "no active grants")
		return nil
	}
	sort.Slice(gl.Grants, func(i, j int) bool { return gl.Grants[i].NotAfter.Before(gl.Grants[j].NotAfter) })
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GRANT\tKIND\tSTATUS\tTARGET\tVALID UNTIL")
	for _, g := range gl.Grants {
		target := sanitize(g.TargetHost)
		if g.LoginUser != "" {
			target = sanitize(g.LoginUser) + "@" + target
		}
		if g.Kind == api.KindCloudflare {
			mode := g.Mode
			if mode == "" {
				mode = api.CFModeProxy
			}
			target = describeCFGrant(g.Scope, g.ScopeParams, "") + " (" + sanitize(mode) + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", sanitize(g.ID), sanitize(g.Kind), sanitize(g.Status), target,
			g.NotAfter.Local().Format(time.RFC3339))
	}
	return tw.Flush()
}

// SSHConfigSnippet renders the opt-in ~/.ssh/config snippet for hosts.
func (e *Env) SSHConfigSnippet(targets []string, aqmasPath string) (string, error) {
	if len(targets) == 0 {
		return "", &UsageError{Msg: "usage: aqmas ssh-config [USER@]HOST... (the fleet hosts plain `ssh HOST` should reach through aqmas)"}
	}
	var ts []Target
	for _, a := range targets {
		t, err := ParseTarget(a, e.User)
		if err != nil {
			return "", err
		}
		ts = append(ts, t)
	}
	cache := e.Paths.CacheDir
	if !safePathRE.MatchString(cache) || !safePathRE.MatchString(aqmasPath) {
		return "", fmt.Errorf("paths %q / %q contain characters ssh_config would reinterpret", cache, aqmasPath)
	}
	var b strings.Builder
	b.WriteString(`# aqmas ssh-config: opt-in snippet so plain "ssh HOST" (and scp, rsync, git) logs in with an
# aqmas certificate. Put it near the TOP of ~/.ssh/config: ssh keeps the first value it sees.
#
# Limitations (read before using):
# - The Match runs "aqmas cert" on every ssh to these hosts. When no cached certificate
#   is valid it blocks until the owner approves; if the request is denied, expires or the
#   server is unreachable, the Match is false and ssh goes on with your usual keys and
#   your other config (this snippet cannot make the certificate the only identity).
# - The reason sent with the request is the fixed text below; agents should use
#   "aqmas ssh --why ..." instead so the owner sees why.
# - Each block matches one login user (Match user) as well as the host: user and host are
#   written literally, no %-tokens reach a shell. Set the user on the command line or in a
#   User line ABOVE this snippet. Generate blocks for other users with USER@HOST.
# - Address and port come from your own config/DNS, not from the grant; the host key is
#   checked against the key aqmas pinned for the target (HostKeyAlias below), so the grant
#   must carry a known_hosts line.
# - ssh reads the files through the "current" link; if another aqmas process renews the
#   grant in the instant between ssh reading the key and the certificate, that login fails
#   and falls back. "aqmas ssh" does not have this race.
# - The cache path below is fixed at generation time (` + cache + `).
#   Regenerate the snippet if XDG_RUNTIME_DIR or AQMAS_CACHE_DIR changes.
`)
	for _, t := range ts {
		d := cache + "/" + t.String() + "/" + currentLink
		fmt.Fprintf(&b, "\nMatch originalhost %s user %s exec \"%s cert --quiet --why 'ssh-config: %s' %s\"\n", t.Host, t.User, aqmasPath, t, t)
		fmt.Fprintf(&b, "    IdentitiesOnly yes\n    IdentityAgent none\n    PreferredAuthentications publickey\n")
		fmt.Fprintf(&b, "    IdentityFile %s/%s\n", d, keyFile)
		fmt.Fprintf(&b, "    CertificateFile %s/%s\n", d, certFile)
		fmt.Fprintf(&b, "    UserKnownHostsFile %s/%s\n", d, knownHostsFile)
		fmt.Fprintf(&b, "    HostKeyAlias %s\n", HostKeyAlias(t.Host))
		fmt.Fprintf(&b, "    StrictHostKeyChecking yes\n")
	}
	return b.String(), nil
}
