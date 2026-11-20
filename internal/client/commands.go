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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", sanitize(g.ID), sanitize(g.Kind), sanitize(g.Status), target,
			g.NotAfter.Local().Format(time.RFC3339))
	}
	return tw.Flush()
}

// SSHConfigSnippet renders the opt-in ~/.ssh/config snippet for hosts.
func (e *Env) SSHConfigSnippet(hosts []string, aqmasPath string) (string, error) {
	if len(hosts) == 0 {
		return "", &UsageError{Msg: "usage: aqmas ssh-config HOST... (the fleet hosts plain `ssh HOST` should reach through aqmas)"}
	}
	for _, h := range hosts {
		if !hostNameRE.MatchString(h) {
			return "", &UsageError{Msg: fmt.Sprintf("invalid host %q", h)}
		}
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
#   server is unreachable, the Match is false and ssh goes on with your usual keys.
# - The reason sent with the request is the fixed text below; agents should use
#   "aqmas ssh --why ..." instead so the owner sees why.
# - %r is the remote user as known when the Match is evaluated: give it on the command
#   line (user@host) or in a User line ABOVE this snippet, else it is your local user name.
# - Address and port come from your own config/DNS, not from the grant; the host key is
#   checked against the key aqmas pinned for the target (HostKeyAlias below).
# - The cache path below is fixed at generation time (` + cache + `).
#   Regenerate the snippet if XDG_RUNTIME_DIR or AQMAS_CACHE_DIR changes.
`)
	for _, h := range hosts {
		fmt.Fprintf(&b, "\nMatch originalhost %s exec \"%s cert --quiet --why 'ssh-config: %%r@%s' %%r@%s\"\n", h, aqmasPath, h, h)
		fmt.Fprintf(&b, "    IdentitiesOnly yes\n    IdentityAgent none\n    PreferredAuthentications publickey\n")
		fmt.Fprintf(&b, "    IdentityFile %s/%%r@%s/%s\n", cache, h, keyFile)
		fmt.Fprintf(&b, "    CertificateFile %s/%%r@%s/%s\n", cache, h, certFile)
		fmt.Fprintf(&b, "    UserKnownHostsFile %s/%%r@%s/%s\n", cache, h, knownHostsFile)
		fmt.Fprintf(&b, "    HostKeyAlias %s\n", HostKeyAlias(h))
		fmt.Fprintf(&b, "    StrictHostKeyChecking yes\n")
	}
	return b.String(), nil
}
