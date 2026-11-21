package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// CloudflareAPIBase is the public API base `cf api` and `cf curl` accept in URLs.
const CloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cfCredentialEnv is removed from every child's environment: legacy global-key credentials
// must never reach a tool that should use aqmas.
var cfCredentialEnv = []string{"CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL", "CF_API_KEY", "CF_API_EMAIL"}

func (e *Env) environ() []string {
	if e.Environ != nil {
		return e.Environ()
	}
	return os.Environ()
}

// childEnv returns base without the credential variables, the keys of set and unset, plus set.
func childEnv(base []string, set map[string]string, unset []string) []string {
	drop := map[string]bool{}
	for _, k := range cfCredentialEnv {
		drop[k] = true
	}
	for _, k := range unset {
		drop[k] = true
	}
	for k := range set {
		drop[k] = true
	}
	var out []string
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+set[k])
	}
	return out
}

func lookupEnv(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// withNoProxy adds 127.0.0.1 to a NO_PROXY value, so the command reaches the shim directly
// even when it routes other traffic through an HTTP(S) proxy.
func withNoProxy(v string) string {
	for _, p := range strings.Split(v, ",") {
		if strings.TrimSpace(p) == "127.0.0.1" {
			return v
		}
	}
	if v == "" {
		return "127.0.0.1"
	}
	return v + ",127.0.0.1"
}

// runChild runs argv with env and the Env's stdio and returns its exit status (128+signal
// when killed). SIGTERM and SIGHUP sent to aqmas are passed on; SIGINT from a terminal reaches
// the child through its process group, and aqmas itself keeps running until the child exits.
func (e *Env) runChild(ctx context.Context, argv []string, env []string) (int, error) {
	if len(argv) == 0 {
		return 0, &UsageError{Msg: "no command given after --"}
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return 0, &UsageError{Msg: fmt.Sprintf("command %q: %v", sanitize(argv[0]), err)}
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = e.Stdin, e.Stdout, e.Stderr
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case s := <-sigs:
			cmd.Process.Signal(s)
		case err := <-done:
			if err == nil {
				return 0, nil
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					return 128 + int(ws.Signal()), nil
				}
				return ee.ExitCode(), nil
			}
			return 0, err
		}
	}
}

// ---- cf scopes ----

// CFScopes runs `aqmas cf scopes`.
func (e *Env) CFScopes(ctx context.Context, asJSON bool) error {
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	cat, err := c.CFCatalogue(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(e.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cat)
	}
	w := e.Stdout
	fmt.Fprintf(w, "account  %s\n", sanitize(cat.AccountID))
	for _, l := range []struct {
		name string
		ids  []api.CFNamedID
	}{{"zones", cat.Zones}, {"tunnels", cat.Tunnels}, {"d1", cat.D1Databases}} {
		names := make([]string, 0, len(l.ids))
		for _, n := range l.ids {
			names = append(names, sanitize(n.Name))
		}
		fmt.Fprintf(w, "%-8s %s\n", l.name, orDash(strings.Join(names, ", ")))
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCOPE\tPARAMS\tRISK\tAUTO\tSTANDING\tMODES\tTTL\tTITLE")
	for _, s := range cat.Scopes {
		var ps []string
		for _, p := range s.Params {
			k := sanitize(p.Key)
			if len(p.Values) > 0 && len(p.Values) <= 6 {
				vs := make([]string, 0, len(p.Values))
				for _, v := range p.Values {
					vs = append(vs, sanitize(v))
				}
				k += "=" + strings.Join(vs, "|")
			}
			if !p.Required {
				k += "?"
			}
			ps = append(ps, k)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s/%s\t%s\n", sanitize(s.Name), orDash(strings.Join(ps, " ")), sanitize(s.Risk),
			yesNo(s.AutoApprove), yesNo(s.StandingAllowed), sanitize(strings.Join(s.Modes, ",")),
			time.Duration(s.DefaultTTL)*time.Second, time.Duration(s.MaxTTL)*time.Second, sanitize(s.Title))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nRequest with: aqmas cf request SCOPE key=value... --why \"...\"  (? = optional parameter)")
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---- cf request ----

// CFRequestCmd runs `aqmas cf request`.
func (e *Env) CFRequestCmd(ctx context.Context, spec CFRequestSpec, ttl time.Duration, why string, asJSON bool) error {
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	sts, err := e.RequestCF(ctx, c, cfg, []CFRequestSpec{spec}, ttl, why)
	if err != nil {
		return err
	}
	st := sts[0]
	if asJSON {
		enc := json.NewEncoder(e.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	g := st.Grant
	end := g.NotAfter.Local().Format(time.RFC3339)
	if g.Indefinite {
		end = "INDEFINITE (until revoked)"
	}
	fmt.Fprintf(e.Stdout, "grant    %s\nscope    %s\nmode     %s\naccount  %s\nvalid    %s .. %s\n", sanitize(g.ID),
		describeCFGrant(g.Cloudflare.Scope, g.Cloudflare.ScopeParams, ""), sanitize(g.Cloudflare.Mode), sanitize(g.Cloudflare.AccountID),
		g.NotBefore.Local().Format(time.RFC3339), end)
	if g.Cloudflare.Mode == api.CFModeToken {
		fmt.Fprintf(e.Stdout, "token    cached for this user (use: aqmas cf token %s ... -- CMD)\n", sanitize(g.Cloudflare.Scope))
	} else {
		fmt.Fprintf(e.Stdout, "use      aqmas cf api ... | aqmas cf env -- CMD\n")
	}
	return nil
}

// ---- cf api ----

// CFAPIOptions are the flags of `aqmas cf api`.
type CFAPIOptions struct {
	Method    string
	Path      string // relative to /client/v4, or a full https://api.cloudflare.com/client/v4/... URL
	Data      string // TEXT, @FILE or @-
	HasData   bool
	Headers   []string
	Grants    []string
	Overrides []string
	Raw       bool
	Why       string
}

// splitCFPath accepts "/zones/x?y", "zones/x", "/client/v4/zones/x" or a full API URL.
func splitCFPath(p string) (path, query string, err error) {
	if rest, ok := strings.CutPrefix(p, CloudflareAPIBase); ok {
		p = rest
	} else if strings.Contains(p, "://") {
		return "", "", &UsageError{Msg: fmt.Sprintf("only %s URLs are accepted, got %q", CloudflareAPIBase, sanitize(p))}
	}
	p = strings.TrimPrefix(p, "/client/v4")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.ContainsAny(p, "#\x00 \t\r\n") {
		return "", "", &UsageError{Msg: fmt.Sprintf("invalid path %q", sanitize(p))}
	}
	path, query, _ = strings.Cut(p, "?")
	return path, query, nil
}

// CFAPI runs `aqmas cf api`: one call through the proxy.
func (e *Env) CFAPI(ctx context.Context, o CFAPIOptions) error {
	method := strings.ToUpper(o.Method)
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return &UsageError{Msg: fmt.Sprintf("method %q: use GET, POST, PUT, PATCH or DELETE", sanitize(o.Method))}
	}
	path, query, err := splitCFPath(o.Path)
	if err != nil {
		return err
	}
	hdr := http.Header{}
	for _, h := range o.Headers {
		k, v, ok := strings.Cut(h, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" {
			return &UsageError{Msg: fmt.Sprintf("-H %q: want 'Name: value'", sanitize(h))}
		}
		switch http.CanonicalHeaderKey(k) {
		case "Content-Type", "Accept", "If-Match", "If-None-Match":
			hdr.Set(k, v)
		default:
			return &UsageError{Msg: fmt.Sprintf("-H %s: only Content-Type, Accept, If-Match and If-None-Match are forwarded (use --grant / --override for aqmas headers)", sanitize(k))}
		}
	}
	for _, g := range o.Grants {
		if !safeID(g) {
			return &UsageError{Msg: fmt.Sprintf("invalid grant id %q", sanitize(g))}
		}
	}
	for _, ov := range o.Overrides {
		if !cfParamKeyRE.MatchString(strings.ReplaceAll(ov, "-", "_")) {
			return &UsageError{Msg: fmt.Sprintf("invalid guard name %q", sanitize(ov))}
		}
	}
	var body io.Reader
	length := int64(-1)
	if o.HasData {
		switch {
		case o.Data == "@-":
			body = e.Stdin
		case strings.HasPrefix(o.Data, "@"):
			f, err := os.Open(o.Data[1:])
			if err != nil {
				return &UsageError{Msg: "--data: " + err.Error()}
			}
			defer f.Close()
			if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
				if fi.Size() > MaxUploadBytes {
					return &UsageError{Msg: "--data: file larger than 100 MiB"}
				}
				length = fi.Size()
			}
			body = f
		default:
			body, length = strings.NewReader(o.Data), int64(len(o.Data))
		}
		if hdr.Get("Content-Type") == "" {
			hdr.Set("Content-Type", "application/json")
		}
	}

	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	grants := o.Grants
	if len(grants) == 0 {
		gs, err := c.ActiveCFProxyGrants(ctx)
		if err != nil {
			return err
		}
		for _, g := range gs {
			grants = append(grants, g.ID)
		}
		if len(grants) == 0 && method == http.MethodGet {
			e.logf("no active Cloudflare grant on this host; requesting cf.read (auto-approved)")
			sts, err := e.RequestCF(ctx, c, cfg, []CFRequestSpec{{Scope: api.CFScopeRead}}, 0, o.Why)
			if err != nil {
				return err
			}
			grants = []string{sts[0].Grant.ID}
		}
	}
	resp, err := c.Proxy(ctx, &ProxyCall{Method: method, Path: path, Query: query, Header: hdr, Body: body, ContentLength: length,
		Grants: grants, Overrides: o.Overrides})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	info := ParseCFInfo(resp.Header)
	if info.GrantUsed != "" {
		e.logf("grant used: %s", info.GrantUsed)
	}
	if info.SnapshotBefore != "" || info.SnapshotAfter != "" {
		e.logf("snapshot before: %s  after: %s  (aqmas cf snapshot get ID)", orDash(info.SnapshotBefore), orDash(info.SnapshotAfter))
	}
	for _, w := range info.Warnings {
		e.logf("warning: %s", w)
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	isJSON := ct == "application/json" || strings.HasSuffix(ct, "+json")
	var msg string
	var stdout io.Writer = e.Stdout
	if e.StdoutIsTTY {
		stdout = ctrlFilter{e.Stdout} // no terminal escapes from response bodies on a terminal
	}
	if isJSON && !o.Raw {
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return &UnreachableError{Err: err}
		}
		var out bytes.Buffer
		if json.Indent(&out, data, "", "  ") == nil {
			out.WriteByte('\n')
			stdout.Write(out.Bytes())
		} else {
			stdout.Write(data)
		}
		msg = cfErrorMessage(data)
	} else if _, err := io.Copy(stdout, resp.Body); err != nil {
		return &UnreachableError{Err: err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	if info.Error == api.CFErrNoGrant {
		if cmd := NeedsScopeCommand(info.NeedsScope); cmd != "" {
			e.logf("no grant allows %s %s; request one with:\n  %s", method, sanitize(path), cmd)
		} else {
			e.logf("no grant allows %s %s, and no scope except cf.admin would", method, sanitize(path))
		}
	}
	if info.IsRefusal() {
		return &CFRefusalError{Code: info.Error, Message: msg, NeedsScope: info.NeedsScope}
	}
	return &CFStatusError{Status: resp.StatusCode, Code: info.Error, Message: msg}
}

// ctrlFilter replaces control bytes other than newline and tab (ESC, CSI...) with '?'.
type ctrlFilter struct{ w io.Writer }

func (c ctrlFilter) Write(p []byte) (int, error) {
	q := make([]byte, len(p))
	for i, b := range p {
		if (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f {
			b = '?'
		}
		q[i] = b
	}
	if _, err := c.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ---- cf env / cf curl ----

// CFEnvOptions are the flags of `aqmas cf env`.
type CFEnvOptions struct {
	Grants   []string
	Requests []CFRequestSpec
	TTL      time.Duration
	Why      string
}

// CFEnv runs `aqmas cf env -- CMD`: CMD sees the local shim as the Cloudflare API. Returns
// CMD's exit status.
func (e *Env) CFEnv(ctx context.Context, o CFEnvOptions, cmd []string) (int, error) {
	return e.cfEnvRun(ctx, o, func(s *Shim) ([]string, func(), error) { return cmd, func() {}, nil })
}

func (e *Env) cfEnvRun(ctx context.Context, o CFEnvOptions, argv func(s *Shim) ([]string, func(), error)) (int, error) {
	for _, g := range o.Grants {
		if !safeID(g) {
			return 0, &UsageError{Msg: fmt.Sprintf("invalid grant id %q", sanitize(g))}
		}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return 0, err
	}
	cat, err := c.CFCatalogue(ctx)
	if err != nil {
		return 0, err
	}
	pinned := append([]string(nil), o.Grants...)
	if len(o.Requests) > 0 {
		for i := range o.Requests {
			o.Requests[i].Mode = api.CFModeProxy
		}
		sts, err := e.RequestCF(ctx, c, cfg, o.Requests, o.TTL, o.Why)
		if err != nil {
			return 0, err
		}
		for _, st := range sts {
			pinned = append(pinned, st.Grant.ID)
		}
	}
	shim, err := e.StartShim(ctx, c, ShimOptions{Grants: pinned, Explicit: len(o.Grants) > 0})
	if err != nil {
		return 0, err
	}
	defer shim.Close()
	if len(shim.Grants()) == 0 {
		e.logf("cf env: no active Cloudflare proxy grant yet; calls are refused until one is approved (aqmas cf request SCOPE ... --why ...)")
	}
	args, cleanup, err := argv(shim)
	if err != nil {
		return 0, err
	}
	defer cleanup()
	base := e.environ()
	env := childEnv(base, map[string]string{
		"CLOUDFLARE_API_BASE_URL": shim.BaseURL(),
		"CF_API_BASE":             shim.BaseURL(),
		"CLOUDFLARE_API_TOKEN":    shim.Bearer(),
		"CF_API_TOKEN":            shim.Bearer(),
		"CLOUDFLARE_ACCOUNT_ID":   cat.AccountID,
		"CF_ACCOUNT_ID":           cat.AccountID,
		"NO_PROXY":                withNoProxy(lookupEnv(base, "NO_PROXY")),
		"no_proxy":                withNoProxy(lookupEnv(base, "no_proxy")),
	}, []string{"CF_API_BASE_URL"})
	return e.runChild(ctx, args, env)
}

// CFCurl runs `aqmas cf curl [ARGS...]`: curl through the shim, with every
// https://api.cloudflare.com/client/v4 URL argument rewritten to it. The shim's bearer is
// handed to curl in a 0600 header file (never on the command line, where ps would show it).
func (e *Env) CFCurl(ctx context.Context, o CFEnvOptions, curlArgs []string) (int, error) {
	return e.cfEnvRun(ctx, o, func(s *Shim) ([]string, func(), error) {
		if err := ensurePrivateDir(e.Paths.CacheDir); err != nil {
			return nil, nil, err
		}
		f, err := os.CreateTemp(e.Paths.CacheDir, ".cf-curl-header-*")
		if err != nil {
			return nil, nil, err
		}
		name := f.Name()
		cleanup := func() { os.Remove(name) }
		if err := f.Chmod(0o600); err == nil {
			_, err = fmt.Fprintf(f, "Authorization: Bearer %s\n", s.Bearer())
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			f.Close()
			cleanup()
			return nil, nil, err
		}
		args := []string{"curl", "-H", "@" + filepath.Clean(name)}
		for _, a := range curlArgs {
			if rest, ok := strings.CutPrefix(a, CloudflareAPIBase); ok && (rest == "" || rest[0] == '/' || rest[0] == '?') {
				a = s.BaseURL() + rest
			}
			args = append(args, a)
		}
		return args, cleanup, nil
	})
}

// ---- snapshots ----

// CFSnapshotList runs `aqmas cf snapshot list`.
func (e *Env) CFSnapshotList(ctx context.Context, object, typ, grant string, asJSON bool) error {
	q := url.Values{}
	if object != "" {
		q.Set("object", object)
	}
	if typ != "" {
		q.Set("type", typ)
	}
	if grant != "" {
		q.Set("grant", grant)
	}
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	l, err := c.CFSnapshots(ctx, q)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(e.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(l)
	}
	if len(l.Snapshots) == 0 {
		fmt.Fprintln(e.Stdout, "no snapshots")
		return nil
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTAKEN\tPHASE\tOBJECT\tWRITE\tGRANT\tHOST\tSIZE")
	for _, s := range l.Snapshots {
		phase := sanitize(s.Phase)
		if s.Missing {
			phase += " (missing)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s %s\t%s\t%s\t%d\n", sanitize(s.ID), s.CreatedAt.Local().Format(time.RFC3339), phase,
			sanitize(s.ObjectKey), sanitize(s.Method), sanitize(s.Path), sanitize(s.GrantID), sanitize(s.Host), s.Size)
	}
	return tw.Flush()
}

// CFSnapshotGet runs `aqmas cf snapshot get ID [-o FILE]`: the content as pretty JSON.
func (e *Env) CFSnapshotGet(ctx context.Context, id, outFile string) error {
	if !safeID(id) {
		return &UsageError{Msg: fmt.Sprintf("invalid snapshot id %q", sanitize(id))}
	}
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	s, err := c.CFSnapshot(ctx, id)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if len(s.Content) == 0 {
		out.WriteString("null")
	} else if err := json.Indent(&out, s.Content, "", "  "); err != nil {
		return fmt.Errorf("snapshot %s: content is not JSON: %w", id, err)
	}
	out.WriteByte('\n')
	e.logf("snapshot %s: %s %s of %s (%s %s by %s, grant %s)", sanitize(s.ID), sanitize(s.Phase), s.CreatedAt.Local().Format(time.RFC3339),
		sanitize(s.ObjectKey), sanitize(s.Method), sanitize(s.Path), sanitize(s.Host), sanitize(s.GrantID))
	if outFile == "" || outFile == "-" {
		_, err = e.Stdout.Write(out.Bytes())
		return err
	}
	return writeFileAtomic(outFile, out.Bytes(), 0o600)
}
