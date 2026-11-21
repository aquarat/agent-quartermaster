package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/client"
)

const cfUsage = `aqmas cf: Cloudflare API access through aqmasd (time-boxed, owner-approved grants)

Usage:
  aqmas cf scopes [--json]
      The scope catalogue, and the zone/tunnel/D1 names parameters may use.
  aqmas cf request SCOPE [key=value...] [--mode proxy|token] [--ttl 2h] [--why TEXT] [--json]
      Request a grant and wait for the owner's decision (cf.read and cf.cache.purge are
      auto-approved). Prints the grant id and validity.
  aqmas cf api METHOD PATH [--data @FILE|@-|TEXT] [-H 'Name: value'] [--grant ID]...
               [--override GUARD] [--raw] [--why TEXT]
      One call through the proxy. PATH is relative to /client/v4 (a full
      https://api.cloudflare.com/client/v4/... URL works too). Body to stdout, aqmas notes
      (grant used, snapshots, warnings) to stderr. A GET with no grant requests cf.read.
  aqmas cf env [--grant ID]... [--request SCOPE [key=value...]]... [--ttl D] [--why T] -- CMD...
      Run CMD (wrangler, curl, scripts) against a local shim that forwards to the proxy:
      CLOUDFLARE_API_BASE_URL, CLOUDFLARE_API_TOKEN (a per-run local bearer, not a Cloudflare
      token), CLOUDFLARE_ACCOUNT_ID are set. Exit status is CMD's.
  aqmas cf curl [--grant ID]... [--request ...] [--why T] -- CURL-ARGS...   (or: aqmas cf curl CURL-ARGS...)
      curl through the shim; https://api.cloudflare.com/client/v4 URLs are rewritten.
  aqmas cf token SCOPE [key=value...] [--ttl D] [--why T] [--print] [--fresh] [-- CMD...]
      A minted child token (token mode, fallback for tools that cannot use the proxy).
      With CMD: run it with CLOUDFLARE_API_TOKEN set (never printed). Without: print the
      token only when stdout is not a terminal, or with --print. Cached until 2 min before expiry.
  aqmas cf snapshot list [--object KEY] [--type T] [--grant ID] [--json]
  aqmas cf snapshot get ID [-o FILE]
      Snapshots aqmasd took before/after writes (needs any active Cloudflare grant).

Exit codes: 0 ok (cf env/curl/token: the command's own), 1 error or upstream non-2xx,
2 usage, 3 denied / aqmas refusal (no_grant, denied, guard_rail), 4 expired,
5 server unreachable, 130 cancelled.
`

// flag kinds for parseArgs.
const (
	flagBool  = iota
	flagValue // --name VALUE, last one wins
	flagMulti // repeatable
	flagGroup // --request SCOPE key=value...: the following key=value words belong to it
)

type group struct {
	name string
	args []string
}

type cfFlags struct {
	str    map[string]string
	multi  map[string][]string
	bool   map[string]bool
	groups []group
	pos    []string
	cmd    []string // after "--"; nil if no "--"
}

func parseArgs(args []string, spec map[string]int) (*cfFlags, error) {
	f := &cfFlags{str: map[string]string{}, multi: map[string][]string{}, bool: map[string]bool{}}
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
		kind, ok := spec[name]
		if !ok {
			return nil, &client.UsageError{Msg: fmt.Sprintf("unknown flag %q", a)}
		}
		if kind == flagBool {
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
		switch kind {
		case flagValue:
			f.str[name] = val
		case flagMulti:
			f.multi[name] = append(f.multi[name], val)
		case flagGroup:
			g := group{name: val}
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && strings.Contains(args[i+1], "=") {
				i++
				g.args = append(g.args, args[i])
			}
			f.groups = append(f.groups, g)
		}
	}
	return f, nil
}

func parseTTL(s string) (time.Duration, error) {
	if s == "indefinite" {
		return client.CFIndefinite, nil
	}
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err == nil && d < 0 {
		return 0, &client.UsageError{Msg: "negative TTL is not supported"}
	}
	if err != nil {
		return 0, &client.UsageError{Msg: "--ttl: " + err.Error()}
	}
	return d, nil
}

func envOptions(f *cfFlags) (client.CFEnvOptions, error) {
	o := client.CFEnvOptions{Grants: f.multi["grant"], Why: f.str["why"]}
	var err error
	if o.TTL, err = parseTTL(f.str["ttl"]); err != nil {
		return o, err
	}
	for _, g := range f.groups {
		spec, err := client.ParseCFSpec(g.name, g.args)
		if err != nil {
			return o, err
		}
		o.Requests = append(o.Requests, spec)
	}
	return o, nil
}

func runCF(ctx context.Context, env *client.Env, args []string) int {
	if len(args) == 0 {
		fmt.Print(cfUsage)
		return client.ExitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		fmt.Print(cfUsage)
		return 0
	case "scopes":
		f, err := parseArgs(rest, map[string]int{"json": flagBool})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) > 0 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas cf scopes [--json]"})
		}
		return fail(env.CFScopes(ctx, f.bool["json"]))
	case "request":
		f, err := parseArgs(rest, map[string]int{"mode": flagValue, "ttl": flagValue, "why": flagValue, "json": flagBool})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) < 1 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas cf request SCOPE [key=value...] [--mode proxy|token] [--ttl 2h] [--why TEXT] [--json]"})
		}
		spec, err := client.ParseCFSpec(f.pos[0], f.pos[1:])
		if err != nil {
			return fail(err)
		}
		switch f.str["mode"] {
		case "", "proxy":
		case "token":
			spec.Mode = "token"
		default:
			return fail(&client.UsageError{Msg: "--mode must be proxy or token"})
		}
		ttl, err := parseTTL(f.str["ttl"])
		if err != nil {
			return fail(err)
		}
		return fail(env.CFRequestCmd(ctx, spec, ttl, f.str["why"], f.bool["json"]))
	case "api":
		f, err := parseArgs(rest, map[string]int{"data": flagValue, "H": flagMulti, "header": flagMulti, "grant": flagMulti,
			"override": flagMulti, "raw": flagBool, "why": flagValue})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) != 2 || f.cmd != nil {
			return fail(&client.UsageError{Msg: "usage: aqmas cf api METHOD PATH [--data @FILE|@-|TEXT] [-H 'Name: value'] [--grant ID]... [--override GUARD] [--raw] [--why TEXT]"})
		}
		data, hasData := f.str["data"]
		var overrides []string
		for _, o := range f.multi["override"] {
			overrides = append(overrides, strings.Split(o, ",")...)
		}
		return fail(env.CFAPI(ctx, client.CFAPIOptions{Method: f.pos[0], Path: f.pos[1], Data: data, HasData: hasData,
			Headers: append(f.multi["H"], f.multi["header"]...), Grants: f.multi["grant"], Overrides: overrides,
			Raw: f.bool["raw"], Why: f.str["why"]}))
	case "env":
		f, err := parseArgs(rest, map[string]int{"grant": flagMulti, "request": flagGroup, "ttl": flagValue, "why": flagValue})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) > 0 {
			return fail(&client.UsageError{Msg: fmt.Sprintf("unexpected %q (scope parameters follow --request SCOPE; the command goes after --)", f.pos[0])})
		}
		if len(f.cmd) == 0 {
			return fail(&client.UsageError{Msg: "usage: aqmas cf env [--grant ID]... [--request SCOPE [key=value...]]... [--ttl D] [--why T] -- CMD..."})
		}
		o, err := envOptions(f)
		if err != nil {
			return fail(err)
		}
		code, err := env.CFEnv(ctx, o, f.cmd)
		if err != nil {
			return fail(err)
		}
		return code
	case "curl":
		var o client.CFEnvOptions
		curlArgs := rest
		for i, a := range rest {
			if a == "--" {
				f, err := parseArgs(rest[:i], map[string]int{"grant": flagMulti, "request": flagGroup, "ttl": flagValue, "why": flagValue})
				if err != nil {
					return fail(err)
				}
				if len(f.pos) > 0 {
					return fail(&client.UsageError{Msg: fmt.Sprintf("unexpected %q before -- (curl arguments go after --)", f.pos[0])})
				}
				if o, err = envOptions(f); err != nil {
					return fail(err)
				}
				curlArgs = rest[i+1:]
				break
			}
		}
		code, err := env.CFCurl(ctx, o, curlArgs)
		if err != nil {
			return fail(err)
		}
		return code
	case "token":
		f, err := parseArgs(rest, map[string]int{"ttl": flagValue, "why": flagValue, "print": flagBool, "fresh": flagBool})
		if err != nil {
			return fail(err)
		}
		if len(f.pos) < 1 {
			return fail(&client.UsageError{Msg: "usage: aqmas cf token SCOPE [key=value...] [--ttl D] [--why T] [--print] [--fresh] [-- CMD...]"})
		}
		spec, err := client.ParseCFSpec(f.pos[0], f.pos[1:])
		if err != nil {
			return fail(err)
		}
		ttl, err := parseTTL(f.str["ttl"])
		if err != nil {
			return fail(err)
		}
		if f.cmd != nil && len(f.cmd) == 0 {
			return fail(&client.UsageError{Msg: "no command after --"})
		}
		code, err := env.CFToken(ctx, client.CFTokenOptions{Spec: spec, TTL: ttl, Why: f.str["why"], Print: f.bool["print"], Fresh: f.bool["fresh"]}, f.cmd)
		if err != nil {
			return fail(err)
		}
		return code
	case "snapshot", "snapshots":
		if len(rest) == 0 {
			return fail(&client.UsageError{Msg: "usage: aqmas cf snapshot list|get ..."})
		}
		switch rest[0] {
		case "list":
			f, err := parseArgs(rest[1:], map[string]int{"object": flagValue, "type": flagValue, "grant": flagValue, "json": flagBool})
			if err != nil {
				return fail(err)
			}
			if len(f.pos) > 0 || f.cmd != nil {
				return fail(&client.UsageError{Msg: "usage: aqmas cf snapshot list [--object KEY] [--type T] [--grant ID] [--json]"})
			}
			return fail(env.CFSnapshotList(ctx, f.str["object"], f.str["type"], f.str["grant"], f.bool["json"]))
		case "get":
			f, err := parseArgs(rest[1:], map[string]int{"o": flagValue, "output": flagValue})
			if err != nil {
				return fail(err)
			}
			if len(f.pos) != 1 || f.cmd != nil {
				return fail(&client.UsageError{Msg: "usage: aqmas cf snapshot get ID [-o FILE]"})
			}
			out := f.str["o"]
			if out == "" {
				out = f.str["output"]
			}
			return fail(env.CFSnapshotGet(ctx, f.pos[0], out))
		}
		return fail(&client.UsageError{Msg: fmt.Sprintf("unknown snapshot command %q (list, get)", rest[0])})
	}
	return fail(&client.UsageError{Msg: fmt.Sprintf("unknown cf command %q (try aqmas cf help)", sub)})
}
