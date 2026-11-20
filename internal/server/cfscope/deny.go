package cfscope

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Deny is the deny-list verdict for a call (docs/CLOUDFLARE.md section 3).
type Deny struct {
	Denied bool
	Reason string // safe to show
	// Push: the call is in one of the first four groups (tokens, members/user, tunnel
	// secrets, tunnel lifecycle): the refusal is pushed, not only audited.
	Push bool
}

type denyEntry struct {
	methods []string // nil: any method; "!GET": any but GET
	pat     []string // lower-case literals or "*"
	below   bool     // also every path below pat
	push    bool
	reason  string
}

func de(methods, path string, below, push bool, reason string) denyEntry {
	var ms []string
	if methods != "*" {
		ms = strings.Split(methods, "|")
	}
	return denyEntry{methods: ms, pat: strings.Split(strings.TrimPrefix(path, "/"), "/"), below: below, push: push, reason: reason}
}

const (
	below = true
	exact = false
	push  = true
	quiet = false
)

var denyList = []denyEntry{
	// Tokens and account takeover.
	de("*", "/user/tokens", below, push, "API tokens"),
	de("*", "/accounts/*/tokens", below, push, "API tokens"),
	de("*", "/memberships", below, push, "account memberships"),
	de("*", "/accounts/*/members", below, push, "account members"),
	de("!GET", "/user", exact, push, "user settings"),
	de("*", "/user", below, push, "user settings"), // "below" here: anything under /user/ (exact /user handled by the entry above)
	// Tunnel secrets.
	de("*", "/accounts/*/cfd_tunnel/*/token", below, push, "tunnel run token"),
	de("*", "/accounts/*/cfd_tunnel/*/management", below, push, "tunnel management token"),
	de("*", "/accounts/*/warp_connector/*/token", below, push, "WARP connector token"),
	de("*", "/accounts/*/tunnels/*/token", below, push, "tunnel token"),
	// Tunnel lifecycle.
	de("POST", "/accounts/*/cfd_tunnel", exact, push, "tunnel creation"),
	de("PUT|PATCH|DELETE", "/accounts/*/cfd_tunnel/*", exact, push, "tunnel lifecycle"),
	de("DELETE", "/accounts/*/cfd_tunnel/*/connections", exact, push, "kicking tunnel connectors"),
	// Service tokens (the response carries client_secret).
	de("POST", "/accounts/*/access/service_tokens", exact, quiet, "Access service token creation"),
	de("*", "/accounts/*/access/service_tokens/*/rotate", below, quiet, "Access service token rotation"),
	de("*", "/accounts/*/access/service_tokens/*/refresh", below, quiet, "Access service token refresh"),
	// Turnstile secrets.
	de("GET", "/accounts/*/challenges/widgets/*", exact, quiet, "Turnstile widget secret"),
	de("*", "/accounts/*/challenges/widgets/*/rotate_secret", below, quiet, "Turnstile secret rotation"),
	// Worker source and live logs.
	de("*", "/accounts/*/workers/scripts/*/tails", below, quiet, "Worker live logs"),
	de("*", "/accounts/*/workers/tails", below, quiet, "Worker live logs"),
	de("GET", "/accounts/*/workers/scripts/*", exact, quiet, "Worker script source"),
	de("*", "/accounts/*/workers/scripts/*/content", below, quiet, "Worker script source"),
	de("*", "/accounts/*/workers/services/*/environments/*/content", below, quiet, "Worker script source"),
	de("GET", "/accounts/*/workers/dispatch/namespaces/*/scripts/*", exact, quiet, "Worker script source"),
	de("*", "/accounts/*/workers/dispatch/namespaces/*/scripts/*/content", below, quiet, "Worker script source"),
	// Storage credentials and dumps.
	de("POST", "/accounts/*/r2/temp-access-credentials", below, quiet, "temporary R2 credentials"),
	de("*", "/accounts/*/d1/database/*/export", below, quiet, "D1 export"),
	// Log shipping.
	de("*", "/accounts/*/logpush", below, quiet, "Logpush"),
	de("*", "/zones/*/logpush", below, quiet, "Logpush"),
	// Certificates and keys.
	de("*", "/certificates", below, quiet, "origin certificates"),
	de("*", "/zones/*/origin_tls_client_auth", below, quiet, "client certificates"),
	de("*", "/zones/*/custom_certificates", below, quiet, "custom certificates"),
	de("!GET", "/zones/*/ssl/certificate_packs", below, quiet, "certificate packs"),
	// Secrets, networks, devices, billing.
	de("!GET", "/accounts/*/secrets_store", below, quiet, "Secrets Store"),
	de("!GET", "/accounts/*/hyperdrive", below, quiet, "Hyperdrive"),
	de("!GET", "/accounts/*/teamnet", below, quiet, "private networks"),
	de("!GET", "/accounts/*/devices", below, quiet, "devices"),
	de("!GET", "/accounts/*/gateway", below, quiet, "Gateway"),
	de("*", "/accounts/*/registrar", below, quiet, "registrar"),
	de("*", "/accounts/*/subscriptions", below, quiet, "billing"),
	de("*", "/zones/*/subscription", below, quiet, "billing"),
	// Zones and analytics.
	de("POST", "/zones", exact, quiet, "zone creation"),
	de("DELETE", "/zones/*", exact, quiet, "zone deletion"),
	de("*", "/graphql", below, quiet, "GraphQL analytics"),
	de("!GET", "/accounts", exact, quiet, "account creation"),
}

// Synthetic endpoints answered by aqmasd itself (docs/CLOUDFLARE.md 3.2); never denied.
func isSynthetic(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	switch path {
	case "/user/tokens/verify", "/user", "/memberships", "/accounts":
		return true
	}
	return false
}

// IsSynthetic reports whether aqmasd answers the call itself.
func IsSynthetic(call Call) bool { return isSynthetic(call.Method, call.Path) }

// decodedLower returns the segments percent-decoded and lower-cased (for deny matching: the
// deny-list must not be dodged by "%74okens" or "/User/Tokens").
func decodedLower(segs []string) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		if d, err := url.PathUnescape(s); err == nil {
			s = d
		}
		out[i] = strings.ToLower(s)
	}
	return out
}

func methodIn(ms []string, m string) bool {
	if ms == nil {
		return true
	}
	for _, x := range ms {
		if x == m || (strings.HasPrefix(x, "!") && x[1:] != m) {
			return true
		}
	}
	return false
}

func patMatch(pat, segs []string, below bool) bool {
	if len(segs) < len(pat) || (!below && len(segs) != len(pat)) {
		return false
	}
	for i, p := range pat {
		if p != "*" && p != segs[i] {
			return false
		}
	}
	return true
}

// CheckDeny applies the built-in deny-list (not extra_deny, which is per scope).
func (c *Catalogue) CheckDeny(call Call) Deny {
	if isSynthetic(call.Method, call.Path) {
		return Deny{}
	}
	segs := decodedLower(call.Segments)
	if len(segs) >= 2 && segs[0] == "accounts" && call.Segments[1] != c.cfg.AccountID {
		return Deny{true, "an account other than the configured one", false}
	}
	for _, e := range denyList {
		if methodIn(e.methods, call.Method) && patMatch(e.pat, segs, e.below) {
			return Deny{true, e.reason, e.push}
		}
	}
	return Deny{}
}

// Denied reports whether the call is on the deny-list (section 3), which no scope, not even
// cf.admin, can pass. The reason is safe to show.
func (c *Catalogue) Denied(call Call) (bool, string) {
	d := c.CheckDeny(call)
	return d.Denied, d.Reason
}

type extraDeny struct {
	method string // "*" = any
	pat    []string
}

// parseExtraDeny parses "METHOD /path/template" ("*" = any method or segment, "{x}" = any
// segment). An entry matches its path and everything below it.
func parseExtraDeny(s string) (extraDeny, error) {
	m, p, ok := strings.Cut(strings.TrimSpace(s), " ")
	p = strings.TrimSpace(p)
	if !ok || m == "" || !strings.HasPrefix(p, "/") || len(p) < 2 {
		return extraDeny{}, fmt.Errorf("extra_deny entry %q: want \"METHOD /path\"", s)
	}
	m = strings.ToUpper(m)
	switch m {
	case "*", "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return extraDeny{}, fmt.Errorf("extra_deny entry %q: bad method", s)
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, x := range parts {
		if x == "" {
			return extraDeny{}, fmt.Errorf("extra_deny entry %q: empty segment", s)
		}
		if strings.HasPrefix(x, "{") && strings.HasSuffix(x, "}") {
			x = "*"
		}
		parts[i] = strings.ToLower(x)
	}
	return extraDeny{method: m, pat: parts}, nil
}

// ValidateExtraDeny checks every scope's extra_deny entries (start-up error otherwise).
func (c *Catalogue) ValidateExtraDeny() error {
	for name, o := range c.cfg.Scopes {
		for _, e := range o.ExtraDeny {
			if _, err := parseExtraDeny(e); err != nil {
				return fmt.Errorf("config: cloudflare.scopes.%q: %v", name, err)
			}
		}
	}
	return nil
}

// ExtraDenied reports whether the scope's config extra_deny refuses the call.
func (c *Catalogue) ExtraDenied(scope string, call Call) bool {
	o, ok := c.cfg.Scopes[scope]
	if !ok || len(o.ExtraDeny) == 0 {
		return false
	}
	segs := decodedLower(call.Segments)
	for _, s := range o.ExtraDeny {
		e, err := parseExtraDeny(s)
		if err != nil {
			return true // fail closed (NewCatalogue rejects these at start)
		}
		if (e.method == "*" || e.method == call.Method) && patMatch(e.pat, segs, true) {
			return true
		}
	}
	return false
}
