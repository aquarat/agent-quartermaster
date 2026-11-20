package cfscope

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Built-in limits.
const (
	hour        = 3600
	AdminMaxTTL = hour // cf.admin (break-glass) grants last at most 1 hour
)

// AllowedPhases are the ruleset phases cf.rulesets may write (docs/CLOUDFLARE.md 2).
var AllowedPhases = []string{
	"http_ratelimit",
	"http_request_cache_settings",
	"http_request_dynamic_redirect",
	"http_request_firewall_custom",
	"http_request_late_transform",
	"http_request_transform",
}

type paramKind int

const (
	pZone paramKind = iota
	pTunnel
	pDB
	pScript
	pProject
	pBucket
	pPhase
	pNameGlob
	pAccessR2
	pAccessD1
)

type paramSpec struct {
	key      string
	kind     paramKind
	required bool
}

type builtin struct {
	scope  Scope
	params []paramSpec
	// autoEligible: config may leave auto-approval on; nothing else can be
	// auto-approved.
	autoEligible bool
	// tokenFor builds the child-token template for resolved params (nil: proxy only).
	tokenFor func(params map[string]string) *TokenTemplate
}

// builtins is THE catalogue. The web UI (web/src/cfscopes.ts) carries the same names with its
// own plain-words text; a scope added here must be added there too.
var builtins = []builtin{
	{scope: Scope{Name: api.CFScopeRead, Title: "Read Cloudflare configuration",
		Description: "GET only, on an allow-list: tunnels and their config, Access apps/policies/groups, zones, DNS, rulesets, zone settings, Workers/Pages/R2/D1 metadata. Never secrets, tokens, logs with personal data or object data.",
		Risk:        api.CFRiskLow, AutoApprove: true, StandingAllowed: true, DefaultTTL: 8 * hour, MaxTTL: 8 * hour},
		autoEligible: true},
	{scope: Scope{Name: api.CFScopeReadPrivate, Title: "Read personal data in Cloudflare",
		Description: "Access request logs and users (household emails, IPs), identity provider settings, email routing addresses, full Pages project and Worker settings.",
		Risk:        api.CFRiskHigh, DefaultTTL: hour, MaxTTL: 2 * hour}},
	{scope: Scope{Name: api.CFScopeDNSEdit, Title: "Edit DNS records",
		Description: "Create, change and delete DNS records in one zone (optionally only names matching a pattern). Apex, mail (MX/SPF/DKIM/DMARC), NS, ACME and protected names are refused.",
		Risk:        api.CFRiskHigh, StandingAllowed: true, DefaultTTL: 2 * hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamZone, pZone, true}, {api.CFParamName, pNameGlob, false}},
		tokenFor: func(p map[string]string) *TokenTemplate {
			t := &TokenTemplate{Zone: []string{"DNS Write", "Zone Read"}}
			if p[api.CFParamName] != "" {
				t.Notes = append(t.Notes, "A child token cannot be limited to a name pattern: it can change every record in the zone.")
			}
			t.Notes = append(t.Notes, "A child token bypasses aqmas's guard rails and snapshots.")
			return t
		}},
	{scope: Scope{Name: api.CFScopeTunnelConfig, Title: "Change a tunnel's routes",
		Description: "Read and replace the whole ingress config of one tunnel (what the internet reaches). aqmas snapshots it first and refuses unsafe rules.",
		Risk:        api.CFRiskHigh, StandingAllowed: true, DefaultTTL: 2 * hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamTunnel, pTunnel, true}}},
	{scope: Scope{Name: api.CFScopeAccessApps, Title: "Create, change and delete Access apps",
		Description: "Access applications (who may reach which hostname). Never on aqmasd's protected hostnames.",
		Risk:        api.CFRiskHigh, StandingAllowed: true, DefaultTTL: 2 * hour, MaxTTL: 8 * hour}},
	{scope: Scope{Name: api.CFScopeAccessPolicies, Title: "Create, change and delete Access policies and groups",
		Description: "Reusable Access policies and groups. Editing a policy shared by several apps is refused.",
		Risk:        api.CFRiskHigh, StandingAllowed: true, DefaultTTL: 2 * hour, MaxTTL: 8 * hour}},
	{scope: Scope{Name: api.CFScopeAccessIdPOrg, Title: "Change Access login methods",
		Description: "Identity providers (OIDC, GitHub, one-time PIN, ...) and the Access organization settings. Affects every login.",
		Risk:        api.CFRiskHigh, DefaultTTL: hour, MaxTTL: 2 * hour}},
	{scope: Scope{Name: api.CFScopeRulesets, Title: "Add and change zone rules",
		Description: "WAF custom rules, rate limits, redirects, cache and transform rules in one zone (optionally one phase). Whole rulesets are never replaced.",
		Risk:        api.CFRiskHigh, StandingAllowed: true, DefaultTTL: 2 * hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamZone, pZone, true}, {api.CFParamPhase, pPhase, false}}},
	{scope: Scope{Name: api.CFScopeZoneSettings, Title: "Change zone settings",
		Description: "Zone settings such as TLS and HTTPS options in one zone. Weakening TLS/HTTPS/HSTS below the owner's decisions is refused.",
		Risk:        api.CFRiskMedium, StandingAllowed: true, DefaultTTL: hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamZone, pZone, true}}},
	{scope: Scope{Name: api.CFScopeCachePurge, Title: "Purge cached files",
		Description: "Purge listed URLs from the cache of one zone (files only, never everything).",
		Risk:        api.CFRiskLow, AutoApprove: true, StandingAllowed: true, DefaultTTL: hour, MaxTTL: 8 * hour},
		params:       []paramSpec{{api.CFParamZone, pZone, true}},
		autoEligible: true,
		tokenFor: func(map[string]string) *TokenTemplate {
			return &TokenTemplate{Zone: []string{"Cache Purge", "Zone Read"}, Notes: []string{"A child token can also purge everything in the zone."}}
		}},
	{scope: Scope{Name: api.CFScopeWorkersDeploy, Title: "Deploy one Worker",
		Description: "Upload and deploy one Worker script with its assets, secrets, cron triggers, routes and custom domains (in the given zone). Data bindings (D1, R2, KV, services, queues, ...) only as listed for the script in aqmasd's worker_bindings; never on protected hostnames.",
		Risk:        api.CFRiskMedium, StandingAllowed: true, DefaultTTL: 2 * hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamScript, pScript, true}, {api.CFParamZone, pZone, false}},
		tokenFor: func(p map[string]string) *TokenTemplate {
			t := &TokenTemplate{Account: []string{"Workers Scripts Write", "Account Settings Read"},
				Notes: []string{"Cloudflare cannot limit a token to one script: this child token can deploy or delete ANY Worker on the account until it expires."}}
			if p[api.CFParamZone] != "" {
				t.Zone = []string{"Workers Routes Write", "Zone Read"}
			}
			return t
		}},
	{scope: Scope{Name: api.CFScopePages, Title: "Deploy one Pages project",
		Description: "Upload deployments, roll back, and manage custom domains of one Pages project. Data bindings only as listed for the project in aqmasd's worker_bindings; never on protected hostnames.",
		Risk:        api.CFRiskMedium, StandingAllowed: true, DefaultTTL: 2 * hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamProject, pProject, true}},
		tokenFor: func(map[string]string) *TokenTemplate {
			return &TokenTemplate{Account: []string{"Pages Write", "Account Settings Read"},
				Notes: []string{"Cloudflare cannot limit a token to one project: this child token works on ANY Pages project on the account."}}
		}},
	{scope: Scope{Name: api.CFScopeD1, Title: "Query or migrate one D1 database",
		Description: "access=read: SELECT/EXPLAIN and read-only PRAGMA only. access=migrate: any SQL, including schema changes and data edits. Export is never allowed.",
		Risk:        api.CFRiskMedium, StandingAllowed: true, DefaultTTL: hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamDB, pDB, true}, {api.CFParamAccess, pAccessD1, true}},
		tokenFor: func(p map[string]string) *TokenTemplate {
			g := "D1 Read"
			if p[api.CFParamAccess] == "migrate" {
				g = "D1 Write"
			}
			return &TokenTemplate{Account: []string{g, "Account Settings Read"},
				Notes: []string{"Cloudflare cannot limit a token to one database: this child token reaches EVERY D1 database on the account, and the SQL is not checked."}}
		}},
	{scope: Scope{Name: api.CFScopeR2Admin, Title: "Manage R2 buckets",
		Description: "List and create buckets; bucket CORS, lifecycle and custom domains (in configured zones, never protected hostnames). No object data, never temporary S3 credentials.",
		Risk:        api.CFRiskMedium, StandingAllowed: true, DefaultTTL: hour, MaxTTL: 8 * hour}},
	{scope: Scope{Name: api.CFScopeR2Objects, Title: "Read or write objects in one R2 bucket",
		Description: "access=read: list and download objects. access=write: also upload and delete.",
		Risk:        api.CFRiskMedium, StandingAllowed: true, DefaultTTL: hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamBucket, pBucket, true}, {api.CFParamAccess, pAccessR2, true}},
		tokenFor: func(p map[string]string) *TokenTemplate {
			g := "Workers R2 Storage Read"
			if p[api.CFParamAccess] == "write" {
				g = "Workers R2 Storage Write"
			}
			return &TokenTemplate{Account: []string{g},
				Notes: []string{"Cloudflare cannot limit this token to one bucket: it reaches EVERY R2 bucket on the account."}}
		}},
	{scope: Scope{Name: api.CFScopeEmail, Title: "Change email routing and sending",
		Description: "Email routing rules and DNS in one zone, destination addresses, and email sending subdomains. Mail is forwarded only to addresses in aqmasd's email_forward_allow.",
		Risk:        api.CFRiskHigh, DefaultTTL: hour, MaxTTL: 8 * hour},
		params: []paramSpec{{api.CFParamZone, pZone, true}}},
	{scope: Scope{Name: api.CFScopeAdmin, Title: "BREAK-GLASS: full Cloudflare access",
		Description: "Any Cloudflare API call except the deny-list (API tokens, members, tunnel run tokens, ...), on any zone or tunnel, for at most 1 hour. Guard rails still apply unless the call names an override.",
		Risk:        api.CFRiskAdmin, DefaultTTL: AdminMaxTTL, MaxTTL: AdminMaxTTL}},
}

var (
	scriptRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	projectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,57}$`)
	bucketRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	// globRE: "foo.example.com" or "*.example.com" (a leading "*." only).
	globRE = regexp.MustCompile(`^(\*\.)?[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))+$`)
)

// NewCatalogue builds the catalogue from config: rejects override entries for unknown scopes,
// overrides that would widen a scope (max TTL above the built-in maximum, etc.).
func NewCatalogue(cfg *config.Cloudflare) (*Catalogue, error) {
	c := &Catalogue{cfg: cfg, scopes: map[string]*Scope{}}
	known := map[string]bool{}
	for _, b := range builtins {
		known[b.scope.Name] = true
	}
	for name := range cfg.Scopes {
		if !known[name] {
			return nil, fmt.Errorf("config: cloudflare.scopes.%q: unknown scope", name)
		}
	}
	for i := range builtins {
		b := &builtins[i]
		sc := b.scope // copy
		sc.Params = paramInfos(b.params, cfg)
		o := cfg.Scopes[sc.Name]
		if o.Disabled {
			continue
		}
		if o.MaxTTLSeconds > 0 {
			if o.MaxTTLSeconds > sc.MaxTTL {
				return nil, fmt.Errorf("config: cloudflare.scopes.%q.max_ttl_seconds %d exceeds the built-in maximum %d", sc.Name, o.MaxTTLSeconds, sc.MaxTTL)
			}
			sc.MaxTTL = o.MaxTTLSeconds
		}
		if o.DefaultTTL > 0 {
			sc.DefaultTTL = o.DefaultTTL
		}
		if sc.DefaultTTL > sc.MaxTTL {
			sc.DefaultTTL = sc.MaxTTL
		}
		if o.NoAutoApprove || !b.autoEligible {
			sc.AutoApprove = false
		}
		if o.NoStanding {
			sc.StandingAllowed = false
		}
		if sc.Name == api.CFScopeAdmin { // fixed: never auto, never standing, at most 1 h
			sc.AutoApprove, sc.StandingAllowed = false, false
			if sc.MaxTTL > AdminMaxTTL {
				sc.MaxTTL = AdminMaxTTL
			}
		}
		if sc.Name == api.CFScopeReadPrivate { // personal data: never auto, never standing
			sc.AutoApprove, sc.StandingAllowed = false, false
		}
		c.scopes[sc.Name] = &sc
		c.order = append(c.order, sc.Name)
	}
	if err := c.ValidateExtraDeny(); err != nil {
		return nil, err
	}
	return c, nil
}

func builtinFor(name string) *builtin {
	for i := range builtins {
		if builtins[i].scope.Name == name {
			return &builtins[i]
		}
	}
	return nil
}

func paramInfos(ps []paramSpec, cfg *config.Cloudflare) []api.CFParamInfo {
	out := []api.CFParamInfo{}
	for _, p := range ps {
		pi := api.CFParamInfo{Key: p.key, Required: p.required}
		switch p.kind {
		case pZone:
			for _, z := range cfg.Zones {
				pi.Values = append(pi.Values, z.Name)
			}
		case pTunnel:
			for _, t := range cfg.Tunnels {
				pi.Values = append(pi.Values, t.Name)
			}
		case pDB:
			for _, d := range cfg.D1Databases {
				pi.Values = append(pi.Values, d.Name)
			}
		case pPhase:
			pi.Values = slices.Clone(AllowedPhases)
		case pAccessR2:
			pi.Values = []string{"read", "write"}
		case pAccessD1:
			pi.Values = []string{"read", "migrate"}
		}
		out = append(out, pi)
	}
	return out
}

// Lookup returns an enabled scope.
func (c *Catalogue) Lookup(name string) (*Scope, bool) {
	s, ok := c.scopes[name]
	return s, ok
}

// Scopes returns the enabled scopes in catalogue order.
func (c *Catalogue) Scopes() []*Scope {
	out := make([]*Scope, 0, len(c.order))
	for _, n := range c.order {
		out = append(out, c.scopes[n])
	}
	return out
}

// Config returns the Cloudflare config the catalogue was built from.
func (c *Catalogue) Config() *config.Cloudflare { return c.cfg }

// Resolve validates a request (scope enabled, mode offered, exactly the allowed parameter
// keys, required ones present, values well-formed and, for zone/tunnel/db, configured) and
// returns its canonical form. Errors are safe to return to the agent.
func (c *Catalogue) Resolve(req api.CloudflareRequest) (*Resolved, error) {
	sc, ok := c.scopes[req.Scope]
	if !ok {
		return nil, fmt.Errorf("unknown or disabled Cloudflare scope %q (see GET /v1/cf/catalogue)", req.Scope)
	}
	b := builtinFor(sc.Name)
	mode := req.Mode
	if mode == "" {
		mode = api.CFModeProxy
	}
	r := &Resolved{Scope: sc, Mode: mode, Params: map[string]string{}, IDs: map[string]string{}}
	specs := map[string]paramSpec{}
	for _, p := range b.params {
		specs[p.key] = p
	}
	for k, v := range req.Params {
		p, ok := specs[k]
		if !ok {
			return nil, fmt.Errorf("scope %s takes no parameter %q", sc.Name, k)
		}
		if v == "" {
			continue // empty = absent
		}
		nv, id, err := c.checkParam(p, v)
		if err != nil {
			return nil, fmt.Errorf("scope %s parameter %s: %v", sc.Name, k, err)
		}
		r.Params[k] = nv
		if id != "" {
			r.IDs[k] = id
		}
	}
	for _, p := range b.params {
		if p.required && r.Params[p.key] == "" {
			return nil, fmt.Errorf("scope %s needs parameter %s", sc.Name, p.key)
		}
	}
	// cf.dns.edit name glob must lie inside the zone.
	if g := r.Params[api.CFParamName]; g != "" {
		z := r.Params[api.CFParamZone]
		base := strings.TrimPrefix(g, "*.")
		if base != z && !strings.HasSuffix(base, "."+z) {
			return nil, fmt.Errorf("scope %s: name %q is not inside zone %q", sc.Name, g, z)
		}
	}
	r.ScopeParams = CanonicalParams(r.Params)
	switch mode {
	case api.CFModeProxy:
	case api.CFModeToken:
		if b.tokenFor == nil || c.cfg.Scopes[sc.Name].NoTokenMode {
			return nil, fmt.Errorf("scope %s is proxy-only (no child tokens)", sc.Name)
		}
		if len(c.cfg.TokenIPCondition) == 0 {
			return nil, fmt.Errorf("child tokens are not configured (cloudflare.token_ip_condition is empty)")
		}
		t := b.tokenFor(r.Params)
		for _, g := range t.Account {
			r.Permissions = append(r.Permissions, g+" (account)")
		}
		for _, g := range t.Zone {
			r.Permissions = append(r.Permissions, g+" (zone "+r.Params[api.CFParamZone]+")")
		}
		r.Notes = append(r.Notes, t.Notes...)
	default:
		return nil, fmt.Errorf("mode must be %q or %q", api.CFModeProxy, api.CFModeToken)
	}
	return r, nil
}

// Token returns the child-token template for a resolved token-mode request (nil otherwise).
func (c *Catalogue) Token(r *Resolved) *TokenTemplate {
	if r.Mode != api.CFModeToken {
		return nil
	}
	b := builtinFor(r.Scope.Name)
	if b == nil || b.tokenFor == nil {
		return nil
	}
	return b.tokenFor(r.Params)
}

// Modes returns the modes a scope offers.
func (c *Catalogue) Modes(name string) []string {
	b := builtinFor(name)
	if b == nil {
		return nil
	}
	if b.tokenFor != nil && !c.cfg.Scopes[name].NoTokenMode && len(c.cfg.TokenIPCondition) > 0 {
		return []string{api.CFModeProxy, api.CFModeToken}
	}
	return []string{api.CFModeProxy}
}

func (c *Catalogue) checkParam(p paramSpec, v string) (norm, id string, err error) {
	switch p.kind {
	case pZone:
		o, ok := c.cfg.Zone(strings.ToLower(v))
		if !ok {
			return "", "", fmt.Errorf("zone %q is not configured in aqmasd", v)
		}
		return o.Name, o.ID, nil
	case pTunnel:
		o, ok := c.cfg.Tunnel(strings.ToLower(v))
		if !ok {
			return "", "", fmt.Errorf("tunnel %q is not configured in aqmasd", v)
		}
		return o.Name, o.ID, nil
	case pDB:
		o, ok := c.cfg.D1(strings.ToLower(v))
		if !ok {
			return "", "", fmt.Errorf("D1 database %q is not configured in aqmasd", v)
		}
		return o.Name, o.ID, nil
	case pScript:
		if !scriptRE.MatchString(v) {
			return "", "", fmt.Errorf("invalid Worker script name")
		}
	case pProject:
		if !projectRE.MatchString(v) {
			return "", "", fmt.Errorf("invalid Pages project name")
		}
	case pBucket:
		if !bucketRE.MatchString(v) {
			return "", "", fmt.Errorf("invalid R2 bucket name")
		}
	case pPhase:
		if !slices.Contains(AllowedPhases, v) {
			return "", "", fmt.Errorf("phase must be one of %s", strings.Join(AllowedPhases, ", "))
		}
	case pNameGlob:
		v = strings.ToLower(v)
		if len(v) > 253 || !globRE.MatchString(v) {
			return "", "", fmt.Errorf(`name must be a DNS name or "*.<name>"`)
		}
	case pAccessR2:
		if v != "read" && v != "write" {
			return "", "", fmt.Errorf(`access must be "read" or "write"`)
		}
	case pAccessD1:
		if v != "read" && v != "migrate" {
			return "", "", fmt.Errorf(`access must be "read" or "migrate"`)
		}
	}
	return v, "", nil
}

// CanonicalParams is the canonical scope_params form: "k=v" pairs, keys sorted bytewise,
// joined with ";"; "" when there are none. Validated values never contain ";" or "=".
func CanonicalParams(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k, v := range p {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+p[k])
	}
	return strings.Join(parts, ";")
}

// ParseParams inverts CanonicalParams.
func ParseParams(s string) (map[string]string, error) {
	out := map[string]string{}
	if s == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("bad scope_params %q", s)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate key in scope_params %q", s)
		}
		out[k] = v
	}
	if CanonicalParams(out) != s {
		return nil, fmt.Errorf("scope_params %q is not canonical", s)
	}
	return out, nil
}

// Reparse turns a stored (scope, scope_params, mode) back into a Resolved; used for grants and
// standing approvals. It fails if the scope or a named object is no longer configured.
func (c *Catalogue) Reparse(scope, scopeParams, mode string) (*Resolved, error) {
	p, err := ParseParams(scopeParams)
	if err != nil {
		return nil, err
	}
	r, err := c.Resolve(api.CloudflareRequest{Scope: scope, Params: p, Mode: mode})
	if err != nil {
		return nil, err
	}
	if r.ScopeParams != scopeParams {
		return nil, fmt.Errorf("scope_params changed meaning since the grant (config edited?)")
	}
	return r, nil
}

// API returns GET /v1/cf/catalogue's body.
func (c *Catalogue) API() api.CFCatalogue {
	out := api.CFCatalogue{AccountID: c.cfg.AccountID, Zones: []api.CFNamedID{}, Tunnels: []api.CFNamedID{}, D1Databases: []api.CFNamedID{}, Scopes: []api.CFScopeInfo{}}
	for _, z := range c.cfg.Zones {
		out.Zones = append(out.Zones, api.CFNamedID{Name: z.Name, ID: z.ID})
	}
	for _, t := range c.cfg.Tunnels {
		out.Tunnels = append(out.Tunnels, api.CFNamedID{Name: t.Name, ID: t.ID})
	}
	for _, d := range c.cfg.D1Databases {
		out.D1Databases = append(out.D1Databases, api.CFNamedID{Name: d.Name, ID: d.ID})
	}
	for _, sc := range c.Scopes() {
		out.Scopes = append(out.Scopes, api.CFScopeInfo{Name: sc.Name, Title: sc.Title, Description: sc.Description, Params: sc.Params,
			Risk: sc.Risk, AutoApprove: sc.AutoApprove, StandingAllowed: sc.StandingAllowed, Modes: c.Modes(sc.Name),
			DefaultTTL: sc.DefaultTTL, MaxTTL: sc.MaxTTL})
	}
	return out
}
