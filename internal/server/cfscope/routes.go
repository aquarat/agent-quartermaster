package cfscope

import (
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// Snapshot types (docs/CLOUDFLARE.md 4.2): Route.Snapshot.
const (
	SnapTunnelConfig          = "tunnel-config"
	SnapAccessApp             = "access-app"
	SnapAccessPolicy          = "access-policy"
	SnapAccessGroup           = "access-group"
	SnapAccessIdP             = "access-idp"
	SnapAccessOrg             = "access-org"
	SnapDNSRecord             = "dns-record"
	SnapDNSName               = "dns-name"
	SnapRulesetEntrypoint     = "ruleset-entrypoint"
	SnapRuleset               = "ruleset"
	SnapZoneSetting           = "zone-setting"
	SnapEmailRules            = "email-rules"
	SnapPagesProject          = "pages-project"
	SnapWorkersScriptSettings = "workers-script-settings"
	SnapWorkersRoutes         = "workers-routes"
	SnapWorkersDomains        = "workers-domains"
	SnapWorkersScriptRoutes   = "workers-script-routes"
)

// Guard sets (Route.Guard): which guard rails and scope checks cfproxy runs on a route.
const (
	GuardTunnel         = "tunnel"
	GuardAccessApp      = "access-app"
	GuardAccessPatch    = "access-patch"
	GuardAccessAppPol   = "access-app-policy" // legacy app-scoped policies: warnings only
	GuardAccessPolicy   = "access-policy"
	GuardIdP            = "idp"
	GuardDNS            = "dns"
	GuardRuleset        = "ruleset"
	GuardZoneSettings   = "zone-settings"
	GuardPurge          = "purge"
	GuardWorkersDomain  = "workers-domain"
	GuardWorkersDomRm   = "workers-domain-remove"
	GuardWorkersRoute   = "workers-route"
	GuardD1             = "d1"
	GuardEmailRules     = "email-rules"
	GuardAccessAppDelWn = "access-app-delete" // warning only (domain still in a tunnel config)
	// Bodies checked for data bindings (scope enforcement, worker_bindings config).
	GuardWorkersBindings = "workers-bindings"
	GuardPagesBindings   = "pages-bindings"
	// Hostname-bearing writes: protected hostnames (and, for R2, configured zones).
	GuardPagesDomain = "pages-domain"
	GuardR2Domain    = "r2-domain"
	// Email destination addresses (email_forward_allow).
	GuardEmailAddress = "email-address"
)

// tseg is one template segment.
type tseg struct {
	lits  []string // literal alternatives ("query|raw"); nil for a placeholder
	ph    string   // placeholder name without braces / '*' / "..."
	never bool     // "{x*}": never bound to a parameter
	rest  bool     // "{key...}": the rest of the path, >= 1 segment
}

// rdef is one route of a scope.
type rdef struct {
	methods  []string
	tmpl     string
	segs     []tseg
	snapshot string
	guard    string
	upload   bool
	jwt      bool
	whenKey  string // route exists only when the grant's param whenKey == whenVal
	whenVal  string
}

type opt func(*rdef)

var (
	optU = func(r *rdef) { r.upload = true }
	optJ = func(r *rdef) { r.jwt = true }
)

func optS(t string) opt       { return func(r *rdef) { r.snapshot = t } }
func optG(g string) opt       { return func(r *rdef) { r.guard = g } }
func optWhen(k, v string) opt { return func(r *rdef) { r.whenKey, r.whenVal = k, v } }
func optSG(s, g string) opt   { return func(r *rdef) { r.snapshot, r.guard = s, g } }
func rt(methods, tmpl string, opts ...opt) rdef {
	r := rdef{methods: strings.Split(methods, "|"), tmpl: tmpl, segs: parseTemplate(tmpl)}
	for _, o := range opts {
		o(&r)
	}
	return r
}

// gets expands several GET paths.
func gets(paths ...string) []rdef {
	out := make([]rdef, 0, len(paths))
	for _, p := range paths {
		out = append(out, rt("GET", p))
	}
	return out
}

func parseTemplate(t string) []tseg {
	if !strings.HasPrefix(t, "/") {
		panic("cfscope: template without leading slash: " + t)
	}
	parts := strings.Split(t[1:], "/")
	segs := make([]tseg, 0, len(parts))
	for i, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			n := p[1 : len(p)-1]
			s := tseg{}
			switch {
			case strings.HasSuffix(n, "..."):
				s.rest, n = true, strings.TrimSuffix(n, "...")
				if i != len(parts)-1 {
					panic("cfscope: {x...} must be last: " + t)
				}
			case strings.HasSuffix(n, "*"):
				s.never, n = true, strings.TrimSuffix(n, "*")
			}
			if _, ok := phKinds[n]; !ok {
				panic("cfscope: unknown placeholder " + n + " in " + t)
			}
			s.ph = n
			segs = append(segs, s)
			continue
		}
		if p == "" {
			panic("cfscope: empty segment in " + t)
		}
		segs = append(segs, tseg{lits: strings.Split(p, "|")})
	}
	return segs
}

// scopeRoutes: the route tables (docs/CLOUDFLARE.md 2.1). Order matters only for which
// route's annotations a call reports when two routes of one scope match.
var scopeRoutes = map[string][]rdef{
	api.CFScopeRead: gets(
		"/accounts/{acct}",
		"/accounts/{acct}/cfd_tunnel",
		"/accounts/{acct}/cfd_tunnel/{tunnel}",
		"/accounts/{acct}/cfd_tunnel/{tunnel}/configurations",
		"/accounts/{acct}/cfd_tunnel/{tunnel}/connections",
		"/accounts/{acct}/access/apps",
		"/accounts/{acct}/access/apps/{id}",
		"/accounts/{acct}/access/apps/{id}/policies",
		"/accounts/{acct}/access/policies",
		"/accounts/{acct}/access/policies/{id}",
		"/accounts/{acct}/access/groups",
		"/accounts/{acct}/access/groups/{id}",
		"/accounts/{acct}/access/organizations",
		"/accounts/{acct}/access/service_tokens",
		"/zones",
		"/zones/{zone}",
		"/zones/{zone}/dns_records",
		"/zones/{zone}/dns_records/export",
		"/zones/{zone}/dns_records/{id}",
		"/zones/{zone}/rulesets",
		"/zones/{zone}/rulesets/{id}",
		"/zones/{zone}/rulesets/phases/{phase*}/entrypoint",
		"/zones/{zone}/settings",
		"/zones/{zone}/settings/{name}",
		"/zones/{zone}/workers/routes",
		"/zones/{zone}/pagerules",
		"/zones/{zone}/bot_management",
		"/zones/{zone}/managed_headers",
		"/zones/{zone}/email/routing",
		"/zones/{zone}/email/routing/rules",
		"/zones/{zone}/email/routing/rules/catch_all",
		"/accounts/{acct}/workers/scripts",
		"/accounts/{acct}/workers/domains",
		"/accounts/{acct}/workers/subdomain",
		"/accounts/{acct}/workers/account-settings",
		"/accounts/{acct}/workers/scripts/{script*}/versions",
		"/accounts/{acct}/workers/scripts/{script*}/deployments",
		"/accounts/{acct}/pages/projects",
		"/accounts/{acct}/pages/projects/{project*}/deployments",
		"/accounts/{acct}/pages/projects/{project*}/deployments/{id}",
		"/accounts/{acct}/pages/projects/{project*}/deployments/{id}/history/logs",
		"/accounts/{acct}/pages/projects/{project*}/domains",
		"/accounts/{acct}/r2/buckets",
		"/accounts/{acct}/r2/buckets/{bucket*}",
		"/accounts/{acct}/d1/database",
		"/accounts/{acct}/d1/database/{db}",
		"/accounts/{acct}/challenges/widgets",
	),

	api.CFScopeReadPrivate: gets(
		"/accounts/{acct}/access/logs/access_requests",
		"/accounts/{acct}/access/users",
		"/accounts/{acct}/access/users/{id}",
		"/accounts/{acct}/access/users/{id}/active_sessions",
		"/accounts/{acct}/access/users/{id}/last_seen_identity",
		"/accounts/{acct}/access/identity_providers",
		"/accounts/{acct}/access/identity_providers/{id}",
		"/accounts/{acct}/email/routing/addresses",
		"/accounts/{acct}/email/routing/addresses/{id}",
		"/accounts/{acct}/pages/projects/{project*}",
		"/accounts/{acct}/workers/scripts/{script*}/settings",
		"/accounts/{acct}/audit_logs",
	),

	api.CFScopeDNSEdit: {
		rt("GET", "/zones/{zone}"),
		rt("GET", "/zones/{zone}/dns_records"),
		rt("GET", "/zones/{zone}/dns_records/{id}"),
		rt("POST", "/zones/{zone}/dns_records", optSG(SnapDNSName, GuardDNS)),
		rt("PUT|PATCH|DELETE", "/zones/{zone}/dns_records/{id}", optSG(SnapDNSRecord, GuardDNS)),
	},

	api.CFScopeTunnelConfig: {
		rt("GET", "/accounts/{acct}/cfd_tunnel/{tunnel}"),
		rt("GET", "/accounts/{acct}/cfd_tunnel/{tunnel}/configurations"),
		rt("PUT", "/accounts/{acct}/cfd_tunnel/{tunnel}/configurations", optSG(SnapTunnelConfig, GuardTunnel)),
	},

	api.CFScopeAccessApps: {
		rt("GET", "/accounts/{acct}/access/apps"),
		rt("GET", "/accounts/{acct}/access/apps/{id}"),
		rt("GET", "/accounts/{acct}/access/apps/{id}/policies"),
		rt("GET", "/accounts/{acct}/access/policies"),
		rt("GET", "/accounts/{acct}/access/policies/{id}"),
		rt("GET", "/accounts/{acct}/access/groups"),
		rt("GET", "/accounts/{acct}/access/groups/{id}"),
		rt("POST", "/accounts/{acct}/access/apps", optSG(SnapAccessApp, GuardAccessApp)),
		rt("PUT", "/accounts/{acct}/access/apps/{id}", optSG(SnapAccessApp, GuardAccessApp)),
		rt("DELETE", "/accounts/{acct}/access/apps/{id}", optSG(SnapAccessApp, GuardAccessAppDelWn)),
		rt("PATCH", "/accounts/{acct}/access/apps/{id}", optG(GuardAccessPatch)),
		rt("POST", "/accounts/{acct}/access/apps/{id}/policies", optSG(SnapAccessApp, GuardAccessAppPol)),
		rt("PUT|DELETE", "/accounts/{acct}/access/apps/{id}/policies/{id}", optSG(SnapAccessApp, GuardAccessAppPol)),
	},

	api.CFScopeAccessPolicies: {
		rt("GET", "/accounts/{acct}/access/policies"),
		rt("GET", "/accounts/{acct}/access/policies/{id}"),
		rt("GET", "/accounts/{acct}/access/groups"),
		rt("GET", "/accounts/{acct}/access/groups/{id}"),
		rt("GET", "/accounts/{acct}/access/apps"),
		rt("POST", "/accounts/{acct}/access/policies", optSG(SnapAccessPolicy, GuardAccessPolicy)),
		rt("PUT|DELETE", "/accounts/{acct}/access/policies/{id}", optSG(SnapAccessPolicy, GuardAccessPolicy)),
		rt("POST", "/accounts/{acct}/access/groups", optSG(SnapAccessGroup, GuardAccessPolicy)),
		rt("PUT|DELETE", "/accounts/{acct}/access/groups/{id}", optSG(SnapAccessGroup, GuardAccessPolicy)),
	},

	api.CFScopeAccessIdPOrg: {
		rt("GET", "/accounts/{acct}/access/identity_providers"),
		rt("POST", "/accounts/{acct}/access/identity_providers", optSG(SnapAccessIdP, GuardIdP)),
		rt("GET", "/accounts/{acct}/access/identity_providers/{id}"),
		rt("PUT|DELETE", "/accounts/{acct}/access/identity_providers/{id}", optSG(SnapAccessIdP, GuardIdP)),
		rt("GET", "/accounts/{acct}/access/organizations"),
		rt("PUT", "/accounts/{acct}/access/organizations", optS(SnapAccessOrg)),
	},

	api.CFScopeRulesets: {
		rt("GET", "/zones/{zone}/rulesets"),
		rt("GET", "/zones/{zone}/rulesets/{id}"),
		rt("GET", "/zones/{zone}/rulesets/phases/{phase}/entrypoint"),
		rt("PUT", "/zones/{zone}/rulesets/phases/{phase}/entrypoint", optSG(SnapRulesetEntrypoint, GuardRuleset)),
		rt("POST", "/zones/{zone}/rulesets/{id}/rules", optSG(SnapRuleset, GuardRuleset)),
		rt("PATCH|DELETE", "/zones/{zone}/rulesets/{id}/rules/{id}", optSG(SnapRuleset, GuardRuleset)),
		// Replacing a whole ruleset by id: the same object as the entrypoint (keep-rules applies).
		rt("PUT", "/zones/{zone}/rulesets/{id}", optSG(SnapRuleset, GuardRuleset)),
	},

	api.CFScopeZoneSettings: {
		rt("GET", "/zones/{zone}/settings"),
		rt("GET", "/zones/{zone}/settings/{name}"),
		rt("PATCH", "/zones/{zone}/settings", optSG(SnapZoneSetting, GuardZoneSettings)),
		rt("PATCH", "/zones/{zone}/settings/{name}", optSG(SnapZoneSetting, GuardZoneSettings)),
	},

	api.CFScopeCachePurge: {
		rt("POST", "/zones/{zone}/purge_cache", optG(GuardPurge)),
	},

	// Verified against wrangler 4.165.0's bundle (deploy, versions upload/deploy, secret
	// put/list/delete/bulk, triggers deploy); see docs/CLOUDFLARE.md 2.1.
	api.CFScopeWorkersDeploy: workersRoutes(),

	api.CFScopePages: pagesRoutes(),

	api.CFScopeD1: {
		rt("GET", "/accounts/{acct}/d1/database"),
		rt("GET", "/accounts/{acct}/d1/database/{db}"),
		rt("GET", "/accounts/{acct}/d1/database/{dbname}"), // wrangler looks a database up by name
		rt("POST", "/accounts/{acct}/d1/database/{db}/query|raw", optG(GuardD1)),
		// `d1 execute --file`: init/ingest/poll; the SQL file itself goes to a presigned URL
		// (not through the proxy) and is never checked, so import needs access=migrate.
		rt("POST", "/accounts/{acct}/d1/database/{db}/import", optWhen("access", "migrate")),
	},

	api.CFScopeR2Admin: {
		rt("GET|POST", "/accounts/{acct}/r2/buckets"),
		rt("GET", "/accounts/{acct}/r2/buckets/{bucket*}"),
		rt("GET|PUT|DELETE", "/accounts/{acct}/r2/buckets/{bucket*}/cors|lifecycle"),
		rt("GET", "/accounts/{acct}/r2/buckets/{bucket*}/domains/custom"),
		rt("POST", "/accounts/{acct}/r2/buckets/{bucket*}/domains/custom", optG(GuardR2Domain)),
		rt("GET", "/accounts/{acct}/r2/buckets/{bucket*}/domains/custom/{name}"),
		rt("PUT|DELETE", "/accounts/{acct}/r2/buckets/{bucket*}/domains/custom/{name}", optG(GuardR2Domain)),
		rt("GET|PUT", "/accounts/{acct}/r2/buckets/{bucket*}/domains/managed"),
	},

	api.CFScopeR2Objects: {
		rt("GET", "/accounts/{acct}/r2/buckets/{bucket}/objects"),
		rt("GET", "/accounts/{acct}/r2/buckets/{bucket}/objects/{key...}"),
		rt("PUT", "/accounts/{acct}/r2/buckets/{bucket}/objects/{key...}", optU, optWhen(api.CFParamAccess, "write")),
		rt("DELETE", "/accounts/{acct}/r2/buckets/{bucket}/objects/{key...}", optWhen(api.CFParamAccess, "write")),
	},

	api.CFScopeEmail: {
		rt("GET", "/zones/{zone}/email/routing/rules"),
		rt("POST", "/zones/{zone}/email/routing/rules", optSG(SnapEmailRules, GuardEmailRules)),
		rt("GET", "/zones/{zone}/email/routing/rules/catch_all"),
		rt("PUT", "/zones/{zone}/email/routing/rules/catch_all", optSG(SnapEmailRules, GuardEmailRules)),
		rt("GET", "/zones/{zone}/email/routing/rules/{id}"),
		rt("PUT|DELETE", "/zones/{zone}/email/routing/rules/{id}", optSG(SnapEmailRules, GuardEmailRules)),
		rt("GET|POST|PATCH|DELETE", "/zones/{zone}/email/routing/dns"),
		rt("POST", "/zones/{zone}/email/routing/enable|disable"),
		rt("GET", "/accounts/{acct}/email/routing/addresses"),
		rt("POST", "/accounts/{acct}/email/routing/addresses", optG(GuardEmailAddress)),
		rt("GET|DELETE", "/accounts/{acct}/email/routing/addresses/{id}"),
		rt("GET|POST|DELETE", "/zones/{zone}/email/sending/{key...}"),
	},
}
