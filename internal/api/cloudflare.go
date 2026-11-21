package api

import (
	"encoding/json"
	"time"
)

// Milestone 2: Cloudflare API access through aqmasd. docs/API.md section 5 describes the wire
// contract; docs/CLOUDFLARE.md the scope catalogue, deny-list, guard rails and snapshots.

// Cloudflare grant modes.
const (
	// CFModeProxy: the agent calls aqmasd's proxy (/cf/client/v4/...) with mTLS and a grant
	// reference; aqmasd checks every call against the scope and injects the parent token. No
	// secret ever reaches the agent. The default.
	CFModeProxy = "proxy"
	// CFModeToken: aqmasd mints a child API token (expiring with the grant, IP-conditioned)
	// and returns its value once. Fallback for tools that cannot use the proxy.
	CFModeToken = "token"
)

// Cloudflare scope names: the built-in catalogue (docs/CLOUDFLARE.md section 2). Scopes are
// defined in code (server internal/server/cfscope and web/src) so the approval UI can always
// describe what it signs; aqmasd's config may only narrow them (docs/CLOUDFLARE.md section 6).
const (
	CFScopeRead           = "cf.read"            // allow-listed GETs; auto-approvable
	CFScopeReadPrivate    = "cf.read.private"    // personal-data reads; never auto
	CFScopeDNSEdit        = "cf.dns.edit"        // zone, optional name glob
	CFScopeTunnelConfig   = "cf.tunnel.config"   // tunnel
	CFScopeAccessApps     = "cf.access.apps"     //
	CFScopeAccessPolicies = "cf.access.policies" //
	CFScopeAccessIdPOrg   = "cf.access.idp-org"  // IdPs and the Access organization
	CFScopeRulesets       = "cf.rulesets"        // zone, optional phase
	CFScopeZoneSettings   = "cf.zone-settings"   // zone
	CFScopeCachePurge     = "cf.cache.purge"     // zone; files only; auto-approvable
	CFScopeWorkersDeploy  = "cf.workers.deploy"  // script, optional zone
	CFScopePages          = "cf.pages"           // project
	CFScopeD1             = "cf.d1"              // db, access read|migrate
	CFScopeR2Admin        = "cf.r2.admin"        // buckets, no object data
	CFScopeR2Objects      = "cf.r2.objects"      // bucket, access read|write
	CFScopeEmail          = "cf.email"           // zone (routing rules) + account addresses/sending
	CFScopeAdmin          = "cf.admin"           // break-glass, 1 h, never auto, never standing
)

// Scope parameter keys (CloudflareRequest.Params). Which keys a scope takes, and which are
// required, is in the catalogue (GET /v1/cf/catalogue, docs/CLOUDFLARE.md section 2).
const (
	CFParamZone    = "zone"    // zone NAME from aqmasd's config, e.g. "example.com"
	CFParamTunnel  = "tunnel"  // tunnel NAME from aqmasd's config, e.g. "home"
	CFParamScript  = "script"  // Worker script name
	CFParamProject = "project" // Pages project name
	CFParamDB      = "db"      // D1 database NAME from aqmasd's config
	CFParamBucket  = "bucket"  // R2 bucket name
	CFParamAccess  = "access"  // "read" | "write" (r2.objects), "read" | "migrate" (d1)
	CFParamPhase   = "phase"   // ruleset phase, e.g. "http_request_dynamic_redirect"
	CFParamName    = "name"    // DNS name glob: "foo.example.com" or "*.example.com"
)

// Cloudflare risk levels (PendingCloudflare.Risk, CFScopeInfo.Risk). PendingItem.Risk stays
// "normal" (low, medium) or "high" (high, admin) for M1 clients.
const (
	CFRiskLow    = "low"
	CFRiskMedium = "medium"
	CFRiskHigh   = "high"
	CFRiskAdmin  = "admin"
)

// Headers of the Cloudflare proxy (agent API, /cf/client/v4/...).
const (
	// CFGrantHeader (request) lists the grant ids the caller offers, comma-separated, at most
	// 8, in order of preference. aqmasd uses the first one that allows the call.
	CFGrantHeader = "X-Aqmas-Grant"
	// CFOverrideHeader (request) names guard rails a cf.admin grant overrides for this call,
	// comma-separated (docs/CLOUDFLARE.md section 4). Ignored, and refused, for other scopes.
	CFOverrideHeader = "X-Aqmas-Override"
	// CFGrantUsedHeader (response) is the grant id that authorised the call.
	CFGrantUsedHeader = "X-Aqmas-Grant-Used"
	// CFSnapshotBeforeHeader / CFSnapshotAfterHeader (response, writes): snapshot ids.
	CFSnapshotBeforeHeader = "X-Aqmas-Snapshot-Before"
	CFSnapshotAfterHeader  = "X-Aqmas-Snapshot-After"
	// CFWarningHeader (response, repeatable): a guard-rail warning, ASCII text.
	CFWarningHeader = "X-Aqmas-Warning"
	// CFErrorHeader (response, refusals): one of the CFErr* codes below.
	CFErrorHeader = "X-Aqmas-Error"
	// CFNeedsScopeHeader (response, CFErrNoGrant): the scope (and parameters, in canonical
	// scope_params form) that would allow the call, e.g. "cf.dns.edit zone=example.com",
	// so the CLI can tell the agent what to request. Absent when no scope (other than
	// cf.admin) allows it; "cf.admin" when only the break-glass scope does.
	CFNeedsScopeHeader = "X-Aqmas-Needs-Scope"
)

// Proxy refusal codes (CFErrorHeader; also errors[0].message prefix "aqmas <code>: ").
const (
	CFErrNoGrant     = "no_grant"     // 403: no offered grant allows this method+path
	CFErrDenied      = "denied"       // 403: on the deny-list (no scope can do it)
	CFErrGuardRail   = "guard_rail"   // 403 (409 for version conflicts): a guard rail refused the write
	CFErrBadPath     = "bad_path"     // 400: path or query not in the accepted form
	CFErrBadRequest  = "bad_request"  // 400: e.g. method-override header, body too large/unparseable
	CFErrRateLimited = "rate_limited" // 429
	CFErrUpstream    = "upstream"     // 502: Cloudflare unreachable / snapshot GET failed
)

// CFErrorNumeric is errors[0].code in aqmasd's Cloudflare-shaped error bodies (a number, as
// Cloudflare's own errors have; tools such as wrangler print errors[].message).
const CFErrorNumeric = 10403

// CloudflareRequest is AccessRequest.Cloudflare (kind "cloudflare").
type CloudflareRequest struct {
	Scope  string            `json:"scope"`            // a CFScope* name
	Params map[string]string `json:"params,omitempty"` // CFParam* keys
	Mode   string            `json:"mode,omitempty"`   // CFModeProxy (default when empty) or CFModeToken
}

// CloudflareGrant is Grant.Cloudflare.
type CloudflareGrant struct {
	Scope       string            `json:"scope"`
	Params      map[string]string `json:"params,omitempty"`
	ScopeParams string            `json:"scope_params"` // canonical form, as signed
	Mode        string            `json:"mode"`
	AccountID   string            `json:"account_id"`
	// ProxyPath is the path prefix of the proxy on the agent API ("/cf/client/v4"): proxy
	// URL = <server> + ProxyPath + "/<cloudflare path>". Set in both modes (a token grant can
	// still read snapshots, not proxy).
	ProxyPath string `json:"proxy_path"`

	// Token mode only.
	// Token is the child API token's value, returned ONCE: on the first GET
	// /v1/requests/{id} after approval (aqmasd mints it then and never stores the value).
	// Later polls carry TokenID and TokenDelivered=true without the value.
	Token          string   `json:"token,omitempty"`
	TokenID        string   `json:"token_id,omitempty"`
	TokenDelivered bool     `json:"token_delivered,omitempty"`
	IPCondition    []string `json:"ip_condition,omitempty"` // CIDRs the token is limited to
	// Permissions is the child token's policy in plain words, e.g.
	// ["Workers Scripts Write (account)", "Workers Routes Write (zone example.com)"].
	Permissions []string `json:"permissions,omitempty"`
}

// PendingCloudflare is PendingItem.Cloudflare: what the approval card shows.
type PendingCloudflare struct {
	Scope       string            `json:"scope"`
	Params      map[string]string `json:"params"`
	ScopeParams string            `json:"scope_params"` // exactly as it will be signed
	Mode        string            `json:"mode"`
	// IPCondition is the token's IP condition as it will be signed (comma-separated CIDRs,
	// sorted); "" in proxy mode.
	IPCondition string `json:"ip_condition"`
	// Title and Description are the server catalogue's plain words. The UI has its own text
	// for every built-in scope and shows the server's only as a supplement.
	Title       string `json:"title"`
	Description string `json:"description"`
	Risk        string `json:"risk"` // CFRisk*
	// StandingAllowed: the card may offer "approve similar for N hours".
	StandingAllowed bool `json:"standing_allowed"`
	// Permissions: the child token's policy in plain words (token mode), as in CloudflareGrant.
	Permissions []string `json:"permissions,omitempty"`
	// Notes the owner should read (e.g. "a child token for Workers Scripts Write can deploy
	// any Worker on the account until it expires").
	Notes []string `json:"notes,omitempty"`
}

// ---- GET /v1/cf/catalogue ----

// CFCatalogue describes the scopes this aqmasd offers (after config narrowing) and the named
// objects scope parameters may refer to.
type CFCatalogue struct {
	AccountID   string        `json:"account_id"`
	Zones       []CFNamedID   `json:"zones"`
	Tunnels     []CFNamedID   `json:"tunnels"`
	D1Databases []CFNamedID   `json:"d1_databases"`
	Scopes      []CFScopeInfo `json:"scopes"`
}

// CFNamedID maps a configured name to the Cloudflare id.
type CFNamedID struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// CFScopeInfo is one catalogue entry.
type CFScopeInfo struct {
	IndefiniteAvailable bool          `json:"indefinite_available,omitempty"`
	Name                string        `json:"name"`
	Title               string        `json:"title"`
	Description         string        `json:"description"`
	Params              []CFParamInfo `json:"params"`
	Risk                string        `json:"risk"`
	AutoApprove         bool          `json:"auto_approve"`     // proxy mode only
	StandingAllowed     bool          `json:"standing_allowed"` // proxy mode only
	Modes               []string      `json:"modes"`            // ["proxy"] or ["proxy","token"]
	DefaultTTL          int           `json:"default_ttl_seconds"`
	MaxTTL              int           `json:"max_ttl_seconds"`
}

// CFParamInfo describes one scope parameter.
type CFParamInfo struct {
	Key      string   `json:"key"`
	Required bool     `json:"required"`
	Values   []string `json:"values,omitempty"` // closed set (access, phase, zone/tunnel/db names)
}

// ---- snapshots: GET /v1/cf/snapshots, GET /v1/cf/snapshots/{id} ----

// CFSnapshot describes one stored snapshot of a Cloudflare object, taken by aqmasd before
// (and after) a write through the proxy.
type CFSnapshot struct {
	ServiceID  string    `json:"service_id,omitempty"`
	HostID     int64     `json:"host_id,omitempty"`
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Phase      string    `json:"phase"`       // "before" | "after"
	ObjectType string    `json:"object_type"` // docs/CLOUDFLARE.md 4.2: tunnel-config, access-app, access-policy, access-group, access-idp, access-org, dns-record, dns-name, ruleset-entrypoint, ruleset, zone-setting, email-rules, pages-project, workers-script-settings, workers-routes, workers-domains, workers-script-routes
	ObjectKey  string    `json:"object_key"`  // e.g. "tunnel-config:<tunnel id>", "dns-record:<zone id>:<record id>"
	Method     string    `json:"method"`      // the write it belongs to
	Path       string    `json:"path"`        // Cloudflare path of the write (no query)
	GrantID    string    `json:"grant_id"`
	Host       string    `json:"host"`    // requesting host of the write
	PairID     string    `json:"pair_id"` // the other phase of the same write, if any
	SHA256     string    `json:"sha256"`  // hex, over Content
	Size       int       `json:"size"`
	Missing    bool      `json:"missing,omitempty"` // "before" of a create: the object did not exist
	// Content is the object as Cloudflare returned it (the GET's "result"), with the same
	// secret redaction as proxied reads. Only in GET /v1/cf/snapshots/{id}.
	Content json.RawMessage `json:"content,omitempty"`
}

// CFSnapshotList is the body of GET /v1/cf/snapshots (newest first, without Content).
type CFSnapshotList struct {
	Snapshots []CFSnapshot `json:"snapshots"`
}
