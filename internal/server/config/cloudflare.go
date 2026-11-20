package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Cloudflare is the [cloudflare] section (milestone 2, docs/CLOUDFLARE.md section 6).
type Cloudflare struct {
	Enabled bool `toml:"enabled"`
	// APIBase is the upstream API root, default "https://api.cloudflare.com/client/v4". Tests
	// point it at a fake; anything but https is refused unless AllowInsecureAPIBase.
	APIBase              string `toml:"api_base"`
	AllowInsecureAPIBase bool   `toml:"allow_insecure_api_base"` // tests only (http:// fake)
	AccountID            string `toml:"account_id"`              // the one account (32 hex)

	// Parent tokens. Each is read once at start from a systemd credential (name, resolved
	// under $CREDENTIALS_DIRECTORY; preferred: the file stays root-owned) or from a file
	// (mode 0600/0400, owned by aqmasd's user). Never logged. Minter is optional: without it
	// token-mode grants are refused.
	ProxyTokenCredential  string `toml:"proxy_token_credential"`  // e.g. "cf-proxy-token"
	ProxyTokenFile        string `toml:"proxy_token_file"`        // alternative to the credential
	MinterTokenCredential string `toml:"minter_token_credential"` // e.g. "cf-minter-token"
	MinterTokenFile       string `toml:"minter_token_file"`

	// TokenIPCondition: CIDRs every child token is limited to (condition.request_ip.in), e.g.
	// the static home IPv4 as "203.0.113.7/32". Required for token mode.
	TokenIPCondition []string `toml:"token_ip_condition"`

	// SnapshotDir defaults to <data_dir>/cf-snapshots. Retention: SnapshotRetentionDays
	// (default 7, never longer) plus the newest snapshot of every object.
	SnapshotDir           string `toml:"snapshot_dir"`
	SnapshotRetentionDays int    `toml:"snapshot_retention_days"`

	// Rate limits per host, proxied calls per minute (default 600) and writes per minute
	// (default 60).
	RatePerMinute      int `toml:"rate_per_minute"`
	WriteRatePerMinute int `toml:"write_rate_per_minute"`
	// MaxBodyBytes caps request bodies on routes whose body aqmasd parses (guard rails; default
	// 2 MiB); UploadMaxBodyBytes caps streamed upload routes (Workers/Pages/R2; default 100 MiB).
	MaxBodyBytes       int64 `toml:"max_body_bytes"`
	UploadMaxBodyBytes int64 `toml:"upload_max_body_bytes"`

	// Guard-rail facts. All empty by default: a guard that needs one simply does not apply.
	// ProtectedAccessHostnames never get an Access app (e.g. the identity provider's own
	// hostname: an Access app on it breaks every login). Together with ProtectedDNSNames they
	// form the protected-hostname set no grant (not even cf.admin) may route, re-route or
	// re-point: Workers routes and custom domains, Pages and R2 custom domains, tunnel ingress
	// rules (which must stay byte-identical), DNS records of exactly that name.
	ProtectedAccessHostnames []string `toml:"protected_access_hostnames"`
	// TraefikOrigin is a tunnel service that needs originServerName == hostname (e.g.
	// "https://192.0.2.10:443"); TraefikPlainOrigins are refused as tunnel services (plain-HTTP
	// origins of that proxy, which redirect-loop).
	TraefikOrigin       string   `toml:"traefik_origin"`
	TraefikPlainOrigins []string `toml:"traefik_plain_origins"`
	// ProtectedDNSNames: names whose records a cf.dns.edit grant may not touch (apex and the
	// mail/ACME/NS records are protected by type and prefix anyway; this adds names).
	ProtectedDNSNames []string `toml:"protected_dns_names"`
	// EmailForwardAllow: the only addresses email routing may forward to (rules and catch-all)
	// or register as destination addresses (cf.email). Empty: none.
	EmailForwardAllow []string `toml:"email_forward_allow"`
	// WorkerBindings lists the data bindings (D1, R2, KV, services, queues, ...) a Worker
	// script or Pages project may have when deployed through a cf.workers.deploy / cf.pages
	// grant. Without an entry: no data bindings at all.
	WorkerBindings []CFBindings `toml:"worker_bindings"`

	Zones       []CFObject `toml:"zones"`        // [[cloudflare.zones]] name, id
	Tunnels     []CFObject `toml:"tunnels"`      // [[cloudflare.tunnels]] name, id (a second tunnel is deliberately absent)
	D1Databases []CFObject `toml:"d1_databases"` // [[cloudflare.d1_databases]] name, id

	// Scopes narrows built-in scopes: [cloudflare.scopes."cf.read"] ... Unknown scope names
	// are a config error. Nothing here can widen a scope (docs/CLOUDFLARE.md section 6).
	Scopes map[string]CFScopeOverride `toml:"scopes"`
}

// CFBindings is one [[cloudflare.worker_bindings]] entry: exactly one of Script and
// PagesProject, and the bindings allowed for it as "<kind>:<value>" (kinds in BindingKinds;
// d1 values are configured D1 database names).
type CFBindings struct {
	Script       string   `toml:"script"`
	PagesProject string   `toml:"pages_project"`
	Allow        []string `toml:"allow"`
}

// BindingKinds are the "<kind>:" prefixes worker_bindings entries may use.
var BindingKinds = map[string]bool{
	"d1": true, "r2": true, "kv": true, "service": true, "queue": true, "durable_object": true,
	"hyperdrive": true, "vectorize": true, "analytics_engine": true, "secrets_store": true,
	"dispatch_namespace": true, "mtls": true, "workflow": true, "pipeline": true, "send_email": true,
}

// AllowedBindings returns the allow list for a Worker script (pages=false) or a Pages
// project (pages=true).
func (c *Cloudflare) AllowedBindings(name string, pages bool) []string {
	var out []string
	for _, b := range c.WorkerBindings {
		if (!pages && b.Script == name && b.Script != "") || (pages && b.PagesProject == name && b.PagesProject != "") {
			out = append(out, b.Allow...)
		}
	}
	return out
}

// ProtectedHostnames is the union of protected_access_hostnames and protected_dns_names,
// lower case, without a trailing dot.
func (c *Cloudflare) ProtectedHostnames() []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range append(append([]string{}, c.ProtectedAccessHostnames...), c.ProtectedDNSNames...) {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// Warnings lists Cloudflare settings that are valid but probably unintended (core logs them
// at start).
func (c *Cloudflare) Warnings() []string {
	if !c.Enabled {
		return nil
	}
	var w []string
	if len(c.ProtectedAccessHostnames) == 0 {
		w = append(w, "cloudflare.protected_access_hostnames is empty: no hostname (e.g. the identity provider's) is protected from Access apps, Workers routes, custom domains or tunnel changes")
	}
	if c.TraefikOrigin == "" {
		w = append(w, "cloudflare.traefik_origin is empty: the tunnel-traefik-sni guard does not apply")
	}
	return w
}

// CFObject is a named Cloudflare object (zone, tunnel, D1 database).
type CFObject struct {
	Name string `toml:"name"`
	ID   string `toml:"id"`
}

// CFScopeOverride narrows one built-in scope. Zero values mean "keep the built-in value".
type CFScopeOverride struct {
	Disabled      bool     `toml:"disabled"`        // scope not offered at all
	MaxTTLSeconds int      `toml:"max_ttl_seconds"` // may only lower the built-in maximum
	DefaultTTL    int      `toml:"default_ttl_seconds"`
	NoAutoApprove bool     `toml:"no_auto_approve"` // turn auto-approval off (cf.read, cf.cache.purge)
	NoStanding    bool     `toml:"no_standing"`     // turn "approve similar" off
	NoTokenMode   bool     `toml:"no_token_mode"`   // proxy only
	ExtraDeny     []string `toml:"extra_deny"`      // more "METHOD /path/template" deny entries
}

var (
	hex32RE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	cfNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)
	credRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9*_]([a-z0-9*_-]{0,62})(\.[a-z0-9*_]([a-z0-9*_-]{0,62}))*$`)
	emailRE  = regexp.MustCompile(`^[a-z0-9.!#$%&'*+/=?^_{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$`)
)

// CFDefaults fills unset Cloudflare values.
func (c *Cloudflare) applyDefaults() {
	if c.APIBase == "" {
		c.APIBase = "https://api.cloudflare.com/client/v4"
	}
	c.APIBase = strings.TrimRight(c.APIBase, "/")
	if c.SnapshotRetentionDays == 0 {
		c.SnapshotRetentionDays = 7
	}
	if c.RatePerMinute == 0 {
		c.RatePerMinute = 600
	}
	if c.WriteRatePerMinute == 0 {
		c.WriteRatePerMinute = 60
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 2 << 20
	}
	if c.UploadMaxBodyBytes == 0 {
		c.UploadMaxBodyBytes = 100 << 20
	}
}

func (c *Cloudflare) validate() error {
	c.applyDefaults()
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.APIBase)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && c.AllowInsecureAPIBase)) {
		return fmt.Errorf("config: cloudflare.api_base must be an https URL")
	}
	if !hex32RE.MatchString(c.AccountID) {
		return fmt.Errorf("config: cloudflare.account_id must be 32 lowercase hex characters")
	}
	if (c.ProxyTokenCredential == "") == (c.ProxyTokenFile == "") {
		return fmt.Errorf("config: set exactly one of cloudflare.proxy_token_credential and proxy_token_file")
	}
	if c.MinterTokenCredential != "" && c.MinterTokenFile != "" {
		return fmt.Errorf("config: set at most one of cloudflare.minter_token_credential and minter_token_file")
	}
	for _, cr := range []string{c.ProxyTokenCredential, c.MinterTokenCredential} {
		if cr != "" && !credRE.MatchString(cr) {
			return fmt.Errorf("config: credential name %q invalid", cr)
		}
	}
	for _, n := range c.TokenIPCondition {
		if _, _, err := net.ParseCIDR(n); err != nil {
			return fmt.Errorf("config: cloudflare.token_ip_condition entry %q is not a CIDR", n)
		}
	}
	if c.SnapshotRetentionDays < 1 || c.SnapshotRetentionDays > 7 {
		return fmt.Errorf("config: cloudflare.snapshot_retention_days must be 1..7")
	}
	if c.RatePerMinute < 1 || c.WriteRatePerMinute < 1 || c.MaxBodyBytes < 1 || c.UploadMaxBodyBytes < 1 {
		return fmt.Errorf("config: cloudflare rate and body limits must be positive")
	}
	check := func(what string, objs []CFObject, idRE *regexp.Regexp) error {
		seen := map[string]bool{}
		for _, o := range objs {
			if !cfNameRE.MatchString(o.Name) || !idRE.MatchString(o.ID) {
				return fmt.Errorf("config: cloudflare.%s entry %q/%q invalid", what, o.Name, o.ID)
			}
			if seen[o.Name] || seen["id:"+o.ID] {
				return fmt.Errorf("config: cloudflare.%s: duplicate %q", what, o.Name)
			}
			seen[o.Name], seen["id:"+o.ID] = true, true
		}
		return nil
	}
	if err := check("zones", c.Zones, hex32RE); err != nil {
		return err
	}
	if err := check("tunnels", c.Tunnels, uuidRE); err != nil {
		return err
	}
	if err := check("d1_databases", c.D1Databases, uuidRE); err != nil {
		return err
	}
	for _, h := range c.ProtectedHostnames() {
		if !hostRE.MatchString(h) {
			return fmt.Errorf("config: cloudflare protected hostname %q invalid (plain DNS name, '*' wildcards allowed)", h)
		}
	}
	for _, e := range c.EmailForwardAllow {
		if !emailRE.MatchString(strings.ToLower(e)) {
			return fmt.Errorf("config: cloudflare.email_forward_allow entry %q is not an email address", e)
		}
	}
	for _, b := range c.WorkerBindings {
		if (b.Script == "") == (b.PagesProject == "") {
			return fmt.Errorf("config: each cloudflare.worker_bindings entry needs exactly one of script and pages_project")
		}
		for _, a := range b.Allow {
			k, v, ok := strings.Cut(a, ":")
			if !ok || v == "" || !BindingKinds[k] || strings.ContainsAny(v, " \t\n") {
				return fmt.Errorf("config: cloudflare.worker_bindings allow entry %q: want \"<kind>:<value>\" (kinds: d1, r2, kv, service, queue, durable_object, ...)", a)
			}
			if k == "d1" {
				if _, ok := c.D1(v); !ok {
					return fmt.Errorf("config: cloudflare.worker_bindings allow entry %q: D1 database %q is not in cloudflare.d1_databases", a, v)
				}
			}
		}
	}
	for name, o := range c.Scopes {
		if o.MaxTTLSeconds < 0 || o.DefaultTTL < 0 {
			return fmt.Errorf("config: cloudflare.scopes.%q: negative ttl", name)
		}
		// Whether name is a built-in scope, and whether the TTLs only narrow it, is checked
		// by internal/server/cfscope.NewCatalogue at start (config cannot import it).
	}
	return nil
}

// Zone, Tunnel and D1 look up a configured object by name.
func (c *Cloudflare) Zone(name string) (CFObject, bool)   { return findObj(c.Zones, name) }
func (c *Cloudflare) Tunnel(name string) (CFObject, bool) { return findObj(c.Tunnels, name) }
func (c *Cloudflare) D1(name string) (CFObject, bool)     { return findObj(c.D1Databases, name) }

func findObj(objs []CFObject, name string) (CFObject, bool) {
	for _, o := range objs {
		if o.Name == name {
			return o, true
		}
	}
	return CFObject{}, false
}
