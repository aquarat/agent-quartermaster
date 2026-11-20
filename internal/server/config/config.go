// Package config loads and validates aqmasd's TOML configuration.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/sshtarget"
)

// DefaultPath is where aqmasd looks for its configuration unless -config is given.
const DefaultPath = "/etc/aqmas/config.toml"

// Config is the whole aqmasd configuration.
type Config struct {
	AgentAPIURL        string   `toml:"agent_api_url"`
	CLIDownloadBaseURL string   `toml:"cli_download_base_url"`
	ListenAgent        string   `toml:"listen_agent"`    // agent API (mTLS), default ":8443"
	ListenWeb          string   `toml:"listen_web"`      // web UI + API, default "127.0.0.1:8080"
	DataDir            string   `toml:"data_dir"`        // default "/var/lib/aqmas"
	PublicBaseURL      string   `toml:"public_base_url"` // e.g. https://approvals.example.com
	OwnerName          string   `toml:"owner_name"`      // display name of the owner
	TLSSANs            []string `toml:"tls_sans"`        // SANs for the agent-API server certificate
	// ClientCertDays is the validity of host client certificates issued at enrollment.
	ClientCertDays int `toml:"client_cert_days"`

	TTL     TTL      `toml:"ttl"`
	Ntfy    Ntfy     `toml:"ntfy"`
	Access  Access   `toml:"access"`
	Targets []Target `toml:"targets"`
	// Cloudflare configures milestone 2 (docs/CLOUDFLARE.md section 6). Absent or
	// enabled=false: kind "cloudflare" requests are refused and /cf/ is not served.
	Cloudflare Cloudflare `toml:"cloudflare"`
}

// TTL is the grant lifetime policy.
type TTL struct {
	OwnerMaxSeconds         int `toml:"owner_max_seconds"`
	OwnerMaxStandingHours   int `toml:"owner_max_standing_hours"`
	DefaultSeconds          int `toml:"default_seconds"`           // 1800
	MaxSeconds              int `toml:"max_seconds"`               // 28800
	MinSeconds              int `toml:"min_seconds"`               // 60
	PendingExpirySeconds    int `toml:"pending_expiry_seconds"`    // 600: undecided requests expire
	EnrollmentExpirySeconds int `toml:"enrollment_expiry_seconds"` // 3600: undecided enrollments expire
	MaxStandingHours        int `toml:"max_standing_hours"`        // 24
}

// Ntfy configures push notifications. Empty TopicURL disables them.
type Ntfy struct {
	TopicURL string `toml:"topic_url"`
}

// Access configures Cloudflare Access JWT validation on the web listener (optional).
type Access struct {
	TeamDomain string `toml:"team_domain"` // e.g. "example.cloudflareaccess.com"
	AUD        string `toml:"aud"`
	// OwnerEmail, when set, must equal the Access token's email claim.
	OwnerEmail string `toml:"owner_email"`
}

// Enabled reports whether Access validation is configured.
func (a Access) Enabled() bool { return a.TeamDomain != "" && a.AUD != "" }

// Target is a host (or service) aqmasd may issue SSH certificates for.
type Target struct {
	Aliases []string `toml:"aliases"`
	Name    string   `toml:"name"`
	Address string   `toml:"address"`
	Port    int      `toml:"port"`
	Users   []string `toml:"users"`
	HostKey string   `toml:"host_key"` // pinned host key, emitted as a known_hosts line
	// PrincipalOverride replaces the "<login_user>@<name>" principal, e.g. for Forgejo, which
	// maps a principal registered on a user account ("Manage SSH Certificate Principals").
	PrincipalOverride string `toml:"principal"`
	ForgejoUser       string `toml:"forgejo_user"` // deprecated alias of principal (docs/HOSTS.md)
	// MaxTTLSeconds caps grants for this target below the global max (0: no extra cap). Useful
	// where source-address is not enforced (Forgejo's built-in SSH server).
	MaxTTLSeconds int  `toml:"max_ttl_seconds"`
	HighRisk      bool `toml:"high_risk"` // shown as risk "high" in the UI
}

// AllowsUser reports whether login user u is configured for t.
func (t Target) AllowsUser(u string) bool {
	for _, x := range t.Users {
		if x == u {
			return true
		}
	}
	return false
}

// Principal returns the certificate principal for login user u on this target.
func (t Target) Principal(u string) string {
	if t.PrincipalOverride != "" {
		return t.PrincipalOverride
	}
	if t.ForgejoUser != "" {
		return t.ForgejoUser
	}
	return u + "@" + t.Name
}

// Target looks up a target by name.
func (c *Config) Target(name string) (Target, bool) {
	for _, t := range c.Targets {
		if t.Name == name {
			return t, true
		}
	}
	return Target{}, false
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var principalRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
var sanRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)
var userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidName reports whether s is acceptable as a host or target name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ValidUser reports whether s is acceptable as a login user name.
func ValidUser(s string) bool { return userRE.MatchString(s) }

// Load reads and validates the configuration at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses and validates a TOML configuration.
func Parse(b []byte) (*Config, error) {
	c := Defaults()
	md, err := toml.Decode(string(b), c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("config: unknown keys: %v", und)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Defaults returns a configuration with every default filled in.
func Defaults() *Config {
	return &Config{
		ListenAgent:    ":8443",
		ListenWeb:      "127.0.0.1:8080",
		DataDir:        "/var/lib/aqmas",
		OwnerName:      "owner",
		ClientCertDays: 730,
		TTL: TTL{
			OwnerMaxSeconds: 86400, OwnerMaxStandingHours: 720,
			DefaultSeconds:          1800,
			MaxSeconds:              28800,
			MinSeconds:              60,
			PendingExpirySeconds:    600,
			EnrollmentExpirySeconds: 3600,
			MaxStandingHours:        24,
		},
	}
}

// Validate checks the configuration for consistency.
func (c *Config) Validate() error {
	for key, v := range map[string]string{"agent_api_url": c.AgentAPIURL, "cli_download_base_url": c.CLIDownloadBaseURL} {
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || !sshtarget.ValidHost(u.Hostname()) || u.User != nil || strings.ContainsAny(v, "?#") || (key == "agent_api_url" && strings.Trim(u.Path, "/") != "") {
			return fmt.Errorf("config: invalid HTTPS URL for %s", key)
		}
	}
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("config: public_base_url must be https://<host> without port or path, got %q", c.PublicBaseURL)
	}
	c.PublicBaseURL = "https://" + u.Host
	if c.DataDir == "" {
		return fmt.Errorf("config: data_dir is required")
	}
	t := &c.TTL
	if t.OwnerMaxSeconds < t.DefaultSeconds || t.OwnerMaxStandingHours < 0 || int64(t.OwnerMaxSeconds) > int64((1<<63-1)/time.Second) || int64(t.OwnerMaxStandingHours) > int64((1<<63-1)/time.Hour) {
		return fmt.Errorf("config: invalid owner device limits")
	}
	if t.MinSeconds <= 0 || t.DefaultSeconds < t.MinSeconds || t.MaxSeconds < t.DefaultSeconds {
		return fmt.Errorf("config: ttl must satisfy 0 < min_seconds <= default_seconds <= max_seconds")
	}
	if t.PendingExpirySeconds <= 0 || t.EnrollmentExpirySeconds <= 0 || t.MaxStandingHours < 0 {
		return fmt.Errorf("config: ttl expiry values must be positive")
	}
	if c.ClientCertDays <= 0 {
		return fmt.Errorf("config: client_cert_days must be positive")
	}
	if c.Ntfy.TopicURL != "" {
		nu, err := url.Parse(c.Ntfy.TopicURL)
		if err != nil || (nu.Scheme != "https" && nu.Scheme != "http") || nu.Host == "" {
			return fmt.Errorf("config: ntfy.topic_url must be an http(s) URL")
		}
	}
	if (c.Access.TeamDomain == "") != (c.Access.AUD == "") {
		return fmt.Errorf("config: access.team_domain and access.aud must be set together")
	}
	if err := c.Cloudflare.validate(); err != nil {
		return err
	}
	if c.Access.TeamDomain != "" && strings.ContainsAny(c.Access.TeamDomain, "/:") {
		return fmt.Errorf("config: access.team_domain is a bare host name, e.g. example.cloudflareaccess.com")
	}
	for _, san := range c.TLSSANs {
		if net.ParseIP(san) == nil && !sanRE.MatchString(san) {
			return fmt.Errorf("config: tls_sans entry %q is neither an IP nor a host name", san)
		}
	}
	seen := map[string]bool{}
	principals := map[string]string{} // principal -> target that issues it
	for i := range c.Targets {
		tg := &c.Targets[i]
		if !ValidName(tg.Name) {
			return fmt.Errorf("config: target name %q invalid", tg.Name)
		}
		if seen[tg.Name] {
			return fmt.Errorf("config: duplicate target %q", tg.Name)
		}
		seen[tg.Name] = true
		if !sshtarget.ValidHost(tg.Address) {
			return fmt.Errorf("config: target %q needs an address", tg.Name)
		}
		if tg.Port == 0 {
			tg.Port = 22
		}
		if tg.Port < 1 || tg.Port > 65535 {
			return fmt.Errorf("config: target %q port out of range", tg.Name)
		}
		if len(tg.Users) == 0 {
			return fmt.Errorf("config: target %q needs at least one user", tg.Name)
		}
		for _, u := range tg.Users {
			if !ValidUser(u) {
				return fmt.Errorf("config: target %q user %q invalid", tg.Name, u)
			}
		}
		if tg.MaxTTLSeconds < 0 || (tg.MaxTTLSeconds > 0 && tg.MaxTTLSeconds < t.MinSeconds) {
			return fmt.Errorf("config: target %q max_ttl_seconds must be 0 (no cap) or at least ttl.min_seconds", tg.Name)
		}
		if tg.PrincipalOverride != "" && tg.ForgejoUser != "" && tg.PrincipalOverride != tg.ForgejoUser {
			return fmt.Errorf("config: target %q sets both principal and forgejo_user", tg.Name)
		}
		// A bare principal equal to a Unix login name would also log in to any host whose sshd
		// trusts the CA without an AuthorizedPrincipalsFile; require "<name>@<something>".
		p := tg.PrincipalOverride
		if p == "" {
			p = tg.ForgejoUser
		}
		if p != "" && (!principalRE.MatchString(p) || !strings.Contains(p, "@")) {
			return fmt.Errorf("config: target %q principal must look like <name>@<service>, e.g. alice@forgejo", tg.Name)
		}
		// One certificate must never open two targets: every principal belongs to one target.
		for _, u := range tg.Users {
			pr := tg.Principal(u)
			if other, dup := principals[pr]; dup && other != tg.Name {
				return fmt.Errorf("config: targets %q and %q would both issue principal %q", other, tg.Name, pr)
			}
			principals[pr] = tg.Name
		}
		if tg.HostKey != "" {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tg.HostKey)); err != nil {
				return fmt.Errorf("config: target %q host_key: %v", tg.Name, err)
			}
		}
	}
	// Shared addresses are allowed; every other spelling must identify a single target.
	reserved := map[string]string{}
	for _, tg := range c.Targets {
		reserved[sshtarget.Key(tg.Address)] = tg.Name
	}
	for _, tg := range c.Targets {
		for _, other := range c.Targets {
			if other.Name != tg.Name && sshtarget.Key(other.Address) == tg.Name {
				return fmt.Errorf("config: name %s shadows target address", tg.Name)
			}
		}
		reserved[tg.Name] = tg.Name
	}
	for _, tg := range c.Targets {
		for _, alias := range tg.Aliases {
			k := sshtarget.Key(alias)
			if !sshtarget.ValidHost(alias) || reserved[k] != "" {
				return fmt.Errorf("config: invalid or shadowing alias %q for %s", alias, tg.Name)
			}
			reserved[k] = tg.Name
		}
	}
	return nil
}

func (p TTL) ForHost(class string) TTL {
	if class == api.ClassOwner {
		p.MaxSeconds = p.OwnerMaxSeconds
		p.MaxStandingHours = p.OwnerMaxStandingHours
	}
	return p
}

func (c *Config) Resolve(selector, user string) (Target, error) {
	key, port, err := sshtarget.Split(selector)
	if err != nil {
		return Target{}, err
	}
	var matches []Target
	for _, t := range c.Targets {
		if port != 0 && port != t.Port {
			continue
		}
		if t.Name == key || sshtarget.Key(t.Address) == key || slices.ContainsFunc(t.Aliases, func(a string) bool { return sshtarget.Key(a) == key }) {
			matches = append(matches, t)
		}
	}
	if len(matches) == 0 {
		return Target{}, fmt.Errorf("unknown target_host or port")
	}
	var names []string
	var resolved Target
	for _, t := range matches {
		if t.AllowsUser(user) {
			names = append(names, t.Name)
			resolved = t
		}
	}
	switch len(names) {
	case 0:
		return Target{}, fmt.Errorf("login_user not allowed on this target")
	case 1:
		return resolved, nil
	}
	sort.Strings(names)
	return Target{}, fmt.Errorf("ambiguous target %q: %s; specify a target name or port", selector, strings.Join(names, ", "))
}
