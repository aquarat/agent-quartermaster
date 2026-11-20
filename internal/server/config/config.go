// Package config loads and validates aqmasd's TOML configuration.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// DefaultPath is where aqmasd looks for its configuration unless -config is given.
const DefaultPath = "/etc/aqmas/config.toml"

// Config is the whole aqmasd configuration.
type Config struct {
	ListenAgent   string   `toml:"listen_agent"`    // agent API (mTLS), default ":8443"
	ListenWeb     string   `toml:"listen_web"`      // web UI + API, default "127.0.0.1:8080"
	DataDir       string   `toml:"data_dir"`        // default "/var/lib/aqmas"
	PublicBaseURL string   `toml:"public_base_url"` // e.g. https://approvals.example.com
	OwnerName     string   `toml:"owner_name"`      // display name of the owner
	TLSSANs       []string `toml:"tls_sans"`        // SANs for the agent-API server certificate
	// ClientCertDays is the validity of host client certificates issued at enrollment.
	ClientCertDays int `toml:"client_cert_days"`

	TTL     TTL      `toml:"ttl"`
	Ntfy    Ntfy     `toml:"ntfy"`
	Access  Access   `toml:"access"`
	Targets []Target `toml:"targets"`
}

// TTL is the grant lifetime policy.
type TTL struct {
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
}

// Enabled reports whether Access validation is configured.
func (a Access) Enabled() bool { return a.TeamDomain != "" && a.AUD != "" }

// Target is a host (or service) aqmasd may issue SSH certificates for.
type Target struct {
	Name        string   `toml:"name"`
	Address     string   `toml:"address"`
	Port        int      `toml:"port"`
	Users       []string `toml:"users"`
	HostKey     string   `toml:"host_key"`     // pinned host key, emitted as a known_hosts line
	ForgejoUser string   `toml:"forgejo_user"` // Forgejo targets: certificate principal is this username
	HighRisk    bool     `toml:"high_risk"`    // shown as risk "high" in the UI
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

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
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
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("config: public_base_url must be https://<host> without port or path, got %q", c.PublicBaseURL)
	}
	c.PublicBaseURL = "https://" + u.Host
	if c.DataDir == "" {
		return fmt.Errorf("config: data_dir is required")
	}
	t := &c.TTL
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
	if c.Access.TeamDomain != "" && strings.ContainsAny(c.Access.TeamDomain, "/:") {
		return fmt.Errorf("config: access.team_domain is a bare host name, e.g. example.cloudflareaccess.com")
	}
	for _, san := range c.TLSSANs {
		if net.ParseIP(san) == nil && !ValidName(san) {
			return fmt.Errorf("config: tls_sans entry %q is neither an IP nor a host name", san)
		}
	}
	seen := map[string]bool{}
	for i := range c.Targets {
		tg := &c.Targets[i]
		if !ValidName(tg.Name) {
			return fmt.Errorf("config: target name %q invalid", tg.Name)
		}
		if seen[tg.Name] {
			return fmt.Errorf("config: duplicate target %q", tg.Name)
		}
		seen[tg.Name] = true
		if tg.Address == "" {
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
		if tg.ForgejoUser != "" && !ValidUser(tg.ForgejoUser) {
			return fmt.Errorf("config: target %q forgejo_user invalid", tg.Name)
		}
		if tg.HostKey != "" {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tg.HostKey)); err != nil {
				return fmt.Errorf("config: target %q host_key: %v", tg.Name, err)
			}
		}
	}
	return nil
}
