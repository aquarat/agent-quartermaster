package config

import (
	"time"

	"github.com/aquarat/agent-quartermaster/internal/release"
)

type Updates struct {
	Repo      string         `toml:"repo"`
	DeployKey string         `toml:"deploy_key"`
	CacheDir  string         `toml:"cache_dir"`
	SpoolDir  string         `toml:"spool_dir"`
	Forgejo   release.Source `toml:"forgejo"`
	GitHub    release.Source `toml:"github"`
	// CheckMinutes is how often the broker looks for a new release (default 5, 1–1440).
	// A check is a git fetch from the forge; the release APIs are asked only when main
	// carries a newer VERSION.
	CheckMinutes int `toml:"check_minutes"`
}

// CheckInterval is the time between update checks.
func (u Updates) CheckInterval() time.Duration {
	m := u.CheckMinutes
	if m <= 0 {
		m = 5
	}
	return time.Duration(min(max(m, 1), 1440)) * time.Minute
}

func (u Updates) Cache() string {
	if u.CacheDir != "" {
		return u.CacheDir
	}
	return "/var/lib/aqmas-releases"
}
func (u Updates) Spool() string {
	if u.SpoolDir != "" {
		return u.SpoolDir
	}
	return "/var/spool/aqmas-update"
}
