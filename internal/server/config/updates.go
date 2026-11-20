package config

import "github.com/aquarat/agent-quartermaster/internal/release"

type Updates struct {
	Repo      string         `toml:"repo"`
	DeployKey string         `toml:"deploy_key"`
	CacheDir  string         `toml:"cache_dir"`
	SpoolDir  string         `toml:"spool_dir"`
	Forgejo   release.Source `toml:"forgejo"`
	GitHub    release.Source `toml:"github"`
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
