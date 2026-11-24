package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/release"
)

// Updates is the [updates] table. GitHub is the one release source every installation has
// (its location is a compiled default; [updates.github] api overrides it for a fork). A
// second, independent source exists only when [updates.second] api names it: no host name
// of one is compiled in.
type Updates struct {
	// Repo is the git remote releases are fetched and rebuilt from; setting it turns update
	// discovery on. https://… (anonymous, a public repository) or ssh://… with DeployKey.
	Repo      string `toml:"repo"`
	DeployKey string `toml:"deploy_key"`
	CacheDir  string `toml:"cache_dir"`
	SpoolDir  string `toml:"spool_dir"`
	// GitHub: api overrides the compiled default; token_file only while the repository is private.
	GitHub release.Source `toml:"github"`
	// Second is the optional second source: the release API base of a Forgejo/Gitea-compatible
	// forge including the repository path (https://HOST/api/v1/repos/OWNER/NAME), and an
	// optional read token. When api is set its manifests must agree with GitHub's, and it
	// being unreachable blocks; when unset only GitHub and the local rebuild are compared.
	Second release.Source `toml:"second"`
	// Legacy is [updates.forgejo], the name of [updates.second] up to 0.8.1. Parse folds it
	// into Second, so nothing else reads it.
	Legacy release.Source `toml:"forgejo"`
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

// Sources are the release sources this configuration compares.
func (u Updates) Sources() release.Sources {
	return release.Sources{GitHub: u.GitHub, Second: u.Second}
}

// SecondIgnored reports a second-source table that names a token but no API: the source is
// then not configured and not used (up to 0.8.1 a compiled default stood in for the API).
func (u Updates) SecondIgnored() bool { return u.Second.API == "" && u.Second.TokenFile != "" }

// normalize folds the legacy table name into Second and checks the shape of every address:
// https only, no credentials, bounded length. What the addresses are is the operator's call.
func (u *Updates) normalize() error {
	if u.Legacy != (release.Source{}) {
		if u.Second != (release.Source{}) && u.Second != u.Legacy {
			return fmt.Errorf("config: [updates.forgejo] is the old name of [updates.second]; keep only [updates.second]")
		}
		u.Second, u.Legacy = u.Legacy, release.Source{}
	}
	if u.Repo != "" && release.GitProtocol(u.Repo) == "" {
		return fmt.Errorf("config: updates.repo must be https://HOST/OWNER/NAME.git or ssh://git@HOST/OWNER/NAME.git, without a password")
	}
	for name, src := range map[string]release.Source{"github": u.GitHub, "second": u.Second} {
		if src.API != "" && !release.ValidAPI(src.API) {
			return fmt.Errorf("config: updates.%s.api must be a plain https URL without credentials (at most 512 characters)", name)
		}
		if src.TokenFile != "" && (!filepath.IsAbs(src.TokenFile) || len(src.TokenFile) > 512) {
			return fmt.Errorf("config: updates.%s.token_file must be an absolute path", name)
		}
	}
	if u.Second.API != "" && !strings.Contains(u.Second.API, "/api/v1/repos/") {
		return fmt.Errorf("config: updates.second.api must be a Forgejo/Gitea release API: https://HOST/api/v1/repos/OWNER/NAME")
	}
	return nil
}
