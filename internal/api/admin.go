package api

import "time"

const ClassAgent = "agent"
const ClassOwner = "owner-device"

type HostInfo struct {
	ID            string     `json:"id"` // enrollment id, never recycled on replacement
	Name          string     `json:"name"`
	Class         string     `json:"class"`
	Address       string     `json:"address"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
	NotBefore     time.Time  `json:"not_before"`
	NotAfter      time.Time  `json:"not_after"`
	RevokedAt     *time.Time `json:"revoked_at"`
	LastRequestAt *time.Time `json:"last_request_at"`
}

// HelpConfig is what the Help page needs to print commands for this installation.
type HelpConfig struct {
	AgentAPIURL string `json:"agent_api_url"`
	// CLIDownloadBaseURL is where the CLI executables are downloaded from, without a
	// trailing slash: the configured cli_download_base_url, else the public GitHub release
	// of the running version. CLIDownloadSource says which ("config", "github", or "" with
	// no address). Neither is ever derived from a request.
	CLIDownloadBaseURL string `json:"cli_download_base_url"`
	CLIDownloadSource  string `json:"cli_download_source"`
	// ReleaseVersion is the release this broker runs ("" for a development build).
	ReleaseVersion string `json:"release_version,omitempty"`
	// CLISHA256 maps each CLI asset name to the SHA-256 in the verified record of the
	// installed release. Absent unless that record exists and is of the running release.
	// aqmas-darwin-amd64 (listed in SHA256SUMS.extra) is present only when the record has
	// that file's digests: not in a record written by a 0.9.2 broker's installer.
	CLISHA256 map[string]string `json:"cli_sha256,omitempty"`
	// CLISHA256Sources is how many published sources that record holds agreeing manifests
	// of (1: GitHub alone, 2: GitHub and a second source); absent with CLISHA256.
	CLISHA256Sources int    `json:"cli_sha256_sources,omitempty"`
	CAPin            string `json:"ca_pin"`
	OwnerMaxSeconds  int    `json:"owner_max_seconds"`
}

type ResolvedTarget struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	MaxSeconds int    `json:"max_seconds"` // host-class policy, before per-target cap
}
