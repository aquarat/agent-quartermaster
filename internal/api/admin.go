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

type HelpConfig struct {
	AgentAPIURL        string `json:"agent_api_url"`
	CLIDownloadBaseURL string `json:"cli_download_base_url"`
	CAPin              string `json:"ca_pin"`
	OwnerMaxSeconds    int    `json:"owner_max_seconds"`
}

type ResolvedTarget struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	MaxSeconds int    `json:"max_seconds"` // host-class policy, before per-target cap
}
