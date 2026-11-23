package api

import (
	"encoding/json"
	"time"
)

// Access to the bastion itself (docs/BASTION-ACCESS.md). A bastion session is its own request
// kind: it is never an SSH target, never in the organisation catalogue, and no standing rule,
// policy auto, batch or window can decide it.

// KindBastion is the request and grant kind of a bastion session.
const KindBastion = "bastion"

// KindSetup is the pending-item kind of a maintenance task queued by an agent.
const KindSetup = "setup"

// Bastion levels.
const (
	LevelInspect = "inspect" // the forced-command account; normal card
	LevelRoot    = "root"    // the owner's admin account; red card
)

// BastionInfo is the body of GET /v1/bastion (404 while bastion access is not installed).
type BastionInfo struct {
	Name              string `json:"name"`
	Address           string `json:"address"`
	Port              int    `json:"port"`
	InspectUser       string `json:"inspect_user"`
	AdminUser         string `json:"admin_user"`
	RootAllowed       bool   `json:"root_allowed"` // this host is on the bastion allowlist
	InspectMaxSeconds int    `json:"inspect_max_seconds"`
	InspectDefault    int    `json:"inspect_default_seconds"`
	RootMaxSeconds    int    `json:"root_max_seconds"`
	// Tasks are the maintenance tasks this host may queue (POST /v1/setup-requests).
	Tasks []string `json:"tasks"`
}

// BastionRequest is the body of POST /v1/bastion/requests. The login user is derived from the
// level by the server; the reason is required.
type BastionRequest struct {
	Level      string    `json:"level"`
	PublicKey  string    `json:"public_key"` // ephemeral ed25519, authorized_keys format
	Reason     string    `json:"reason"`
	TTLSeconds int       `json:"ttl_seconds"`
	Requester  Requester `json:"requester"`
}

// PendingBastion is the bastion detail of a PendingItem with kind "bastion". The card is
// rendered from the signed canonical text; this is what the page expects that text to say.
type PendingBastion struct {
	Level          string `json:"level"`
	Target         string `json:"target"`
	TargetAddress  string `json:"target_address"`
	TargetPort     int    `json:"target_port"`
	LoginUser      string `json:"login_user"`
	Principal      string `json:"principal"`
	KeyFingerprint string `json:"key_fingerprint"`
	HostID         string `json:"host_id"` // the requester's enrollment
	SSHCA          string `json:"ssh_ca"`
	HostKey        string `json:"host_key"`
	CertProfile    string `json:"cert_profile"`
	Sealed         bool   `json:"sealed"`
	// OpenBuckets are the labels of the buckets open right now, sorted (root only).
	OpenBuckets  []string `json:"open_buckets"`
	AlertChannel bool     `json:"alert_channel"` // root only
}

// BastionHost is one enrolled host on Admin → Bastion access.
type BastionHost struct {
	ID      string `json:"id"` // enrollment ID
	Name    string `json:"name"`
	Class   string `json:"class"`
	Address string `json:"address"` // enrollment address
	Allowed bool   `json:"allowed"`
	// AllowedAddress is the address root's list pins for this host (requests and logins).
	AllowedAddress string `json:"allowed_address,omitempty"`
	// Gone: listed, but no longer a live enrollment (revoked, replaced or expired).
	Gone bool `json:"gone,omitempty"`
}

// BastionSession is one bastion grant, newest first.
type BastionSession struct {
	GrantID        string     `json:"grant_id"`
	Level          string     `json:"level"`
	RequestingHost string     `json:"requesting_host"`
	LoginUser      string     `json:"login_user"`
	NotBefore      time.Time  `json:"not_before"`
	NotAfter       time.Time  `json:"not_after"`
	Status         string     `json:"status"` // active, expired, revoked
	CloseBuckets   bool       `json:"close_buckets"`
	Closed         int        `json:"closed_count"`
	Alert          string     `json:"alert"` // "", sent, failed, off (no notification channel)
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
}

// BastionView is the body of GET /api/ui/bastion.
type BastionView struct {
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name,omitempty"`
	Address     string `json:"address,omitempty"`
	Port        int    `json:"port,omitempty"`
	AdminUser   string `json:"admin_user,omitempty"`
	InspectUser string `json:"inspect_user"`
	SSHCA       string `json:"ssh_ca"` // fingerprint the access task signs
	Sealed      bool   `json:"sealed"`
	// AlertChannel: a push channel exists; without one a root approval alerts nobody.
	AlertChannel bool             `json:"alert_channel"`
	Hosts        []BastionHost    `json:"hosts"`
	Sessions     []BastionSession `json:"sessions"`
	// RootUntil is set while an unexpired, unrevoked root certificate exists.
	RootUntil *time.Time `json:"root_until,omitempty"`
	// Tasks are the ids of the Setup tasks shown in this section, in order.
	Tasks []string `json:"tasks"`
}

// BastionDecision is the response of a decide on a bastion request.
type BastionDecision struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Level  string `json:"level"`
	Closed int    `json:"closed_count"` // buckets closed before the certificate was issued
	Alert  string `json:"alert"`        // root: sent, failed, off
}

// SetupRequest is the body of POST /v1/setup-requests: an agent queues a routine maintenance
// task for the owner to approve. Nothing runs without the owner's tap.
type SetupRequest struct {
	Task      string          `json:"task"`
	Params    json.RawMessage `json:"params,omitempty"`
	Reason    string          `json:"reason"`
	Requester Requester       `json:"requester"`
}

// SetupRunStatus is the runner's public report of one approved run.
type SetupRunStatus struct {
	State    string            `json:"state"` // queued, running, waiting, done, failed, refused
	Step     string            `json:"step,omitempty"`
	Message  string            `json:"message,omitempty"`
	Log      []string          `json:"log,omitempty"`
	Result   map[string]string `json:"result,omitempty"`
	Finished string            `json:"finished_at,omitempty"`
}

// SetupRequestStatus is the body of GET /v1/setup-requests/{id}.
type SetupRequestStatus struct {
	ID           string          `json:"id"`
	Task         string          `json:"task"`
	Status       string          `json:"status"` // pending, approved, denied, expired, cancelled
	DecisionNote string          `json:"decision_note,omitempty"`
	Run          *SetupRunStatus `json:"run,omitempty"`
}

// PendingSetup is the detail of a PendingItem with kind "setup".
type PendingSetup struct {
	Task       string   `json:"task"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	Reversible string   `json:"reversible"`
	Warning    string   `json:"warning,omitempty"`
	Params     string   `json:"params"` // the task's canonical parameter text
	// Blocked says why the task cannot be approved right now ("" when it can).
	Blocked string `json:"blocked,omitempty"`
}
