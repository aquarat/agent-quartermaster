// Package api holds the wire types shared by aqmasd (server), aqmas (CLI) and the web UI.
// It is the contract between the parallel workstreams: change it only by agreement, and keep
// docs/API.md in step.
package api

import "time"

// Error is the body of every non-2xx response.
type Error struct {
	Code    string `json:"error"`   // bad_request, unauthenticated, forbidden, not_found, conflict, expired, denied, internal
	Message string `json:"message"` // human text
}

// Status values for requests, enrollments and grants.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusRevoked  = "revoked"
)

// Request kinds. Only KindSSH exists in milestone 1.
const (
	KindSSH = "ssh"
)

// ---- Host enrollment (agent API, no client certificate) ----

type EnrollRequest struct {
	Hostname               string   `json:"hostname"`
	CSRPEM                 string   `json:"csr_pem"`
	SSHHostKeyFingerprints []string `json:"ssh_host_key_fingerprints,omitempty"`
	Note                   string   `json:"note,omitempty"`
}

type EnrollResponse struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	ApproveURL  string `json:"approve_url"`
	PollAfterMS int    `json:"poll_after_ms"`
}

type EnrollStatus struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	ClientCertPEM string `json:"client_cert_pem,omitempty"` // returned once
	CACertPEM     string `json:"ca_cert_pem,omitempty"`     // client CA, returned with the cert
}

// ---- Access requests (agent API, client certificate required) ----

type Requester struct {
	Tool      string `json:"tool"` // claude-code, opencode, owner-cli, other (self-reported, untrusted)
	SessionID string `json:"session_id,omitempty"`
	CWD       string `json:"cwd,omitempty"`
	PID       int    `json:"pid,omitempty"`
	User      string `json:"user"`
}

type SSHRequest struct {
	TargetHost string `json:"target_host"`
	LoginUser  string `json:"login_user"`
	PublicKey  string `json:"public_key"` // ephemeral ed25519, authorized_keys format
}

type AccessRequest struct {
	Kind       string      `json:"kind"`
	SSH        *SSHRequest `json:"ssh,omitempty"`
	Reason     string      `json:"reason"` // untrusted, display only, max 500 chars
	TTLSeconds int         `json:"ttl_seconds"`
	Requester  Requester   `json:"requester"`
}

type RequestCreated struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	ApproveURL  string    `json:"approve_url"`
	PollAfterMS int       `json:"poll_after_ms"`
	ExpiresAt   time.Time `json:"expires_at"` // when an undecided request expires
}

type SSHGrant struct {
	Certificate    string   `json:"certificate"` // OpenSSH user certificate, authorized_keys format
	Principals     []string `json:"principals"`
	TargetHost     string   `json:"target_host"`
	TargetAddress  string   `json:"target_address"`
	TargetPort     int      `json:"target_port"`
	LoginUser      string   `json:"login_user"`
	KnownHostsLine string   `json:"known_hosts_line,omitempty"`
}

type Grant struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SSH       *SSHGrant `json:"ssh,omitempty"`
}

type RequestStatus struct {
	ID           string     `json:"id"`
	Kind         string     `json:"kind"`
	Status       string     `json:"status"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`
	Grant        *Grant     `json:"grant,omitempty"`
}

type GrantSummary struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"`
	TargetHost string    `json:"target_host,omitempty"`
	LoginUser  string    `json:"login_user,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
}

type GrantList struct {
	Grants []GrantSummary `json:"grants"`
}

// ---- Web UI API ----

type PendingSSH struct {
	TargetHost     string `json:"target_host"`
	LoginUser      string `json:"login_user"`
	KeyFingerprint string `json:"key_fingerprint"`
}

type PendingItem struct {
	ID                string      `json:"id"`
	Kind              string      `json:"kind"` // ssh, enrollment
	CreatedAt         time.Time   `json:"created_at"`
	ExpiresAt         time.Time   `json:"expires_at"`
	RequestingHost    string      `json:"requesting_host"`
	RequestingAddress string      `json:"requesting_address"`
	Requester         Requester   `json:"requester"`
	Reason            string      `json:"reason"`
	SSH               *PendingSSH `json:"ssh,omitempty"`
	TTLRequested      int         `json:"ttl_requested"`
	TTLMax            int         `json:"ttl_max"`
	Risk              string      `json:"risk"` // normal, high
	SimilarRecent     int         `json:"similar_recent"`
}

type StandingApproval struct {
	ID             string    `json:"id"`
	RequestingHost string    `json:"requesting_host"`
	Kind           string    `json:"kind"`
	TargetHost     string    `json:"target_host"`
	LoginUser      string    `json:"login_user"`
	MaxTTLSeconds  int       `json:"max_ttl_seconds"`
	ExpiresAt      time.Time `json:"expires_at"`
	Uses           int       `json:"uses"`
}

type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"` // owner, host:<name>, system
	Action string    `json:"action"`
	Object string    `json:"object"` // request:<id>, grant:<id>, enrollment:<id>, ...
	Detail string    `json:"detail,omitempty"`
}

type UIOwner struct {
	Name     string `json:"name"`
	Passkeys int    `json:"passkeys"`
}

type UIState struct {
	Owner    UIOwner            `json:"owner"`
	Pending  []PendingItem      `json:"pending"`
	Standing []StandingApproval `json:"standing"`
	Recent   []AuditEntry       `json:"recent"`
}

// ChallengeRequest asks for a WebAuthn challenge that commits to one exact action.
type ChallengeRequest struct {
	Action        string `json:"action"` // approve, deny, revoke
	TTLSeconds    int    `json:"ttl_seconds,omitempty"`
	StandingHours int    `json:"standing_hours,omitempty"`
}

// ChallengeResponse carries the WebAuthn PublicKeyCredentialRequestOptions as raw JSON so the
// browser can pass it to navigator.credentials.get after base64url decoding, plus the exact
// canonical action text the challenge commits to (shown to the owner).
type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Canonical   string `json:"canonical"`
	PublicKey   any    `json:"public_key"`
}

// DecideRequest carries the assertion for a previously issued challenge.
type DecideRequest struct {
	ChallengeID string `json:"challenge_id"`
	Assertion   any    `json:"assertion"` // PublicKeyCredential JSON from the browser
}
