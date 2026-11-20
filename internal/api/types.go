// Package api holds the wire types shared by aqmasd (server), aqmas (CLI) and the web UI.
// It is the contract between the parallel workstreams: change it only by agreement, and keep
// docs/API.md in step.
package api

import (
	"encoding/json"
	"time"
)

// Error is the body of every non-2xx response.
type Error struct {
	Code    string `json:"error"`   // see the Err* constants
	Message string `json:"message"` // human text
}

// Status values for requests, enrollments and grants.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusRevoked  = "revoked"
	// StatusCancelled: the requesting host withdrew a pending request (POST /v1/requests/{id}/cancel).
	StatusCancelled = "cancelled"
)

// Error codes (Error.Code).
const (
	ErrBadRequest      = "bad_request"
	ErrUnauthenticated = "unauthenticated"
	ErrForbidden       = "forbidden"
	ErrNotFound        = "not_found"
	ErrConflict        = "conflict"
	ErrExpired         = "expired"
	ErrDenied          = "denied"
	ErrRateLimited     = "rate_limited" // HTTP 429: too many pending requests/enrollments
	ErrInternal        = "internal"
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
	// RequestingHost is set in the web UI's state (who holds the access); the agent API's
	// GET /v1/grants omits it (always the calling host).
	RequestingHost string `json:"requesting_host,omitempty"`
}

// SSHCA is the body of GET /v1/ssh-ca: the SSH user CA that signs every grant certificate.
type SSHCA struct {
	PublicKey   string `json:"public_key"`  // authorized_keys format
	Fingerprint string `json:"fingerprint"` // SHA256:<base64>, as ssh-keygen -l prints it
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

// PendingEnrollment is the enrollment detail of a PendingItem with kind "enrollment".
type PendingEnrollment struct {
	CSRFingerprint         string   `json:"csr_fingerprint"`           // SHA256:<hex> of the CSR's PKIX public key
	SSHHostKeyFingerprints []string `json:"ssh_host_key_fingerprints"` // as reported by the host (untrusted)
	ReplacesExisting       bool     `json:"replaces_existing"`         // approving revokes the current host of that name
}

// PendingItem is an SSH request (kind "ssh") or a host enrollment (kind "enrollment") in the
// web UI. For enrollments requesting_host is the proposed name, reason the enroll note, and
// ttl_requested/ttl_max are 0.
type PendingItem struct {
	ID                string             `json:"id"`
	Kind              string             `json:"kind"` // ssh, enrollment
	CreatedAt         time.Time          `json:"created_at"`
	ExpiresAt         time.Time          `json:"expires_at"`
	RequestingHost    string             `json:"requesting_host"`
	RequestingAddress string             `json:"requesting_address"`
	Requester         Requester          `json:"requester"`
	Reason            string             `json:"reason"`
	SSH               *PendingSSH        `json:"ssh,omitempty"`
	TTLRequested      int                `json:"ttl_requested"`
	TTLMax            int                `json:"ttl_max"`
	Risk              string             `json:"risk"` // normal, high
	SimilarRecent     int                `json:"similar_recent"`
	Enrollment        *PendingEnrollment `json:"enrollment,omitempty"`
	// Status is set by GET /api/ui/requests/{id} and /api/ui/enrollments/{id} (the item may
	// have been decided since); UIState.pending items are always pending and omit it.
	Status string `json:"status,omitempty"`
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
	Grants   []GrantSummary     `json:"grants"` // active grants, newest first, with requesting_host
	Recent   []AuditEntry       `json:"recent"`
}

// UISession is the body of GET /api/ui/session (works without a session).
type UISession struct {
	Authenticated bool    `json:"authenticated"`
	Owner         UIOwner `json:"owner"`
}

// OK is the body of calls that only report success (login/finish, register/finish, logout).
type OK struct {
	OK bool `json:"ok"`
}

// RevokeResult is the body of /api/ui/standing/{id}/revoke and /api/ui/grants/{id}/revoke.
type RevokeResult struct {
	OK     bool   `json:"ok"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// CeremonyBegin is the response of login/begin and passkeys/register/begin. PublicKey is the
// bare WebAuthn options object (PublicKeyCredentialRequestOptions for login,
// PublicKeyCredentialCreationOptions for registration). The WebAuthn session state stays on
// the server, keyed by ChallengeID, which the matching finish call must send back.
type CeremonyBegin struct {
	ChallengeID string `json:"challenge_id"`
	PublicKey   any    `json:"public_key"`
}

// LoginFinish is the body of POST /api/ui/login/finish.
type LoginFinish struct {
	ChallengeID string          `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"` // PublicKeyCredential JSON from the browser
}

// RegisterBegin is the body of POST /api/ui/passkeys/register/begin: EnrollCode for the first
// passkey (from aqmasd passkey-enroll-code), otherwise a session plus ChallengeID/Assertion
// for a {"action":"add","object":"passkey"} challenge from POST /api/ui/passkeys/challenge.
type RegisterBegin struct {
	EnrollCode  string          `json:"enroll_code,omitempty"`
	ChallengeID string          `json:"challenge_id,omitempty"`
	Assertion   json.RawMessage `json:"assertion,omitempty"`
}

// RegisterFinish is the body of POST /api/ui/passkeys/register/finish.
type RegisterFinish struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"` // PublicKeyCredential JSON from the browser
	Name        string          `json:"name,omitempty"`
}

// ChallengeRequest asks for a WebAuthn challenge that commits to one exact action.
type ChallengeRequest struct {
	Action        string `json:"action"` // approve, deny (requests, enrollments); revoke (standing, grants); add (passkeys)
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
	ChallengeID string          `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"` // PublicKeyCredential JSON from the browser
}
