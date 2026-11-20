// Package policy holds the TTL and standing-approval rules.
package policy

import (
	"fmt"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// ClampTTL turns a requested TTL into the policy TTL: 0 or negative means the default; values
// are clamped into [min, max].
func ClampTTL(requested int, t config.TTL) int {
	switch {
	case requested <= 0:
		return t.DefaultSeconds
	case requested < t.MinSeconds:
		return t.MinSeconds
	case requested > t.MaxSeconds:
		return t.MaxSeconds
	}
	return requested
}

// ApproverTTL applies the approver's choice: 0 keeps the (already clamped) requested TTL; the
// approver may shorten it, never lengthen it.
func ApproverTTL(requested, chosen int, t config.TTL) (int, error) {
	if chosen == 0 {
		return requested, nil
	}
	if chosen < t.MinSeconds {
		return 0, fmt.Errorf("ttl_seconds must be at least %d", t.MinSeconds)
	}
	if chosen > requested {
		return 0, fmt.Errorf("ttl_seconds may only shorten the requested %d", requested)
	}
	return chosen, nil
}

// StandingHours validates the approver's "approve similar requests for N hours".
func StandingHours(h int, t config.TTL) error {
	if h < 0 || h > t.MaxStandingHours {
		return fmt.Errorf("standing_hours must be between 0 and %d", t.MaxStandingHours)
	}
	return nil
}

// Rule is a standing approval.
type Rule struct {
	HostID      int64
	PeerAddress string
	Kind        string
	Target      string
	LoginUser   string
	MaxTTL      int
	ExpiresAt   time.Time
	Revoked     bool
}

// Candidate is a new request that might be auto-approved.
type Candidate struct {
	HostID      int64
	PeerAddress string
	Kind        string
	Target      string
	LoginUser   string
	TTL         int // after clamping
}

// Matches reports whether rule auto-approves c at now: same enrolled host connecting from the
// same address as the request the owner approved, kind, target and login user, TTL within the
// rule's maximum, rule neither expired nor revoked. Binding the address means a host's stolen
// client key used from another machine gets no silent approvals.
func Matches(r Rule, c Candidate, now time.Time) bool {
	return !r.Revoked &&
		now.Before(r.ExpiresAt) &&
		r.HostID == c.HostID &&
		r.PeerAddress != "" && r.PeerAddress == c.PeerAddress &&
		r.Kind == c.Kind &&
		r.Target == c.Target &&
		r.LoginUser == c.LoginUser &&
		c.TTL > 0 && c.TTL <= r.MaxTTL
}
