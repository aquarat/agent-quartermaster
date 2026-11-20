// Package cfscope is the Cloudflare scope catalogue (docs/CLOUDFLARE.md section 2): the
// built-in scopes, their parameters, risk, approval policy, child-token templates and route
// tables (method + path templates), the deny-list that always wins (section 3), parameter
// validation and the canonical scope_params form.
//
// CONTRACT (milestone 2 lead): the exported API below is what internal/server (core) and
// internal/server/cfproxy build against. The cf-proxy workstream owns this package and fills
// in the implementation; change exported signatures only by agreement with the lead.
package cfscope

import (
	"errors"
	"net/http"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// ErrNotImplemented marks contract stubs.
var ErrNotImplemented = errors.New("cfscope: not implemented")

// Scope is one built-in catalogue entry after config narrowing.
type Scope struct {
	Name        string
	Title       string // plain words, e.g. "Read Cloudflare configuration"
	Description string
	Params      []api.CFParamInfo
	Risk        string // api.CFRisk*
	// AutoApprove (proxy mode only): requests are approved without the owner.
	AutoApprove bool
	// StandingAllowed (proxy mode only): the owner may "approve similar for N hours".
	StandingAllowed bool
	DefaultTTL      int // seconds
	MaxTTL          int // seconds; cf.admin is at most 3600
	// Token is the child-token template; nil = proxy mode only.
	Token *TokenTemplate
}

// TokenTemplate is the child token policy for a scope in token mode.
type TokenTemplate struct {
	// Policies: permission group NAMES (resolved to ids via GET /user/tokens/permission_groups
	// by the minter) per resource level: "account" (the configured account) or "zone" (the
	// grant's zone parameter).
	Account []string
	Zone    []string
	// Notes are shown on the approval card (e.g. "Workers Scripts Write cannot be limited to
	// one script").
	Notes []string
}

// Resolved is a validated request for a scope: what is signed and what the proxy enforces.
type Resolved struct {
	Scope       *Scope
	Mode        string            // api.CFModeProxy | api.CFModeToken
	Params      map[string]string // normalised (names, lower case where Cloudflare is)
	ScopeParams string            // canonical: "k=v;k=v", keys sorted bytewise, "" when none
	// IDs maps parameter keys to Cloudflare ids: "zone" -> zone id, "tunnel" -> tunnel id,
	// "db" -> D1 database id. Script/project/bucket names are used as they are.
	IDs map[string]string
	// Permissions (token mode): the child token's policy in plain words.
	Permissions []string
	Notes       []string
}

// Catalogue is the built-in scope table narrowed by config (catalogue.go).
type Catalogue struct {
	cfg    *config.Cloudflare
	scopes map[string]*Scope
	order  []string
}

// Call is one proxied API call, already normalised by cfproxy (docs/CLOUDFLARE.md section 3.1):
// Path is the Cloudflare path below /client/v4 with a leading slash and no query, every
// segment validated; Segments is Path split on "/" (without the empty first element).
type Call struct {
	Method   string
	Path     string
	Segments []string
	Query    string // raw query, already validated
}

// Route is a matched route of a scope.
type Route struct {
	Scope    string
	Template string            // e.g. "PUT /accounts/{acct}/cfd_tunnel/{tunnel}/configurations"
	Vars     map[string]string // placeholder values
	Write    bool              // not GET/HEAD
	// Snapshot names the object type to snapshot before/after a write ("" = none); Guard
	// names the guard rail set (cfproxy); Upload marks streamed bodies (UploadMaxBodyBytes);
	// JWTPassthrough marks routes authenticated by an upload JWT from the client instead of
	// the parent token (Workers assets, Pages assets).
	Snapshot       string
	Guard          string
	Upload         bool
	JWTPassthrough bool
	// Redact lists response redactions beyond the global safety net.
	Redact []string
}

// IsWrite reports whether method m changes state.
func IsWrite(m string) bool {
	return m != http.MethodGet && m != http.MethodHead
}
