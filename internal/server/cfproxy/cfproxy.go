// Package cfproxy is aqmasd's Cloudflare API proxy (docs/CLOUDFLARE.md sections 3-5): path
// normalisation, grant selection, scope matching (cfscope), the deny-list, guard rails,
// automatic snapshots before/after writes, parent-token injection, response redaction,
// synthetic endpoints, per-host rate limits and audit, plus the snapshot store and its agent
// endpoints, and the child-token minter client.
//
// CONTRACT (milestone 2 lead): the exported API below is what internal/server (core) builds
// against. The cf-proxy workstream owns this package and fills in the implementation; change
// exported signatures only by agreement with the lead.
package cfproxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// ErrNotImplemented marks contract stubs.
var ErrNotImplemented = errors.New("cfproxy: not implemented")

// PathPrefix is where the proxy is mounted on the agent API.
const PathPrefix = "/cf/client/v4"

// Caller is the authenticated host (core does the mTLS check before calling the proxy).
type Caller struct {
	HostID      int64
	HostName    string
	PeerAddress string // as seen on the mTLS connection
}

// Grant is an active proxy-mode Cloudflare grant as core stores it.
type Grant struct {
	ID          string
	HostID      int64
	HostName    string
	PeerAddress string // address of the request that created the grant
	Scope       string
	ScopeParams string
	Mode        string
	NotAfter    time.Time
}

// GrantSource is implemented by core over its store.
type GrantSource interface {
	// ProxyGrants returns, in the order of ids, those grants that belong to hostID, are kind
	// "cloudflare" and mode "proxy", approved, not revoked and not expired at now. Unknown or
	// foreign ids are skipped silently.
	ProxyGrants(ctx context.Context, hostID int64, ids []string, now time.Time) ([]Grant, error)
	// HasActiveGrant reports whether hostID holds any active Cloudflare grant (either mode):
	// the condition for reading snapshots.
	HasActiveGrant(ctx context.Context, hostID int64, now time.Time) (bool, error)
	// Audit appends to the audit log (actor "host:<name>" or "system").
	Audit(ctx context.Context, actor, action, object, detail string) error
}

// Options configures a Proxy.
type Options struct {
	Config     *config.Cloudflare
	Catalogue  *cfscope.Catalogue
	Grants     GrantSource
	ProxyToken string // the proxy parent token (never logged)
	// SnapshotDir is where snapshots live (core resolves the default <data_dir>/cf-snapshots).
	SnapshotDir string
	Notify      func(title, text string) // ntfy push (may be nil)
	Log         *slog.Logger
	Now         func() time.Time
	HTTPClient  *http.Client // upstream client (tests inject one)
}

// Proxy serves the proxy and snapshot endpoints.
type Proxy struct {
	o Options
}

// New prepares the proxy (creates SnapshotDir 0700 if missing).
func New(o Options) (*Proxy, error) { return &Proxy{o: o}, ErrNotImplemented }

// Serve handles one proxied call; r.URL.Path starts with PathPrefix. core has authenticated
// the caller.
func (p *Proxy) Serve(w http.ResponseWriter, r *http.Request, c Caller) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// ServeSnapshotList handles GET /v1/cf/snapshots (query: object, type, grant, limit).
func (p *Proxy) ServeSnapshotList(w http.ResponseWriter, r *http.Request, c Caller) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// ServeSnapshotGet handles GET /v1/cf/snapshots/{id}.
func (p *Proxy) ServeSnapshotGet(w http.ResponseWriter, r *http.Request, c Caller, id string) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Prune applies snapshot retention (retention days + newest per object key). core calls it
// from its sweeper about hourly.
func (p *Proxy) Prune(ctx context.Context, now time.Time) error { return ErrNotImplemented }

// ---- child tokens ----

// Minter mints and deletes child tokens with the minter parent token.
type Minter struct {
	apiBase   string
	token     string
	accountID string
	client    *http.Client
}

// NewMinter returns a minter; token is the minter parent token.
func NewMinter(cfg *config.Cloudflare, token string, client *http.Client) *Minter {
	return &Minter{apiBase: cfg.APIBase, token: token, accountID: cfg.AccountID, client: client}
}

// MintRequest describes one child token.
type MintRequest struct {
	Name      string // "aqmas:<grant id>:<host>"
	NotBefore time.Time
	ExpiresOn time.Time
	IPIn      []string // condition.request_ip.in
	Resolved  *cfscope.Resolved
}

// Minted is a new child token. Value is returned to the agent once and never stored.
type Minted struct {
	ID    string
	Value string
}

// UpstreamToken is a token listed upstream.
type UpstreamToken struct {
	ID        string
	Name      string
	ExpiresOn time.Time
	Status    string
}

// Mint creates the token (POST /user/tokens) from the scope's template, resolving permission
// group names via GET /user/tokens/permission_groups (cached).
func (m *Minter) Mint(ctx context.Context, req MintRequest) (*Minted, error) {
	return nil, ErrNotImplemented
}

// Delete deletes a token (DELETE /user/tokens/{id}); 404 counts as success.
func (m *Minter) Delete(ctx context.Context, id string) error { return ErrNotImplemented }

// ListAqmas lists upstream tokens whose name starts with "aqmas:" (all pages).
func (m *Minter) ListAqmas(ctx context.Context) ([]UpstreamToken, error) {
	return nil, ErrNotImplemented
}
