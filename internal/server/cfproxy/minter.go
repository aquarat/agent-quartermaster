package cfproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// ---- child tokens (docs/CLOUDFLARE.md 5) ----

// Minter mints and deletes child tokens with the minter parent token.
type Minter struct {
	apiBase   string
	token     string
	accountID string
	client    *http.Client
	catalogue *cfscope.Catalogue // optional: Catalogue.Token for the template

	mu     sync.Mutex
	groups map[string]string // permission group name -> id
}

// NewMinter returns a minter; token is the minter parent token.
func NewMinter(cfg *config.Cloudflare, token string, client *http.Client) *Minter {
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base := cfg.APIBase
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	return &Minter{apiBase: strings.TrimRight(base, "/"), token: token, accountID: cfg.AccountID, client: &c}
}

// WithCatalogue sets the catalogue whose Token templates Mint uses (default: the built-in
// definitions).
func (m *Minter) WithCatalogue(c *cfscope.Catalogue) *Minter {
	m.catalogue = c
	return m
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

type cfEnvelope struct {
	Success    bool            `json:"success"`
	Errors     []cfErrorItem   `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// call makes one request with the minter token. Errors carry Cloudflare's error messages
// only, never a body (a mint answer contains the token value).
func (m *Minter) call(ctx context.Context, method, path string, q url.Values, body any) (int, *cfEnvelope, error) {
	u := m.apiBase + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, errors.New("minter: cannot build request")
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("minter: %w", scrubErr(err))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("minter: reading answer: %w", scrubErr(err))
	}
	var env cfEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("minter: %s %s answered %d (not JSON)", method, path, resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 || !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, asciiOnly(clip(e.Message, 200))))
		}
		return resp.StatusCode, &env, fmt.Errorf("minter: %s %s answered %d: %s", method, path, resp.StatusCode, strings.Join(msgs, "; "))
	}
	return resp.StatusCode, &env, nil
}

// permissionGroups resolves names to ids (cached; refreshed once when a name is missing).
func (m *Minter) permissionGroups(ctx context.Context, names []string) (map[string]string, error) {
	m.mu.Lock()
	cached := m.groups
	m.mu.Unlock()
	missing := func(g map[string]string) bool {
		for _, n := range names {
			if _, ok := g[n]; !ok {
				return true
			}
		}
		return false
	}
	if cached == nil || missing(cached) {
		_, env, err := m.call(ctx, http.MethodGet, "/user/tokens/permission_groups", nil, nil)
		if err != nil {
			return nil, err
		}
		var list []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(env.Result, &list); err != nil {
			return nil, errors.New("minter: permission groups did not parse")
		}
		g := map[string]string{}
		for _, x := range list {
			g[x.Name] = x.ID
		}
		m.mu.Lock()
		m.groups = g
		m.mu.Unlock()
		cached = g
	}
	for _, n := range names {
		if _, ok := cached[n]; !ok {
			return nil, fmt.Errorf("minter: Cloudflare has no permission group %q", n)
		}
	}
	return cached, nil
}

type pgRef struct {
	ID string `json:"id"`
}

type policy struct {
	Effect           string            `json:"effect"`
	PermissionGroups []pgRef           `json:"permission_groups"`
	Resources        map[string]string `json:"resources"`
}

type mintBody struct {
	Name      string   `json:"name"`
	NotBefore string   `json:"not_before"`
	ExpiresOn string   `json:"expires_on"`
	Policies  []policy `json:"policies"`
	Condition struct {
		RequestIP struct {
			In []string `json:"in"`
		} `json:"request_ip"`
	} `json:"condition"`
}

func cfTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// template returns the child-token template for a resolved token-mode request.
func (m *Minter) template(r *cfscope.Resolved) (*cfscope.TokenTemplate, error) {
	cat := m.catalogue
	if cat == nil {
		cat = &cfscope.Catalogue{} // Token only reads the built-in definitions
	}
	if t := cat.Token(r); t != nil {
		return t, nil
	}
	return nil, errors.New("minter: scope has no child-token template")
}

// Mint creates the token (POST /user/tokens) from the scope's template, resolving permission
// group names via GET /user/tokens/permission_groups (cached).
func (m *Minter) Mint(ctx context.Context, req MintRequest) (*Minted, error) {
	if req.Resolved == nil || req.Resolved.Mode != api.CFModeToken {
		return nil, errors.New("minter: not a token-mode request")
	}
	if len(req.IPIn) == 0 {
		return nil, errors.New("minter: no IP condition")
	}
	if !req.ExpiresOn.After(req.NotBefore) {
		return nil, errors.New("minter: expires_on must be after not_before")
	}
	t, err := m.template(req.Resolved)
	if err != nil {
		return nil, err
	}
	groups, err := m.permissionGroups(ctx, append(append([]string{}, t.Account...), t.Zone...))
	if err != nil {
		return nil, err
	}
	b := mintBody{Name: req.Name, NotBefore: cfTime(req.NotBefore), ExpiresOn: cfTime(req.ExpiresOn)}
	b.Condition.RequestIP.In = append([]string{}, req.IPIn...)
	refs := func(names []string) []pgRef {
		out := make([]pgRef, 0, len(names))
		for _, n := range names {
			out = append(out, pgRef{ID: groups[n]})
		}
		return out
	}
	if len(t.Account) > 0 {
		b.Policies = append(b.Policies, policy{Effect: "allow", PermissionGroups: refs(t.Account),
			Resources: map[string]string{"com.cloudflare.api.account." + m.accountID: "*"}})
	}
	if len(t.Zone) > 0 {
		zid := req.Resolved.IDs[api.CFParamZone]
		if zid == "" {
			return nil, errors.New("minter: zone permissions without a zone")
		}
		b.Policies = append(b.Policies, policy{Effect: "allow", PermissionGroups: refs(t.Zone),
			Resources: map[string]string{"com.cloudflare.api.account.zone." + zid: "*"}})
	}
	if len(b.Policies) == 0 {
		return nil, errors.New("minter: empty template")
	}
	_, env, err := m.call(ctx, http.MethodPost, "/user/tokens", nil, b)
	if err != nil {
		return nil, err
	}
	var res struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil || res.ID == "" || res.Value == "" {
		return nil, errors.New("minter: mint answer without id/value")
	}
	return &Minted{ID: res.ID, Value: res.Value}, nil
}

// Delete deletes a token (DELETE /user/tokens/{id}); 404 counts as success.
func (m *Minter) Delete(ctx context.Context, id string) error {
	if !grantIDRE.MatchString(id) {
		return errors.New("minter: bad token id")
	}
	st, _, err := m.call(ctx, http.MethodDelete, "/user/tokens/"+id, nil, nil)
	if st == http.StatusNotFound {
		return nil
	}
	return err
}

// ListAqmas lists upstream tokens whose name starts with "aqmas:" (all pages).
func (m *Minter) ListAqmas(ctx context.Context) ([]UpstreamToken, error) {
	var out []UpstreamToken
	for page := 1; page <= 100; page++ {
		q := url.Values{"page": {fmt.Sprint(page)}, "per_page": {"50"}}
		_, env, err := m.call(ctx, http.MethodGet, "/user/tokens", q, nil)
		if err != nil {
			return nil, err
		}
		var list []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			ExpiresOn string `json:"expires_on"`
		}
		if err := json.Unmarshal(env.Result, &list); err != nil {
			return nil, errors.New("minter: token list did not parse")
		}
		for _, t := range list {
			if !strings.HasPrefix(t.Name, "aqmas:") {
				continue
			}
			ut := UpstreamToken{ID: t.ID, Name: t.Name, Status: t.Status}
			if t.ExpiresOn != "" {
				ut.ExpiresOn, _ = time.Parse(time.RFC3339, t.ExpiresOn)
			}
			out = append(out, ut)
		}
		tp := env.ResultInfo.TotalPages
		if len(list) == 0 || (tp > 0 && page >= tp) || (tp == 0 && len(list) < 50) {
			return out, nil
		}
	}
	return nil, errors.New("minter: too many token pages")
}
