package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/testutil/fakecf"
)

const (
	testAccount  = "0123456789abcdef0123456789abcdef"
	testZoneID   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testTunnelID = "11111111-2222-4333-8444-555555555555"
	testParent   = "fake-parent-token-0123456789"
)

// fakeCF is the Cloudflare side of the fake agent API: catalogue, snapshots, kind
// "cloudflare" requests, and the proxy (fakecf.StandIn in front of an in-memory fakecf).
type fakeCF struct {
	disabled  bool
	fake      *fakecf.Fake
	upstream  *httptest.Server
	standIn   *fakecf.StandIn
	needs     string // X-Aqmas-Needs-Scope on no_grant
	mintFail  int    // 502 answers before a token is minted
	snapshots []api.CFSnapshot
	ttl       time.Duration
}

func (f *fakeServer) setupCF(mux *http.ServeMux) {
	fk, err := fakecf.New(fakecf.Options{Tokens: []string{testParent}, AccountID: testAccount,
		Zones:   []fakecf.Named{{Name: "example.com", ID: testZoneID}},
		Tunnels: []fakecf.Named{{Name: "home", ID: testTunnelID}}, PagesProjects: []string{"site"}})
	if err != nil {
		f.t.Fatal(err)
	}
	f.cf.fake = fk
	f.cf.upstream = httptest.NewServer(fk)
	f.t.Cleanup(f.cf.upstream.Close)
	f.cf.needs = "cf.dns.edit zone=example.com"
	f.cf.ttl = time.Hour
	f.cf.standIn = &fakecf.StandIn{Upstream: f.cf.upstream.URL, ParentToken: testParent, AccountID: testAccount, Allow: f.allowCF,
		OnWrite: func(method, path string, h http.Header) {
			h.Set(api.CFSnapshotBeforeHeader, "SNAPB1")
			h.Set(api.CFSnapshotAfterHeader, "SNAPA1")
			h.Add(api.CFWarningHeader, "first warning")
			h.Add(api.CFWarningHeader, "second \u202ewarning")
		}}
	mux.HandleFunc("GET /v1/cf/catalogue", f.handleCatalogue)
	mux.HandleFunc("GET /v1/cf/snapshots", f.handleSnapshots)
	mux.HandleFunc("GET /v1/cf/snapshots/{id}", f.handleSnapshot)
	mux.HandleFunc("/cf/client/v4/", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := f.host(w, r); !ok {
			return
		}
		f.cf.standIn.ServeHTTP(w, r)
	})
}

// allowCF: the first offered grant that is this host's, active, proxy mode and (for cf.read)
// a GET.
func (f *fakeServer) allowCF(r *http.Request, method, cfPath string, offered []string) (string, string) {
	host := r.TLS.PeerCertificates[0].Subject.CommonName
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range offered {
		for _, fr := range f.requests {
			g := fr.granted
			if g == nil || g.ID != id || fr.host != host || fr.revoked || g.Cloudflare == nil || g.Cloudflare.Mode != api.CFModeProxy || time.Now().After(g.NotAfter) {
				continue
			}
			if g.Cloudflare.Scope == api.CFScopeRead && method != http.MethodGet {
				continue
			}
			return id, ""
		}
	}
	return "", f.cf.needs
}

func (f *fakeServer) handleCatalogue(w http.ResponseWriter, r *http.Request) {
	if _, ok := f.host(w, r); !ok {
		return
	}
	if f.cf.disabled {
		apiErr(w, 404, "not_found", "cloudflare is not enabled")
		return
	}
	writeJSON(w, 200, api.CFCatalogue{AccountID: testAccount,
		Zones:       []api.CFNamedID{{Name: "example.com", ID: testZoneID}},
		Tunnels:     []api.CFNamedID{{Name: "home", ID: testTunnelID}},
		D1Databases: []api.CFNamedID{},
		Scopes: []api.CFScopeInfo{
			{Name: "cf.read", Title: "Read Cloudflare configuration", Risk: "low", AutoApprove: true, StandingAllowed: true, Modes: []string{"proxy"}, DefaultTTL: 28800, MaxTTL: 28800, Params: []api.CFParamInfo{}},
			{Name: "cf.dns.edit", Title: "Edit DNS \x1b[2Jrecords", Risk: "high", StandingAllowed: true, Modes: []string{"proxy", "token"}, DefaultTTL: 7200, MaxTTL: 28800,
				Params: []api.CFParamInfo{{Key: "zone", Required: true, Values: []string{"example.com"}}, {Key: "name"}}},
		}})
}

func (f *fakeServer) hasActiveCF(host string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fr := range f.requests {
		if fr.host == host && fr.granted != nil && fr.granted.Cloudflare != nil && !fr.revoked {
			return true
		}
	}
	return false
}

func (f *fakeServer) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	host, ok := f.host(w, r)
	if !ok {
		return
	}
	if !f.hasActiveCF(host) {
		apiErr(w, 403, "forbidden", "an active Cloudflare grant is needed")
		return
	}
	out := api.CFSnapshotList{Snapshots: []api.CFSnapshot{}}
	q := r.URL.Query()
	for _, s := range f.cf.snapshots {
		if (q.Get("object") == "" || q.Get("object") == s.ObjectKey) && (q.Get("type") == "" || q.Get("type") == s.ObjectType) &&
			(q.Get("grant") == "" || q.Get("grant") == s.GrantID) {
			s.Content = nil
			out.Snapshots = append(out.Snapshots, s)
		}
	}
	writeJSON(w, 200, out)
}

func (f *fakeServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	host, ok := f.host(w, r)
	if !ok {
		return
	}
	if !f.hasActiveCF(host) {
		apiErr(w, 403, "forbidden", "an active Cloudflare grant is needed")
		return
	}
	for _, s := range f.cf.snapshots {
		if s.ID == r.PathValue("id") {
			writeJSON(w, 200, s)
			return
		}
	}
	apiErr(w, 404, "not_found", "no such snapshot")
}

func (f *fakeServer) createCF(w http.ResponseWriter, host string, req api.AccessRequest) {
	cf := req.Cloudflare
	if cf == nil || !strings.HasPrefix(cf.Scope, "cf.") || cf.Scope == "cf.bogus" {
		apiErr(w, 400, "bad_request", "unknown scope \x1b[31m"+fmt.Sprint(cf != nil))
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created++
	id := fmt.Sprintf("REQ%04d", f.created)
	auto := (cf.Scope == api.CFScopeRead || cf.Scope == api.CFScopeCachePurge) && cf.Mode != api.CFModeToken
	f.requests[id] = &fakeReq{req: req, host: host, auto: auto}
	status := api.StatusPending
	if auto {
		status = api.StatusApproved
	}
	writeJSON(w, 201, api.RequestCreated{ID: id, Status: status, ApproveURL: "https://aqmas.example/#r=" + id, PollAfterMS: 1, ExpiresAt: time.Now().Add(10 * time.Minute)})
}

// statusCF answers GET /v1/requests/{id} for a Cloudflare request (f.mu held).
func (f *fakeServer) statusCF(w http.ResponseWriter, id string, fr *fakeReq) {
	k := api.KindCloudflare
	switch {
	case fr.cancelled:
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: k, Status: api.StatusCancelled})
		return
	case fr.revoked:
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: k, Status: api.StatusRevoked})
		return
	case !fr.auto && fr.polls <= f.requestPending:
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: k, Status: api.StatusPending})
		return
	case !fr.auto && f.requestDecision != api.StatusApproved:
		now := time.Now()
		writeJSON(w, 200, api.RequestStatus{ID: id, Kind: k, Status: f.requestDecision, DecidedAt: &now, DecisionNote: f.decisionNote})
		return
	}
	req := fr.req.Cloudflare
	mode := req.Mode
	if mode == "" {
		mode = api.CFModeProxy
	}
	if fr.granted == nil {
		now := time.Now()
		fr.granted = &api.Grant{ID: "G" + id, Kind: k, NotBefore: now, NotAfter: now.Add(f.cf.ttl), Cloudflare: &api.CloudflareGrant{
			Scope: req.Scope, Params: req.Params, ScopeParams: canonicalScopeParams(req.Params), Mode: mode, AccountID: testAccount,
			ProxyPath: "/cf/client/v4"}}
	}
	g := *fr.granted
	cf := *g.Cloudflare
	g.Cloudflare = &cf
	if mode == api.CFModeToken {
		if !fr.delivered {
			if f.cf.mintFail > 0 {
				f.cf.mintFail--
				apiErr(w, 502, "internal", "mint failed")
				return
			}
			id, value := f.mintChild(g.ID, g.NotAfter)
			fr.granted.Cloudflare.TokenID = id
			cf.TokenID, cf.Token = id, value
			fr.delivered = true
		} else {
			cf.TokenDelivered = true
		}
		cf.IPCondition = []string{"192.0.2.1/32"}
		cf.Permissions = []string{"DNS Write (zone example.com)"}
	}
	writeJSON(w, 200, api.RequestStatus{ID: id, Kind: k, Status: api.StatusApproved, Grant: &g})
}

// mintChild mints a real fakecf child token with the parent token (in process).
func (f *fakeServer) mintChild(grantID string, notAfter time.Time) (string, string) {
	body, _ := json.Marshal(map[string]any{"name": "aqmas:" + grantID + ":build-box", "expires_on": notAfter.UTC().Format(time.RFC3339),
		"policies": []any{map[string]any{"effect": "allow", "resources": map[string]string{"com.cloudflare.api.account.zone." + testZoneID: "*"},
			"permission_groups": []any{map[string]string{"id": "4755a26eedb94da69e1066d98aa820be"}}}}})
	req := httptest.NewRequest(http.MethodPost, "/client/v4/user/tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testParent)
	rec := httptest.NewRecorder()
	f.cf.fake.ServeHTTP(rec, req)
	var out struct {
		Result struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Result.Value == "" {
		f.t.Errorf("fake mint failed: %s", rec.Body)
	}
	return out.Result.ID, out.Result.Value
}

// approveCF creates an approved proxy grant for host directly (as if approved in another
// terminal) and returns its id.
func (f *fakeServer) approveCF(host, scope string, params map[string]string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created++
	id := fmt.Sprintf("REQ%04d", f.created)
	now := time.Now()
	f.requests[id] = &fakeReq{host: host, req: api.AccessRequest{Kind: api.KindCloudflare, Cloudflare: &api.CloudflareRequest{Scope: scope, Params: params}},
		granted: &api.Grant{ID: "G" + id, Kind: api.KindCloudflare, NotBefore: now, NotAfter: now.Add(time.Hour), Cloudflare: &api.CloudflareGrant{
			Scope: scope, Params: params, ScopeParams: canonicalScopeParams(params), Mode: api.CFModeProxy, AccountID: testAccount}}}
	return "G" + id
}
