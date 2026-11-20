package cfproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
)

const fakeMinter = "FAKE-MINTER-TOKEN-do-not-leak-0002"

func TestMinter(t *testing.T) {
	cf := newFakeCF(t)
	cfg := testConfig(cf.srv.URL + "/client/v4")
	cat, err := cfscope.NewCatalogue(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pgCalls := 0
	cf.on("GET /user/tokens/permission_groups", func(w http.ResponseWriter, r *http.Request) {
		pgCalls++
		cfJSON(w, 200, []any{
			map[string]any{"id": "pg-dns", "name": "DNS Write"}, map[string]any{"id": "pg-zr", "name": "Zone Read"},
			map[string]any{"id": "pg-ws", "name": "Workers Scripts Write"}, map[string]any{"id": "pg-as", "name": "Account Settings Read"},
			map[string]any{"id": "pg-wr", "name": "Workers Routes Write"},
		})
	})
	var mintBodies []map[string]any
	cf.on("POST /user/tokens", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		mintBodies = append(mintBodies, b)
		cfJSON(w, 200, map[string]any{"id": "tok1", "value": "CHILD-VALUE"})
	})
	m := NewMinter(cfg, fakeMinter, cf.srv.Client()).WithCatalogue(cat)
	nb := time.Date(2026, 11, 20, 12, 0, 0, 500, time.UTC)
	res, err := cat.Resolve(api.CloudflareRequest{Scope: api.CFScopeWorkersDeploy, Mode: api.CFModeToken, Params: map[string]string{"script": "hello", "zone": "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Mint(context.Background(), MintRequest{Name: "aqmas:G1:hosta", NotBefore: nb, ExpiresOn: nb.Add(2 * time.Hour), IPIn: []string{"203.0.113.7/32"}, Resolved: res})
	if err != nil || got.ID != "tok1" || got.Value != "CHILD-VALUE" {
		t.Fatalf("mint %+v %v", got, err)
	}
	b := mintBodies[0]
	if b["name"] != "aqmas:G1:hosta" || b["not_before"] != "2026-11-20T12:00:00Z" || b["expires_on"] != "2026-11-20T14:00:00Z" {
		t.Fatalf("body %v", b)
	}
	if in := b["condition"].(map[string]any)["request_ip"].(map[string]any)["in"].([]any); len(in) != 1 || in[0] != "203.0.113.7/32" {
		t.Fatalf("condition %v", b["condition"])
	}
	pols := b["policies"].([]any)
	if len(pols) != 2 {
		t.Fatalf("policies %v", pols)
	}
	p0, p1 := pols[0].(map[string]any), pols[1].(map[string]any)
	if p0["effect"] != "allow" || p0["resources"].(map[string]any)["com.cloudflare.api.account."+acct] != "*" ||
		len(p0["permission_groups"].([]any)) != 2 || p0["permission_groups"].([]any)[0].(map[string]any)["id"] != "pg-ws" {
		t.Fatalf("account policy %v", p0)
	}
	if p1["resources"].(map[string]any)["com.cloudflare.api.account.zone."+zoneA] != "*" || p1["permission_groups"].([]any)[0].(map[string]any)["id"] != "pg-wr" {
		t.Fatalf("zone policy %v", p1)
	}
	// Second mint: permission groups cached.
	dres, _ := cat.Resolve(api.CloudflareRequest{Scope: api.CFScopeDNSEdit, Mode: api.CFModeToken, Params: map[string]string{"zone": "example.com"}})
	if _, err := m.Mint(context.Background(), MintRequest{Name: "aqmas:G2:x", NotBefore: nb, ExpiresOn: nb.Add(time.Hour), IPIn: []string{"203.0.113.7/32"}, Resolved: dres}); err != nil {
		t.Fatal(err)
	}
	if pgCalls != 1 {
		t.Fatalf("permission groups fetched %d times", pgCalls)
	}
	for _, u := range cf.requests() {
		if u.Auth != "Bearer "+fakeMinter {
			t.Fatalf("auth %q", u.Auth)
		}
	}
	// Unknown permission group (refetched once, then an error); proxy-mode request refused.
	pres, _ := cat.Resolve(api.CloudflareRequest{Scope: api.CFScopePages, Mode: api.CFModeToken, Params: map[string]string{"project": "blog"}})
	if _, err := m.Mint(context.Background(), MintRequest{Name: "n", NotBefore: nb, ExpiresOn: nb.Add(time.Hour), IPIn: []string{"x"}, Resolved: pres}); err == nil || !strings.Contains(err.Error(), "Pages Write") || pgCalls != 2 {
		t.Fatalf("missing group: %v %d", err, pgCalls)
	}
	rres, _ := cat.Resolve(api.CloudflareRequest{Scope: api.CFScopeRead})
	if _, err := m.Mint(context.Background(), MintRequest{Name: "n", NotBefore: nb, ExpiresOn: nb.Add(time.Hour), IPIn: []string{"x"}, Resolved: rres}); err == nil {
		t.Fatal("proxy-mode mint")
	}

	// Mint failure: the error has Cloudflare's message, never the token.
	cf.on("POST /user/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1001,"message":"bad policy"}],"result":{"value":"LEAKED"}}`))
	})
	_, err = m.Mint(context.Background(), MintRequest{Name: "n", NotBefore: nb, ExpiresOn: nb.Add(time.Hour), IPIn: []string{"x"}, Resolved: dres})
	if err == nil || !strings.Contains(err.Error(), "1001 bad policy") || strings.Contains(err.Error(), "LEAKED") || strings.Contains(err.Error(), fakeMinter) {
		t.Fatalf("mint error %v", err)
	}

	// Delete: 2xx and 404 ok, 500 an error.
	cf.on("DELETE /user/tokens/gone", func(w http.ResponseWriter, r *http.Request) { cfJSON(w, 404, nil) })
	cf.on("DELETE /user/tokens/boom", func(w http.ResponseWriter, r *http.Request) { cfJSON(w, 500, nil) })
	if err := m.Delete(context.Background(), "tok1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(context.Background(), "gone"); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(context.Background(), "boom"); err == nil {
		t.Fatal("500 delete")
	}
	if err := m.Delete(context.Background(), "../x"); err == nil {
		t.Fatal("bad id")
	}

	// ListAqmas pages through and filters.
	cf.on("GET /user/tokens", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		var res []any
		switch page {
		case "1":
			res = []any{map[string]any{"id": "t1", "name": "aqmas:G1:h", "status": "active", "expires_on": "2026-11-20T14:00:00Z"}, map[string]any{"id": "t2", "name": "owner token"}}
		case "2":
			res = []any{map[string]any{"id": "t3", "name": "aqmas:G3:h", "status": "expired"}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": res, "result_info": map[string]any{"page": page, "total_pages": 2}})
	})
	list, err := m.ListAqmas(context.Background())
	if err != nil || len(list) != 2 || list[0].ID != "t1" || list[1].ID != "t3" || !list[0].ExpiresOn.Equal(time.Date(2026, 11, 20, 14, 0, 0, 0, time.UTC)) {
		t.Fatalf("list %+v %v", list, err)
	}
}
