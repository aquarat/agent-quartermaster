package fakecf

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

func contextWith(r *http.Request, c *call) context.Context {
	return context.WithValue(r.Context(), ctxKey{}, c)
}

// handle registers pattern (with the /client/v4 prefix added) for h.
func (f *Fake) handle(pattern string, h handler) {
	method, path, _ := strings.Cut(pattern, " ")
	f.mux.HandleFunc(method+" "+Prefix+path, func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Context().Value(ctxKey{}).(*call)
		if c == nil {
			cfError(w, http.StatusInternalServerError, 10000, "fake: no call context")
			return
		}
		c.r = r
		if a := r.PathValue("acct"); a != "" && a != f.o.AccountID {
			c.err(http.StatusForbidden, 9109, "Unauthorized to access requested resource")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if z := r.PathValue("zone"); z != "" && f.zones[z] == nil {
			c.err(http.StatusNotFound, 7003, "Could not route to "+sanitizePath(r.URL.EscapedPath())+", perhaps your object identifier is invalid?")
			return
		}
		h(c)
	})
}

func (f *Fake) routes() {
	f.mux = http.NewServeMux()

	// identity
	f.handle("GET /user", func(c *call) {
		c.ok(map[string]any{"id": "fakeuser0000", "email": "owner@example.invalid", "first_name": "Fake", "last_name": "Owner",
			"suspended": false, "two_factor_authentication_enabled": true})
	})
	f.handle("GET /memberships", func(c *call) {
		c.paged([]any{map[string]any{"id": "membership1", "status": "accepted",
			"account": map[string]any{"id": f.o.AccountID, "name": f.o.AccountName}, "roles": []string{"Administrator"}}}, 20)
	})
	f.handle("GET /accounts", func(c *call) {
		c.paged([]any{f.accountObj()}, 20)
	})
	f.handle("GET /accounts/{acct}", func(c *call) { c.ok(f.accountObj()) })

	f.tokenRoutes()
	f.zoneRoutes()
	f.tunnelRoutes()
	f.accessRoutes()
	f.workersRoutes()
	f.pagesRoutes()
	f.d1Routes()
	f.r2Routes()
}

func (f *Fake) accountObj() map[string]any {
	return map[string]any{"id": f.o.AccountID, "name": f.o.AccountName, "type": "standard",
		"settings": map[string]any{"enforce_twofactor": false}, "created_on": "2020-01-01T00:00:00Z"}
}

// ---- API tokens ----

var permissionGroups = []map[string]any{
	{"id": "4755a26eedb94da69e1066d98aa820be", "name": "DNS Write", "scopes": []string{"com.cloudflare.api.account.zone"}},
	{"id": "c8fed203ed3043cba015a93ad1616f1f", "name": "Zone Read", "scopes": []string{"com.cloudflare.api.account.zone"}},
	{"id": "e17beae8b8cb423a99b1730f21238bed", "name": "Cache Purge", "scopes": []string{"com.cloudflare.api.account.zone"}},
	{"id": "28f4b596e7d643029c524985477ae49a", "name": "Workers Routes Write", "scopes": []string{"com.cloudflare.api.account.zone"}},
	{"id": "e086da7e2179491d91ee5f35b3ca210a", "name": "Workers Scripts Write", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "c1fde68c7bcc44588cbb6ddbc16d6480", "name": "Account Settings Read", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "8d28297797f24fb8a0c332fe0866ec89", "name": "Pages Write", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "192192df92ee43ac90f2aeeffce67e35", "name": "D1 Read", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "09b2857d1c31407795e75e3fed8617a1", "name": "D1 Write", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "b4992e1108244f5d8bfbd5744320c2e1", "name": "Workers R2 Storage Read", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "bf7481a1826f439697cb59a20b22293e", "name": "Workers R2 Storage Write", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "959972745952452f8be2452be8cbb9f2", "name": "Access: Apps and Policies Write", "scopes": []string{"com.cloudflare.api.account"}},
	{"id": "686d18d5ac6c441c867cbf6771e58a0a", "name": "API Tokens Write", "scopes": []string{"com.cloudflare.api.user"}},
}

func (f *Fake) tokenRoutes() {
	parentOnly := func(h handler) handler {
		return func(c *call) {
			if !c.parent {
				c.err(http.StatusForbidden, 9109, "Unauthorized to access requested resource")
				return
			}
			h(c)
		}
	}
	f.handle("GET /user/tokens/verify", func(c *call) {
		if c.child != nil {
			c.ok(map[string]any{"id": c.child.ID, "status": "active", "not_before": ts(c.child.NotBefore), "expires_on": ts(c.child.ExpiresOn)})
			return
		}
		c.ok(map[string]any{"id": "parent-token", "status": "active"})
	})
	f.handle("GET /user/tokens/permission_groups", parentOnly(func(c *call) {
		out := []any{}
		for _, g := range permissionGroups {
			out = append(out, g)
		}
		c.ok(out)
	}))
	f.handle("GET /user/tokens", parentOnly(func(c *call) {
		items := []any{}
		for _, t := range f.tokenStatesLocked() {
			items = append(items, tokenObj(t))
		}
		c.paged(items, 20)
	}))
	f.handle("GET /user/tokens/{id}", parentOnly(func(c *call) {
		t := f.children[c.pv("id")]
		if t == nil || t.Deleted {
			c.err(http.StatusNotFound, 1003, "Token not found")
			return
		}
		s := t.TokenState
		s.Status = f.childStatus(t)
		c.ok(tokenObj(s))
	}))
	f.handle("DELETE /user/tokens/{id}", parentOnly(func(c *call) {
		t := f.children[c.pv("id")]
		if t == nil || t.Deleted {
			c.err(http.StatusNotFound, 1003, "Token not found")
			return
		}
		t.Deleted = true
		c.ok(map[string]any{"id": t.ID})
	}))
	f.handle("POST /user/tokens", parentOnly(func(c *call) {
		var in struct {
			Name      string          `json:"name"`
			Policies  json.RawMessage `json:"policies"`
			NotBefore string          `json:"not_before"`
			ExpiresOn string          `json:"expires_on"`
			Condition json.RawMessage `json:"condition"`
		}
		if !c.body(&in) {
			return
		}
		var pols []struct {
			Effect           string            `json:"effect"`
			Resources        map[string]string `json:"resources"`
			PermissionGroups []struct {
				ID string `json:"id"`
			} `json:"permission_groups"`
		}
		if in.Name == "" || json.Unmarshal(in.Policies, &pols) != nil || len(pols) == 0 {
			c.err(http.StatusBadRequest, 1001, "name and policies are required")
			return
		}
		known := map[string]bool{}
		for _, g := range permissionGroups {
			known[g["id"].(string)] = true
		}
		for _, p := range pols {
			if p.Effect != "allow" && p.Effect != "deny" || len(p.Resources) == 0 || len(p.PermissionGroups) == 0 {
				c.err(http.StatusBadRequest, 1001, "each policy needs effect, resources and permission_groups")
				return
			}
			for _, g := range p.PermissionGroups {
				if !known[g.ID] {
					c.err(http.StatusBadRequest, 1001, "unknown permission group "+sanitizePath(g.ID))
					return
				}
			}
		}
		now := f.now()
		nb, ex := now, now.Add(24*time.Hour)
		if in.NotBefore != "" {
			t, err := time.Parse(time.RFC3339, in.NotBefore)
			if err != nil {
				c.err(http.StatusBadRequest, 1001, "not_before: "+err.Error())
				return
			}
			nb = t
		}
		if in.ExpiresOn != "" {
			t, err := time.Parse(time.RFC3339, in.ExpiresOn)
			if err != nil {
				c.err(http.StatusBadRequest, 1001, "expires_on: "+err.Error())
				return
			}
			ex = t
		}
		if !ex.After(nb) {
			c.err(http.StatusBadRequest, 1001, "expires_on must be after not_before")
			return
		}
		t := &childToken{TokenState: TokenState{ID: randHex(16), Name: in.Name, IssuedOn: now, NotBefore: nb.UTC(), ExpiresOn: ex.UTC(),
			Policies: in.Policies, Condition: in.Condition}, value: "fakecf-child-" + randHex(20), seq: len(f.children)}
		f.children[t.ID] = t
		s := t.TokenState
		s.Status = "active"
		o := tokenObj(s)
		o["value"] = t.value
		c.ok(o)
	}))
}

func tokenObj(t TokenState) map[string]any {
	o := map[string]any{"id": t.ID, "name": t.Name, "status": t.Status, "issued_on": ts(t.IssuedOn), "modified_on": ts(t.IssuedOn),
		"not_before": t.NotBefore.Format(time.RFC3339), "expires_on": t.ExpiresOn.Format(time.RFC3339)}
	if t.Status == "deleted" {
		o["status"] = "disabled"
	}
	if len(t.Policies) > 0 {
		o["policies"] = t.Policies
	}
	if len(t.Condition) > 0 {
		o["condition"] = t.Condition
	}
	return o
}

// ---- zones, DNS, rulesets, settings, cache, workers routes ----

type zone struct {
	named      Named
	created    time.Time
	dns        *coll
	rulesets   *coll
	entry      map[string]string // phase -> ruleset id
	settings   map[string]any
	settingMod map[string]time.Time
	routes     *coll
	emailRules *coll
}

func newZone(n Named, now time.Time) *zone {
	z := &zone{named: n, created: now, dns: newColl(), rulesets: newColl(), entry: map[string]string{}, routes: newColl(), emailRules: newColl(),
		settings: map[string]any{
			"always_use_https":         "on",
			"min_tls_version":          "1.2",
			"ssl":                      "strict",
			"tls_1_3":                  "on",
			"automatic_https_rewrites": "on",
			"security_header": map[string]any{"strict_transport_security": map[string]any{
				"enabled": true, "max_age": 31536000, "include_subdomains": false, "preload": false, "nosniff": true}},
			"cache_level":      "aggressive",
			"browser_check":    "on",
			"development_mode": "off",
		}, settingMod: map[string]time.Time{}}
	return z
}

func (f *Fake) zoneObj(z *zone) map[string]any {
	return map[string]any{"id": z.named.ID, "name": z.named.Name, "status": "active", "paused": false, "type": "full",
		"account":      map[string]any{"id": f.o.AccountID, "name": f.o.AccountName},
		"name_servers": []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"},
		"created_on":   ts(z.created), "modified_on": ts(z.created), "plan": map[string]any{"name": "Free Website"}}
}

func (f *Fake) settingObj(z *zone, name string) map[string]any {
	mod := z.settingMod[name]
	var m any
	if !mod.IsZero() {
		m = ts(mod)
	}
	return map[string]any{"id": name, "value": z.settings[name], "editable": true, "modified_on": m}
}

func (f *Fake) zoneRoutes() {
	f.handle("GET /zones", func(c *call) {
		name := c.r.URL.Query().Get("name")
		ids := make([]string, 0, len(f.zones))
		for id := range f.zones {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return f.zones[ids[i]].named.Name < f.zones[ids[j]].named.Name })
		items := []any{}
		for _, id := range ids {
			z := f.zones[id]
			if name != "" && z.named.Name != name {
				continue
			}
			items = append(items, f.zoneObj(z))
		}
		c.paged(items, 20)
	})
	f.handle("GET /zones/{zone}", func(c *call) { c.ok(f.zoneObj(f.zones[c.pv("zone")])) })
	f.handle("POST /zones/{zone}/purge_cache", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		c.ok(map[string]any{"id": randHex(16)})
	})

	// DNS
	f.handle("GET /zones/{zone}/dns_records", func(c *call) {
		z := f.zones[c.pv("zone")]
		q := c.r.URL.Query()
		items := []any{}
		for _, o := range z.dns.list() {
			r := o.(map[string]any)
			if n := firstNonEmpty(q.Get("name"), q.Get("name.exact")); n != "" && !strings.EqualFold(r["name"].(string), n) {
				continue
			}
			if t := q.Get("type"); t != "" && r["type"] != t {
				continue
			}
			if v := firstNonEmpty(q.Get("content"), q.Get("content.exact")); v != "" && r["content"] != v {
				continue
			}
			items = append(items, r)
		}
		c.paged(items, 100)
	})
	f.handle("GET /zones/{zone}/dns_records/export", func(c *call) {
		z := f.zones[c.pv("zone")]
		var b strings.Builder
		for _, o := range z.dns.list() {
			r := o.(map[string]any)
			b.WriteString(r["name"].(string) + ".\t1\tIN\t" + r["type"].(string) + "\t" + toString(r["content"]) + "\n")
		}
		c.w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.w.WriteHeader(http.StatusOK)
		c.w.Write([]byte(b.String()))
	})
	f.handle("GET /zones/{zone}/dns_records/{id}", func(c *call) {
		z := f.zones[c.pv("zone")]
		if r := z.dns.get(c.pv("id")); r != nil {
			c.ok(r)
			return
		}
		c.err(http.StatusNotFound, 81044, "Record does not exist.")
	})
	dnsWrite := func(c *call, z *zone, id string, in map[string]any, merge map[string]any) {
		now := ts(f.now())
		rec := in
		if merge != nil {
			rec = clone(merge)
			for k, v := range in {
				rec[k] = v
			}
		}
		name, _ := rec["name"].(string)
		typ, _ := rec["type"].(string)
		if name == "" || typ == "" || rec["content"] == nil {
			c.err(http.StatusBadRequest, 9000, "DNS records need name, type and content")
			return
		}
		if name == "@" {
			name = z.named.Name
		} else if !strings.HasSuffix(name, z.named.Name) {
			name = name + "." + z.named.Name
		}
		rec["name"] = name
		rec["id"] = id
		rec["zone_id"] = z.named.ID
		rec["zone_name"] = z.named.Name
		rec["proxiable"] = typ == "A" || typ == "AAAA" || typ == "CNAME"
		if _, ok := rec["proxied"]; !ok {
			rec["proxied"] = false
		}
		if _, ok := rec["ttl"]; !ok {
			rec["ttl"] = 1
		}
		if merge != nil {
			rec["created_on"] = merge["created_on"]
		} else {
			rec["created_on"] = now
		}
		rec["modified_on"] = now
		z.dns.put(id, rec)
		c.ok(rec)
	}
	f.handle("POST /zones/{zone}/dns_records", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		dnsWrite(c, f.zones[c.pv("zone")], randHex(16), in, nil)
	})
	f.handle("PUT /zones/{zone}/dns_records/{id}", func(c *call) {
		z := f.zones[c.pv("zone")]
		old := z.dns.get(c.pv("id"))
		if old == nil {
			c.err(http.StatusNotFound, 81044, "Record does not exist.")
			return
		}
		var in map[string]any
		if !c.body(&in) {
			return
		}
		in["created_on"] = old["created_on"]
		dnsWrite(c, z, c.pv("id"), in, map[string]any{"created_on": old["created_on"]})
	})
	f.handle("PATCH /zones/{zone}/dns_records/{id}", func(c *call) {
		z := f.zones[c.pv("zone")]
		old := z.dns.get(c.pv("id"))
		if old == nil {
			c.err(http.StatusNotFound, 81044, "Record does not exist.")
			return
		}
		var in map[string]any
		if !c.body(&in) {
			return
		}
		dnsWrite(c, z, c.pv("id"), in, old)
	})
	f.handle("DELETE /zones/{zone}/dns_records/{id}", func(c *call) {
		if !f.zones[c.pv("zone")].dns.del(c.pv("id")) {
			c.err(http.StatusNotFound, 81044, "Record does not exist.")
			return
		}
		c.ok(map[string]any{"id": c.pv("id")})
	})

	// rulesets
	rulesetSummary := func(rs map[string]any) map[string]any {
		o := clone(rs)
		delete(o, "rules")
		return o
	}
	f.handle("GET /zones/{zone}/rulesets", func(c *call) {
		items := []any{}
		for _, o := range f.zones[c.pv("zone")].rulesets.list() {
			items = append(items, rulesetSummary(o.(map[string]any)))
		}
		c.ok(items)
	})
	f.handle("GET /zones/{zone}/rulesets/{id}", func(c *call) {
		if rs := f.zones[c.pv("zone")].rulesets.get(c.pv("id")); rs != nil {
			c.ok(rs)
			return
		}
		c.err(http.StatusNotFound, 10003, "could not find ruleset "+sanitizePath(c.pv("id")))
	})
	f.handle("GET /zones/{zone}/rulesets/phases/{phase}/entrypoint", func(c *call) {
		z := f.zones[c.pv("zone")]
		if id, ok := z.entry[c.pv("phase")]; ok {
			c.ok(z.rulesets.get(id))
			return
		}
		c.err(http.StatusNotFound, 10003, "could not find entrypoint ruleset in the '"+sanitizePath(c.pv("phase"))+"' phase")
	})
	f.handle("PUT /zones/{zone}/rulesets/phases/{phase}/entrypoint", func(c *call) {
		z := f.zones[c.pv("zone")]
		var in map[string]any
		if !c.body(&in) {
			return
		}
		phase := c.pv("phase")
		id, exists := z.entry[phase]
		version := 1
		if exists {
			version = atoiAny(z.rulesets.get(id)["version"]) + 1
		} else {
			id = randHex(16)
		}
		rs := map[string]any{"id": id, "name": firstNonEmpty(toString(in["name"]), "default"), "description": toString(in["description"]),
			"kind": "zone", "phase": phase, "version": itoa(version), "last_updated": ts(f.now())}
		rs["rules"] = normaliseRules(in["rules"], version, f.now())
		z.entry[phase] = id
		z.rulesets.put(id, rs)
		c.ok(rs)
	})
	f.handle("POST /zones/{zone}/rulesets/{id}/rules", func(c *call) {
		z := f.zones[c.pv("zone")]
		rs := z.rulesets.get(c.pv("id"))
		if rs == nil {
			c.err(http.StatusNotFound, 10003, "could not find ruleset")
			return
		}
		var in map[string]any
		if !c.body(&in) {
			return
		}
		v := atoiAny(rs["version"]) + 1
		rules, _ := rs["rules"].([]any)
		rules = append(rules, normaliseRules([]any{in}, v, f.now())...)
		rs["rules"], rs["version"], rs["last_updated"] = rules, itoa(v), ts(f.now())
		c.ok(rs)
	})
	ruleOp := func(del bool) handler {
		return func(c *call) {
			z := f.zones[c.pv("zone")]
			rs := z.rulesets.get(c.pv("id"))
			if rs == nil {
				c.err(http.StatusNotFound, 10003, "could not find ruleset")
				return
			}
			var in map[string]any
			if !del && !c.body(&in) {
				return
			}
			rules, _ := rs["rules"].([]any)
			out := []any{}
			found := false
			v := atoiAny(rs["version"]) + 1
			for _, r := range rules {
				rm := r.(map[string]any)
				if rm["id"] == c.pv("rule") {
					found = true
					if del {
						continue
					}
					for k, val := range in {
						rm[k] = val
					}
					rm["id"], rm["version"], rm["last_updated"] = c.pv("rule"), itoa(v), ts(f.now())
				}
				out = append(out, rm)
			}
			if !found {
				c.err(http.StatusNotFound, 10003, "could not find rule")
				return
			}
			rs["rules"], rs["version"], rs["last_updated"] = out, itoa(v), ts(f.now())
			c.ok(rs)
		}
	}
	f.handle("PATCH /zones/{zone}/rulesets/{id}/rules/{rule}", ruleOp(false))
	f.handle("DELETE /zones/{zone}/rulesets/{id}/rules/{rule}", ruleOp(true))

	// settings
	f.handle("GET /zones/{zone}/settings", func(c *call) {
		z := f.zones[c.pv("zone")]
		names := make([]string, 0, len(z.settings))
		for k := range z.settings {
			names = append(names, k)
		}
		sort.Strings(names)
		out := []any{}
		for _, n := range names {
			out = append(out, f.settingObj(z, n))
		}
		c.ok(out)
	})
	f.handle("GET /zones/{zone}/settings/{name}", func(c *call) {
		z := f.zones[c.pv("zone")]
		if _, ok := z.settings[c.pv("name")]; !ok {
			c.err(http.StatusNotFound, 1003, "Invalid or missing zone setting")
			return
		}
		c.ok(f.settingObj(z, c.pv("name")))
	})
	f.handle("PATCH /zones/{zone}/settings/{name}", func(c *call) {
		z := f.zones[c.pv("zone")]
		var in struct {
			Value any `json:"value"`
		}
		if !c.body(&in) {
			return
		}
		if in.Value == nil {
			c.err(http.StatusBadRequest, 1007, "value is required")
			return
		}
		z.settings[c.pv("name")] = in.Value
		z.settingMod[c.pv("name")] = f.now()
		c.ok(f.settingObj(z, c.pv("name")))
	})
	f.handle("PATCH /zones/{zone}/settings", func(c *call) {
		z := f.zones[c.pv("zone")]
		var in struct {
			Items []struct {
				ID    string `json:"id"`
				Value any    `json:"value"`
			} `json:"items"`
		}
		if !c.body(&in) {
			return
		}
		out := []any{}
		for _, it := range in.Items {
			z.settings[it.ID] = it.Value
			z.settingMod[it.ID] = f.now()
			out = append(out, f.settingObj(z, it.ID))
		}
		c.ok(out)
	})

	// Workers routes
	f.handle("GET /zones/{zone}/workers/routes", func(c *call) { c.ok(f.zones[c.pv("zone")].routes.list()) })
	f.handle("POST /zones/{zone}/workers/routes", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		in["id"] = randHex(16)
		f.zones[c.pv("zone")].routes.put(in["id"].(string), in)
		c.ok(in)
	})
	f.handle("PUT /zones/{zone}/workers/routes/{id}", func(c *call) {
		z := f.zones[c.pv("zone")]
		if z.routes.get(c.pv("id")) == nil {
			c.err(http.StatusNotFound, 10020, "route not found")
			return
		}
		var in map[string]any
		if !c.body(&in) {
			return
		}
		in["id"] = c.pv("id")
		z.routes.put(c.pv("id"), in)
		c.ok(in)
	})
	f.handle("DELETE /zones/{zone}/workers/routes/{id}", func(c *call) {
		if !f.zones[c.pv("zone")].routes.del(c.pv("id")) {
			c.err(http.StatusNotFound, 10020, "route not found")
			return
		}
		c.ok(map[string]any{"id": c.pv("id")})
	})

	// Email routing rules (enough for snapshots of cf.email)
	f.handle("GET /zones/{zone}/email/routing/rules", func(c *call) { c.paged(f.zones[c.pv("zone")].emailRules.list(), 20) })
	f.handle("POST /zones/{zone}/email/routing/rules", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		in["id"], in["tag"] = randHex(16), randHex(16)
		f.zones[c.pv("zone")].emailRules.put(in["id"].(string), in)
		c.ok(in)
	})
}

func normaliseRules(v any, version int, now time.Time) []any {
	in, _ := v.([]any)
	out := []any{}
	for _, r := range in {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		rm = clone(rm)
		if toString(rm["id"]) == "" {
			rm["id"] = randHex(16)
		}
		rm["version"] = itoa(version)
		rm["last_updated"] = ts(now)
		out = append(out, rm)
	}
	return out
}

// ---- tunnels ----

type tunnel struct {
	named   Named
	version int
	config  json.RawMessage
	created time.Time
}

func (f *Fake) tunnelObj(t *tunnel) map[string]any {
	return map[string]any{"id": t.named.ID, "name": t.named.Name, "status": "healthy", "tun_type": "cfd_tunnel",
		"created_at": ts(t.created), "deleted_at": nil, "account_tag": f.o.AccountID, "remote_config": true,
		"connections": []any{map[string]any{"colo_name": "lhr01", "id": uuid(), "is_pending_reconnect": false, "origin_ip": "192.0.2.1"}}}
}

func (f *Fake) tunnelRoutes() {
	tun := func(h func(c *call, t *tunnel)) handler {
		return func(c *call) {
			t := f.tunnels[c.pv("tunnel")]
			if t == nil {
				c.err(http.StatusNotFound, 1003, "Tunnel not found")
				return
			}
			h(c, t)
		}
	}
	f.handle("GET /accounts/{acct}/cfd_tunnel", func(c *call) {
		items := []any{}
		ids := make([]string, 0, len(f.tunnels))
		for id := range f.tunnels {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			items = append(items, f.tunnelObj(f.tunnels[id]))
		}
		c.paged(items, 20)
	})
	f.handle("GET /accounts/{acct}/cfd_tunnel/{tunnel}", tun(func(c *call, t *tunnel) { c.ok(f.tunnelObj(t)) }))
	f.handle("GET /accounts/{acct}/cfd_tunnel/{tunnel}/connections", tun(func(c *call, t *tunnel) {
		c.ok(f.tunnelObj(t)["connections"])
	}))
	configObj := func(t *tunnel) map[string]any {
		return map[string]any{"tunnel_id": t.named.ID, "version": t.version, "config": t.config, "source": "cloudflare", "created_at": ts(f.now())}
	}
	f.handle("GET /accounts/{acct}/cfd_tunnel/{tunnel}/configurations", tun(func(c *call, t *tunnel) { c.ok(configObj(t)) }))
	f.handle("PUT /accounts/{acct}/cfd_tunnel/{tunnel}/configurations", tun(func(c *call, t *tunnel) {
		var in struct {
			Config json.RawMessage `json:"config"`
		}
		if !c.body(&in) {
			return
		}
		var probe map[string]any
		if len(in.Config) == 0 || json.Unmarshal(in.Config, &probe) != nil {
			c.err(http.StatusBadRequest, 1055, "config must be an object")
			return
		}
		t.config = in.Config
		t.version++
		c.ok(configObj(t))
	}))
}

// ---- Access ----

func (f *Fake) accessRoutes() {
	crud := func(base string, cl func(c *call) *coll, kind string, extra func(o map[string]any, create bool)) {
		f.handle("GET "+base, func(c *call) { c.paged(cl(c).list(), 50) })
		f.handle("GET "+base+"/{id}", func(c *call) {
			if o := cl(c).get(c.pv("id")); o != nil {
				c.ok(o)
				return
			}
			c.err(http.StatusNotFound, 12130, kind+" not found")
		})
		f.handle("POST "+base, func(c *call) {
			var in map[string]any
			if !c.body(&in) {
				return
			}
			in["id"] = uuid()
			in["created_at"], in["updated_at"] = ts(f.now()), ts(f.now())
			if extra != nil {
				extra(in, true)
			}
			cl(c).put(in["id"].(string), in)
			c.okStatus(http.StatusCreated, in)
		})
		f.handle("PUT "+base+"/{id}", func(c *call) {
			old := cl(c).get(c.pv("id"))
			if old == nil {
				c.err(http.StatusNotFound, 12130, kind+" not found")
				return
			}
			var in map[string]any
			if !c.body(&in) {
				return
			}
			in["id"], in["created_at"], in["updated_at"] = c.pv("id"), old["created_at"], ts(f.now())
			if aud, ok := old["aud"]; ok {
				in["aud"] = aud
			}
			if extra != nil {
				extra(in, false)
			}
			cl(c).put(c.pv("id"), in)
			c.ok(in)
		})
		f.handle("DELETE "+base+"/{id}", func(c *call) {
			if !cl(c).del(c.pv("id")) {
				c.err(http.StatusNotFound, 12130, kind+" not found")
				return
			}
			c.ok(map[string]any{"id": c.pv("id")})
		})
	}
	apps := func(*call) *coll { return f.apps }
	crud("/accounts/{acct}/access/apps", apps, "application", func(o map[string]any, create bool) {
		if create {
			o["aud"] = randHex(32)
		}
	})
	f.handle("PATCH /accounts/{acct}/access/apps/{id}", func(c *call) {
		c.err(http.StatusMethodNotAllowed, 10405, "Method not allowed: PATCH is not supported for Access applications")
	})
	crud("/accounts/{acct}/access/policies", func(*call) *coll { return f.policies }, "policy", func(o map[string]any, create bool) {
		if _, ok := o["reusable"]; !ok {
			o["reusable"] = true
		}
	})
	crud("/accounts/{acct}/access/groups", func(*call) *coll { return f.groups }, "group", nil)
	appPolicies := func(c *call) *coll {
		id := c.pv("app")
		if f.appPol[id] == nil {
			f.appPol[id] = newColl()
		}
		return f.appPol[id]
	}
	crud("/accounts/{acct}/access/apps/{app}/policies", appPolicies, "policy", nil)
	f.handle("GET /accounts/{acct}/access/organizations", func(c *call) {
		c.ok(map[string]any{"name": "fake", "auth_domain": "fake.cloudflareaccess.com", "session_duration": "24h"})
	})
	f.handle("GET /accounts/{acct}/access/service_tokens", func(c *call) { c.paged([]any{}, 50) })
}

// ---- R2 buckets (list only; enough for cf.read) ----

func (f *Fake) r2Routes() {
	f.handle("GET /accounts/{acct}/r2/buckets", func(c *call) { c.ok(map[string]any{"buckets": f.r2.list()}) })
	f.handle("POST /accounts/{acct}/r2/buckets", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		n := toString(in["name"])
		if n == "" {
			c.err(http.StatusBadRequest, 10005, "name required")
			return
		}
		o := map[string]any{"name": n, "creation_date": ts(f.now()), "location": "WEUR"}
		f.r2.put(n, o)
		c.ok(o)
	})
}

// ---- small helpers ----

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func atoiAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n := 0
		for _, ch := range t {
			if ch < '0' || ch > '9' {
				return n
			}
			n = n*10 + int(ch-'0')
		}
		return n
	}
	return 0
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
