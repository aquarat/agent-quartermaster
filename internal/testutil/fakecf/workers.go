package fakecf

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ---- Workers ----

type script struct {
	name        string
	created     time.Time
	modified    time.Time
	etag        string
	meta        map[string]any
	settings    map[string]any
	secrets     map[string]string // name -> type
	schedules   []any
	subdomain   bool
	previews    bool
	hasAssets   bool
	versions    []map[string]any
	deployments []map[string]any
}

// readMultipart parses a multipart/form-data body into field name -> content (each part read
// fully, at most 128 MiB in total).
func readMultipart(c *call) (map[string][]byte, map[string]string, bool) {
	mt, params, err := mime.ParseMediaType(c.r.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") {
		c.err(http.StatusBadRequest, 10021, "expected a multipart/form-data body")
		return nil, nil, false
	}
	mr := multipart.NewReader(io.LimitReader(c.r.Body, 128<<20), params["boundary"])
	out, types := map[string][]byte{}, map[string]string{}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.err(http.StatusBadRequest, 10021, "bad multipart body: "+err.Error())
			return nil, nil, false
		}
		data, err := io.ReadAll(p)
		if err != nil {
			c.err(http.StatusBadRequest, 10021, "bad multipart part: "+err.Error())
			return nil, nil, false
		}
		out[p.FormName()] = data
		types[p.FormName()] = p.Header.Get("Content-Type")
	}
	return out, types, true
}

func (f *Fake) scriptObj(s *script) map[string]any {
	o := map[string]any{"id": s.name, "tag": randHexFor(s.name), "etag": s.etag, "handlers": []string{"fetch", "scheduled"},
		"modified_on": ts(s.modified), "created_on": ts(s.created), "usage_model": "standard", "has_assets": s.hasAssets,
		"has_modules": true, "startup_time_ms": 1, "compatibility_date": toString(s.meta["compatibility_date"]),
		"compatibility_flags": s.meta["compatibility_flags"], "placement_mode": "", "logpush": false, "tail_consumers": nil}
	if len(s.deployments) > 0 {
		o["deployment_id"] = s.deployments[len(s.deployments)-1]["id"]
	}
	return o
}

func randHexFor(name string) string {
	h := sha256.Sum256([]byte("tag:" + name))
	return hex.EncodeToString(h[:16])
}

// upload takes a Workers script/version multipart body; it returns the new version.
func (f *Fake) uploadScript(c *call, name string, deploy bool) (*script, map[string]any, bool) {
	parts, _, ok := readMultipart(c)
	if !ok {
		return nil, nil, false
	}
	var meta map[string]any
	if err := json.Unmarshal(parts["metadata"], &meta); err != nil {
		c.err(http.StatusBadRequest, 10021, "metadata part missing or not JSON")
		return nil, nil, false
	}
	mainModule := toString(meta["main_module"])
	if mainModule == "" {
		mainModule = toString(meta["body_part"])
	}
	if mainModule == "" || parts[mainModule] == nil {
		c.err(http.StatusBadRequest, 10021, "No such module: main_module/body_part not in the upload")
		return nil, nil, false
	}
	hasAssets := false
	if a, ok := meta["assets"].(map[string]any); ok {
		jwt := toString(a["jwt"])
		j := f.jwts[jwt]
		if j == nil || j.kind != "workers-completion" || j.script != name {
			c.err(http.StatusBadRequest, 10200, "assets: invalid or missing completion token")
			return nil, nil, false
		}
		hasAssets = true
	}
	s := f.scripts[name]
	now := f.now()
	if s == nil {
		if !deploy {
			c.err(http.StatusNotFound, 10007, "This Worker does not exist on your account.")
			return nil, nil, false
		}
		s = &script{name: name, created: now, secrets: map[string]string{}, settings: map[string]any{}}
		f.scripts[name] = s
	}
	if b, ok := meta["bindings"].([]any); ok {
		for _, x := range b {
			if bm, ok := x.(map[string]any); ok && (bm["type"] == "secret_text" || bm["type"] == "secret_key") {
				s.secrets[toString(bm["name"])] = toString(bm["type"])
			}
		}
	}
	sum := sha256.Sum256(parts[mainModule])
	s.etag = hex.EncodeToString(sum[:])
	s.meta = meta
	s.modified = now
	s.hasAssets = hasAssets
	v := map[string]any{"id": uuid(), "number": len(s.versions) + 1, "created_on": ts(now),
		"metadata":    map[string]any{"author_email": "owner@example.invalid", "source": "wrangler", "created_on": ts(now), "modified_on": ts(now), "has_preview": true},
		"annotations": meta["annotations"], "resources": map[string]any{"script": map[string]any{"etag": s.etag, "handlers": []string{"fetch", "scheduled"}},
			"bindings": meta["bindings"], "script_runtime": map[string]any{"compatibility_date": meta["compatibility_date"]}},
		"startup_time_ms": 1}
	s.versions = append(s.versions, v)
	if deploy {
		s.deployments = append(s.deployments, map[string]any{"id": uuid(), "source": "wrangler", "strategy": "percentage",
			"author_email": "owner@example.invalid", "created_on": ts(now),
			"versions": []any{map[string]any{"version_id": v["id"], "percentage": 100}}})
	}
	return s, v, true
}

func (f *Fake) workersRoutes() {
	sc := func(h func(c *call, s *script)) handler {
		return func(c *call) {
			s := f.scripts[c.pv("script")]
			if s == nil {
				c.err(http.StatusNotFound, 10007, "This Worker does not exist on your account.")
				return
			}
			h(c, s)
		}
	}
	f.handle("GET /accounts/{acct}/workers/scripts", func(c *call) {
		names := make([]string, 0, len(f.scripts))
		for n := range f.scripts {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []any{}
		for _, n := range names {
			out = append(out, f.scriptObj(f.scripts[n]))
		}
		c.ok(out)
	})
	f.handle("GET /accounts/{acct}/workers/services/{script}", func(c *call) {
		s := f.scripts[c.pv("script")]
		if s == nil {
			c.err(http.StatusNotFound, 10090, "This Worker does not exist on your account.")
			return
		}
		so := f.scriptObj(s)
		so["last_deployed_from"] = "wrangler"
		c.ok(map[string]any{"id": s.name, "default_environment": map[string]any{"environment": "production", "script": so,
			"created_on": ts(s.created), "modified_on": ts(s.modified)}, "created_on": ts(s.created), "modified_on": ts(s.modified)})
	})
	// The newer Workers resource (wrangler reads the per-Worker subdomain settings here).
	workerObj := func(s *script) map[string]any {
		return map[string]any{"id": randHexFor(s.name), "name": s.name, "created_on": ts(s.created), "updated_on": ts(s.modified),
			"subdomain": map[string]any{"enabled": s.subdomain, "previews_enabled": s.previews}, "observability": map[string]any{"enabled": false},
			"tags": []string{}, "logpush": false, "previews_base_config": s.settings["previews_base_config"]}
	}
	f.handle("GET /accounts/{acct}/workers/workers/{script}", sc(func(c *call, s *script) { c.ok(workerObj(s)) }))
	f.handle("PATCH /accounts/{acct}/workers/workers/{script}", sc(func(c *call, s *script) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		if v, ok := in["previews_base_config"]; ok {
			s.settings["previews_base_config"] = v
		}
		if sd, ok := in["subdomain"].(map[string]any); ok {
			if v, ok := sd["enabled"].(bool); ok {
				s.subdomain = v
			}
			if v, ok := sd["previews_enabled"].(bool); ok {
				s.previews = v
			}
		}
		c.ok(workerObj(s))
	}))
	f.handle("GET /accounts/{acct}/workers/scripts/{script}", func(c *call) {
		c.err(http.StatusForbidden, 10000, "fakecf: script content download is not simulated")
	})
	f.handle("PUT /accounts/{acct}/workers/scripts/{script}", func(c *call) {
		s, _, ok := f.uploadScript(c, c.pv("script"), true)
		if !ok {
			return
		}
		c.ok(f.scriptObj(s))
	})
	f.handle("DELETE /accounts/{acct}/workers/scripts/{script}", sc(func(c *call, s *script) {
		delete(f.scripts, s.name)
		c.ok(nil)
	}))
	settingsGet := sc(func(c *call, s *script) {
		o := map[string]any{"logpush": false, "tail_consumers": nil, "observability": map[string]any{"enabled": false},
			"bindings": s.meta["bindings"], "compatibility_date": s.meta["compatibility_date"], "compatibility_flags": s.meta["compatibility_flags"],
			"usage_model": "standard", "tags": nil}
		for k, v := range s.settings {
			o[k] = v
		}
		c.ok(o)
	})
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/settings", settingsGet)
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/script-settings", settingsGet)
	f.handle("PATCH /accounts/{acct}/workers/scripts/{script}/settings", sc(func(c *call, s *script) {
		parts, _, ok := readMultipart(c)
		if !ok {
			return
		}
		var in map[string]any
		if err := json.Unmarshal(parts["settings"], &in); err != nil {
			c.err(http.StatusBadRequest, 10021, "settings part missing or not JSON")
			return
		}
		for k, v := range in {
			s.settings[k] = v
		}
		settingsGet(c)
	}))
	f.handle("PATCH /accounts/{acct}/workers/scripts/{script}/script-settings", sc(func(c *call, s *script) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		for k, v := range in {
			s.settings[k] = v
		}
		settingsGet(c)
	}))

	// assets
	f.handle("POST /accounts/{acct}/workers/scripts/{script}/assets-upload-session", func(c *call) {
		var in struct {
			Manifest map[string]struct {
				Hash string `json:"hash"`
				Size int64  `json:"size"`
			} `json:"manifest"`
		}
		if !c.body(&in) {
			return
		}
		missing := []string{}
		seen := map[string]bool{}
		for _, e := range in.Manifest {
			if e.Hash == "" {
				c.err(http.StatusBadRequest, 10021, "manifest entry without hash")
				return
			}
			if !f.wAssets[e.Hash] && !seen[e.Hash] {
				missing = append(missing, e.Hash)
				seen[e.Hash] = true
			}
		}
		sort.Strings(missing)
		exp := f.now().Add(time.Hour)
		if len(missing) == 0 {
			jwt := f.newJWTLocked(&jwtInfo{kind: "workers-completion", exp: exp, script: c.pv("script")}, nil)
			c.ok(map[string]any{"jwt": jwt, "buckets": []any{}})
			return
		}
		buckets := [][]string{}
		size := 2
		if f.o.SingleAssetUploads {
			size = 1
		}
		for i := 0; i < len(missing); i += size {
			buckets = append(buckets, missing[i:min(i+size, len(missing))])
		}
		claims := map[string]any{}
		if f.o.SingleAssetUploads {
			claims["wrangler_single_asset_uploads"] = true
		}
		jwt := f.newJWTLocked(&jwtInfo{kind: "workers-upload", exp: exp, script: c.pv("script"), pending: seen}, claims)
		c.ok(map[string]any{"jwt": jwt, "buckets": buckets})
	})
	finishUpload := func(c *call) {
		if len(c.jwt.pending) == 0 {
			jwt := f.newJWTLocked(&jwtInfo{kind: "workers-completion", exp: f.now().Add(time.Hour), script: c.jwt.script}, nil)
			c.okStatus(http.StatusCreated, map[string]any{"jwt": jwt})
			return
		}
		c.okStatus(http.StatusAccepted, map[string]any{})
	}
	f.handle("POST /accounts/{acct}/workers/assets/upload", func(c *call) {
		if c.jwt == nil || c.jwt.kind != "workers-upload" {
			c.err(http.StatusUnauthorized, 8000013, "upload JWT required")
			return
		}
		parts, _, ok := readMultipart(c)
		if !ok {
			return
		}
		b64 := c.r.URL.Query().Get("base64") == "true"
		for hash, data := range parts {
			if b64 {
				if _, err := base64.StdEncoding.DecodeString(string(data)); err != nil {
					c.err(http.StatusBadRequest, 10021, "asset "+sanitizePath(hash)+" is not base64")
					return
				}
			}
			if !c.jwt.pending[hash] {
				c.err(http.StatusBadRequest, 10021, "asset "+sanitizePath(hash)+" is not part of this upload session")
				return
			}
			delete(c.jwt.pending, hash)
			f.wAssets[hash] = true
		}
		finishUpload(c)
	})
	f.handle("POST /accounts/{acct}/workers/assets/upload/{hash}", func(c *call) {
		if c.jwt == nil || c.jwt.kind != "workers-upload" {
			c.err(http.StatusUnauthorized, 8000013, "upload JWT required")
			return
		}
		hash := c.pv("hash")
		if !c.jwt.pending[hash] {
			c.err(http.StatusBadRequest, 10021, "asset is not part of this upload session")
			return
		}
		io.Copy(io.Discard, c.r.Body)
		delete(c.jwt.pending, hash)
		f.wAssets[hash] = true
		finishUpload(c)
	})

	// subdomain, schedules, secrets
	f.handle("GET /accounts/{acct}/workers/subdomain", func(c *call) { c.ok(map[string]any{"subdomain": f.wSubdomain}) })
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/subdomain", sc(func(c *call, s *script) {
		c.ok(map[string]any{"enabled": s.subdomain, "previews_enabled": s.previews})
	}))
	f.handle("POST /accounts/{acct}/workers/scripts/{script}/subdomain", sc(func(c *call, s *script) {
		var in struct {
			Enabled         bool  `json:"enabled"`
			PreviewsEnabled *bool `json:"previews_enabled"`
		}
		if !c.body(&in) {
			return
		}
		s.subdomain = in.Enabled
		if in.PreviewsEnabled != nil {
			s.previews = *in.PreviewsEnabled
		} else {
			s.previews = in.Enabled
		}
		c.ok(map[string]any{"enabled": s.subdomain, "previews_enabled": s.previews})
	}))
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/schedules", sc(func(c *call, s *script) {
		c.ok(map[string]any{"schedules": nonNil(s.schedules)})
	}))
	f.handle("PUT /accounts/{acct}/workers/scripts/{script}/schedules", sc(func(c *call, s *script) {
		var in []map[string]any
		if !c.body(&in) {
			return
		}
		s.schedules = nil
		for _, x := range in {
			if toString(x["cron"]) == "" {
				c.err(http.StatusBadRequest, 10100, "invalid cron")
				return
			}
			s.schedules = append(s.schedules, map[string]any{"cron": x["cron"], "created_on": ts(f.now()), "modified_on": ts(f.now())})
		}
		c.ok(map[string]any{"schedules": nonNil(s.schedules)})
	}))
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/secrets", sc(func(c *call, s *script) {
		names := make([]string, 0, len(s.secrets))
		for n := range s.secrets {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []any{}
		for _, n := range names {
			out = append(out, map[string]any{"name": n, "type": s.secrets[n]})
		}
		c.ok(out)
	}))
	f.handle("PUT /accounts/{acct}/workers/scripts/{script}/secrets", sc(func(c *call, s *script) {
		var in struct {
			Name string `json:"name"`
			Text string `json:"text"`
			Type string `json:"type"`
		}
		if !c.body(&in) {
			return
		}
		if in.Name == "" || in.Type == "" {
			c.err(http.StatusBadRequest, 10021, "name and type are required")
			return
		}
		s.secrets[in.Name] = in.Type
		s.versions = append(s.versions, map[string]any{"id": uuid(), "number": len(s.versions) + 1, "created_on": ts(f.now()),
			"metadata": map[string]any{"source": "api", "author_email": "owner@example.invalid"}})
		c.ok(map[string]any{"name": in.Name, "type": in.Type})
	}))
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/secrets/{name}", sc(func(c *call, s *script) {
		t, ok := s.secrets[c.pv("name")]
		if !ok {
			c.err(http.StatusNotFound, 10056, "secret not found")
			return
		}
		c.ok(map[string]any{"name": c.pv("name"), "type": t})
	}))
	f.handle("DELETE /accounts/{acct}/workers/scripts/{script}/secrets/{name}", sc(func(c *call, s *script) {
		if _, ok := s.secrets[c.pv("name")]; !ok {
			c.err(http.StatusNotFound, 10056, "secret not found")
			return
		}
		delete(s.secrets, c.pv("name"))
		c.ok(nil)
	}))

	// versions and deployments
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/versions", sc(func(c *call, s *script) {
		items := []any{}
		for i := len(s.versions) - 1; i >= 0; i-- {
			items = append(items, s.versions[i])
		}
		c.ok(map[string]any{"items": items})
	}))
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/versions/{id}", sc(func(c *call, s *script) {
		for _, v := range s.versions {
			if v["id"] == c.pv("id") {
				c.ok(v)
				return
			}
		}
		c.err(http.StatusNotFound, 10007, "version not found")
	}))
	f.handle("POST /accounts/{acct}/workers/scripts/{script}/versions", func(c *call) {
		_, v, ok := f.uploadScript(c, c.pv("script"), f.scripts[c.pv("script")] == nil)
		if !ok {
			return
		}
		c.ok(v)
	})
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/deployments", sc(func(c *call, s *script) {
		ds := []any{}
		for i := len(s.deployments) - 1; i >= 0; i-- {
			ds = append(ds, s.deployments[i])
		}
		c.ok(map[string]any{"deployments": ds})
	}))
	f.handle("POST /accounts/{acct}/workers/scripts/{script}/deployments", sc(func(c *call, s *script) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		d := map[string]any{"id": uuid(), "source": "api", "strategy": firstNonEmpty(toString(in["strategy"]), "percentage"),
			"author_email": "owner@example.invalid", "created_on": ts(f.now()), "versions": in["versions"], "annotations": in["annotations"]}
		s.deployments = append(s.deployments, d)
		c.ok(d)
	}))

	// account-level bits wrangler reads
	f.handle("GET /accounts/{acct}/workers/account-settings", func(c *call) {
		c.ok(map[string]any{"default_usage_model": "standard", "green_compute": false})
	})
	f.handle("GET /accounts/{acct}/workers/durable_objects/namespaces", func(c *call) { c.paged([]any{}, 1000) })
	f.handle("GET /accounts/{acct}/workers/domains", func(c *call) { c.ok(f.wDomains.list()) })
	f.handle("PUT /accounts/{acct}/workers/domains", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		in["id"] = randHex(16)
		f.wDomains.put(in["id"].(string), in)
		c.ok(in)
	})
	f.handle("DELETE /accounts/{acct}/workers/domains/{id}", func(c *call) {
		if !f.wDomains.del(c.pv("id")) {
			c.err(http.StatusNotFound, 100114, "domain not found")
			return
		}
		c.ok(nil)
	})
	f.handle("GET /accounts/{acct}/workers/scripts/{script}/domains/records", func(c *call) { c.ok([]any{}) })
	f.handle("PUT /accounts/{acct}/workers/scripts/{script}/domains/records", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		c.ok(nonNil(nil))
	})
}

func nonNil(v []any) []any {
	if v == nil {
		return []any{}
	}
	return v
}

// ---- Pages ----

type pagesProject struct {
	obj         map[string]any
	deployments *coll
}

func newPagesProject(name string, now time.Time) *pagesProject {
	cfg := map[string]any{"compatibility_date": "2024-01-01", "env_vars": map[string]any{}, "fail_open": true, "usage_model": "standard"}
	return &pagesProject{deployments: newColl(), obj: map[string]any{
		"id": uuid(), "name": name, "subdomain": name + ".pages.dev", "domains": []string{name + ".pages.dev"},
		"production_branch": "main", "created_on": ts(now), "source": nil,
		"build_config":       map[string]any{"build_command": "", "destination_dir": "", "root_dir": ""},
		"deployment_configs": map[string]any{"production": cfg, "preview": clone(cfg)},
	}}
}

func (f *Fake) pagesRoutes() {
	pr := func(h func(c *call, p *pagesProject)) handler {
		return func(c *call) {
			p := f.pages[c.pv("project")]
			if p == nil {
				c.err(http.StatusNotFound, 8000007, "Project not found. The specified project name does not match any of your existing projects.")
				return
			}
			h(c, p)
		}
	}
	f.handle("GET /accounts/{acct}/pages/projects", func(c *call) {
		names := make([]string, 0, len(f.pages))
		for n := range f.pages {
			names = append(names, n)
		}
		sort.Strings(names)
		items := []any{}
		for _, n := range names {
			items = append(items, f.pages[n].obj)
		}
		c.paged(items, 10)
	})
	f.handle("POST /accounts/{acct}/pages/projects", func(c *call) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		n := toString(in["name"])
		if n == "" || f.pages[n] != nil {
			c.err(http.StatusBadRequest, 8000002, "project name missing or taken")
			return
		}
		p := newPagesProject(n, f.now())
		if b := toString(in["production_branch"]); b != "" {
			p.obj["production_branch"] = b
		}
		f.pages[n] = p
		c.ok(p.obj)
	})
	f.handle("GET /accounts/{acct}/pages/projects/{project}", pr(func(c *call, p *pagesProject) { c.ok(p.obj) }))
	f.handle("PATCH /accounts/{acct}/pages/projects/{project}", pr(func(c *call, p *pagesProject) {
		var in map[string]any
		if !c.body(&in) {
			return
		}
		for k, v := range in {
			if k != "id" && k != "name" {
				p.obj[k] = v
			}
		}
		c.ok(p.obj)
	}))
	f.handle("GET /accounts/{acct}/pages/projects/{project}/upload-token", pr(func(c *call, p *pagesProject) {
		jwt := f.newJWTLocked(&jwtInfo{kind: "pages-upload", exp: f.now().Add(time.Hour), project: c.pv("project")}, nil)
		c.ok(map[string]any{"jwt": jwt})
	}))
	pagesJWT := func(h handler) handler {
		return func(c *call) {
			if c.jwt == nil || c.jwt.kind != "pages-upload" {
				c.err(http.StatusUnauthorized, 8000013, "Pages upload JWT required")
				return
			}
			h(c)
		}
	}
	f.handle("POST /pages/assets/check-missing", pagesJWT(func(c *call) {
		var in struct {
			Hashes []string `json:"hashes"`
		}
		if !c.body(&in) {
			return
		}
		missing := []string{}
		for _, h := range in.Hashes {
			if !f.pAssets[h] {
				missing = append(missing, h)
			}
		}
		c.ok(missing)
	}))
	f.handle("POST /pages/assets/upload", pagesJWT(func(c *call) {
		var in []struct {
			Key    string `json:"key"`
			Value  string `json:"value"`
			Base64 bool   `json:"base64"`
		}
		if !c.body(&in) {
			return
		}
		for _, a := range in {
			if a.Key == "" {
				c.err(http.StatusBadRequest, 8000096, "asset without key")
				return
			}
			f.pAssets[a.Key] = true
		}
		c.ok(nil)
	}))
	f.handle("POST /pages/assets/upsert-hashes", pagesJWT(func(c *call) {
		var in struct {
			Hashes []string `json:"hashes"`
		}
		if !c.body(&in) {
			return
		}
		c.ok(nil)
	}))
	f.handle("GET /accounts/{acct}/pages/projects/{project}/deployments", pr(func(c *call, p *pagesProject) {
		items := p.deployments.list()
		for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
			items[i], items[j] = items[j], items[i]
		}
		c.paged(items, 25)
	}))
	f.handle("POST /accounts/{acct}/pages/projects/{project}/deployments", pr(func(c *call, p *pagesProject) {
		parts, _, ok := readMultipart(c)
		if !ok {
			return
		}
		var manifest map[string]string
		if err := json.Unmarshal(parts["manifest"], &manifest); err != nil {
			c.err(http.StatusBadRequest, 8000096, "manifest part missing or not JSON")
			return
		}
		for path, h := range manifest {
			if !f.pAssets[h] {
				c.err(http.StatusBadRequest, 8000096, "asset "+sanitizePath(path)+" was not uploaded")
				return
			}
		}
		branch := firstNonEmpty(string(parts["branch"]), toString(p.obj["production_branch"]))
		env := "preview"
		if branch == p.obj["production_branch"] {
			env = "production"
		}
		now := ts(f.now())
		id := uuid()
		name := toString(p.obj["name"])
		stage := func(n string) map[string]any {
			return map[string]any{"name": n, "started_on": now, "ended_on": now, "status": "success"}
		}
		d := map[string]any{"id": id, "short_id": id[:8], "project_id": p.obj["id"], "project_name": name, "environment": env,
			"url": "https://" + id[:8] + "." + name + ".pages.dev", "created_on": now, "modified_on": now,
			"latest_stage":       stage("deploy"),
			"stages":             []any{stage("queued"), stage("initialize"), stage("clone_repo"), stage("build"), stage("deploy")},
			"deployment_trigger": map[string]any{"type": "ad_hoc", "metadata": map[string]any{"branch": branch, "commit_hash": string(parts["commit_hash"]), "commit_message": string(parts["commit_message"])}},
			"aliases":            []string{}, "is_skipped": false, "files": len(manifest),
			"build_config": p.obj["build_config"], "source": nil, "env_vars": map[string]any{}}
		p.deployments.put(id, d)
		p.obj["latest_deployment"] = d
		c.ok(d)
	}))
	f.handle("GET /accounts/{acct}/pages/projects/{project}/deployments/{id}", pr(func(c *call, p *pagesProject) {
		if d := p.deployments.get(c.pv("id")); d != nil {
			c.ok(d)
			return
		}
		c.err(http.StatusNotFound, 8000009, "deployment not found")
	}))
	f.handle("DELETE /accounts/{acct}/pages/projects/{project}/deployments/{id}", pr(func(c *call, p *pagesProject) {
		if !p.deployments.del(c.pv("id")) {
			c.err(http.StatusNotFound, 8000009, "deployment not found")
			return
		}
		c.ok(nil)
	}))
	f.handle("GET /accounts/{acct}/pages/projects/{project}/deployments/{id}/history/logs", pr(func(c *call, p *pagesProject) {
		c.ok(map[string]any{"total": 0, "includes_container_logs": false, "data": []any{}})
	}))
	f.handle("GET /accounts/{acct}/pages/projects/{project}/domains", pr(func(c *call, p *pagesProject) { c.ok([]any{}) }))
}
