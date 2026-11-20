package cfproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"sort"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Data bindings (scope enforcement for cf.workers.deploy and cf.pages): a deployed Worker or
// Pages project may only bind the data the owner listed for it in
// [[cloudflare.worker_bindings]] (docs/CLOUDFLARE.md 4). Without it, a deploy grant for one
// script would reach every D1 database, bucket and namespace on the account.

// bindingAliases: fields refused per binding type (alternative names for the data).
var bindingAliases = map[string][]string{
	"d1":           {"database_name", "uuid"},
	"kv_namespace": {"id", "namespace"},
	"r2_bucket":    {"bucket", "id"},
	"queue":        {"queue", "id"},
	"service":      {"script", "script_name"},
	"hyperdrive":   {"hyperdrive_id"},
}

// freeBindings carry no account data.
var freeBindings = map[string]bool{
	"plain_text": true, "secret_text": true, "json": true, "assets": true, "version_metadata": true,
	"ai": true, "browser": true, "inherit": true, "wasm_module": true, "text_blob": true,
	"data_blob": true, "images": true, "ratelimit": true, "media": true, "secret_key": true,
}

// bindingNeed returns the worker_bindings entry ("<kind>:<value>") a Workers binding needs,
// "" when it needs none.
func bindingNeed(b map[string]any, script string, cfg *config.Cloudflare) (string, error) {
	t := str(b["type"])
	if freeBindings[t] {
		return "", nil
	}
	need := func(kind, field string) (string, error) {
		v := str(b[field])
		if v == "" {
			return "", fmt.Errorf("binding %q of type %s has no %s", str(b["name"]), t, field)
		}
		return kind + ":" + v, nil
	}
	// Alias fields Cloudflare might read instead of the one aqmasd checks.
	for _, alias := range bindingAliases[t] {
		if _, ok := b[alias]; ok {
			return "", fmt.Errorf("binding %q: field %q is not accepted (use the canonical field)", asciiOnly(str(b["name"])), alias)
		}
	}
	switch t {
	case "d1":
		id := str(b["id"])
		if dbid, ok := b["database_id"]; ok {
			if id != "" && str(dbid) != id {
				return "", fmt.Errorf("D1 binding %q has two different database ids", asciiOnly(str(b["name"])))
			}
			id = str(dbid)
		}
		for _, d := range cfg.D1Databases {
			if d.ID == id {
				return "d1:" + d.Name, nil
			}
		}
		return "", fmt.Errorf("D1 binding %q is not to a database configured in aqmasd", str(b["name"]))
	case "r2_bucket":
		return need("r2", "bucket_name")
	case "kv_namespace":
		return need("kv", "namespace_id")
	case "service":
		if str(b["service"]) == script {
			return "", nil
		}
		return need("service", "service")
	case "queue":
		return need("queue", "queue_name")
	case "durable_object_namespace", "workflow":
		sn := str(b["script_name"])
		if sn == "" || sn == script {
			if t == "durable_object_namespace" && str(b["namespace_id"]) != "" {
				return need("durable_object", "namespace_id")
			}
			return "", nil
		}
		if t == "workflow" {
			return need("workflow", "workflow_name")
		}
		return "durable_object:" + sn, nil
	case "hyperdrive":
		return need("hyperdrive", "id")
	case "vectorize":
		return need("vectorize", "index_name")
	case "analytics_engine":
		return need("analytics_engine", "dataset")
	case "secrets_store_secret":
		if str(b["store_id"]) == "" || str(b["secret_name"]) == "" {
			return "", fmt.Errorf("secrets store binding %q incomplete", str(b["name"]))
		}
		return "secrets_store:" + str(b["store_id"]) + "/" + str(b["secret_name"]), nil
	case "dispatch_namespace":
		return need("dispatch_namespace", "namespace")
	case "mtls_certificate":
		return need("mtls", "certificate_id")
	case "pipelines":
		return need("pipeline", "pipeline")
	case "send_email":
		return need("send_email", "name")
	}
	return "", fmt.Errorf("binding type %q is not allowed through aqmas", asciiOnly(t))
}

func allowSet(list []string) map[string]bool {
	m := map[string]bool{}
	for _, a := range list {
		m[a] = true
	}
	return m
}

// checkWorkerSettings checks a Workers metadata/settings object against the script's
// worker_bindings entry.
func checkWorkerSettings(meta map[string]any, script string, cfg *config.Cloudflare) error {
	return checkBindingsMeta(meta, script, "script", allowSet(cfg.AllowedBindings(script, false)), cfg)
}

// checkBindingsMeta checks bindings[], tail_consumers[] (a tail consumer receives the
// script's logs) and Durable Object migrations (a transfer from another script takes over its
// objects' data) of a Workers metadata/settings object. owner is the script (or Pages project)
// the upload is for.
func checkBindingsMeta(meta map[string]any, owner, what string, allow map[string]bool, cfg *config.Cloudflare) error {
	var missing []string
	if v, ok := meta["bindings"]; ok && v != nil && arr(v) == nil {
		return errors.New("bindings must be an array")
	}
	for _, b := range arr(meta["bindings"]) {
		m := obj(b)
		if m == nil {
			return errors.New("bindings entries must be objects")
		}
		n, err := bindingNeed(m, owner, cfg)
		if err != nil {
			return err
		}
		if n != "" && !allow[n] {
			missing = append(missing, n)
		}
	}
	for _, tc := range arr(meta["tail_consumers"]) {
		s := str(obj(tc)["service"])
		if s == "" {
			return errors.New("tail consumer without service")
		}
		if s != owner && !allow["service:"+s] {
			missing = append(missing, "service:"+s)
		}
	}
	if mig, ok := meta["migrations"]; ok && mig != nil {
		k := map[string][]string{"from_script": nil}
		collect(mig, k)
		for _, fs := range k["from_script"] {
			if fs != owner && !allow["durable_object:"+fs] {
				missing = append(missing, "durable_object:"+fs)
			}
		}
		if obj(mig) == nil && arr(mig) == nil {
			return errors.New("migrations must be an object")
		}
	}
	if len(missing) > 0 {
		missing = uniq(missing)
		return fmt.Errorf("%s %s may not bind %s (not in aqmasd's worker_bindings for it)", what, owner, strings.Join(missing, ", "))
	}
	return nil
}

// mpPart is one part of a multipart/form-data body as aqmasd parsed it.
type mpPart struct {
	name, filename, ctype string
	body                  []byte
}

// parseMultipartStrict parses a multipart/form-data body so that aqmasd and Cloudflare cannot
// disagree about it: every part has exactly one parseable Content-Disposition (form-data, a
// unique ASCII name, optionally a filename, no other parameters), at most one Content-Type,
// no other headers; names are unique. The body is re-encoded from these parts
// (encodeMultipart) before it goes upstream.
func parseMultipartStrict(ct string, body []byte) ([]mpPart, error) {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "multipart/form-data" || params["boundary"] == "" {
		return nil, errors.New("this upload must be multipart/form-data")
	}
	var out []mpPart
	seen := map[string]bool{}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("malformed multipart body")
		}
		for k, v := range p.Header {
			if k != "Content-Disposition" && k != "Content-Type" {
				return nil, fmt.Errorf("multipart header %q is not accepted", asciiOnly(k))
			}
			if len(v) != 1 {
				return nil, fmt.Errorf("repeated multipart header %s", k)
			}
		}
		rawCD := p.Header.Get("Content-Disposition")
		dt, dp, err := mime.ParseMediaType(rawCD)
		// RFC 2231 forms (name*=, name*0=) are decoded by Go but maybe not by Cloudflare.
		if err != nil || dt != "form-data" || strings.Contains(rawCD, "*") {
			return nil, errors.New("unparseable multipart Content-Disposition")
		}
		for k := range dp {
			if k != "name" && k != "filename" {
				return nil, fmt.Errorf("multipart Content-Disposition parameter %q is not accepted", asciiOnly(k))
			}
		}
		name := dp["name"]
		if name == "" || !printableASCII(name) || !printableASCII(dp["filename"]) {
			return nil, errors.New("multipart part names must be printable ASCII")
		}
		if seen[foldKey(name)] {
			return nil, fmt.Errorf("duplicate multipart part %q", asciiOnly(name))
		}
		seen[foldKey(name)] = true
		ctype := p.Header.Get("Content-Type")
		if ctype != "" {
			if _, _, err := mime.ParseMediaType(ctype); err != nil {
				return nil, fmt.Errorf("multipart part %q: bad Content-Type", name)
			}
		}
		b, err := io.ReadAll(p)
		if err != nil {
			return nil, errors.New("malformed multipart body")
		}
		out = append(out, mpPart{name: name, filename: dp["filename"], ctype: ctype, body: b})
	}
	return out, nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// quoteEscaper escapes quoted-string content as mime/multipart's Writer does.
var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

// encodeMultipart writes parts as a fresh multipart/form-data body.
func encodeMultipart(parts []mpPart) ([]byte, string) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for _, p := range parts {
		cd := `form-data; name="` + quoteEscaper.Replace(p.name) + `"`
		if p.filename != "" {
			cd += `; filename="` + quoteEscaper.Replace(p.filename) + `"`
		}
		h := textproto.MIMEHeader{"Content-Disposition": {cd}}
		if p.ctype != "" {
			h.Set("Content-Type", p.ctype)
		}
		w, _ := mw.CreatePart(h)
		_, _ = w.Write(p.body)
	}
	_ = mw.Close()
	return b.Bytes(), mw.FormDataContentType()
}

// jsonParts returns the named parts as JSON objects; a part whose name folds to one of names
// must be spelled exactly.
func jsonParts(parts []mpPart, names ...string) (map[string]map[string]any, error) {
	want := map[string]string{}
	for _, n := range names {
		want[foldKey(n)] = n
	}
	out := map[string]map[string]any{}
	for _, p := range parts {
		canon, ok := want[foldKey(p.name)]
		if !ok {
			continue
		}
		if canon != p.name {
			return nil, fmt.Errorf("multipart part %q must be named %q", asciiOnly(p.name), canon)
		}
		if err := checkJSONKeys(p.body); err != nil {
			return nil, fmt.Errorf("multipart part %q: %v", p.name, err)
		}
		v, err := decodeJSON(p.body)
		if err != nil || obj(v) == nil {
			return nil, fmt.Errorf("multipart part %q must be a JSON object", p.name)
		}
		out[p.name] = obj(v)
	}
	return out, nil
}

// pagesDeployParts are the parts `wrangler pages deploy` sends; anything else is refused.
var pagesDeployParts = map[string]bool{
	"manifest": true, "branch": true, "commit_message": true, "commit_hash": true, "commit_dirty": true,
	"_headers": true, "_redirects": true, "_routes.json": true, "_worker.bundle": true,
	"functions-filepath-routing-config.json": true, "wrangler_config_hash": true, "pages_build_output_dir": true,
}

// checkPagesDeployment checks a Pages deployment upload: only known parts; the
// `_worker.bundle` part (itself a Workers multipart upload whose metadata carries the
// bindings of the project's wrangler config) is parsed, checked against the project's
// worker_bindings entry and re-encoded. It returns the parts to send.
func checkPagesDeployment(parts []mpPart, project string, cfg *config.Cloudflare) ([]mpPart, error) {
	for i, p := range parts {
		if !pagesDeployParts[p.name] {
			return nil, fmt.Errorf("Pages deployment part %q is not accepted through aqmas", asciiOnly(p.name))
		}
		if p.name != "_worker.bundle" {
			continue
		}
		line, _, _ := bytes.Cut(p.body, []byte("\r\n"))
		if !bytes.HasPrefix(line, []byte("--")) || len(line) < 3 {
			return nil, errors.New("_worker.bundle is not a multipart bundle")
		}
		inner, err := parseMultipartStrict(mime.FormatMediaType("multipart/form-data", map[string]string{"boundary": string(line[2:])}), p.body)
		if err != nil {
			return nil, fmt.Errorf("_worker.bundle: %v", err)
		}
		metas, err := jsonParts(inner, "metadata")
		if err != nil {
			return nil, fmt.Errorf("_worker.bundle: %v", err)
		}
		if len(metas) != 1 {
			return nil, errors.New("_worker.bundle needs exactly one metadata part")
		}
		if err := checkBindingsMeta(metas["metadata"], project, "project", allowSet(cfg.AllowedBindings(project, true)), cfg); err != nil {
			return nil, err
		}
		body, _ := encodeMultipart(inner)
		parts[i].body = body
	}
	return parts, nil
}

// pagesBindingKeys maps deployment_configs.<env> keys holding data bindings to the kind and
// the field naming the data; pagesFreeKeys need nothing.
var pagesBindingKeys = map[string][2]string{
	"d1_databases": {"d1", "id"}, "kv_namespaces": {"kv", "namespace_id"}, "r2_buckets": {"r2", "name"},
	"services": {"service", "service"}, "queue_producers": {"queue", "name"},
	"durable_object_namespaces": {"durable_object", "namespace_id"}, "analytics_engine_datasets": {"analytics_engine", "dataset"},
	"hyperdrive_bindings": {"hyperdrive", "id"}, "vectorize_bindings": {"vectorize", "index_name"},
	"mtls_certificates": {"mtls", "certificate_id"},
}

var pagesFreeKeys = map[string]bool{
	"env_vars": true, "ai_bindings": true, "browsers": true, "compatibility_date": true, "compatibility_flags": true,
	"usage_model": true, "fail_open": true, "always_use_latest_compatibility_date": true,
	"build_image_major_version": true, "placement": true, "limits": true, "wrangler_config_hash": true,
}

// checkPagesProject checks a Pages project PATCH body's deployment_configs bindings.
func checkPagesProject(body any, project string, cfg *config.Cloudflare) error {
	dc, ok := obj(body)["deployment_configs"]
	if !ok || dc == nil {
		return nil
	}
	if obj(dc) == nil {
		return errors.New("deployment_configs must be an object")
	}
	allow := allowSet(cfg.AllowedBindings(project, true))
	var missing []string
	for env, conf := range obj(dc) {
		if env != "production" && env != "preview" {
			return fmt.Errorf("unknown deployment config %q", asciiOnly(env))
		}
		if conf == nil {
			continue
		}
		for k, v := range obj(conf) {
			if pagesFreeKeys[k] || v == nil {
				continue
			}
			kf, isData := pagesBindingKeys[k]
			if !isData {
				return fmt.Errorf("deployment config key %q is not allowed through aqmas", asciiOnly(k))
			}
			if obj(v) == nil {
				return fmt.Errorf("%s must be an object", k)
			}
			for name, bv := range obj(v) {
				if bv == nil {
					continue // removing a binding
				}
				val := str(obj(bv)[kf[1]])
				if val == "" {
					return fmt.Errorf("binding %s.%s has no %s", k, asciiOnly(name), kf[1])
				}
				n := kf[0] + ":" + val
				if kf[0] == "d1" {
					n = ""
					for _, d := range cfg.D1Databases {
						if d.ID == val {
							n = "d1:" + d.Name
						}
					}
					if n == "" {
						return fmt.Errorf("D1 binding %s is not to a database configured in aqmasd", asciiOnly(name))
					}
				}
				if kf[0] == "service" && val == project {
					continue
				}
				if !allow[n] {
					missing = append(missing, n)
				}
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("project %s may not bind %s (not in aqmasd's worker_bindings for it)", project, strings.Join(uniq(missing), ", "))
	}
	return nil
}
