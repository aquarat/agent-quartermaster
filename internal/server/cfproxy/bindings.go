package cfproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"sort"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Data bindings (scope enforcement for cf.workers.deploy and cf.pages): a deployed Worker or
// Pages project may only bind the data the owner listed for it in
// [[cloudflare.worker_bindings]] (docs/CLOUDFLARE.md 4). Without it, a deploy grant for one
// script would reach every D1 database, bucket and namespace on the account.

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
	switch t {
	case "d1":
		id := str(b["id"])
		if id == "" {
			id = str(b["database_id"])
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

// checkWorkerSettings checks a Workers metadata/settings object: bindings[] and
// tail_consumers[] (a tail consumer receives the script's logs: a service binding).
func checkWorkerSettings(meta map[string]any, script string, cfg *config.Cloudflare) error {
	allow := allowSet(cfg.AllowedBindings(script, false))
	var missing []string
	if v, ok := meta["bindings"]; ok && v != nil && arr(v) == nil {
		return errors.New("bindings must be an array")
	}
	for _, b := range arr(meta["bindings"]) {
		m := obj(b)
		if m == nil {
			return errors.New("bindings entries must be objects")
		}
		n, err := bindingNeed(m, script, cfg)
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
		if s != script && !allow["service:"+s] {
			missing = append(missing, "service:"+s)
		}
	}
	if len(missing) > 0 {
		missing = uniq(missing)
		return fmt.Errorf("script %s may not bind %s (not in aqmasd's worker_bindings for it)", script, strings.Join(missing, ", "))
	}
	return nil
}

// workerParts reads the named JSON parts of a multipart body. Every part whose name folds to
// one of names must be spelled exactly and appear once; transfer encodings are refused.
func workerParts(ct string, body []byte, names ...string) (map[string]map[string]any, error) {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "multipart/form-data" || params["boundary"] == "" {
		return nil, errors.New("this upload must be multipart/form-data")
	}
	want := map[string]string{}
	for _, n := range names {
		want[foldKey(n)] = n
	}
	out := map[string]map[string]any{}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("malformed multipart body")
		}
		name := p.FormName()
		canon, isWanted := want[foldKey(name)]
		if !isWanted {
			continue
		}
		if canon != name {
			return nil, fmt.Errorf("multipart part %q must be named %q", asciiOnly(name), canon)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("duplicate multipart part %q", name)
		}
		if p.Header.Get("Content-Transfer-Encoding") != "" || p.Header.Get("Content-Encoding") != "" {
			return nil, fmt.Errorf("multipart part %q: transfer encodings are not accepted", name)
		}
		b, err := io.ReadAll(io.LimitReader(p, 4<<20+1))
		if err != nil || len(b) > 4<<20 {
			return nil, fmt.Errorf("multipart part %q unreadable or too large", name)
		}
		if err := checkJSONKeys(b); err != nil {
			return nil, fmt.Errorf("multipart part %q: %v", name, err)
		}
		v, err := decodeJSON(b)
		if err != nil || obj(v) == nil {
			return nil, fmt.Errorf("multipart part %q must be a JSON object", name)
		}
		out[name] = obj(v)
	}
	return out, nil
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
