package cfproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bodies that guard rails or scope checks read must mean the same to aqmasd and to
// Cloudflare. Cloudflare may match JSON keys case-insensitively (as Go's encoding/json does,
// Unicode simple folding included) and may keep the first or the last of duplicate keys, so on
// those routes aqmasd refuses: invalid UTF-8, two keys of one object that fold to the same
// name (exact duplicates included), and any key that folds to a field name aqmasd reads
// without being spelled exactly that way.

// guardedKeys: the field names guard rails and scope checks read, by fold key.
var guardedKeys = map[string]string{}

func init() {
	for _, k := range []string{
		// Access
		"domain", "self_hosted_domains", "destinations", "uri", "hostname", "session_duration",
		"decision", "include", "exclude", "require", "everyone", "group", "policies", "id", "reusable",
		// tunnels
		"config", "ingress", "originRequest", "originServerName", "noTLSVerify", "matchSNItoHost",
		"http2Origin", "access", "service", "path", "version",
		// DNS
		"name", "type", "content", "proxied",
		// rulesets, settings, purge
		"rules", "phase", "value", "items", "files", "url", "strict_transport_security",
		"include_subdomains", "preload",
		// Workers, Pages, R2 domains
		"script", "zone_id", "zone_name", "zoneId", "pattern", "origins", "environment", "bindings",
		"tail_consumers", "script_name", "class_name", "namespace_id", "bucket_name", "database_id",
		"queue_name", "index_name", "dataset", "store_id", "secret_name", "namespace", "certificate_id",
		"workflow_name", "pipeline", "deployment_configs", "production", "preview", "d1_databases",
		"kv_namespaces", "r2_buckets", "services", "queue_producers", "durable_object_namespaces",
		"analytics_engine_datasets", "hyperdrive_bindings", "vectorize_bindings", "mtls_certificates",
		"env_vars", "custom_domain",
		// D1, email
		"sql", "batch", "params", "actions", "matchers", "email",
	} {
		guardedKeys[foldKey(k)] = k
	}
}

// foldKey maps s to a canonical case-folded form: every rune becomes the smallest rune of its
// simple-folding orbit (so "K" (Kelvin), "k" and "K" agree, as do "ſ", "s" and "S").
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		b.WriteRune(m)
	}
	return b.String()
}

// checkJSONKeys applies the rules above to one JSON document.
func checkJSONKeys(b []byte) error {
	if !utf8.Valid(b) {
		return errors.New("the body is not valid UTF-8")
	}
	type frame struct {
		obj  bool
		key  bool // an object expecting a key (or '}')
		seen map[string]string
	}
	var st []*frame
	valueDone := func() {
		if len(st) > 0 && st[len(st)-1].obj {
			st[len(st)-1].key = true
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("the body is not valid JSON")
		}
		if n := len(st); n > 0 && st[n-1].obj && st[n-1].key {
			top := st[n-1]
			if tok == json.Delim('}') {
				st = st[:n-1]
				valueDone()
				continue
			}
			k, _ := tok.(string)
			fk := foldKey(k)
			if prev, dup := top.seen[fk]; dup {
				return fmt.Errorf("duplicate JSON key %q (also %q, ignoring case)", asciiOnly(k), asciiOnly(prev))
			}
			if canon, guarded := guardedKeys[fk]; guarded && canon != k {
				return fmt.Errorf("JSON key %q must be spelled %q", asciiOnly(k), canon)
			}
			top.seen[fk] = k
			top.key = false
			continue
		}
		switch tok {
		case json.Delim('{'):
			st = append(st, &frame{obj: true, key: true, seen: map[string]string{}})
		case json.Delim('['):
			st = append(st, &frame{})
		case json.Delim(']'):
			st = st[:len(st)-1]
			valueDone()
		default:
			valueDone()
		}
	}
}

// requestIsJSON: an empty or JSON Content-Type.
func requestIsJSON(ct string) bool {
	if strings.TrimSpace(ct) == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}
