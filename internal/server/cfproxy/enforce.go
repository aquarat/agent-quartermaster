package cfproxy

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
)

// Scope enforcement (docs/CLOUDFLARE.md 4, last paragraph): limits of a non-admin grant that
// need the body or the before-snapshot. Not guard rails: never overridable, and cf.admin is
// not limited by them. A violation answers 403 no_grant.

// nameGlobMatch: "*.example.com" matches one or more labels below example.com (not
// example.com itself); anything else matches exactly.
func nameGlobMatch(glob, name string) bool {
	glob, name = strings.ToLower(glob), strings.ToLower(name)
	if base, ok := strings.CutPrefix(glob, "*."); ok {
		return strings.HasSuffix(name, "."+base) && len(name) > len(base)+1
	}
	return glob == name
}

// enforceDNSName: with a name param every record written or touched matches the glob.
func enforceDNSName(glob, zone, method string, body, before map[string]any) error {
	if glob == "" {
		return nil
	}
	var names []string
	if method != "DELETE" {
		if n := str(body["name"]); n != "" || method == "POST" || method == "PUT" {
			names = append(names, fqdn(n, zone))
		}
	}
	if method != "POST" {
		names = append(names, fqdn(str(before["name"]), zone))
	}
	for _, n := range names {
		if n == "" || !nameGlobMatch(glob, n) {
			return fmt.Errorf("the grant only covers DNS names matching %s", glob)
		}
	}
	return nil
}

// enforcePurge: exactly {"files":[...]}, 1-30 entries, http(s) URLs in the zone.
func enforcePurge(body any, zone string) error {
	m := obj(body)
	files := arr(m["files"])
	if m == nil || len(m) != 1 || files == nil {
		return fmt.Errorf(`cache purge takes only {"files":[...]} (purging everything needs cf.admin)`)
	}
	if len(files) < 1 || len(files) > 30 {
		return fmt.Errorf("purge 1 to 30 files per call")
	}
	for _, f := range files {
		s := str(f)
		if o := obj(f); o != nil {
			s = str(o["url"])
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
			return fmt.Errorf("purge entries must be http(s) URLs")
		}
		if !inZone(u.Hostname(), zone) {
			return fmt.Errorf("purge URL host %s is not in zone %s", u.Hostname(), zone)
		}
	}
	return nil
}

// collect walks JSON and gathers string values of the given keys.
func collect(v any, keys map[string][]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok {
				if _, want := keys[k]; want {
					keys[k] = append(keys[k], s)
				}
			}
			collect(e, keys)
		}
	case []any:
		for _, e := range x {
			collect(e, keys)
		}
	}
}

// enforceWorkersDomain: every hostname in the zone param's zone, every service/script the
// grant's script, zone_id/zone_name the zone.
func enforceWorkersDomain(body any, script, zoneName, zoneID string) error {
	if zoneName == "" {
		return fmt.Errorf("custom domains need the grant's zone parameter")
	}
	k := map[string][]string{"hostname": nil, "service": nil, "script": nil, "zone_id": nil, "zone_name": nil}
	collect(body, k)
	for _, h := range k["hostname"] {
		if !inZone(h, zoneName) {
			return fmt.Errorf("hostname %s is not in zone %s", h, zoneName)
		}
	}
	for _, s := range append(k["service"], k["script"]...) {
		if s != script {
			return fmt.Errorf("the custom domain must point at script %s", script)
		}
	}
	for _, z := range k["zone_id"] {
		if z != zoneID {
			return fmt.Errorf("zone_id is not the grant's zone")
		}
	}
	for _, z := range k["zone_name"] {
		if !strings.EqualFold(z, zoneName) {
			return fmt.Errorf("zone_name is not the grant's zone")
		}
	}
	return nil
}

// enforceWorkersRoute: a zone route's script is the grant's script; on the script's own
// route list (PUT .../scripts/{s}/routes) every pattern is in the grant's zone.
func enforceWorkersRoute(rt cfscope.Route, body any, script, zoneName, zoneID string) error {
	if rt.Vars["script"] != "" { // PUT .../workers/scripts/{script}/routes: [{pattern, zone_id|zone_name}]
		routes := arr(body)
		if body != nil && routes == nil {
			return fmt.Errorf("expected a JSON array of routes")
		}
		if len(routes) > 0 && zoneName == "" {
			return fmt.Errorf("routes need the grant's zone parameter")
		}
		for _, r := range routes {
			m := obj(r)
			if s := str(r); s != "" {
				m = map[string]any{"pattern": s}
			}
			host := routeHost(str(m["pattern"]))
			if host == "" || !inZone(host, zoneName) {
				return fmt.Errorf("route %q is not in zone %s", str(m["pattern"]), zoneName)
			}
			if z := str(m["zone_id"]); z != "" && z != zoneID {
				return fmt.Errorf("route zone_id is not the grant's zone")
			}
			if z := str(m["zone_name"]); z != "" && !strings.EqualFold(z, zoneName) {
				return fmt.Errorf("route zone_name is not the grant's zone")
			}
			if s := str(m["script"]); s != "" && s != script {
				return fmt.Errorf("route script must be %s", script)
			}
		}
		return nil
	}
	if rt.Write && !strings.HasPrefix(rt.Template, "DELETE ") {
		if s := str(obj(body)["script"]); s != script {
			return fmt.Errorf("route script must be %s", script)
		}
	}
	return nil
}

// routeHost: "*.example.com/*" -> "example.com" style host for zone checks.
func routeHost(pattern string) string {
	p := strings.ToLower(pattern)
	p = strings.TrimPrefix(strings.TrimPrefix(p, "https://"), "http://")
	if i := strings.Index(p, "/"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimPrefix(p, "*.")
	p = strings.TrimPrefix(p, "*")
	return p
}

// enforceRulesetPhase: the ruleset written must be in an allowed phase (and the grant's).
func enforceRulesetPhase(before any, grantPhase string) error {
	ph := str(obj(before)["phase"])
	if !slices.Contains(cfscope.AllowedPhases, ph) {
		return fmt.Errorf("ruleset phase %q is not one cf.rulesets may change", ph)
	}
	if grantPhase != "" && ph != grantPhase {
		return fmt.Errorf("the grant covers phase %s, this ruleset is %s", grantPhase, ph)
	}
	return nil
}

// ---- D1 read-only SQL ----

// d1Statements extracts the SQL of a D1 query body: {"sql": "..."} or [{"sql": "..."}...]
// ("batch").
func d1Statements(body any) ([]string, error) {
	var out []string
	add := func(v any) error {
		s, ok := obj(v)["sql"].(string)
		if !ok {
			return fmt.Errorf(`D1 query body needs "sql"`)
		}
		out = append(out, s)
		return nil
	}
	if a := arr(body); a != nil {
		for _, e := range a {
			if err := add(e); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	if b := obj(body); b != nil {
		if batch := arr(b["batch"]); batch != nil {
			for _, e := range batch {
				if err := add(e); err != nil {
					return nil, err
				}
			}
			return out, nil
		}
		return out, add(b)
	}
	return nil, fmt.Errorf("D1 query body must be JSON")
}

// sqlTokens splits SQL into upper-case words, single-character punctuation and ";", dropping
// comments and string/identifier literals (a literal becomes "”"). ok=false for an
// unterminated literal or comment.
func sqlTokens(sql string) ([]string, bool) {
	var toks []string
	rs := []rune(sql)
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '-' && i+1 < len(rs) && rs[i+1] == '-':
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(rs) && rs[i+1] == '*':
			end := strings.Index(string(rs[i+2:]), "*/")
			if end < 0 {
				return nil, false
			}
			i += 2 + len([]rune(string(rs[i+2:])[:end])) + 2
		case c == '\'' || c == '"' || c == '`' || c == '[':
			closer := c
			if c == '[' {
				closer = ']'
			}
			j := i + 1
			for {
				if j >= len(rs) {
					return nil, false
				}
				if rs[j] == closer {
					if closer != ']' && j+1 < len(rs) && rs[j+1] == closer { // doubled quote
						j += 2
						continue
					}
					break
				}
				j++
			}
			if c == '\'' {
				toks = append(toks, "''")
			} else {
				toks = append(toks, "IDENT")
			}
			i = j + 1
		case unicode.IsLetter(c) || c == '_':
			j := i
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_' || rs[j] == '$') {
				j++
			}
			toks = append(toks, strings.ToUpper(string(rs[i:j])))
			i = j
		default:
			toks = append(toks, string(c))
			i++
		}
	}
	return toks, true
}

var writeKeywords = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "REPLACE": true, "CREATE": true, "DROP": true,
	"ALTER": true, "ATTACH": true, "DETACH": true, "VACUUM": true, "REINDEX": true, "ANALYZE": true,
	"PRAGMA": true, "BEGIN": true, "COMMIT": true, "ROLLBACK": true, "SAVEPOINT": true, "RELEASE": true,
	"UPSERT": true,
}

var readPragmas = map[string]bool{
	"TABLE_LIST": true, "TABLE_INFO": true, "TABLE_XINFO": true, "INDEX_LIST": true,
	"INDEX_INFO": true, "FOREIGN_KEY_LIST": true,
}

// readOnlySQL reports whether every statement is SELECT, EXPLAIN, WITH ... SELECT or a
// read-only PRAGMA.
func readOnlySQL(sql string) error {
	toks, ok := sqlTokens(sql)
	if !ok {
		return fmt.Errorf("unterminated literal or comment in SQL")
	}
	var stmts [][]string
	cur := []string{}
	for _, t := range toks {
		if t == ";" {
			if len(cur) > 0 {
				stmts = append(stmts, cur)
			}
			cur = []string{}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		stmts = append(stmts, cur)
	}
	if len(stmts) == 0 {
		return fmt.Errorf("no SQL statement")
	}
	for _, st := range stmts {
		switch st[0] {
		case "PRAGMA":
			// PRAGMA [schema.]name[(arg)] — never "= value".
			rest := st[1:]
			if len(rest) >= 2 && rest[1] == "." {
				rest = rest[2:]
			}
			if len(rest) == 0 || !readPragmas[rest[0]] || slices.Contains(rest, "=") {
				return fmt.Errorf("only read-only PRAGMAs (table_list, table_info, ...) are allowed with access=read")
			}
			continue
		case "SELECT", "EXPLAIN", "WITH":
		default:
			return fmt.Errorf("access=read allows only SELECT, EXPLAIN, WITH ... SELECT and read-only PRAGMA (got %s)", st[0])
		}
		for i, t := range st {
			if !writeKeywords[t] {
				continue
			}
			// replace(...) is a function, not REPLACE INTO.
			if t == "REPLACE" && i+1 < len(st) && st[i+1] == "(" {
				continue
			}
			return fmt.Errorf("access=read does not allow %s", t)
		}
	}
	return nil
}
