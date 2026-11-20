package cfproxy

import (
	"reflect"
	"sort"
	"strings"
)

// Ruleset rules can redirect, rewrite, block or re-route a protected hostname as surely as a
// Workers route can. Guards (docs/CLOUDFLARE.md 4):
//   - GRulesetProtected (never overridable): a new or changed rule may not newly cover a
//     protected hostname, and a rule that covers one may not change its action,
//     action_parameters or become enabled.
//   - GRulesetProtectedRemoval (overridable by cf.admin): in http_request_late_transform and
//     http_request_firewall_custom, a rule covering a protected hostname is usually protective
//     (removing a spoofable header, blocking): it may not stop covering it or be deleted.
//
// "Covers" is decided conservatively from the expression: only a top-level conjunction with
// an `http.host eq "x"` / `http.host == "x"` / `http.host in {"x" "y"}` conjunct restricts the
// hosts; the rule then covers the protected names those strings touch (in every such
// conjunct). Any other expression ("true", a path test, an `or`, ends_with/contains on the
// host, ...) covers every protected hostname.
const (
	GRulesetProtected        = "ruleset-protected-hostname"
	GRulesetProtectedRemoval = "ruleset-protected-removal"
)

// rulesetUncheckedPhases neither route, rewrite nor block requests (logging, managed rule
// deployments).
var rulesetUncheckedPhases = map[string]bool{
	"http_log_custom_fields": true, "http_request_firewall_managed": true,
	"http_response_firewall_managed": true, "ddos_l7": true, "http_request_sbfm": true,
}

// protectivePhases: removing a protected hostname from a rule here weakens it.
var protectivePhases = map[string]bool{"http_request_late_transform": true, "http_request_firewall_custom": true}

type exprTok struct {
	s   string
	str bool // a string literal (s is its value)
}

// exprTokens tokenises a Cloudflare rules expression (wirefilter): strings ("..." with only
// \" and \\ escapes), punctuation and operators, words. ok=false (unjudgeable: the rule
// counts as covering every protected hostname) for an unterminated string, any other escape,
// or a raw string.
func exprTokens(e string) ([]exprTok, bool) {
	var out []exprTok
	for i := 0; i < len(e); {
		c := e[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(e) && e[j] != '"'; j++ {
				if e[j] == '\\' {
					// Only \" and \\ can be judged; any other escape (\x69 = "i", ...)
					// makes the whole expression unjudgeable.
					if j+1 >= len(e) || (e[j+1] != '"' && e[j+1] != '\\') {
						return nil, false
					}
					j++
				}
				b.WriteByte(e[j])
			}
			if j >= len(e) {
				return nil, false
			}
			out = append(out, exprTok{s: b.String(), str: true})
			i = j + 1
		case c == 'r' && i+1 < len(e) && (e[i+1] == '"' || e[i+1] == '#') && (i == 0 || strings.IndexByte(" \t\n\r(){}[],=!<>&|^~", e[i-1]) >= 0):
			return nil, false // raw strings (r"…", r#"…"#): judged conservatively as unjudgeable
		case strings.IndexByte("(){}[],", c) >= 0:
			out = append(out, exprTok{s: string(c)})
			i++
		case strings.IndexByte("=!<>&|^~", c) >= 0:
			j := i + 1
			for j < len(e) && strings.IndexByte("=!<>&|^~", e[j]) >= 0 {
				j++
			}
			out = append(out, exprTok{s: e[i:j]})
			i = j
		default:
			goto word
		}
		continue
	word:
		j := i
		for j < len(e) && strings.IndexByte(" \t\n\r\"(){}[],=!<>&|^~", e[j]) < 0 {
			j++
		}
		if j == i {
			j = i + 1
		}
		out = append(out, exprTok{s: e[i:j]})
		i = j
	}
	return out, true
}

// conjuncts splits tokens at top-level "and"/"&&"; ok=false when the top level has any other
// boolean operator (or, xor, ||, ^^).
func conjuncts(toks []exprTok) ([][]exprTok, bool) {
	var out [][]exprTok
	depth, start := 0, 0
	for i, t := range toks {
		if t.str {
			continue
		}
		switch t.s {
		case "(", "{", "[":
			depth++
		case ")", "}", "]":
			depth--
		}
		if depth != 0 {
			continue
		}
		switch strings.ToLower(t.s) {
		case "and", "&&":
			out = append(out, toks[start:i])
			start = i + 1
		case "or", "||", "xor", "^^":
			return nil, false
		}
	}
	return append(out, toks[start:]), depth == 0
}

// hostRestriction: the names of an `http.host eq|== "x"` or `http.host in {...}` conjunct
// (ok=false for anything else). A conjunct wrapped in parentheses is a nested conjunction.
func hostRestrictions(c []exprTok) [][]string {
	if len(c) >= 2 && !c[0].str && c[0].s == "(" && !c[len(c)-1].str && c[len(c)-1].s == ")" {
		inner, ok := conjuncts(c[1 : len(c)-1])
		if !ok {
			return nil
		}
		var out [][]string
		for _, ic := range inner {
			out = append(out, hostRestrictions(ic)...)
		}
		return out
	}
	if len(c) < 3 || c[0].str || c[0].s != "http.host" {
		return nil
	}
	switch op := c[1]; {
	case !op.str && (op.s == "eq" || op.s == "=="):
		if len(c) == 3 && c[2].str {
			return [][]string{{c[2].s}}
		}
	case !op.str && op.s == "in":
		if len(c) < 4 || c[2].str || c[2].s != "{" || c[len(c)-1].str || c[len(c)-1].s != "}" {
			return nil
		}
		var names []string
		for _, t := range c[3 : len(c)-1] {
			switch {
			case t.str:
				names = append(names, t.s)
			case t.s == ",":
			default:
				return nil
			}
		}
		if len(names) > 0 {
			return [][]string{names}
		}
	}
	return nil
}

// exprCovers returns the protected hostnames an expression may match.
func exprCovers(expr string, protected []string) map[string]bool {
	all := map[string]bool{}
	for _, p := range protected {
		all[p] = true
	}
	toks, ok := exprTokens(expr)
	if !ok {
		return all
	}
	cs, ok := conjuncts(toks)
	if !ok {
		return all
	}
	var restr [][]string
	for _, c := range cs {
		restr = append(restr, hostRestrictions(c)...)
	}
	if len(restr) == 0 {
		return all
	}
	out := map[string]bool{}
	for _, p := range protected {
		inAll := true
		for _, names := range restr {
			hit := false
			for _, n := range names {
				if q, h := protectedHit(n, []string{p}); h && q == p {
					hit = true
					break
				}
			}
			if !hit {
				inAll = false
				break
			}
		}
		if inAll {
			out[p] = true
		}
	}
	return out
}

func ruleEnabled(r map[string]any) bool {
	e, ok := r["enabled"].(bool)
	return !ok || e
}

func sameRule(a, b map[string]any) bool {
	return str(a["expression"]) == str(b["expression"]) && str(a["action"]) == str(b["action"]) &&
		reflect.DeepEqual(a["action_parameters"], b["action_parameters"]) && ruleEnabled(a) == ruleEnabled(b)
}

func sortedKeys(m map[string]bool) string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return strings.Join(k, ", ")
}

// guardRulesetProtected checks rules written (new or changed; for a changed rule prior holds
// its before-snapshot version by id) and rules removed, in phase.
func guardRulesetProtected(phase string, written []map[string]any, prior map[string]map[string]any, removed []map[string]any, protected []string) []*finding {
	if len(protected) == 0 || rulesetUncheckedPhases[phase] {
		return nil
	}
	var fs []*finding
	for _, r := range written {
		old := prior[str(r["id"])]
		if old != nil && sameRule(r, old) {
			continue // unchanged: not re-checked
		}
		nc := exprCovers(str(r["expression"]), protected)
		if old == nil {
			if len(nc) > 0 && !(phase == "http_request_firewall_custom" && str(r["action"]) == "log") {
				fs = append(fs, refuseG(GRulesetProtected, "a new rule could match the protected hostname %s: restrict it with http.host eq \"...\" or http.host in {...} (joined with and) to other names", sortedKeys(nc)))
			}
			continue
		}
		pc := exprCovers(str(old["expression"]), protected)
		newly, kept, dropped := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for p := range nc {
			if pc[p] {
				kept[p] = true
			} else {
				newly[p] = true
			}
		}
		for p := range pc {
			if !nc[p] {
				dropped[p] = true
			}
		}
		switch {
		case len(newly) > 0:
			fs = append(fs, refuseG(GRulesetProtected, "the changed rule %s would newly match the protected hostname %s", asciiOnly(str(r["id"])), sortedKeys(newly)))
		case len(kept) > 0 && (str(r["action"]) != str(old["action"]) || !reflect.DeepEqual(r["action_parameters"], old["action_parameters"]) || (ruleEnabled(r) && !ruleEnabled(old))):
			fs = append(fs, refuseG(GRulesetProtected, "rule %s matches the protected hostname %s: its action, action_parameters and enabled state may not change", asciiOnly(str(r["id"])), sortedKeys(kept)))
		}
		if protectivePhases[phase] && len(pc) > 0 && ruleEnabled(old) && !ruleEnabled(r) {
			fs = append(fs, refuseG(GRulesetProtectedRemoval, "disabling rule %s drops coverage of the protected hostname %s (it likely protects it)", asciiOnly(str(r["id"])), sortedKeys(pc)))
		}
		if len(dropped) > 0 && protectivePhases[phase] {
			fs = append(fs, refuseG(GRulesetProtectedRemoval, "rule %s would stop covering the protected hostname %s (it likely protects it)", asciiOnly(str(r["id"])), sortedKeys(dropped)))
		}
	}
	if protectivePhases[phase] {
		for _, r := range removed {
			if c := exprCovers(str(r["expression"]), protected); len(c) > 0 {
				fs = append(fs, refuseG(GRulesetProtectedRemoval, "removing rule %s drops coverage of the protected hostname %s (it likely protects it)", asciiOnly(str(r["id"])), sortedKeys(c)))
			}
		}
	}
	return fs
}

// rulesetWrite collects, for one ruleset write, the phase, the rules written, the prior
// versions by id and the rules removed.
func rulesetWrite(method, snapshot string, vars map[string]string, body, before any) (phase string, written []map[string]any, prior map[string]map[string]any, removed []map[string]any) {
	b := obj(before)
	phase = str(b["phase"])
	if vars["phase"] != "" {
		phase = vars["phase"]
	}
	prior = map[string]map[string]any{}
	for _, r := range arr(b["rules"]) {
		if m := obj(r); m != nil && str(m["id"]) != "" {
			prior[str(m["id"])] = m
		}
	}
	ruleID := vars["id2"] // .../rulesets/{id}/rules/{id}
	switch {
	case method == "PUT": // entrypoint or whole ruleset
		seen := map[string]bool{}
		for _, r := range arr(obj(body)["rules"]) {
			m := obj(r)
			if m == nil {
				m = map[string]any{}
			}
			seen[str(m["id"])] = true
			written = append(written, m)
		}
		for id, r := range prior {
			if !seen[id] {
				removed = append(removed, r)
			}
		}
	case method == "POST":
		m := map[string]any{}
		for k, v := range obj(body) {
			m[k] = v
		}
		delete(m, "id") // a new rule; an id in the body names nothing existing
		written = append(written, m)
	case method == "PATCH" && ruleID != "":
		m := map[string]any{}
		for k, v := range prior[ruleID] {
			m[k] = v
		}
		for k, v := range obj(body) {
			m[k] = v
		}
		m["id"] = ruleID
		written = append(written, m)
	case method == "DELETE" && ruleID != "":
		if r := prior[ruleID]; r != nil {
			removed = append(removed, r)
		}
	}
	return
}
