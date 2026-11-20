package cfproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// Guard rail names (docs/CLOUDFLARE.md section 4).
const (
	GTunnelWholeConfig  = "tunnel-whole-config"
	GTunnelCatchAll     = "tunnel-catch-all"
	GTunnelTraefikSNI   = "tunnel-traefik-sni"
	GTunnelPlainOrigin  = "tunnel-plain-origin"
	GTunnelNoTLSVerify  = "tunnel-no-tls-verify"
	GTunnelAccessAud    = "tunnel-access-aud"
	GTunnelVersion      = "tunnel-version"
	GAccessProtected    = "access-protected-hostname"
	GAccessPatch        = "access-patch"
	GAccessPolicyShared = "access-policy-shared"
	GIdPDelete          = "idp-delete"
	GDNSProtected       = "dns-protected"
	GRulesetKeepRules   = "ruleset-keep-rules"
	GRulesetPhase       = "ruleset-phase"
	GZoneSettingsPolicy = "zone-settings-policy"
	GWorkersDomainRm    = "workers-domain-remove"
	GRedactedWrite      = "redacted-write"
	GEmailForward       = "email-forward"
)

// neverOverridable guards refuse even with a cf.admin override.
var neverOverridable = map[string]bool{GAccessProtected: true, GAccessPatch: true, GRedactedWrite: true, GRulesetPhase: true, GProtectedHost: true, GRulesetProtected: true}

// overridable lists the names X-Aqmas-Override accepts.
var overridable = map[string]bool{
	GTunnelWholeConfig: true, GTunnelCatchAll: true, GTunnelTraefikSNI: true, GTunnelPlainOrigin: true,
	GTunnelNoTLSVerify: true, GTunnelAccessAud: true, GTunnelVersion: true, GAccessPolicyShared: true,
	GIdPDelete: true, GDNSProtected: true, GRulesetKeepRules: true, GZoneSettingsPolicy: true, GWorkersDomainRm: true,
	GEmailForward: true, GRulesetProtectedRemoval: true,
}

// finding is one guard-rail refusal.
type finding struct {
	guard  string
	msg    string
	status int // 0 = 403
}

func refuseG(guard, format string, a ...any) *finding {
	return &finding{guard: guard, msg: fmt.Sprintf(format, a...)}
}

// ---- small JSON helpers (values from decodeJSON) ----

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func truthy(v any) bool {
	b, _ := v.(bool)
	return b
}

func num(v any) int64 {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			f, _ := x.Float64()
			return int64(f)
		}
		return n
	case float64:
		return int64(x)
	}
	return -1
}

// fqdn normalises a DNS record name against its zone ("@"/"" = apex, relative names get the
// zone appended), lower case, no trailing dot.
func fqdn(name, zone string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	zone = strings.ToLower(zone)
	if n == "" {
		return ""
	}
	if n == "@" {
		return zone
	}
	if zone == "" || n == zone || strings.HasSuffix(n, "."+zone) {
		return n
	}
	return n + "." + zone
}

// ---- tunnel (PUT .../cfd_tunnel/{t}/configurations) ----

type ingressRule struct {
	hostname, path, service string
	origin                  map[string]any
}

func ingressOf(config any) []ingressRule {
	var out []ingressRule
	for _, r := range arr(obj(config)["ingress"]) {
		m := obj(r)
		out = append(out, ingressRule{hostname: strings.ToLower(str(m["hostname"])), path: str(m["path"]), service: str(m["service"]), origin: obj(m["originRequest"])})
	}
	return out
}

func (r ingressRule) key() string { return r.hostname + "|" + r.path }

// guardTunnelWholeConfig: the body must be {"config":{"ingress":[...], ...}}.
func guardTunnelWholeConfig(body any) *finding {
	m := obj(body)
	if m == nil || len(m) != 1 || obj(m["config"]) == nil || len(arr(obj(m["config"])["ingress"])) == 0 {
		return refuseG(GTunnelWholeConfig, `the body must be the whole config: {"config":{"ingress":[...]}} (GET it, change it, PUT it back)`)
	}
	return nil
}

// guardTunnelCatchAll: the last rule must be the catch-all.
func guardTunnelCatchAll(rules []ingressRule) *finding {
	if len(rules) == 0 {
		return refuseG(GTunnelCatchAll, "no ingress rules")
	}
	last := rules[len(rules)-1]
	if last.service != "http_status:404" || last.hostname != "" || last.path != "" {
		return refuseG(GTunnelCatchAll, `the last ingress rule must be {"service":"http_status:404"} without hostname or path`)
	}
	return nil
}

func normOrigin(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "/")
}

// guardTunnelTraefikSNI: rules to Traefik need originServerName == hostname (warnings when
// matchSNItoHost / http2Origin are not set).
func guardTunnelTraefikSNI(rules []ingressRule, traefik string) (*finding, []string) {
	var warns []string
	for _, r := range rules {
		if traefik == "" || !sameService(r.service, traefik) {
			continue
		}
		if !strings.EqualFold(str(r.origin["originServerName"]), r.hostname) || r.hostname == "" {
			return refuseG(GTunnelTraefikSNI, "rule %q to Traefik needs originRequest.originServerName = the hostname (otherwise it redirect-loops)", r.hostname), nil
		}
		if !truthy(r.origin["matchSNItoHost"]) || !truthy(r.origin["http2Origin"]) {
			warns = append(warns, fmt.Sprintf("rule %s to Traefik: matchSNItoHost and http2Origin should be true", r.hostname))
		}
	}
	return nil, warns
}

// guardTunnelPlainOrigin: plain-HTTP Traefik origins redirect-loop.
func guardTunnelPlainOrigin(rules []ingressRule, plain []string) *finding {
	for _, r := range rules {
		for _, p := range plain {
			if sameService(r.service, p) {
				return refuseG(GTunnelPlainOrigin, "rule %q uses %s, which redirect-loops; use the Traefik https origin with originServerName", r.hostname, p)
			}
		}
	}
	return nil
}

// guardTunnelNoTLSVerify: noTLSVerify may not be newly switched on (per rule, or globally).
func guardTunnelNoTLSVerify(after, before any) *finding {
	bRules := map[string]bool{}
	for _, r := range ingressOf(before) {
		bRules[r.key()] = truthy(r.origin["noTLSVerify"])
	}
	if truthy(obj(obj(after)["originRequest"])["noTLSVerify"]) && !truthy(obj(obj(before)["originRequest"])["noTLSVerify"]) {
		return refuseG(GTunnelNoTLSVerify, "global originRequest.noTLSVerify switched on")
	}
	for _, r := range ingressOf(after) {
		if truthy(r.origin["noTLSVerify"]) && !bRules[r.key()] {
			return refuseG(GTunnelNoTLSVerify, "rule %q switches noTLSVerify on", r.hostname)
		}
	}
	return nil
}

// guardTunnelAccessAud: a hostname whose rule carried originRequest.access keeps it unchanged.
func guardTunnelAccessAud(after, before any) *finding {
	now := map[string][]ingressRule{}
	for _, r := range ingressOf(after) {
		now[r.hostname] = append(now[r.hostname], r)
	}
	for _, b := range ingressOf(before) {
		acc, had := b.origin["access"]
		if !had || acc == nil || b.hostname == "" {
			continue
		}
		for _, a := range now[b.hostname] {
			if a.path == b.path && !reflect.DeepEqual(a.origin["access"], acc) {
				return refuseG(GTunnelAccessAud, "rule %q had originRequest.access (Access aud check); it may not be removed or changed", b.hostname)
			}
		}
	}
	return nil
}

// guardTunnelVersion: the live version must be the one this host last read.
func guardTunnelVersion(live int64, last int64, read bool) *finding {
	if !read || live != last {
		f := refuseG(GTunnelVersion, "the tunnel config changed since this host last read it (or it never read it): GET the config again and re-apply your change")
		f.status = 409
		return f
	}
	return nil
}

// tunnelHostDiff returns added, changed and removed hostnames.
func tunnelHostDiff(after, before any) (add, chg, del []string) {
	bm, am := map[string]string{}, map[string]string{}
	for _, r := range ingressOf(before) {
		if r.hostname != "" {
			b, _ := json.Marshal(r.origin)
			bm[r.hostname] += r.path + "|" + r.service + "|" + string(b) + ";"
		}
	}
	for _, r := range ingressOf(after) {
		if r.hostname != "" {
			b, _ := json.Marshal(r.origin)
			am[r.hostname] += r.path + "|" + r.service + "|" + string(b) + ";"
		}
	}
	for h, v := range am {
		if bv, ok := bm[h]; !ok {
			add = append(add, h)
		} else if bv != v {
			chg = append(chg, h)
		}
	}
	for h := range bm {
		if _, ok := am[h]; !ok {
			del = append(del, h)
		}
	}
	sort.Strings(add)
	sort.Strings(chg)
	sort.Strings(del)
	return
}

// ---- Access ----

// accessHosts collects every host an Access app body names: domain, self_hosted_domains[],
// destinations[].uri / .hostname.
func accessHosts(body any) []string {
	m := obj(body)
	var out []string
	if d := str(m["domain"]); d != "" {
		out = append(out, d)
	}
	for _, d := range arr(m["self_hosted_domains"]) {
		out = append(out, str(d))
	}
	for _, d := range arr(m["destinations"]) {
		dm := obj(d)
		for _, k := range []string{"uri", "hostname"} {
			if s := str(dm[k]); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// hostOf reduces "https://Host.Example:443/path" to "host.example"; ok=false when the value
// cannot be judged safely (non-ASCII, escapes, user info...).
func hostOf(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if strings.ContainsAny(s, "@%\\ ") {
		return "", false
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(s, ".")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '*' || c == '_') {
			return "", false
		}
	}
	return s, s != ""
}

// coversHost: does pattern (exact, or with '*' wildcards anywhere) cover host?
func coversHost(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("^" + strings.Join(parts, ".*") + "$")
	return err != nil || re.MatchString(host)
}

// guardAccessProtected: no Access app may cover a protected hostname (never overridable).
func guardAccessProtected(body any, protected []string) *finding {
	for _, raw := range accessHosts(body) {
		h, ok := hostOf(raw)
		if !ok {
			return refuseG(GAccessProtected, "cannot judge the domain %q; use plain host names", raw)
		}
		for _, p := range protected {
			if p = strings.ToLower(p); coversHost(h, p) || coversHost(p, h) {
				return refuseG(GAccessProtected, "%s must never get an Access app (it would break every login)", p)
			}
		}
	}
	return nil
}

func guardAccessPatch() *finding {
	return refuseG(GAccessPatch, "PATCH on Access apps fails with 10405: GET it, change it, PUT the whole object")
}

// accessAppWarnings: session_duration above 730h.
func accessAppWarnings(body any) []string {
	d := str(obj(body)["session_duration"])
	if d == "" {
		return nil
	}
	if dur, err := time.ParseDuration(d); err == nil && dur > 730*time.Hour {
		return []string{fmt.Sprintf("Access app session_duration %s is above 730h", d)}
	}
	return nil
}

// policyWarnings: decision bypass, or an "everyone" include.
func policyWarnings(body any) []string {
	var w []string
	m := obj(body)
	if strings.EqualFold(str(m["decision"]), "bypass") {
		w = append(w, "policy decision is bypass")
	}
	for _, inc := range arr(m["include"]) {
		if _, ok := obj(inc)["everyone"]; ok {
			w = append(w, `policy includes "everyone"`)
			break
		}
	}
	return w
}

// countReferences counts apps referencing a policy (app.policies[].id) or a group (any
// {"group":{"id":...}} inside the app).
func countReferences(apps []any, id string, group bool) int {
	n := 0
	for _, a := range apps {
		if group {
			if refersGroup(a, id) {
				n++
			}
			continue
		}
		for _, p := range arr(obj(a)["policies"]) {
			if str(obj(p)["id"]) == id {
				n++
				break
			}
		}
	}
	return n
}

func refersGroup(v any, id string) bool {
	switch x := v.(type) {
	case map[string]any:
		if g := obj(x["group"]); g != nil && str(g["id"]) == id {
			return true
		}
		for _, e := range x {
			if refersGroup(e, id) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if refersGroup(e, id) {
				return true
			}
		}
	}
	return false
}

// guardAccessPolicyShared: a policy or group used by more than one app is not edited in place.
func guardAccessPolicyShared(refs int, what string) *finding {
	if refs > 1 {
		return refuseG(GAccessPolicyShared, "this %s is referenced by %d apps: change which policy the app references instead", what, refs)
	}
	return nil
}

func guardIdPDelete() *finding {
	return refuseG(GIdPDelete, "deleting an identity provider breaks every login that uses it")
}

// ---- DNS ----

var protectedDNSTypes = map[string]bool{"MX": true, "NS": true, "SOA": true, "CAA": true, "SPF": true}

// dnsProtectedReason: why a record may not be touched ("" = fine).
func dnsProtectedReason(rec map[string]any, zone string, protected []string) string {
	if rec == nil {
		return ""
	}
	name := fqdn(str(rec["name"]), zone)
	typ := strings.ToUpper(str(rec["type"]))
	content := strings.ToLower(strings.TrimLeft(str(rec["content"]), "\" "))
	switch {
	case name != "" && name == strings.ToLower(zone):
		return "records at the zone apex"
	case protectedDNSTypes[typ]:
		return typ + " records"
	case typ == "TXT" && (strings.HasPrefix(name, "_dmarc.") || strings.Contains(name, "._domainkey.") || strings.HasPrefix(name, "_domainkey.") || strings.HasPrefix(content, "v=spf1")):
		return "mail authentication TXT records (SPF/DKIM/DMARC)"
	case strings.HasPrefix(name, "_acme-challenge."):
		return "ACME challenge records"
	}
	for _, p := range protected {
		if name != "" && name == fqdn(p, zone) {
			return "the protected name " + name
		}
	}
	return ""
}

// guardDNSProtected checks the written record (body, merged over before for PATCH) and the
// existing one.
func guardDNSProtected(method string, body, before map[string]any, zone string, protected []string) *finding {
	var recs []map[string]any
	switch method {
	case "POST", "PUT":
		recs = append(recs, body)
	case "PATCH":
		recs = append(recs, mergeRecord(before, body))
	}
	if method != "POST" {
		recs = append(recs, before)
	}
	for _, r := range recs {
		if why := dnsProtectedReason(r, zone, protected); why != "" {
			return refuseG(GDNSProtected, "%s are protected", why)
		}
	}
	return nil
}

func mergeRecord(before, body map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range before {
		out[k] = v
	}
	for k, v := range body {
		out[k] = v
	}
	return out
}

// dnsWarnings: tunnel CNAME not proxied, A record to a private address.
func dnsWarnings(rec map[string]any) []string {
	var w []string
	typ := strings.ToUpper(str(rec["type"]))
	content := strings.ToLower(strings.TrimSuffix(str(rec["content"]), "."))
	if typ == "CNAME" && strings.HasSuffix(content, ".cfargotunnel.com") && !truthy(rec["proxied"]) {
		w = append(w, "CNAME to a tunnel with proxied:false does not work")
	}
	if typ == "A" {
		if ip := net.ParseIP(content); ip != nil && ip.IsPrivate() {
			w = append(w, "A record points at a private (RFC 1918) address")
		}
	}
	return w
}

// ---- rulesets ----

// guardRulesetKeepRules: an entrypoint PUT keeps every rule id the ruleset had.
func guardRulesetKeepRules(body, before any) *finding {
	keep := map[string]bool{}
	for _, r := range arr(obj(body)["rules"]) {
		if id := str(obj(r)["id"]); id != "" {
			keep[id] = true
		}
	}
	var dropped []string
	for _, r := range arr(obj(before)["rules"]) {
		if id := str(obj(r)["id"]); id != "" && !keep[id] {
			dropped = append(dropped, id)
		}
	}
	if len(dropped) > 0 {
		return refuseG(GRulesetKeepRules, "the PUT drops %d existing rule(s): add rules, never replace a ruleset", len(dropped))
	}
	return nil
}

// ---- zone settings ----

// zoneSettingItems: [{id, value}] from a single-setting or bulk PATCH body.
func zoneSettingItems(name string, body any) []map[string]any {
	if name != "" {
		return []map[string]any{{"id": name, "value": obj(body)["value"]}}
	}
	var out []map[string]any
	for _, it := range arr(obj(body)["items"]) {
		if m := obj(it); m != nil {
			out = append(out, m)
		}
	}
	return out
}

// guardZoneSettingsPolicy: HTTPS on, TLS >= 1.2, SSL strict, no HSTS includeSubDomains/preload.
func guardZoneSettingsPolicy(items []map[string]any) *finding {
	for _, it := range items {
		id, v := strings.ToLower(str(it["id"])), it["value"]
		switch id {
		case "always_use_https":
			if s := strings.ToLower(str(v)); s != "on" {
				return refuseG(GZoneSettingsPolicy, "always_use_https must stay on")
			}
		case "min_tls_version":
			if s := str(v); s != "1.2" && s != "1.3" {
				return refuseG(GZoneSettingsPolicy, "min_tls_version must be 1.2 or higher")
			}
		case "ssl":
			if s := strings.ToLower(str(v)); s != "strict" {
				return refuseG(GZoneSettingsPolicy, "ssl must stay strict")
			}
		case "security_header":
			h := obj(obj(v)["strict_transport_security"])
			if truthy(h["include_subdomains"]) || truthy(h["preload"]) {
				return refuseG(GZoneSettingsPolicy, "HSTS include_subdomains and preload stay off")
			}
		}
	}
	return nil
}

// ---- Workers ----

func guardWorkersDomainRemove() *finding {
	return refuseG(GWorkersDomainRm, "removing a Worker custom domain deletes its DNS record")
}

// guardRedactedWrite: never write a redacted object back.
func guardRedactedWrite() *finding {
	return refuseG(GRedactedWrite, "the body contains %q: writing a redacted object back would destroy the secret; set the real value", RedactedMarker)
}

// ---- warnings helpers ----

// zoneFor returns the configured zone (name, id) a hostname lies in.
func zoneFor(cfg *config.Cloudflare, host string) (config.CFObject, bool) {
	best := config.CFObject{}
	for _, z := range cfg.Zones {
		if (host == z.Name || strings.HasSuffix(host, "."+z.Name)) && len(z.Name) > len(best.Name) {
			best = z
		}
	}
	return best, best.Name != ""
}

// inZone: host is the zone or below it.
func inZone(host, zone string) bool {
	host, zone = strings.TrimSuffix(strings.ToLower(host), "."), strings.ToLower(zone)
	return zone != "" && (host == zone || strings.HasSuffix(host, "."+zone))
}

func uniq(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

// ---- email routing ----

func emailAllowed(addr string, allow []string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	for _, x := range allow {
		if a != "" && a == strings.ToLower(strings.TrimSpace(x)) {
			return true
		}
	}
	return false
}

// guardEmailActions: routing rules (and the catch-all) forward only to email_forward_allow;
// "worker" actions (mail handed to a Worker) and unknown action types are refused too.
func guardEmailActions(body any, allow []string) *finding {
	for _, a := range arr(obj(body)["actions"]) {
		m := obj(a)
		switch t := str(m["type"]); t {
		case "drop":
		case "forward":
			vals := arr(m["value"])
			if len(vals) == 0 {
				return refuseG(GEmailForward, "a forward action needs its addresses")
			}
			for _, v := range vals {
				if !emailAllowed(str(v), allow) {
					return refuseG(GEmailForward, "forwarding to %s: not in aqmasd's email_forward_allow", asciiOnly(str(v)))
				}
			}
		default:
			return refuseG(GEmailForward, "email routing action %q is not allowed (only forward to email_forward_allow, or drop)", asciiOnly(t))
		}
	}
	return nil
}

// guardEmailAddress: destination addresses only from email_forward_allow.
func guardEmailAddress(body any, allow []string) *finding {
	if e := str(obj(body)["email"]); !emailAllowed(e, allow) {
		return refuseG(GEmailForward, "destination address %s is not in aqmasd's email_forward_allow", asciiOnly(e))
	}
	return nil
}
