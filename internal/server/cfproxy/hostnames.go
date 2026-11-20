package cfproxy

import (
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// GProtectedHost refuses any write that routes, re-routes or re-points a protected hostname
// (config ProtectedHostnames: protected_access_hostnames + protected_dns_names). Never
// overridable.
const GProtectedHost = "protected-hostname"

// protectedHit reports the protected name a candidate (a hostname, URL, route pattern or
// wildcard) touches: exact, a wildcard in the candidate covering it, or a wildcard in the
// protected list covering the candidate. A candidate that cannot be judged (non-ASCII,
// escapes, user info) counts as a hit.
func protectedHit(candidate string, protected []string) (string, bool) {
	if len(protected) == 0 {
		return "", false
	}
	h, ok := hostOf(candidate)
	if !ok {
		return candidate, true
	}
	for _, p := range protected {
		if coversHost(h, p) || coversHost(p, h) {
			return p, true
		}
	}
	return "", false
}

// guardProtectedHosts: none of the candidates may touch a protected hostname.
func guardProtectedHosts(cands []string, protected []string, what string) *finding {
	for _, c := range cands {
		if p, hit := protectedHit(c, protected); hit {
			return refuseG(GProtectedHost, "%s %q touches the protected hostname %s", what, asciiOnly(c), asciiOnly(p))
		}
	}
	return nil
}

// guardTunnelProtected: ingress rules whose hostname touches a protected hostname must be
// byte-identical (same objects, same order) before and after, and the config-wide
// originRequest defaults (which apply to those rules too) must not change.
func guardTunnelProtected(after, before any, protected []string) *finding {
	if len(protected) == 0 {
		return nil
	}
	pick := func(cfg any) ([]any, bool) {
		var out []any
		for _, r := range arr(obj(cfg)["ingress"]) {
			h := str(obj(r)["hostname"])
			if h == "" {
				continue
			}
			if _, hit := protectedHit(h, protected); hit {
				out = append(out, r)
			}
		}
		return out, len(out) > 0
	}
	a, aHas := pick(after)
	b, bHas := pick(before)
	if !reflect.DeepEqual(a, b) {
		return refuseG(GProtectedHost, "ingress rules for protected hostnames may not be added, removed, reordered or changed")
	}
	// Order: a rule without a hostname (it matches every host, e.g. a path-only rule) may not
	// come before a protected hostname's rule, except as the last (catch-all) rule.
	if aHas {
		ing := arr(obj(after)["ingress"])
		lastProt := -1
		for i, r := range ing {
			if _, hit := protectedHit(str(obj(r)["hostname"]), protected); str(obj(r)["hostname"]) != "" && hit {
				lastProt = i
			}
		}
		for i, r := range ing[:lastProt+1] {
			if strings.TrimSpace(str(obj(r)["hostname"])) == "" && i != len(ing)-1 {
				return refuseG(GProtectedHost, "an ingress rule without a hostname (it matches every host) may not come before a protected hostname's rule")
			}
		}
	}
	if (aHas || bHas) && !reflect.DeepEqual(obj(after)["originRequest"], obj(before)["originRequest"]) {
		return refuseG(GProtectedHost, "the config-wide originRequest applies to a protected hostname's rule and may not change")
	}
	return nil
}

// ---- tunnel service URLs ----

// svcKey normalises a tunnel service URL to scheme://ip-or-host:port; ok=false when it is not
// a URL. IPv4 written with leading zeros or as IPv4-mapped IPv6 normalises to the plain form.
func svcKey(s string) (keys []string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return nil, false
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https", "wss":
			port = "443"
		case "http", "ws":
			port = "80"
		}
	}
	if n, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(n)
	}
	for _, h := range hostForms(strings.ToLower(u.Hostname())) {
		keys = append(keys, scheme+"://"+h+":"+port)
	}
	return keys, true
}

// hostForms: the address a host may stand for: IPs canonicalised, dotted quads with leading
// zeros read both as decimal and as octal (resolvers differ).
func hostForms(h string) []string {
	h = strings.TrimSuffix(h, ".")
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []string{v4.String()}
		}
		return []string{ip.String()}
	}
	parts := strings.Split(h, ".")
	if len(parts) == 4 {
		dec, oct := make([]string, 4), make([]string, 4)
		for i, p := range parts {
			d, err1 := strconv.ParseUint(p, 10, 8)
			if err1 != nil || p == "" {
				return []string{h}
			}
			dec[i] = strconv.FormatUint(d, 10)
			if o, err := strconv.ParseUint(p, 8, 8); err == nil && len(p) > 1 && p[0] == '0' {
				oct[i] = strconv.FormatUint(o, 10)
			} else {
				oct[i] = dec[i]
			}
		}
		return []string{strings.Join(dec, "."), strings.Join(oct, ".")}
	}
	return []string{h}
}

// sameService: do two tunnel service URLs reach the same origin (any normalised form)?
func sameService(a, b string) bool {
	ka, okA := svcKey(a)
	kb, okB := svcKey(b)
	if !okA || !okB {
		return normOrigin(a) == normOrigin(b)
	}
	for _, x := range ka {
		for _, y := range kb {
			if x == y {
				return true
			}
		}
	}
	return false
}
