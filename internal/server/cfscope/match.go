package cfscope

import (
	"regexp"
	"slices"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

type phKind int

const (
	phAcct phKind = iota
	phZone
	phTunnel
	phDB
	phScript
	phProject
	phBucket
	phPhase
	phID
	phName
	phKey
	phDBName
)

var phKinds = map[string]phKind{
	"acct": phAcct, "zone": phZone, "tunnel": phTunnel, "db": phDB, "script": phScript,
	"project": phProject, "bucket": phBucket, "phase": phPhase, "id": phID, "name": phName,
	"key": phKey, "dbname": phDBName,
}

// paramOf maps a placeholder to the scope parameter it binds to ("" = never bound).
var paramOf = map[string]string{
	"zone": api.CFParamZone, "tunnel": api.CFParamTunnel, "db": api.CFParamDB,
	"script": api.CFParamScript, "project": api.CFParamProject, "bucket": api.CFParamBucket,
	"phase": api.CFParamPhase, "dbname": api.CFParamDB,
}

var (
	hex32RE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuidRE    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	idRE      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	anyPhase  = regexp.MustCompile(`^[a-z_]{1,64}$`)
	keySegRE  = regexp.MustCompile(`^[A-Za-z0-9._~!$&'()*+,=:@%-]+$`)
	objNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`) // R2 bucket (as bucketRE)
)

type mmode int

const (
	// mGrant: the grant's scope, its parameters bind placeholders, zone/tunnel/db configured.
	mGrant mmode = iota
	// mHint: configured objects, nothing bound (NeedsScope derives the parameters).
	mHint
	// mAdmin: well-formed only, literals and ids case-insensitive (annotation lookup for
	// cf.admin, which may reach unconfigured objects).
	mAdmin
)

func scopeHasParam(scope, key string) bool {
	b := builtinFor(scope)
	if b == nil {
		return false
	}
	for _, p := range b.params {
		if p.key == key {
			return true
		}
	}
	return false
}

// matchVar checks one placeholder segment.
func (c *Catalogue) matchVar(s tseg, seg string, mode mmode, scope string, r *Resolved) (string, bool) {
	if strings.Contains(seg, "%") {
		return "", false // percent-encoded segments match only {key...}
	}
	v := seg
	kind := phKinds[s.ph]
	if mode == mAdmin && (kind == phZone || kind == phTunnel || kind == phDB) {
		v = strings.ToLower(v)
	}
	bound := mode == mGrant && !s.never && paramOf[s.ph] != "" && scopeHasParam(scope, paramOf[s.ph])
	switch kind {
	case phAcct:
		return v, v == c.cfg.AccountID
	case phZone, phTunnel, phDB:
		re := uuidRE
		if kind == phZone {
			re = hex32RE
		}
		if !re.MatchString(v) {
			return "", false
		}
		if mode == mAdmin {
			return v, true
		}
		if !c.configuredID(kind, v) {
			return "", false
		}
		if bound && r.IDs[paramOf[s.ph]] != v {
			return "", false
		}
		return v, true
	case phScript, phProject, phBucket:
		re := scriptRE
		switch kind {
		case phProject:
			re = projectRE
		case phBucket:
			re = objNameRE
		}
		if mode == mAdmin {
			v = strings.ToLower(v)
		}
		if !re.MatchString(v) {
			return "", false
		}
		if bound && r.Params[paramOf[s.ph]] != v {
			return "", false
		}
		return v, true
	case phPhase:
		if s.never || mode == mAdmin {
			return v, anyPhase.MatchString(v)
		}
		if !slices.Contains(AllowedPhases, v) {
			return "", false
		}
		if bound && r.Params[api.CFParamPhase] != "" && r.Params[api.CFParamPhase] != v {
			return "", false
		}
		return v, true
	case phDBName:
		// A configured D1 database's NAME (wrangler's lookup by name); the value reported is
		// the database id.
		if mode == mAdmin {
			return v, nameRE.MatchString(v)
		}
		o, ok := c.cfg.D1(v)
		if !ok || (bound && r.Params[api.CFParamDB] != v) {
			return "", false
		}
		return o.ID, true
	case phID:
		return v, idRE.MatchString(v)
	case phName:
		return v, nameRE.MatchString(v)
	}
	return "", false
}

func (c *Catalogue) configuredID(kind phKind, id string) bool {
	var objs = c.cfg.Zones
	switch kind {
	case phTunnel:
		objs = c.cfg.Tunnels
	case phDB:
		objs = c.cfg.D1Databases
	}
	for _, o := range objs {
		if o.ID == id {
			return true
		}
	}
	return false
}

func litMatch(lits []string, seg string, fold bool) bool {
	for _, l := range lits {
		if l == seg || (fold && strings.EqualFold(l, seg)) {
			return true
		}
	}
	return false
}

// matchRoute matches one route; vars maps placeholder names to values (a repeated
// placeholder gets a "2" suffix: {id}/.../{id} -> "id", "id2").
func (c *Catalogue) matchRoute(rd *rdef, call Call, mode mmode, scope string, r *Resolved) (map[string]string, bool) {
	if !slices.Contains(rd.methods, call.Method) {
		return nil, false
	}
	if mode == mGrant && rd.whenKey != "" && r.Params[rd.whenKey] != rd.whenVal {
		return nil, false
	}
	segs := call.Segments
	vars := map[string]string{}
	put := func(k, v string) {
		if _, dup := vars[k]; dup {
			k += "2"
		}
		vars[k] = v
	}
	for i, s := range rd.segs {
		if s.rest {
			if i >= len(segs) {
				return nil, false
			}
			for _, x := range segs[i:] {
				if !keySegRE.MatchString(x) {
					return nil, false
				}
			}
			put(s.ph, strings.Join(segs[i:], "/"))
			return vars, true
		}
		if i >= len(segs) {
			return nil, false
		}
		if s.lits != nil {
			if !litMatch(s.lits, segs[i], mode == mAdmin) {
				return nil, false
			}
			continue
		}
		v, ok := c.matchVar(s, segs[i], mode, scope, r)
		if !ok {
			return nil, false
		}
		put(s.ph, v)
	}
	if len(segs) != len(rd.segs) {
		return nil, false
	}
	return vars, true
}

func (rd *rdef) route(scope string, call Call, vars map[string]string) Route {
	return Route{Scope: scope, Template: call.Method + " " + rd.tmpl, Vars: vars, Write: IsWrite(call.Method),
		Snapshot: rd.snapshot, Guard: rd.guard, Upload: rd.upload, JWTPassthrough: rd.jwt}
}

// annotate finds the first route of any other scope matching the call's method and template
// (well-formed placeholders, nothing bound): the snapshot type and guard rails cf.admin calls
// inherit.
func (c *Catalogue) annotate(call Call) (*rdef, map[string]string, bool) {
	for i := range builtins {
		name := builtins[i].scope.Name
		if name == api.CFScopeAdmin {
			continue
		}
		rs := scopeRoutes[name]
		for j := range rs {
			if vars, ok := c.matchRoute(&rs[j], call, mAdmin, name, nil); ok {
				return &rs[j], vars, true
			}
		}
	}
	return nil, nil, false
}

// Match returns the first route of the grant's scope (with its resolved parameters) that
// allows the call, or ok=false. Deny-listed and extra_deny'd calls never match.
func (c *Catalogue) Match(r *Resolved, call Call) (Route, bool) {
	if r == nil || r.Scope == nil {
		return Route{}, false
	}
	scope := r.Scope.Name
	if _, ok := c.scopes[scope]; !ok {
		return Route{}, false
	}
	if c.CheckDeny(call).Denied || isSynthetic(call.Method, call.Path) || c.ExtraDenied(scope, call) {
		return Route{}, false
	}
	if scope == api.CFScopeAdmin {
		if rd, vars, ok := c.annotate(call); ok {
			rt := rd.route(api.CFScopeAdmin, call, vars)
			return rt, true
		}
		for _, s := range call.Segments {
			if strings.Contains(s, "%") {
				return Route{}, false // percent-encoding only where a {key...} route allows it
			}
		}
		return Route{Scope: api.CFScopeAdmin, Template: call.Method + " " + call.Path, Vars: map[string]string{}, Write: IsWrite(call.Method)}, true
	}
	rs := scopeRoutes[scope]
	for i := range rs {
		if vars, ok := c.matchRoute(&rs[i], call, mGrant, scope, r); ok {
			return rs[i].route(scope, call, vars), true
		}
	}
	return Route{}, false
}

var riskOrder = map[string]int{api.CFRiskLow: 0, api.CFRiskMedium: 1, api.CFRiskHigh: 2, api.CFRiskAdmin: 3}

// NeedsScope returns the narrowest scope (and canonical params) that would allow the call,
// for the X-Aqmas-Needs-Scope hint: "" when none does, "cf.admin" when only that does.
func (c *Catalogue) NeedsScope(call Call) string { return c.NeedsScopeFor(call, nil) }

// NeedsScopeFor is NeedsScope taking the caller's offered grants into account: a parameter
// the path does not name (e.g. the Worker script on /zones/{zone}/workers/routes) is taken
// from a held grant of the same scope.
func (c *Catalogue) NeedsScopeFor(call Call, held []*Resolved) string {
	if c.CheckDeny(call).Denied || isSynthetic(call.Method, call.Path) {
		return ""
	}
	scopes := c.Scopes()
	slices.SortStableFunc(scopes, func(a, b *Scope) int { return riskOrder[a.Risk] - riskOrder[b.Risk] })
	for _, sc := range scopes {
		if sc.Name == api.CFScopeAdmin {
			continue
		}
		rs := scopeRoutes[sc.Name]
		for i := range rs {
			vars, ok := c.matchRoute(&rs[i], call, mHint, sc.Name, nil)
			if !ok {
				continue
			}
			if res := c.hintParams(sc.Name, &rs[i], call, vars, held); res != nil {
				if m, ok := c.Match(res, call); ok && m.Scope == sc.Name {
					if res.ScopeParams == "" {
						return sc.Name
					}
					return sc.Name + " " + res.ScopeParams
				}
			}
		}
	}
	if a, ok := c.scopes[api.CFScopeAdmin]; ok {
		if _, ok := c.Match(&Resolved{Scope: a, Mode: api.CFModeProxy}, call); ok {
			return api.CFScopeAdmin
		}
	}
	return ""
}

// hintParams derives a scope's parameters from the path variables (and held grants).
func (c *Catalogue) hintParams(scope string, rd *rdef, call Call, vars map[string]string, held []*Resolved) *Resolved {
	b := builtinFor(scope)
	p := map[string]string{}
	for _, ps := range b.params {
		switch ps.key {
		case api.CFParamZone, api.CFParamTunnel, api.CFParamDB:
			ph := map[string]string{api.CFParamZone: "zone", api.CFParamTunnel: "tunnel", api.CFParamDB: "db"}[ps.key]
			id := vars[ph]
			if id == "" && ps.key == api.CFParamDB {
				id = vars["dbname"]
			}
			if id != "" {
				p[ps.key] = c.nameOf(ps.key, id)
			}
		case api.CFParamScript, api.CFParamProject, api.CFParamBucket, api.CFParamPhase:
			if v := vars[ps.key]; v != "" && !isNever(rd, ps.key) {
				p[ps.key] = v
			}
		case api.CFParamAccess:
			switch {
			case rd.whenKey == api.CFParamAccess:
				p[ps.key] = rd.whenVal
			default:
				p[ps.key] = "read"
			}
		}
	}
	for _, ps := range b.params {
		if p[ps.key] != "" || !ps.required {
			continue
		}
		for _, h := range held {
			if h != nil && h.Scope != nil && h.Scope.Name == scope && h.Params[ps.key] != "" {
				p[ps.key] = h.Params[ps.key]
				break
			}
		}
	}
	res, err := c.Resolve(api.CloudflareRequest{Scope: scope, Params: p, Mode: api.CFModeProxy})
	if err != nil {
		return nil
	}
	return res
}

func isNever(rd *rdef, ph string) bool {
	for _, s := range rd.segs {
		if s.ph == ph {
			return s.never
		}
	}
	return false
}

func (c *Catalogue) nameOf(key, id string) string {
	objs := c.cfg.Zones
	switch key {
	case api.CFParamTunnel:
		objs = c.cfg.Tunnels
	case api.CFParamDB:
		objs = c.cfg.D1Databases
	}
	for _, o := range objs {
		if o.ID == id {
			return o.Name
		}
	}
	return ""
}

// ZoneName returns the configured name of a zone id ("" if not configured).
func (c *Catalogue) ZoneName(id string) string { return c.nameOf(api.CFParamZone, id) }

// TunnelName returns the configured name of a tunnel id ("" if not configured).
func (c *Catalogue) TunnelName(id string) string { return c.nameOf(api.CFParamTunnel, id) }

// SplitPath splits a normalised path into segments (without the empty first element).
func SplitPath(p string) []string {
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}
