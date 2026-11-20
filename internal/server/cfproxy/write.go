package cfproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
)

// ---- upstream answers ----

type upResp struct {
	resp     *http.Response
	isJSON   bool
	raw      []byte         // original JSON (for result.id); nil when streamed
	out      []byte         // redacted JSON
	doc      map[string]any // parsed original (JSON objects only)
	redacted int
}

func isJSONType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.Contains(strings.ToLower(ct), "json")
	}
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// objectData: routes whose answer is the caller's own stored data (R2 object bodies), passed
// through without JSON redaction (a JSON file in a bucket is not a Cloudflare object).
func objectData(rt cfscope.Route) bool {
	return rt.Vars["key"] != "" && strings.Contains(rt.Template, "/r2/buckets/{bucket}/objects/{key...}") && !rt.Write
}

// readUpstream checks the status and reads (and redacts) JSON answers; other answers are
// streamed by write.
func readUpstream(resp *http.Response, rt cfscope.Route) (*upResp, *refusal) {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, refuse(http.StatusBadGateway, api.CFErrUpstream, fmt.Sprintf("Cloudflare answered a redirect (%d); aqmasd never follows redirects", resp.StatusCode))
	}
	u := &upResp{resp: resp, isJSON: isJSONType(resp.Header.Get("Content-Type")) && !(objectData(rt) && resp.StatusCode/100 == 2)}
	if !u.isJSON {
		return u, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRedactBytes+1))
	if err != nil {
		return nil, refuse(http.StatusBadGateway, api.CFErrUpstream, "reading Cloudflare's answer failed")
	}
	if len(b) > maxRedactBytes {
		return nil, refuse(http.StatusBadGateway, api.CFErrUpstream, "Cloudflare's JSON answer is too large to check for secrets")
	}
	u.raw = b
	if len(bytes.TrimSpace(b)) == 0 {
		u.out = b
		return u, nil
	}
	v, err := decodeJSON(b)
	if err != nil {
		return nil, refuse(http.StatusBadGateway, api.CFErrUpstream, "Cloudflare's JSON answer did not parse (not passed on unchecked)")
	}
	u.doc, _ = v.(map[string]any)
	if out, n, err := redactJSON(b); err == nil {
		u.out, u.redacted = out, n
	}
	return u, nil
}

// write sends status, allow-listed headers, X-Aqmas-* headers already set on w, and body.
func (u *upResp) write(w http.ResponseWriter, warnings []string) {
	h := w.Header()
	for _, k := range forwardResponseHeaders {
		if v := u.resp.Header.Values(k); len(v) > 0 {
			h[k] = append([]string(nil), v...)
		}
	}
	if u.redacted > 0 {
		warnings = append(warnings, fmt.Sprintf("redacted %d fields", u.redacted))
	}
	for _, wn := range warnings {
		h.Add(api.CFWarningHeader, asciiOnly(wn))
	}
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(u.resp.StatusCode)
	if u.isJSON {
		_, _ = w.Write(u.out)
		return
	}
	_, _ = io.Copy(w, u.resp.Body)
}

// ---- writes (docs/CLOUDFLARE.md 4.1) ----

type guardCtx struct {
	call     cfscope.Call
	route    cfscope.Route
	host     Caller
	admin    bool
	res      *cfscope.Resolved
	body     any // parsed request body (nil if none / not JSON)
	before   any // before-snapshot result (nil when missing or none)
	zoneName string
}

func (p *Proxy) serveWrite(w http.ResponseWriter, r *http.Request, c Caller, call cfscope.Call, cd *candidate, route cfscope.Route, overrides map[string]bool) {
	ctx := r.Context()
	gid := cd.g.ID
	admin := cd.res.Scope.Name == api.CFScopeAdmin
	refuseW := func(rf *refusal, audit bool) { p.refused(ctx, w, c, call, gid, rf, audit, false) }

	// The upload JWT (J routes) replaces the parent token.
	auth := "Bearer " + p.o.ProxyToken
	if route.JWTPassthrough {
		a := r.Header.Get("Authorization")
		if !strings.HasPrefix(a, "Bearer ") || len(a) < 8 || strings.ContainsAny(a, "\r\n") {
			refuseW(refuse(http.StatusBadRequest, api.CFErrBadRequest, "this upload call needs the upload JWT as Authorization: Bearer"), false)
			return
		}
		auth = a
	}

	// 2. Body (bounded), parsed for guard rails.
	var (
		body    io.Reader
		clen    int64
		raw     []byte
		parsed  any
		scanner *markerScanner
	)
	if route.Upload {
		if r.ContentLength > p.uploadMax {
			refuseW(refuse(http.StatusRequestEntityTooLarge, api.CFErrBadRequest, "upload too large"), false)
			return
		}
		scanner = &markerScanner{r: r.Body, limit: p.uploadMax}
		body, clen = scanner, r.ContentLength
	} else {
		b, err := io.ReadAll(io.LimitReader(r.Body, p.maxBody+1))
		if err != nil {
			refuseW(refuse(http.StatusBadRequest, api.CFErrBadRequest, "reading the body failed"), false)
			return
		}
		if int64(len(b)) > p.maxBody {
			refuseW(refuse(http.StatusRequestEntityTooLarge, api.CFErrBadRequest, "body too large"), false)
			return
		}
		raw = b
		if len(bytes.TrimSpace(b)) > 0 {
			v, err := decodeJSON(b)
			if err == nil {
				parsed = v
			} else if route.Guard != "" || route.Snapshot == cfscope.SnapDNSName {
				refuseW(refuse(http.StatusBadRequest, api.CFErrBadRequest, "the body must be JSON on this route"), false)
				return
			}
		}
		if containsMarker(raw, parsed) {
			rf := refuse(http.StatusForbidden, api.CFErrGuardRail, guardRedactedWrite().msg)
			rf.guard = GRedactedWrite
			refuseW(rf, true)
			return
		}
		body, clen = bytes.NewReader(raw), int64(len(raw))
	}

	zoneName, err := p.zoneName(ctx, route.Vars["zone"])
	if err != nil {
		p.log.Warn("cf proxy: zone lookup", "error", err)
		refuseW(refuse(http.StatusBadGateway, api.CFErrUpstream, "zone lookup failed; nothing written"), false)
		return
	}

	// 3. Before-snapshot (fetched now, stored once the guards pass).
	spec, err := snapshotSpec(route, call, parsed, zoneName)
	if err != nil {
		refuseW(refuse(http.StatusBadRequest, api.CFErrBadRequest, err.Error()), false)
		return
	}
	var before *apiResult
	beforeMissing := spec != nil && spec.create
	if spec != nil && !spec.create {
		ar, err := p.get(ctx, spec.get)
		switch {
		case err != nil:
			p.log.Warn("cf proxy: before-snapshot", "error", err, "path", call.Path)
			refuseW(refuse(http.StatusBadGateway, api.CFErrUpstream, "before-snapshot failed; nothing written"), false)
			return
		case ar.ok():
			before = ar
		case ar.status == http.StatusNotFound && spec.missingOK:
			beforeMissing = true
		default:
			refuseW(refuse(http.StatusBadGateway, api.CFErrUpstream, fmt.Sprintf("before-snapshot GET answered %d; nothing written", ar.status)), false)
			return
		}
	}
	g := &guardCtx{call: call, route: route, host: c, admin: admin, res: cd.res, body: parsed, zoneName: zoneName}
	if before != nil {
		g.before = before.result
	}

	// 4. Scope enforcement (not for cf.admin), then guard rails.
	readOnlyD1 := false
	if !admin {
		if hint, err := p.enforce(g); err != nil {
			rf := refuse(http.StatusForbidden, api.CFErrNoGrant, err.Error())
			rf.needs = hint
			refuseW(rf, true)
			return
		}
		readOnlyD1 = route.Guard == cfscope.GuardD1 && cd.res.Params[api.CFParamAccess] == "read"
	}
	findings, warnings, err := p.guards(ctx, g)
	if err != nil {
		p.log.Warn("cf proxy: guard lookup", "error", err, "path", call.Path)
		refuseW(refuse(http.StatusBadGateway, api.CFErrUpstream, "a guard-rail lookup failed; nothing written"), false)
		return
	}
	var applied []string
	for _, f := range findings {
		if admin && overrides[f.guard] && !neverOverridable[f.guard] {
			applied = append(applied, f.guard)
			continue
		}
		st := f.status
		if st == 0 {
			st = http.StatusForbidden
		}
		rf := refuse(st, api.CFErrGuardRail, f.msg)
		rf.guard = f.guard
		refuseW(rf, true)
		return
	}
	applied = uniq(applied)

	// Store the before-snapshot.
	var beforeID, afterID string
	snapMeta := func(phase, key string) api.CFSnapshot {
		return api.CFSnapshot{CreatedAt: p.now().UTC(), Phase: phase, ObjectType: spec.typ, ObjectKey: key, Method: call.Method, Path: call.Path, GrantID: gid, Host: c.HostName}
	}
	beforeMeta := api.CFSnapshot{}
	if spec != nil {
		beforeID, afterID = ids.New(), ids.New()
		key := spec.key
		if spec.create {
			key = "" // filled once the id is known (after)
		}
		beforeMeta = snapMeta("before", key)
		beforeMeta.ID, beforeMeta.PairID = beforeID, afterID
		content := []byte("null")
		if before != nil {
			content = redactedResult(before.result)
		}
		beforeMeta.Missing = beforeMissing
		if spec.create {
			// Stored after the write, when the object key is known.
		} else if err := p.snaps.put(beforeMeta, content); err != nil {
			p.log.Error("cf proxy: storing before-snapshot", "error", err)
			refuseW(refuse(http.StatusBadGateway, api.CFErrUpstream, "storing the before-snapshot failed; nothing written"), false)
			return
		}
	}

	// 5. Forward.
	resp, err := p.do(ctx, call.Method, call.Path, call.Query, body, clen, r.Header, auth)
	if err != nil {
		switch {
		case scanner != nil && scanner.found:
			rf := refuse(http.StatusForbidden, api.CFErrGuardRail, guardRedactedWrite().msg)
			rf.guard = GRedactedWrite
			refuseW(rf, true)
		case scanner != nil && scanner.tooLarge:
			refuseW(refuse(http.StatusRequestEntityTooLarge, api.CFErrBadRequest, "upload too large"), false)
		default:
			p.log.Warn("cf proxy: upstream write", "error", err, "path", call.Path)
			refuseW(refuse(http.StatusBadGateway, api.CFErrUpstream, "Cloudflare unreachable (the write may or may not have happened)"), true)
		}
		return
	}
	defer resp.Body.Close()
	up, rf := readUpstream(resp, route)
	if rf != nil {
		refuseW(rf, true)
		return
	}
	ok2xx := resp.StatusCode/100 == 2

	// After-snapshot.
	if spec != nil && ok2xx {
		getPath, key := spec.get, spec.key
		if spec.afterGet != nil {
			id := str(obj(up.doc["result"])["id"])
			if id == "" {
				getPath = ""
			} else {
				getPath = spec.afterGet(id)
				key = spec.afterKey(id)
			}
		}
		if spec.create {
			beforeMeta.ObjectKey = key
			if key == "" {
				beforeMeta.ObjectKey = spec.typ + ":?"
			}
			if err := p.snaps.put(beforeMeta, []byte("null")); err != nil {
				p.log.Error("cf proxy: storing before-snapshot", "error", err)
				beforeID = ""
			}
		}
		stored := false
		if getPath != "" {
			ar, err := p.get(ctx, getPath)
			if err == nil && (ar.ok() || ar.status == http.StatusNotFound) {
				m := snapMeta("after", key)
				m.ID, m.PairID = afterID, beforeID
				content := []byte("null")
				if ar.ok() {
					content = redactedResult(ar.result)
				} else {
					m.Missing = true
				}
				if err := p.snaps.put(m, content); err == nil {
					stored = true
				}
				if route.Snapshot == cfscope.SnapTunnelConfig && ar.ok() {
					if v := num(obj(ar.result)["version"]); v >= 0 {
						p.setVersion(c.HostID, route.Vars["tunnel"], v)
					}
				}
			}
		}
		if !stored {
			warnings = append(warnings, "after-snapshot failed")
			afterID = ""
			if beforeID != "" {
				_ = p.snaps.setPair(beforeID, beforeMeta.CreatedAt, "")
			}
		}
	} else if spec != nil {
		afterID = "" // the write failed: no after
		if beforeID != "" && !spec.create {
			_ = p.snaps.setPair(beforeID, beforeMeta.CreatedAt, "")
		}
		if spec.create {
			beforeID = ""
		}
	}

	// Warnings computed after the write (best effort).
	var hostDiff string
	if route.Snapshot == cfscope.SnapTunnelConfig && route.Guard == cfscope.GuardTunnel {
		add, chg, del := tunnelHostDiff(obj(parsed)["config"], obj(g.before)["config"])
		hostDiff = diffText(add, chg, del)
		if ok2xx {
			warnings = append(warnings, p.tunnelAddWarnings(ctx, add)...)
		}
	}

	// 6. Audit + push (writes that changed something), log.
	objName := call.Path
	if spec != nil && spec.key != "" {
		objName = spec.key
	}
	detail := fmt.Sprintf("%s %s status=%d before=%s after=%s warnings=%d", call.Method, call.Path, resp.StatusCode, dash(beforeID), dash(afterID), len(warnings))
	if len(applied) > 0 {
		detail += " overrides=" + strings.Join(applied, ",")
	}
	if hostDiff != "" {
		detail += " hosts=" + hostDiff
	}
	if err := p.o.Grants.Audit(ctx, "host:"+c.HostName, "cf_write", "grant:"+gid, clip(detail, 2000)); err != nil {
		p.log.Error("cf proxy: audit", "error", err)
	}
	quiet := route.JWTPassthrough || readOnlyD1
	if ok2xx && (!quiet || len(applied) > 0) {
		text := fmt.Sprintf("aqmas: %s %s %s", c.HostName, call.Method, objName)
		if len(applied) > 0 {
			text += " OVERRIDE " + strings.Join(applied, ",")
		}
		if cd.g.Ref != "" {
			text += " [ref " + cd.g.Ref + "]"
		}
		p.notify("aqmas: "+c.HostName, clip(text, 300))
	}
	p.log.Info("cf proxy write", "method", call.Method, "path", call.Path, "status", resp.StatusCode, "grant", gid, "host", c.HostName, "before", beforeID, "after", afterID, "overrides", strings.Join(applied, ","))

	// 7. Response.
	h := w.Header()
	h.Set(api.CFGrantUsedHeader, gid)
	if beforeID != "" {
		h.Set(api.CFSnapshotBeforeHeader, beforeID)
	}
	if afterID != "" {
		h.Set(api.CFSnapshotAfterHeader, afterID)
	}
	for _, a := range applied {
		warnings = append(warnings, "guard "+a+" overridden")
	}
	up.write(w, warnings)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func diffText(add, chg, del []string) string {
	var parts []string
	for _, h := range add {
		parts = append(parts, "+"+h)
	}
	for _, h := range chg {
		parts = append(parts, "~"+h)
	}
	for _, h := range del {
		parts = append(parts, "-"+h)
	}
	return strings.Join(parts, " ")
}

// redactedResult serialises a GET's result with the response redaction applied.
func redactedResult(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	cp, err := decodeJSON(b)
	if err != nil {
		return []byte("null")
	}
	redactValue(cp)
	return encodeJSON(cp)
}

// enforce applies the non-admin scope limits; it returns an error and an optional
// X-Aqmas-Needs-Scope hint.
func (p *Proxy) enforce(g *guardCtx) (string, error) {
	rt, res := g.route, g.res
	switch rt.Guard {
	case cfscope.GuardDNS:
		if err := enforceDNSName(res.Params[api.CFParamName], g.zoneName, g.call.Method, obj(g.body), obj(g.before)); err != nil {
			return api.CFScopeDNSEdit + " zone=" + g.zoneName, err
		}
	case cfscope.GuardPurge:
		if err := enforcePurge(g.body, g.zoneName); err != nil {
			return api.CFScopeAdmin, err
		}
	case cfscope.GuardD1:
		if res.Params[api.CFParamAccess] == "read" {
			stmts, err := d1Statements(g.body)
			if err == nil {
				for _, s := range stmts {
					if err = readOnlySQL(s); err != nil {
						break
					}
				}
			}
			if err != nil {
				return api.CFScopeD1 + " " + cfscope.CanonicalParams(map[string]string{api.CFParamDB: res.Params[api.CFParamDB], api.CFParamAccess: "migrate"}), err
			}
		}
	case cfscope.GuardWorkersDomain:
		if g.call.Method != http.MethodDelete {
			if err := enforceWorkersDomain(g.body, res.Params[api.CFParamScript], res.Params[api.CFParamZone], res.IDs[api.CFParamZone]); err != nil {
				return "", err
			}
		}
	case cfscope.GuardWorkersRoute:
		if err := enforceWorkersRoute(rt, g.body, res.Params[api.CFParamScript], res.Params[api.CFParamZone], res.IDs[api.CFParamZone]); err != nil {
			return "", err
		}
	case cfscope.GuardRuleset:
		if rt.Snapshot == cfscope.SnapRuleset {
			if err := enforceRulesetPhase(g.before, res.Params[api.CFParamPhase]); err != nil {
				return "", err
			}
		}
	}
	return "", nil
}

// guards runs the route's guard rails. An error means a lookup a guard needs failed.
func (p *Proxy) guards(ctx context.Context, g *guardCtx) ([]*finding, []string, error) {
	var fs []*finding
	var warns []string
	add := func(f *finding) {
		if f != nil {
			fs = append(fs, f)
		}
	}
	m := g.call.Method
	switch g.route.Guard {
	case cfscope.GuardTunnel:
		add(guardTunnelWholeConfig(g.body))
		after := obj(g.body)["config"]
		beforeCfg := obj(g.before)["config"]
		rules := ingressOf(after)
		add(guardTunnelCatchAll(rules))
		f, w := guardTunnelTraefikSNI(rules, p.cfg.TraefikOrigin)
		add(f)
		warns = append(warns, w...)
		add(guardTunnelPlainOrigin(rules, p.cfg.TraefikPlainOrigins))
		add(guardTunnelNoTLSVerify(after, beforeCfg))
		add(guardTunnelAccessAud(after, beforeCfg))
		last, read := p.lastVersion(g.host.HostID, g.route.Vars["tunnel"])
		add(guardTunnelVersion(num(obj(g.before)["version"]), last, read))
	case cfscope.GuardAccessApp:
		add(guardAccessProtected(g.body, p.cfg.ProtectedAccessHostnames))
		warns = append(warns, accessAppWarnings(g.body)...)
	case cfscope.GuardAccessPatch:
		add(guardAccessPatch())
	case cfscope.GuardAccessAppDelWn:
		warns = append(warns, p.appInTunnelWarnings(ctx, g.before)...)
	case cfscope.GuardAccessAppPol:
		if m != http.MethodDelete {
			warns = append(warns, policyWarnings(g.body)...)
		}
	case cfscope.GuardAccessPolicy:
		if m != http.MethodDelete {
			warns = append(warns, policyWarnings(g.body)...)
		}
		if id := g.route.Vars["id"]; id != "" && (m == http.MethodPut || m == http.MethodDelete) {
			apps, err := p.getAll(ctx, "/accounts/"+g.route.Vars["acct"]+"/access/apps", 100, 20)
			if err != nil {
				return nil, nil, err
			}
			group := g.route.Snapshot == cfscope.SnapAccessGroup
			what := "policy"
			if group {
				what = "group"
			}
			add(guardAccessPolicyShared(countReferences(apps, id, group), what))
		}
	case cfscope.GuardIdP:
		if m == http.MethodDelete {
			add(guardIdPDelete())
		}
	case cfscope.GuardDNS:
		before := obj(g.before)
		if g.route.Snapshot == cfscope.SnapDNSName {
			before = nil // POST: the before is the list of same-name records
		}
		add(guardDNSProtected(m, obj(g.body), before, g.zoneName, p.cfg.ProtectedDNSNames))
		switch m {
		case http.MethodPost, http.MethodPut:
			warns = append(warns, dnsWarnings(obj(g.body))...)
		case http.MethodPatch:
			warns = append(warns, dnsWarnings(mergeRecord(before, obj(g.body)))...)
		}
	case cfscope.GuardRuleset:
		if g.route.Snapshot == cfscope.SnapRulesetEntrypoint {
			add(guardRulesetKeepRules(g.body, g.before))
		}
		if m == http.MethodDelete {
			warns = append(warns, "a ruleset rule is being deleted")
		}
	case cfscope.GuardZoneSettings:
		add(guardZoneSettingsPolicy(zoneSettingItems(g.route.Vars["name"], g.body)))
	case cfscope.GuardWorkersDomRm:
		add(guardWorkersDomainRemove())
	}
	return fs, warns, nil
}

// tunnelAddWarnings: newly added hostnames without a proxied DNS record in a configured zone
// or without an Access app (best effort).
func (p *Proxy) tunnelAddWarnings(ctx context.Context, added []string) []string {
	var warns []string
	if len(added) > 10 {
		added = added[:10]
	}
	var apps []any
	appsLoaded := false
	for _, h := range added {
		z, ok := zoneFor(p.cfg, h)
		proxied := false
		if ok {
			if ar, err := p.get(ctx, "/zones/"+z.ID+"/dns_records?name="+h); err == nil && ar.ok() {
				for _, rec := range arr(ar.result) {
					if truthy(obj(rec)["proxied"]) {
						proxied = true
					}
				}
			} else {
				continue // lookup failed: no claim either way
			}
		}
		if !proxied {
			warns = append(warns, "tunnel hostname "+h+" has no proxied DNS record in a configured zone")
		}
		if !appsLoaded {
			apps, _ = p.getAll(ctx, "/accounts/"+p.cfg.AccountID+"/access/apps", 100, 20)
			appsLoaded = true
		}
		if apps != nil && !appCovers(apps, h) {
			warns = append(warns, "tunnel hostname "+h+" has no Access app")
		}
	}
	return warns
}

func appCovers(apps []any, host string) bool {
	for _, a := range apps {
		for _, d := range accessHosts(a) {
			if hp, ok := hostOf(d); ok && coversHost(hp, host) {
				return true
			}
		}
	}
	return false
}

// appInTunnelWarnings: deleting an Access app whose hostname a configured tunnel still routes.
func (p *Proxy) appInTunnelWarnings(ctx context.Context, before any) []string {
	hosts := map[string]bool{}
	for _, d := range accessHosts(before) {
		if h, ok := hostOf(d); ok {
			hosts[h] = true
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	var warns []string
	for _, t := range p.cfg.Tunnels {
		ar, err := p.get(ctx, "/accounts/"+p.cfg.AccountID+"/cfd_tunnel/"+t.ID+"/configurations")
		if err != nil || !ar.ok() {
			continue
		}
		for _, r := range ingressOf(obj(obj(ar.result)["config"])) {
			if hosts[r.hostname] {
				warns = append(warns, "deleting the Access app of "+r.hostname+", which tunnel "+t.Name+" still routes")
			}
		}
	}
	sort.Strings(warns)
	return warns
}
