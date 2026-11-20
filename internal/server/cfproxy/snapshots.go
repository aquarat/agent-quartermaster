package cfproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
)

// ---- which object a write touches (docs/CLOUDFLARE.md 4.2) ----

// snapSpec says how to snapshot the object a write touches.
type snapSpec struct {
	typ string
	key string
	// get is the escaped path (and query) of the GET; "" for creates (before = missing).
	get string
	// create: the object id comes from the write's response result.id; afterGet builds the
	// after-snapshot GET path from it.
	create   bool
	afterGet func(id string) string
	afterKey func(id string) string
	// missingOK: a 404 on the before GET means "no object yet" (not a failure).
	missingOK bool
}

// snapshotSpec builds the spec for a matched write. body is the parsed request body (may be
// nil); zoneName resolves zone ids for dns-name.
func snapshotSpec(rt cfscope.Route, call cfscope.Call, body any, zoneName string) (*snapSpec, error) {
	v := rt.Vars
	acct := "/accounts/" + v["acct"]
	z := v["zone"]
	switch rt.Snapshot {
	case "":
		return nil, nil
	case cfscope.SnapTunnelConfig:
		return &snapSpec{typ: rt.Snapshot, key: "tunnel-config:" + v["tunnel"], get: acct + "/cfd_tunnel/" + v["tunnel"] + "/configurations"}, nil
	case cfscope.SnapAccessApp, cfscope.SnapAccessPolicy, cfscope.SnapAccessGroup, cfscope.SnapAccessIdP:
		coll := map[string]string{cfscope.SnapAccessApp: "apps", cfscope.SnapAccessPolicy: "policies", cfscope.SnapAccessGroup: "groups", cfscope.SnapAccessIdP: "identity_providers"}[rt.Snapshot]
		base := acct + "/access/" + coll + "/"
		if id := v["id"]; id != "" {
			return &snapSpec{typ: rt.Snapshot, key: rt.Snapshot + ":" + id, get: base + id}, nil
		}
		return &snapSpec{typ: rt.Snapshot, create: true,
			afterGet: func(id string) string { return base + url.PathEscape(id) },
			afterKey: func(id string) string { return rt.Snapshot + ":" + id }}, nil
	case cfscope.SnapAccessOrg:
		return &snapSpec{typ: rt.Snapshot, key: "access-org", get: acct + "/access/organizations"}, nil
	case cfscope.SnapDNSRecord:
		return &snapSpec{typ: rt.Snapshot, key: "dns-record:" + z + ":" + v["id"], get: "/zones/" + z + "/dns_records/" + v["id"]}, nil
	case cfscope.SnapDNSName:
		name := fqdn(str(obj(body)["name"]), zoneName)
		if name == "" {
			return nil, errors.New("DNS record body has no name")
		}
		k := "dns-name:" + z + ":" + name
		return &snapSpec{typ: rt.Snapshot, key: k, get: "/zones/" + z + "/dns_records?name=" + url.QueryEscape(name),
			afterGet: func(id string) string { return "/zones/" + z + "/dns_records/" + url.PathEscape(id) },
			afterKey: func(string) string { return k }}, nil
	case cfscope.SnapRulesetEntrypoint:
		return &snapSpec{typ: rt.Snapshot, key: "ruleset-entrypoint:" + z + ":" + v["phase"], get: "/zones/" + z + "/rulesets/phases/" + v["phase"] + "/entrypoint", missingOK: true}, nil
	case cfscope.SnapRuleset:
		return &snapSpec{typ: rt.Snapshot, key: "ruleset:" + z + ":" + v["id"], get: "/zones/" + z + "/rulesets/" + v["id"]}, nil
	case cfscope.SnapZoneSetting:
		if n := v["name"]; n != "" {
			return &snapSpec{typ: rt.Snapshot, key: "zone-setting:" + z + ":" + n, get: "/zones/" + z + "/settings/" + n}, nil
		}
		return &snapSpec{typ: rt.Snapshot, key: "zone-setting:" + z + ":all", get: "/zones/" + z + "/settings"}, nil
	case cfscope.SnapEmailRules:
		return &snapSpec{typ: rt.Snapshot, key: "email-rules:" + z, get: "/zones/" + z + "/email/routing/rules"}, nil
	case cfscope.SnapPagesProject:
		return &snapSpec{typ: rt.Snapshot, key: "pages-project:" + v["project"], get: acct + "/pages/projects/" + v["project"]}, nil
	case cfscope.SnapWorkersScriptSettings:
		// The same resource the write changes (settings or script-settings).
		return &snapSpec{typ: rt.Snapshot, key: "workers-script-settings:" + v["script"], get: call.Path}, nil
	case cfscope.SnapWorkersScriptRoutes:
		return &snapSpec{typ: rt.Snapshot, key: "workers-script-routes:" + v["script"], get: acct + "/workers/scripts/" + v["script"] + "/routes"}, nil
	case cfscope.SnapWorkersRoutes:
		return &snapSpec{typ: rt.Snapshot, key: "workers-routes:" + z, get: "/zones/" + z + "/workers/routes"}, nil
	case cfscope.SnapWorkersDomains:
		return &snapSpec{typ: rt.Snapshot, key: "workers-domains", get: acct + "/workers/domains"}, nil
	}
	return nil, fmt.Errorf("unknown snapshot type %q", rt.Snapshot)
}

// ---- the store ----

var snapIDRE = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

type snapStore struct {
	dir string
	mu  sync.Mutex
}

func newSnapStore(dir string) (*snapStore, error) {
	if dir == "" {
		return nil, errors.New("cfproxy: SnapshotDir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &snapStore{dir: dir}, nil
}

func dayDir(t time.Time) string { return t.UTC().Format("2006-01-02") }

// put stores content (already redacted) and its metadata.
func (s *snapStore) put(meta api.CFSnapshot, content []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !snapIDRE.MatchString(meta.ID) {
		return errors.New("bad snapshot id")
	}
	sum := sha256.Sum256(content)
	meta.SHA256 = hex.EncodeToString(sum[:])
	meta.Size = len(content)
	meta.Content = nil
	d := filepath.Join(s.dir, dayDir(meta.CreatedAt))
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	if err := writeFile0600(filepath.Join(d, meta.ID+".json"), content); err != nil {
		return err
	}
	mb, _ := json.Marshal(meta)
	return writeFile0600(filepath.Join(d, meta.ID+".meta.json"), mb)
}

// setPair rewrites a snapshot's pair id (e.g. "" when the after-snapshot failed).
func (s *snapStore) setPair(id string, created time.Time, pair string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := filepath.Join(s.dir, dayDir(created), id+".meta.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var m api.CFSnapshot
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	m.PairID = pair
	mb, _ := json.Marshal(m)
	return writeFile0600(p, mb)
}

func writeFile0600(p string, b []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}

type snapFile struct {
	meta api.CFSnapshot
	dir  string
}

// all lists every snapshot's metadata.
func (s *snapStore) all() ([]snapFile, error) {
	days, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []snapFile
	for _, d := range days {
		if !d.IsDir() {
			continue
		}
		dp := filepath.Join(s.dir, d.Name())
		files, err := os.ReadDir(dp)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".meta.json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dp, f.Name()))
			if err != nil {
				continue
			}
			var m api.CFSnapshot
			if json.Unmarshal(b, &m) != nil || !snapIDRE.MatchString(m.ID) {
				continue
			}
			out = append(out, snapFile{meta: m, dir: dp})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].meta, out[j].meta
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.After(b.CreatedAt)
		}
		if a.Phase != b.Phase { // same instant: the after-snapshot is the newer state
			return a.Phase == "after"
		}
		return a.ID > b.ID
	})
	return out, nil
}

func (s *snapStore) get(id string) (*api.CFSnapshot, error) {
	if !snapIDRE.MatchString(id) {
		return nil, os.ErrNotExist
	}
	days, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	for _, d := range days {
		if !d.IsDir() {
			continue
		}
		dp := filepath.Join(s.dir, d.Name())
		mb, err := os.ReadFile(filepath.Join(dp, id+".meta.json"))
		if err != nil {
			continue
		}
		var m api.CFSnapshot
		if err := json.Unmarshal(mb, &m); err != nil {
			return nil, err
		}
		cb, err := os.ReadFile(filepath.Join(dp, id+".json"))
		if err != nil {
			return nil, err
		}
		m.Content = json.RawMessage(cb)
		return &m, nil
	}
	return nil, os.ErrNotExist
}

// prune deletes snapshots older than days, except the newest of each object key; empty day
// directories go too.
func (s *snapStore) prune(now time.Time, days int) (int, error) {
	all, err := s.all() // newest first
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	seen := map[string]bool{}
	n := 0
	for _, f := range all {
		k := f.meta.ObjectKey
		newest := !seen[k]
		seen[k] = true
		if newest || !f.meta.CreatedAt.Before(cutoff) {
			continue
		}
		os.Remove(filepath.Join(f.dir, f.meta.ID+".json"))
		if err := os.Remove(filepath.Join(f.dir, f.meta.ID+".meta.json")); err == nil {
			n++
		}
	}
	daysDirs, _ := os.ReadDir(s.dir)
	for _, d := range daysDirs {
		if d.IsDir() {
			os.Remove(filepath.Join(s.dir, d.Name())) // only succeeds when empty
		}
	}
	return n, nil
}

// ---- agent endpoints ----

// ScopeLister is implemented by core (optional): the scopes of hostID's active Cloudflare
// grants, either mode. Without it the sensitive snapshot types are never served.
type ScopeLister interface {
	ActiveScopes(ctx context.Context, hostID int64, now time.Time) ([]string, error)
}

// sensitiveSnapshots: object types whose content is personal or settings data; reading them
// needs an active grant of one of these scopes (cf.read.private, the scope that writes them,
// or cf.admin).
var sensitiveSnapshots = map[string][]string{
	cfscope.SnapAccessIdP:             {api.CFScopeReadPrivate, api.CFScopeAccessIdPOrg, api.CFScopeAdmin},
	cfscope.SnapPagesProject:          {api.CFScopeReadPrivate, api.CFScopePages, api.CFScopeAdmin},
	cfscope.SnapWorkersScriptSettings: {api.CFScopeReadPrivate, api.CFScopeWorkersDeploy, api.CFScopeAdmin},
}

// snapReader decides which snapshots a host may read: only those taken for its own writes,
// and the sensitive types only with a matching active grant.
type snapReader struct {
	host   string
	scopes map[string]bool
}

func (sr snapReader) may(m api.CFSnapshot) bool {
	if m.Host != sr.host {
		return false
	}
	if need, ok := sensitiveSnapshots[m.ObjectType]; ok {
		for _, s := range need {
			if sr.scopes[s] {
				return true
			}
		}
		return false
	}
	return true
}

func (p *Proxy) snapReaderFor(ctx context.Context, c Caller) (snapReader, error) {
	sr := snapReader{host: c.HostName, scopes: map[string]bool{}}
	if sl, ok := p.o.Grants.(ScopeLister); ok {
		scopes, err := sl.ActiveScopes(ctx, c.HostID, p.now())
		if err != nil {
			return sr, err
		}
		for _, s := range scopes {
			sr.scopes[s] = true
		}
	}
	return sr, nil
}

func (p *Proxy) snapshotAllowed(w http.ResponseWriter, r *http.Request, c Caller) bool {
	ok, err := p.o.Grants.HasActiveGrant(r.Context(), c.HostID, p.now())
	if err != nil {
		p.log.Error("cf snapshots: grant check", "error", err)
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal error")
		return false
	}
	if !ok {
		writeAPIError(w, http.StatusForbidden, "forbidden", "reading Cloudflare snapshots needs an active Cloudflare grant (cf.read is enough)")
		return false
	}
	return true
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.Error{Code: code, Message: msg})
}

func writeAPIJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// ServeSnapshotList handles GET /v1/cf/snapshots (query: object, type, grant, limit).
func (p *Proxy) ServeSnapshotList(w http.ResponseWriter, r *http.Request, c Caller) {
	if !p.snapshotAllowed(w, r, c) {
		return
	}
	q := r.URL.Query()
	limit := 50
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 {
			writeAPIError(w, http.StatusBadRequest, "bad_request", "limit must be a positive integer")
			return
		}
		limit = min(n, 500)
	}
	sr, err := p.snapReaderFor(r.Context(), c)
	var all []snapFile
	if err == nil {
		all, err = p.snaps.all()
	}
	if err != nil {
		p.log.Error("cf snapshots: list", "error", err)
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := api.CFSnapshotList{Snapshots: []api.CFSnapshot{}}
	for _, f := range all {
		m := f.meta
		if !sr.may(m) || (q.Get("object") != "" && m.ObjectKey != q.Get("object")) || (q.Get("type") != "" && m.ObjectType != q.Get("type")) || (q.Get("grant") != "" && m.GrantID != q.Get("grant")) {
			continue
		}
		m.Content = nil
		out.Snapshots = append(out.Snapshots, m)
		if len(out.Snapshots) >= limit {
			break
		}
	}
	writeAPIJSON(w, out)
}

// ServeSnapshotGet handles GET /v1/cf/snapshots/{id}.
func (p *Proxy) ServeSnapshotGet(w http.ResponseWriter, r *http.Request, c Caller, id string) {
	if !p.snapshotAllowed(w, r, c) {
		return
	}
	sr, err := p.snapReaderFor(r.Context(), c)
	if err != nil {
		p.log.Error("cf snapshots: scopes", "error", err)
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	m, err := p.snaps.get(id)
	if err == nil && m.Host != c.HostName {
		err = os.ErrNotExist // another host's snapshot: as if it did not exist
	}
	if err == nil && !sr.may(*m) {
		writeAPIError(w, http.StatusForbidden, "forbidden", "this snapshot type needs an active cf.read.private grant (or of the scope that wrote it)")
		return
	}
	if errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if err != nil {
		p.log.Error("cf snapshots: get", "error", err)
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeAPIJSON(w, m)
}
