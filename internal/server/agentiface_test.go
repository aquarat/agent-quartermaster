//go:build linux

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
)

// setPolicy replaces one organisation's policy through the signed org_policy
// flow, as Settings does: the plan is the catalogue's own rows plus the change.
func (v *vaultEnv) setPolicy(slug string, change func(*api.DurationPolicy)) int {
	v.t.Helper()
	var cat api.Catalogue
	mustStatus(v.t, "catalogue", v.web("GET", "/api/ui/catalogue", nil, &cat), 200)
	for _, o := range cat.Orgs {
		if o.Slug != slug {
			continue
		}
		old, next := o.Policy, o.Policy
		change(&next)
		rules := append([]api.CatalogueRule{}, o.Rules...)
		raw, _ := json.Marshal(api.CatalogueChange{Owner: cat.OwnerID, Org: o.CatalogueNode, OldPolicy: &old, Policy: &next, OldRules: &o.Rules, Rules: &rules, ResultRevision: o.Revision + 1})
		return v.decideTap(v.auth, "/api/ui/catalogue/org_policy/"+o.ID, api.ChallengeRequest{Action: "replace", Plan: string(raw)})
	}
	v.t.Fatalf("no organisation %s", slug)
	return 0
}

// rawGet returns the status and body of an agent GET.
func (v *vaultEnv) rawGet(c *http.Client, path string) (int, string) {
	v.t.Helper()
	resp, err := c.Get(v.env.agent.URL + path)
	requireNoError(v.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	v.seen.Write(b)
	return resp.StatusCode, string(b)
}

func (v *vaultEnv) hostCatalogue(c *http.Client) (api.HostCatalogue, string) {
	v.t.Helper()
	st, body := v.rawGet(c, "/v2/catalogue")
	mustStatus(v.t, "host catalogue", st, 200)
	var out api.HostCatalogue
	requireNoError(v.t, json.Unmarshal([]byte(body), &out))
	return out, body
}

// createSecret plays Vault → Add item → Secret: one sealed upload, one tap.
func (v *vaultEnv) createSecretChallenge(id, slug, title, name, value, note, link string) (vaultReviewResp, int) {
	v.t.Helper()
	edit := envset.Edit{Op: "import", Entries: []envset.Entry{{Name: name, Value: value}}, Salt: bytes.Repeat([]byte{7}, 32)}
	plain, _ := json.Marshal(edit)
	commit, err := edit.Commit(envset.Binding{Org: v.org, Service: v.service, Set: id})
	requireNoError(v.t, err)
	attempt, enc, ct := v.sealUpload("edit", id, plain)
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "secret-create", "id": id, "service_id": v.service, "set_slug": slug, "set_title": title, "note": note, "url": link, "attempt_id": attempt, "enc": enc, "ciphertext": ct, "commitment": commit}, &r)
	if st == 200 {
		v.expect(r, "secret-create", id, with(v.target, "set_id", id, "set_slug", slug, "set_title", title, "kind", "secret", "revision", 0, "attempt_id", attempt, "env_name", name, "note", note, "url", link, "commitment", commit, "result_revision", 1, "recipient", v.recipient))
	}
	return r, st
}
func (v *vaultEnv) createSecret(id, slug, title, name, value, note, link string) {
	v.t.Helper()
	r, st := v.createSecretChallenge(id, slug, title, name, value, note, link)
	mustStatus(v.t, "secret challenge", st, 200)
	var out struct {
		Path string `json:"path"`
		Env  string `json:"env_name"`
	}
	mustStatus(v.t, "secret finish", v.tap(r, &out), 200)
	if out.Path != "client-a/paas/"+slug || out.Env != name {
		v.t.Fatalf("created secret: %+v", out)
	}
}

// release asks for path in a delivery mode, has the owner approve it and
// collects it once; it returns the entries and each step's status.
func (v *vaultEnv) ask(c *http.Client, path, mode string) (envset.Release, int) {
	v.t.Helper()
	var b envset.Binding
	mustStatus(v.t, "binding", v.host(c, "GET", "/v2/env/set?path="+path, nil, &b), 200)
	var rel envset.Release
	st := v.host(c, "POST", "/v2/env/requests", map[string]any{"binding": b, "mode": mode, "reason": "use the API key", "ttl_seconds": 600}, &rel)
	return rel, st
}
func (v *vaultEnv) deliver(c *http.Client, rel envset.Release) (envset.Collection, string) {
	v.t.Helper()
	var r tapResp
	mustStatus(v.t, "env challenge", v.web("POST", "/api/ui/seal/env/challenge", map[string]any{"id": rel.ID, "action": "approve", "ttl_seconds": 600}, &r), 200)
	as, pkt := v.fix.tapWith(v.t, v.s, v.auth, r)
	mustStatus(v.t, "env approve", v.web("POST", "/api/ui/seal/env/finish", map[string]any{"challenge_id": r.ChallengeID, "assertion": as, "open": pkt}, nil), 200)
	var got envset.Release
	mustStatus(v.t, "release", v.host(c, "GET", "/v2/env/requests/"+rel.ID, nil, &got), 200)
	var out envset.Collection
	mustStatus(v.t, "collect", v.host(c, "POST", "/v2/grants/"+got.Grant+"/collect", map[string]any{}, &out), 200)
	return out, r.Canonical
}

const secretID = "dddddddddddddddddddddddddddddddd"

// Discovery is per organisation and off by default. A host sees the sets and
// targets of the organisations that admit it AND turned listing on; every
// other organisation is as if it did not exist; a host admitted nowhere hears
// not_admitted. Names only, never a value.
func TestHostCatalogueDiscovery(t *testing.T) {
	v := newVault(t)
	const sentinel = "sentinel-discovery-value-91ab"
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: sentinel}, {Name: "DB_URL", Value: "postgres://app@192.0.2.10/app"}}}, nil)
	v.createSecret(secretID, "tailnet", "Tailnet API key", "TAILNET_API_KEY", sentinel+"-secret", "admin console key", "https://example.com/keys")
	f := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", "")

	// Off everywhere: an admitted host learns nothing, and is told so.
	got, body := v.hostCatalogue(v.agent)
	if got.Discovery || len(got.Credentials) != 0 || len(got.Targets) != 0 || strings.Contains(body, "client-a") || strings.Contains(body, "db-1") {
		t.Fatalf("discovery off: %s", body)
	}
	// A policy replacement in the shape every earlier release signed still applies ...
	mustStatus(t, "old-shape policy", v.setPolicy("client-a", func(p *api.DurationPolicy) { p.Default = 1800 }), 200)
	st, raw := 0, ""
	catalogueJSON := func() string {
		req, _ := http.NewRequest("GET", v.env.web.URL+"/api/ui/catalogue", nil)
		req.Header.Set("Cookie", sessionCookie+"="+v.sess)
		resp, err := http.DefaultClient.Do(req)
		requireNoError(t, err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if raw = catalogueJSON(); strings.Contains(raw, `"discovery"`) || strings.Contains(raw, `"deny_get"`) {
		t.Fatalf("a policy without the new switches changed its wire shape: %s", raw)
	}
	// ... and the owner turns listing on for one organisation with the same signed flow.
	mustStatus(t, "enable discovery", v.setPolicy("client-a", func(p *api.DurationPolicy) { p.Discovery = true }), 200)
	if raw = catalogueJSON(); !strings.Contains(raw, `"standing_indefinite":true,"discovery":true}`) {
		t.Fatalf("the catalogue does not carry the switch: %s", raw)
	}
	if !v.audited("org_policy_replace", `"discovery":true`) {
		t.Fatal("the policy change is not in the log with its plan")
	}
	got, body = v.hostCatalogue(v.agent)
	if !got.Discovery || len(got.Credentials) != 3 || len(got.Targets) != 0 {
		t.Fatalf("discovery on for client-a: %s", body)
	}
	byPath := map[string]api.HostCredential{}
	for _, c := range got.Credentials {
		byPath[c.Path] = c
	}
	if c := byPath["client-a/paas/staging"]; c.Kind != "env-set" || strings.Join(c.Names, ",") != "APP_TOKEN,DB_URL" || c.Approval != "owner" || !strings.Contains(c.Use, "aqmas run client-a/paas/staging") {
		t.Fatalf("env set entry: %+v", c)
	}
	if c := byPath["client-a/paas/tailnet"]; c.Kind != "secret" || c.Env != "TAILNET_API_KEY" || len(c.Names) != 0 || c.Note != "admin console key" || c.URL != "https://example.com/keys" || c.Title != "Tailnet API key" {
		t.Fatalf("secret entry: %+v", c)
	}
	if c := byPath[f.path]; c.Kind != "signer" || c.Scheme != "ed25519" || !strings.Contains(c.Use, "aqmas sign "+f.path) {
		t.Fatalf("signer entry: %+v", c)
	}
	// The personal organisation still has listing off: its targets stay unnamed.
	if strings.Contains(body, "db-1") || strings.Contains(body, "personal") || strings.Contains(body, "192.0.2.61") {
		t.Fatalf("an organisation with listing off leaked into the answer: %s", body)
	}
	// Another host admitted to the same organisation sees the same; once its admission
	// there ends, that organisation is gone from its answer, like one that never existed.
	if other, _ := v.hostCatalogue(v.other); len(other.Credentials) != 3 {
		t.Fatalf("second admitted host: %+v", other)
	}
	_, err := v.s.store.DB().Exec(`UPDATE org_hosts SET active=0,generation=generation+1 WHERE org_id=? AND host_id=(SELECT id FROM hosts WHERE name='other')`, v.org)
	requireNoError(t, err)
	other, body := v.hostCatalogue(v.other)
	if other.Discovery || len(other.Credentials) != 0 || strings.Contains(body, "client-a") || strings.Contains(body, "tailnet") {
		t.Fatalf("a host no longer admitted to client-a: %s", body)
	}
	// Listing on for personal too: the SSH targets, with what a login needs.
	mustStatus(t, "enable discovery for personal", v.setPolicy("personal", func(p *api.DurationPolicy) { p.Discovery = true }), 200)
	got, body = v.hostCatalogue(v.agent)
	if len(got.Targets) != 2 || len(got.Credentials) != 3 {
		t.Fatalf("both organisations: %s", body)
	}
	if x := got.Targets[0]; x.Name != "db-1" || x.Path != "personal/fleet/db-1" || x.Address != "192.0.2.61" || x.Port != 22 || strings.Join(x.Users, ",") != "alice" || x.Approval != "owner-or-standing" || x.Use != `aqmas ssh alice@db-1 --why "..."` {
		t.Fatalf("target: %+v", x)
	}
	if other, body = v.hostCatalogue(v.other); !other.Discovery || len(other.Targets) != 2 || len(other.Credentials) != 0 || strings.Contains(body, "client-a") {
		t.Fatalf("personal only: %s", body)
	}
	// Off again: nothing is listed, and the row a previous release reads is unchanged.
	mustStatus(t, "disable discovery", v.setPolicy("client-a", func(p *api.DurationPolicy) { p.Discovery = false }), 200)
	if got, body = v.hostCatalogue(v.agent); len(got.Credentials) != 0 || len(got.Targets) != 2 || strings.Contains(body, "client-a") {
		t.Fatalf("after turning listing off: %s", body)
	}
	// A host with no admission anywhere is told about its own state, as everywhere else.
	_, err = v.s.store.DB().Exec(`UPDATE org_hosts SET active=0,generation=generation+1 WHERE active=1 AND host_id=(SELECT id FROM hosts WHERE name='other')`)
	requireNoError(t, err)
	var e api.Error
	st, raw = v.rawGet(v.other, "/v2/catalogue")
	requireNoError(t, json.Unmarshal([]byte(raw), &e))
	if st != 404 || e.Code != api.ErrNotAdmitted {
		t.Fatalf("unadmitted host: %d %s", st, raw)
	}
	if where := v.leaked([]byte(sentinel)); where != "" {
		t.Fatalf("a value reached %s", where)
	}
}

// A secret is one value under one environment variable name: created with its
// value in one tap, stored like a one-key env set (its own bucket, sealed to
// its public key), delivered by run or get, revealed and replaced like one key.
func TestSecretLifecycle(t *testing.T) {
	v := newVault(t)
	const value = "tskey-api-sentinel-5f0c2a"
	for name, bad := range map[string][]string{
		"two words in a URL": {"x", "https://example.com/a b"},
		"a script URL":       {"x", "javascript:alert(1)"},
		"a control in note":  {"line\nbreak", ""},
	} {
		if _, st := v.createSecretChallenge(secretID, "tailnet", "Tailnet API key", "TAILNET_API_KEY", value, bad[0], bad[1]); st != 400 {
			t.Fatalf("%s: %d", name, st)
		}
	}
	v.createSecret(secretID, "tailnet", "Tailnet API key", "TAILNET_API_KEY", value, "admin console key", "https://example.com/keys")
	if !v.audited("vault_secret_create", "client-a/paas/tailnet revision=1 env=TAILNET_API_KEY") {
		t.Fatal("creation not audited")
	}
	if _, st := v.createSecretChallenge("ffffffffffffffffffffffffffffffff", "tailnet", "Again", "TAILNET_API_KEY", value, "", ""); st != 409 {
		t.Fatalf("a second secret with the same slug: %d", st)
	}
	var state struct {
		Sets []struct {
			SetID    string `json:"set_id"`
			Kind     string
			Revision int
			Names    []string
			Note     string
			URL      string
		}
	}
	mustStatus(t, "state", v.web("GET", "/api/ui/seal/vault/state", nil, &state), 200)
	found := false
	for _, s := range state.Sets {
		if s.SetID == secretID {
			found = s.Kind == "secret" && s.Revision == 1 && strings.Join(s.Names, ",") == "TAILNET_API_KEY" && s.Note == "admin console key" && s.URL == "https://example.com/keys"
		} else if s.Kind != "env-set" {
			t.Fatalf("another set changed kind: %+v", s)
		}
	}
	if !found {
		t.Fatalf("state: %+v", state)
	}
	var cat api.Catalogue
	mustStatus(t, "catalogue", v.web("GET", "/api/ui/catalogue", nil, &cat), 200)
	kinds := map[string]string{}
	for _, o := range cat.Orgs {
		for _, sv := range o.Services {
			for _, s := range sv.Sets {
				kinds[s.ID] = s.Kind
			}
		}
	}
	if kinds[secretID] != "secret" || kinds[v.set] != "env-set" {
		t.Fatalf("catalogue kinds: %v", kinds)
	}

	// aqmas run: the same release an env set has, carrying the one value.
	rel, st := v.ask(v.agent, "client-a/paas/tailnet", "process")
	mustStatus(t, "run request", st, 200)
	got, _ := v.deliver(v.agent, rel)
	if len(got.Entries) != 1 || got.Entries[0] != (envset.Entry{Name: "TAILNET_API_KEY", Value: value}) || got.Release.Mode != "process" {
		t.Fatalf("run delivery: %+v", got.Release)
	}
	// aqmas get: its own delivery mode, which the owner signs and the log names.
	rel, st = v.ask(v.agent, "client-a/paas/tailnet", "get")
	mustStatus(t, "get request", st, 200)
	if rel.Mode != "get" {
		t.Fatalf("mode: %s", rel.Mode)
	}
	got, canonical := v.deliver(v.agent, rel)
	if len(got.Entries) != 1 || got.Entries[0].Value != value || got.Release.Mode != "get" || !strings.Contains(canonical, `\"mode\":\"get\"`) {
		t.Fatalf("get delivery: %+v\n%s", got.Release, canonical)
	}
	if !v.audited("env_collect_get", "client-a/paas/tailnet revision=1") || !v.audited("env_request", "client-a/paas/tailnet mode=get") {
		t.Fatal("get not audited as get")
	}
	// Collected once: a second collection of the same grant is refused.
	mustStatus(t, "second collect", v.host(v.agent, "POST", "/v2/grants/"+got.Release.Grant+"/collect", map[string]any{}, nil), 409)
	// get is for secrets: an env set, even with one key, is delivered by run.
	v.commit(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "one-key-value"}}}, nil)
	if _, st = v.ask(v.agent, "client-a/paas/staging", "get"); st != 400 {
		t.Fatalf("get on an env set: %d", st)
	}
	if _, st = v.ask(v.agent, "client-a/paas/tailnet", "print"); st != 400 {
		t.Fatalf("unknown mode: %d", st)
	}
	// The other host's requests are its own: it cannot see this one.
	mustStatus(t, "another host's release", v.host(v.other, "GET", "/v2/env/requests/"+rel.ID, nil, nil), 404)

	// Reveal: its own tap, the same ceremony as one env key.
	k, err := seal.NewRecipient()
	requireNoError(t, err)
	target := with(v.target, "set_id", secretID, "set_slug", "tailnet", "set_title", "Tailnet API key", "kind", "secret")
	var r vaultReviewResp
	mustStatus(t, "reveal challenge", v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "reveal", "id": secretID, "names": []string{"TAILNET_API_KEY"}, "recipient": encodeID(k.Public())}, &r), 200)
	v.expect(r, "reveal", secretID, with(target, "revision", 1, "names", []string{"TAILNET_API_KEY"}, "recipient", encodeID(k.Public())))
	var sealed struct{ Enc, Ciphertext string }
	mustStatus(t, "reveal finish", v.tap(r, &sealed), 200)
	if !v.audited("vault_reveal", "client-a/paas/tailnet revision=1 names=TAILNET_API_KEY") {
		t.Fatal("reveal not audited")
	}

	// Replace keeps it one value; a second key is refused before any tap.
	replace := func(edit envset.Edit) int {
		edit.Salt = bytes.Repeat([]byte{9}, 32)
		plain, _ := json.Marshal(edit)
		commit, err := edit.Commit(envset.Binding{Org: v.org, Service: v.service, Set: secretID, Revision: 1})
		requireNoError(t, err)
		attempt, enc, ct := v.sealUpload("edit", secretID, plain)
		var r vaultReviewResp
		st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "commit", "id": secretID, "attempt_id": attempt, "enc": enc, "ciphertext": ct, "commitment": commit}, &r)
		if st != 200 {
			return st
		}
		changes, _ := edit.Changes([]string{"TAILNET_API_KEY"})
		v.expect(r, "commit", secretID, with(target, "revision", 1, "attempt_id", attempt, "operation", edit.Op, "changes", changes, "commitment", commit, "result_revision", 2, "recipient", v.recipient))
		return v.tap(r, nil)
	}
	if st = replace(envset.Edit{Op: "merge", Entries: []envset.Entry{{Name: "OTHER_API_KEY", Value: "x"}}}); st != 400 {
		t.Fatalf("a second key in a secret: %d", st)
	}
	if st = replace(envset.Edit{Op: "merge", Remove: []string{"TAILNET_API_KEY"}}); st != 400 {
		t.Fatalf("emptying a secret: %d", st)
	}
	mustStatus(t, "replace the value", replace(envset.Edit{Op: "import", Entries: []envset.Entry{{Name: "TAILNET_API_KEY", Value: value + "-2"}}}), 200)
	rel, st = v.ask(v.agent, "client-a/paas/tailnet", "get")
	mustStatus(t, "get after replace", st, 200)
	if got, _ = v.deliver(v.agent, rel); got.Entries[0].Value != value+"-2" || got.Release.Revision != 2 {
		t.Fatalf("replaced value not delivered: revision %d", got.Release.Revision)
	}

	// The owner can turn get off for the organisation; run is unchanged.
	mustStatus(t, "deny get", v.setPolicy("client-a", func(p *api.DurationPolicy) { p.DenyGet = true }), 200)
	if _, st = v.ask(v.agent, "client-a/paas/tailnet", "get"); st != 403 {
		t.Fatalf("get while turned off: %d", st)
	}
	if _, st = v.ask(v.agent, "client-a/paas/tailnet", "process"); st != 200 {
		t.Fatalf("run while get is off: %d", st)
	}

	// Convert: an env set with exactly one key becomes a secret, with a tap.
	convert := func() (vaultReviewResp, int) {
		var r vaultReviewResp
		st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "secret-convert", "id": v.set, "note": "", "url": ""}, &r)
		return r, st
	}
	r, st = convert()
	mustStatus(t, "convert challenge", st, 200)
	v.expect(r, "secret-convert", v.set, with(v.target, "revision", 1, "env_name", "APP_TOKEN", "note", "", "url", ""))
	mustStatus(t, "convert finish", v.tap(r, nil), 200)
	if _, st = convert(); st != 409 {
		t.Fatalf("converting a secret again: %d", st)
	}
	mustStatus(t, "state", v.web("GET", "/api/ui/seal/vault/state", nil, &state), 200)
	for _, s := range state.Sets {
		if s.Kind != "secret" {
			t.Fatalf("after convert: %+v", s)
		}
	}
	for _, secret := range []string{value, value + "-2", "one-key-value"} {
		if where := v.leaked([]byte(secret)); where != "" && where != "responses" {
			t.Fatalf("a value reached %s in the clear", where)
		}
	}
}
