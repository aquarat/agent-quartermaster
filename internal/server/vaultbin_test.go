package server

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

type binState struct {
	Sets []struct {
		SetID    string `json:"set_id"`
		SetSlug  string `json:"set_slug"`
		Kind     string
		Revision int
	}
	Deleted []struct {
		SetID     string `json:"set_id"`
		SetSlug   string `json:"set_slug"`
		Kind      string
		Revision  int
		Names     []string
		DeletedAt int64  `json:"deleted_at"`
		PurgeAt   int64  `json:"purge_at"`
		DeletedBy string `json:"deleted_by"`
		Digest    string
		PathTaken bool `json:"path_taken"`
	}
	Bin      int `json:"bin_seconds"`
	Requests []signer.Request
}

func (v *vaultEnv) binState() (s binState) {
	v.t.Helper()
	mustStatus(v.t, "vault state", v.web("GET", "/api/ui/seal/vault/state", nil, &s), 200)
	return s
}

// setTarget is the signed target of a set in the test organisation.
func (v *vaultEnv) setTarget(id, slug, title, kind string, revision int) map[string]any {
	return with(v.target, "set_id", id, "set_slug", slug, "set_title", title, "kind", kind, "revision", revision)
}

// deleteChallenge asks to delete a set at the revision the page showed and
// checks the canonical is exactly what the owner chose.
func (v *vaultEnv) deleteChallenge(id, slug, title, kind string, revision int, fingerprint string) (vaultReviewResp, int) {
	v.t.Helper()
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "delete", "id": id, "revision": revision}, &r)
	if st == 200 {
		v.expect(r, "delete", id, with(v.setTarget(id, slug, title, kind, revision), "path", "client-a/paas/"+slug, "fingerprint", fingerprint, "bin_seconds", 604800))
		if r.Open != nil {
			v.t.Fatal("a delete offers to open a bucket")
		}
	}
	return r, st
}

type deleteResult struct {
	OK      bool
	PurgeAt int64 `json:"purge_at"`
	Ended   store.Ended
}

func (v *vaultEnv) delete(id, slug, title, kind string, revision int, fingerprint string) deleteResult {
	v.t.Helper()
	r, st := v.deleteChallenge(id, slug, title, kind, revision, fingerprint)
	mustStatus(v.t, "delete challenge", st, 200)
	var out deleteResult
	mustStatus(v.t, "delete finish", v.tap(r, &out), 200)
	return out
}

// binChallenge asks for restore or purge of a binned set, canonical checked.
func (v *vaultEnv) binChallenge(action, id string) (vaultReviewResp, int) {
	v.t.Helper()
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": action, "id": id}, &r)
	if st != 200 {
		return r, st
	}
	for _, d := range v.binState().Deleted {
		if d.SetID != id {
			continue
		}
		var title string
		requireNoError(v.t, v.s.store.DB().QueryRow(`SELECT title FROM credential_sets WHERE id=?`, id).Scan(&title))
		meta := with(v.setTarget(id, d.SetSlug, title, d.Kind, d.Revision), "path", "client-a/paas/"+d.SetSlug, "deleted_at", d.DeletedAt)
		if action == "purge" {
			meta["digest"] = d.Digest
		}
		v.expect(r, action, id, meta)
		if r.Open != nil {
			v.t.Fatalf("%s offers to open a bucket", action)
		}
		return r, st
	}
	v.t.Fatalf("%s challenge for a set that is not in the bin", action)
	return r, st
}
func (v *vaultEnv) count(query string, args ...any) (n int) {
	v.t.Helper()
	requireNoError(v.t, v.s.store.DB().QueryRow(query, args...).Scan(&n))
	return n
}

// Delete moves an item to the bin with one tap over its path, kind and
// revision. From that moment it does not exist for hosts, everything that
// could still use it has ended, and its path is free. Restore brings it back
// as it was with nothing live; a taken path refuses it.
func TestVaultDeleteAndRestore(t *testing.T) {
	v := newVault(t)
	const value, path = "tskey-bin-sentinel-31", "client-a/paas/tailnet"
	mustStatus(t, "listing on", v.setPolicy("client-a", func(p *api.DurationPolicy) { p.Discovery = true }), 200)
	v.createSecret(secretID, "tailnet", "Tailnet API key", "TAILNET_API_KEY", value, "", "")

	// A live don't-ask-again rule, an approved release nobody collected and a pending request.
	rel, st := v.ask(v.agent, path, "process")
	mustStatus(t, "request", st, 200)
	if got, _ := v.deliverWith(v.agent, rel, 3600); got.Entries[0].Value != value {
		t.Fatal("delivery before the delete")
	}
	uncollected, st := v.ask(v.other, path, "process")
	mustStatus(t, "second request", st, 200)
	_, st = v.envDecide(map[string]any{"id": uncollected.ID, "action": "approve", "ttl_seconds": 600})
	mustStatus(t, "approve without collecting", st, 200)
	uncollected = v.relStatus(v.other, uncollected)
	waiting, st := v.ask(v.other, path, "get")
	mustStatus(t, "pending request", st, 200)
	if open := openBuckets(t, v.s); len(open) != 1 {
		t.Fatalf("the secret's bucket should be held open: %v", open)
	}

	// The tap is bound to the revision the page showed.
	if _, st := v.deleteChallenge(secretID, "tailnet", "Tailnet API key", "secret", 0, ""); st != 409 {
		t.Fatalf("a stale revision: %d", st)
	}
	if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "delete", "id": secretID}, nil); st != 400 {
		t.Fatalf("no revision: %d", st)
	}
	for name, id := range map[string]string{"an unknown set": "0123456789abcdef0123456789abcdef", "the organisation": vOrg} {
		if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "delete", "id": id, "revision": 0}, nil); st != 404 {
			t.Fatalf("delete of %s: %d", name, st)
		}
	}
	// A value saved between the review and the tap makes the signed text stale.
	stale, st := v.deleteChallenge(secretID, "tailnet", "Tailnet API key", "secret", 1, "")
	mustStatus(t, "delete challenge", st, 200)
	v.set = secretID
	v.target = v.setTarget(secretID, "tailnet", "Tailnet API key", "secret", 0)
	delete(v.target, "revision")
	v.commit(envset.Edit{Op: "import", Entries: []envset.Entry{{Name: "TAILNET_API_KEY", Value: value}}}, []string{"TAILNET_API_KEY"})
	if st := v.tap(stale, nil); st != 409 {
		t.Fatalf("a delete signed for an earlier revision applied: %d", st)
	}
	if len(v.binState().Deleted) != 0 {
		t.Fatal("the stale delete binned the set")
	}
	// The new revision ended the earlier rule and releases; make them again.
	rel, st = v.ask(v.agent, path, "process")
	mustStatus(t, "request", st, 200)
	v.deliverWith(v.agent, rel, 3600)
	uncollected, st = v.ask(v.other, path, "process")
	mustStatus(t, "second request", st, 200)
	_, st = v.envDecide(map[string]any{"id": uncollected.ID, "action": "approve", "ttl_seconds": 600})
	mustStatus(t, "approve without collecting", st, 200)
	uncollected = v.relStatus(v.other, uncollected)
	waiting, st = v.ask(v.other, path, "get")
	mustStatus(t, "pending request", st, 200)

	before := v.clock.Now()
	out := v.delete(secretID, "tailnet", "Tailnet API key", "secret", 2, "")
	if !out.OK || out.PurgeAt != before.Add(7*24*time.Hour).UnixMilli() || out.Ended != (store.Ended{Standing: 1, Releases: 1, Pending: 1}) {
		t.Fatalf("delete result: %+v", out)
	}

	// Gone for hosts: the same not_found as a path that never existed.
	for name, c := range map[string]*http.Client{"the host with the rule": v.agent, "the other host": v.other} {
		st, body := v.rawGet(c, "/v2/env/set?path="+path)
		st2, never := v.rawGet(c, "/v2/env/set?path=client-a/paas/never-existed")
		if st != 404 || st2 != 404 || body != never {
			t.Fatalf("%s can tell a deleted secret from a missing one: %d %s / %d %s", name, st, body, st2, never)
		}
	}
	if st := v.host(v.other, "POST", "/v2/grants/"+uncollected.Grant+"/collect", map[string]any{}, nil); st != 404 {
		t.Fatalf("an approved release was collected after the delete: %d", st)
	}
	if st := v.host(v.other, "GET", "/v2/env/requests/"+waiting.ID, nil, nil); st != 404 {
		t.Fatalf("a pending request survived the delete: %d", st)
	}
	if cat, raw := v.hostCatalogue(v.agent); len(cat.Credentials) != 0 || strings.Contains(raw, "tailnet") {
		t.Fatalf("the catalogue lists a deleted secret: %s", raw)
	}
	var env struct {
		Releases []envset.Release  `json:"releases"`
		Standing []envset.Standing `json:"standing"`
	}
	mustStatus(t, "env state", v.web("GET", "/api/ui/seal/env/state", nil, &env), 200)
	if len(env.Standing) != 0 || len(env.Releases) != 0 {
		t.Fatalf("rules or cards survived the delete: %+v", env)
	}
	if open := openBuckets(t, v.s); len(open) != 0 {
		t.Fatalf("the deleted secret's bucket is still open: %v", open)
	}
	// The bin: who, when, how long, and a digest; the Vault no longer lists it.
	s := v.binState()
	if len(s.Sets) != 1 || s.Sets[0].SetID != vSet || s.Bin != 604800 {
		t.Fatalf("live sets after the delete: %+v", s.Sets)
	}
	if len(s.Deleted) != 1 {
		t.Fatalf("bin: %+v", s.Deleted)
	}
	d := s.Deleted[0]
	if d.SetID != secretID || d.SetSlug != "tailnet" || d.Kind != "secret" || d.Revision != 2 || strings.Join(d.Names, ",") != "TAILNET_API_KEY" || d.DeletedAt != before.UnixMilli() || d.PurgeAt != out.PurgeAt || d.DeletedBy == "" || len(d.Digest) != 64 || d.PathTaken {
		t.Fatalf("binned item: %+v", d)
	}
	if !v.audited("vault_delete", path+" kind=secret revision=2 digest="+d.Digest) || !v.audited("vault_delete", "ended=grants:0,standing:1,releases:1,pending:1") {
		t.Fatal("delete not audited with path, kind, digest and what it ended")
	}
	if st := v.web("GET", "/api/ui/seal/vault/history?set="+secretID, nil, nil); st != 404 {
		t.Fatalf("history of a binned set: %d", st)
	}
	// Nothing edits or reveals a binned item.
	for _, action := range []string{"reveal", "standing-cap", "delete"} {
		if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": action, "id": secretID, "names": []string{"TAILNET_API_KEY"}, "recipient": "x", "revision": 2, "standing_cap_seconds": 0}, nil); st != 404 {
			t.Fatalf("%s on a binned set: %d", action, st)
		}
	}

	// The path is free: a new secret takes it. Then the old one cannot come back.
	const second = "99999999999999999999999999999999"
	v.createSecret(second, "tailnet", "Tailnet API key", "TAILNET_API_KEY", "another-value-entirely", "", "")
	if s = v.binState(); !s.Deleted[0].PathTaken {
		t.Fatal("the bin does not say that the path is taken")
	}
	if _, st := v.binChallenge("restore", secretID); st != 409 {
		t.Fatalf("restore over a live item: %d", st)
	}
	// Taken between the review and the tap: refused at finish as well.
	v.delete(second, "tailnet", "Tailnet API key", "secret", 1, "")
	restore, st := v.binChallenge("restore", secretID)
	mustStatus(t, "restore challenge", st, 200)
	const third = "88888888888888888888888888888888"
	v.createSecret(third, "tailnet", "Tailnet API key", "TAILNET_API_KEY", "a-third-value", "", "")
	if st := v.tap(restore, nil); st != 409 {
		t.Fatalf("restore applied over an item created after the review: %d", st)
	}
	v.delete(third, "tailnet", "Tailnet API key", "secret", 1, "")

	// Restore: the item as it was, same value and revision, nothing live.
	restore, st = v.binChallenge("restore", secretID)
	mustStatus(t, "restore challenge", st, 200)
	var restored struct {
		OK   bool
		Path string
	}
	mustStatus(t, "restore", v.tap(restore, &restored), 200)
	if restored.Path != path || !v.audited("vault_restore", path+" kind=secret revision=2") {
		t.Fatalf("restore result: %+v", restored)
	}
	s = v.binState()
	if len(s.Deleted) != 2 || len(s.Sets) != 2 {
		t.Fatalf("after restore: %d live, %d binned", len(s.Sets), len(s.Deleted))
	}
	rel, st = v.ask(v.agent, path, "process")
	mustStatus(t, "request after restore", st, 200)
	if got := v.relStatus(v.agent, rel); got.Status != "pending" || got.Revision != 2 {
		t.Fatalf("a don't-ask-again rule came back with the restore: %+v", got)
	}
	if got, _ := v.deliver(v.agent, rel); len(got.Entries) != 1 || got.Entries[0].Value != value {
		t.Fatal("the restored secret has another value")
	}
	if st := v.host(v.other, "POST", "/v2/grants/"+uncollected.Grant+"/collect", map[string]any{}, nil); st == 200 {
		t.Fatal("a release from before the delete was collected after the restore")
	}
	if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "restore", "id": secretID}, nil); st != 404 {
		t.Fatalf("restore of a live set: %d", st)
	}
	if where := v.leaked([]byte(value)); where != "" && where != "responses" {
		t.Fatalf("the value appears in %s", where)
	}
}

// A deleted signer signs nothing: its grant ends with the delete and does not
// come back with a restore; the key itself does.
func TestVaultDeleteSigner(t *testing.T) {
	v := newVault(t)
	const id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	f := v.createSigner(id, "release-key", "ed25519-sha256", "")
	fp := signer.Fingerprint(f.pub)
	a := signItemFor(f.scheme, "a.bin", []byte("artifact a"))
	req, st := v.askSign(v.agent, f, 600, 5, a)
	mustStatus(t, "request", st, 200)
	grant := v.approveSign(f, req, 600, 5)
	if _, st := v.sign(v.agent, grant, a); st != 200 {
		t.Fatalf("sign before the delete: %d", st)
	}
	pending, st := v.askSign(v.other, f, 0, 0, a)
	mustStatus(t, "pending request", st, 200)

	out := v.delete(id, "release-key", "Release key", "signer", 0, fp)
	if out.Ended != (store.Ended{Grants: 1, Pending: 1}) {
		t.Fatalf("ended: %+v", out.Ended)
	}
	if _, st := v.sign(v.agent, grant, a); st != 404 {
		t.Fatalf("signed with a deleted key: %d", st)
	}
	for _, p := range []string{"/v2/sign/key?path=" + f.path, "/v2/sign/requests/" + pending.ID, "/v2/sign/grants/" + grant} {
		if st := v.host(v.agent, "GET", p, nil, nil); st != 404 {
			t.Fatalf("%s after the delete: %d", p, st)
		}
	}
	if open := openBuckets(t, v.s); len(open) != 0 {
		t.Fatalf("the deleted signer's bucket is still open: %v", open)
	}
	s := v.binState()
	if len(s.Requests) != 0 || len(s.Deleted) != 1 || s.Deleted[0].Kind != "signer" {
		t.Fatalf("state after the delete: %+v", s)
	}
	if !v.audited("vault_delete", "fingerprint="+fp) {
		t.Fatal("the audit row does not name the key")
	}

	r, st := v.binChallenge("restore", id)
	mustStatus(t, "restore challenge", st, 200)
	mustStatus(t, "restore", v.tap(r, nil), 200)
	if _, st := v.sign(v.agent, grant, a); st == 200 {
		t.Fatal("a grant came back with the restore")
	}
	req, st = v.askSign(v.agent, f, 0, 0, a)
	mustStatus(t, "request after restore", st, 200)
	signed, st := v.sign(v.agent, v.approveSign(f, req, 0, 1), a)
	if st != 200 || !f.scheme.Verify(f.pub, a, signed.Signatures[0].Signature) {
		t.Fatalf("the restored key does not sign as before: %d", st)
	}
}

// Purge destroys the sealed records and the bucket, by a tap ("Purge now") or
// by itself seven days after the delete, with no bucket open and no key. The
// audit log keeps path, kind, who, when and the digest.
func TestVaultPurge(t *testing.T) {
	v := newVault(t)
	const first, second, value = secretID, "99999999999999999999999999999999", "tskey-purge-sentinel-58"
	v.createSecret(first, "tailnet", "Tailnet API key", "TAILNET_API_KEY", value, "", "")
	v.createSecret(second, "registry", "Registry token", "REGISTRY_TOKEN", "another-"+value, "", "")
	f := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", "")
	var ciphertext []byte
	requireNoError(t, v.s.store.DB().QueryRow(`SELECT payload FROM env_revisions WHERE set_id=?`, first).Scan(&ciphertext))
	if len(ciphertext) < 64 {
		t.Fatal("no sealed record to follow")
	}
	inFiles := func() bool {
		for _, name := range []string{"aqmas.db", "aqmas.db-wal"} {
			if b, err := os.ReadFile(filepath.Join(v.cfg.DataDir, name)); err == nil && bytes.Contains(b, ciphertext[len(ciphertext)-48:]) {
				return true
			}
		}
		return false
	}
	if !inFiles() {
		t.Fatal("the sealed record is not where the test looks for it")
	}
	rows := func(set string) int {
		n := 0
		for _, q := range []string{
			`SELECT count(*) FROM env_revisions WHERE set_id=?`, `SELECT count(*) FROM buckets WHERE ref=?`, `SELECT count(*) FROM secret_sets WHERE set_id=?`,
			`SELECT count(*) FROM signer_keys WHERE set_id=?`, `SELECT count(*) FROM credential_sets WHERE id=?`, `SELECT count(*) FROM deleted_sets WHERE set_id=?`,
			`SELECT count(*) FROM env_releases WHERE set_id=?`, `SELECT count(*) FROM sign_requests WHERE set_id=?`, `SELECT count(*) FROM env_standing WHERE set_id=?`,
		} {
			n += v.count(q, set)
		}
		return n
	}

	// A live item cannot be purged: delete comes first.
	if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "purge", "id": first}, nil); st != 404 {
		t.Fatalf("purge of a live set: %d", st)
	}
	rel, st := v.ask(v.agent, "client-a/paas/tailnet", "process")
	mustStatus(t, "request", st, 200)
	v.deliverWith(v.agent, rel, 3600)
	v.delete(first, "tailnet", "Tailnet API key", "secret", 1, "")
	digest := v.binState().Deleted[0].Digest

	// Purge now: one tap over the path and the digest.
	purge, st := v.binChallenge("purge", first)
	mustStatus(t, "purge challenge", st, 200)
	mustStatus(t, "purge", v.tap(purge, nil), 200)
	if n := rows(first); n != 0 {
		t.Fatalf("%d rows of the purged secret are left", n)
	}
	if inFiles() {
		t.Fatal("the purged secret's sealed record is still in the store files")
	}
	if !v.audited("vault_purge", "client-a/paas/tailnet kind=secret digest="+digest) {
		t.Fatal("purge not audited with path, kind and digest")
	}
	if s := v.binState(); len(s.Deleted) != 0 {
		t.Fatalf("bin after purge: %+v", s.Deleted)
	}
	for _, action := range []string{"restore", "purge"} {
		if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": action, "id": first}, nil); st != 404 {
			t.Fatalf("%s after purge: %d", action, st)
		}
	}
	if st := v.tap(purge, nil); st == 200 {
		t.Fatal("a purge tap was replayed")
	}
	if where := v.leaked([]byte(value)); where != "" && where != "responses" {
		t.Fatalf("the purged value appears in %s", where)
	}

	// Automatic: seven days after the delete, with every bucket closed.
	v.delete(second, "registry", "Registry token", "secret", 1, "")
	v.clock.Advance(24 * time.Hour)
	v.login() // the session is eight hours long
	v.delete(f.id, "release-key", "Release key", "signer", 0, signer.Fingerprint(f.pub))
	v.lock()
	v.clock.Advance(6*24*time.Hour - time.Minute)
	v.login()
	v.s.purgeDue(t.Context())
	if s := v.binState(); len(s.Deleted) != 2 {
		t.Fatalf("purged before the seven days were over: %+v", s.Deleted)
	}
	v.clock.Advance(2 * time.Minute)
	v.login()
	// A restore that is asked for after the deadline is refused even before the sweep.
	if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "restore", "id": second}, nil); st != 409 {
		t.Fatalf("restore after the seven days: %d", st)
	}
	v.s.purgeDue(t.Context())
	if n := rows(second); n != 0 {
		t.Fatalf("%d rows of the auto-purged secret are left", n)
	}
	if s := v.binState(); len(s.Deleted) != 1 || s.Deleted[0].SetID != f.id {
		t.Fatalf("bin after the first automatic purge: %+v", s.Deleted)
	}
	if n := v.count(`SELECT count(*) FROM audit WHERE actor='system' AND action='vault_purge' AND detail LIKE 'auto client-a/paas/registry kind=secret digest=%'`); n != 1 {
		t.Fatalf("automatic purge audited %d times", n)
	}
	// The signer was deleted a day later: it goes a day later, on the Vault's own read.
	v.clock.Advance(24 * time.Hour)
	v.login()
	if s := v.binState(); len(s.Deleted) != 0 {
		t.Fatalf("the bin lists an item whose time is over: %+v", s.Deleted)
	}
	if n := rows(f.id); n != 0 {
		t.Fatalf("%d rows of the auto-purged signer are left", n)
	}
	// The path of a purged item is free like any other.
	v.createSecret(first, "tailnet", "Tailnet API key", "TAILNET_API_KEY", value, "", "")
}
