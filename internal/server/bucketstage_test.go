//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server/cfproxy"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// Staging tests (docs/BUCKETS.md §8, §10): a genuine format-1 store is built
// with the format-1 primitives v0.4.1 used, then moved to buckets through the
// staging page exactly as the browser drives it.

const (
	sentinelValue  = "SENTINEL-env-value\nsecond line\twith tab"
	sentinelSecond = "SENTINEL-other-value"
	sentinelTopic  = "https://ntfy.example.com/SENTINELnoticeTOPIC01"
)

// v041DDL is format 1's seal schema (git show v0.4.1:internal/server/sealdb.go).
const v041DDL = `CREATE TABLE seal_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1), manifest TEXT NOT NULL, inventory BLOB NOT NULL, canonical TEXT NOT NULL, assertion BLOB NOT NULL) STRICT;
CREATE TABLE seal_wraps(passkey INTEGER PRIMARY KEY REFERENCES passkeys(id) ON DELETE CASCADE, salt BLOB NOT NULL UNIQUE CHECK(length(salt)=32), wrap BLOB NOT NULL CHECK(length(wrap)=73), generation INTEGER NOT NULL, tested_at INTEGER NOT NULL) STRICT;
CREATE TRIGGER seal_keep_unlock BEFORE DELETE ON passkeys WHEN EXISTS(SELECT 1 FROM seal_wraps WHERE passkey=OLD.id) AND (SELECT count(*) FROM seal_wraps)<=1 BEGIN SELECT RAISE(ABORT,'last tested unlock credential'); END;
DROP TRIGGER IF EXISTS signer_key_immutable;
CREATE TRIGGER signer_key_immutable BEFORE UPDATE OF set_id,scheme,public_key,origin,blob,payload,wrap ON signer_keys BEGIN SELECT RAISE(ABORT,'immutable signer key'); END;`

// f1 is what the test knows about the format-1 store it built.
type f1 struct {
	inst       seal.ID
	identity   *age.X25519Identity
	recipient  string
	secret     []byte // the owner passkey's software PRF
	spare      *vauth.Authenticator
	entries    []envset.Entry
	signers    map[string][]byte // set → private key
	cas        map[string][]byte // role → PEM
	ciphertext [][]byte          // format-1 ciphertexts that must not survive
	manifest   string
}

// legacyKEK is this test's format-1 KEK of a passkey: any 32 bytes the page would
// derive from the PRF at the format-1 salt.
func legacyKEK(secret []byte, salt seal.ID) []byte {
	h := sha256.Sum256(append(append([]byte("v041-kek"), secret...), salt[:]...))
	return h[:]
}

const (
	signEd, signEC = "dddddddddddddddddddddddddddddddd", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

// newFormat1 builds a v0.4.1 sealed store (schema 8): CAs, the Cloudflare
// proxy and minter parents and the ntfy topic in the inventory, a live env
// revision with multi-line values (an older nulled one and a draft too), an
// Ed25519 and an ECDSA signer, unlock wraps for two passkeys.
func newFormat1(t *testing.T) (*vaultEnv, *f1) {
	t.Helper()
	ctx := t.Context()
	logs := &syncBuffer{}
	cfg := cfConfig(t, true)
	e := newEnvWith(t, cfg, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		o.newCFProxy = func(cfproxy.Options) (cfProxy, error) { return &fakeProxy{}, nil }
	})
	e.setupOwner()
	spare := vauth.New(testBase)
	e.addPasskey(spare, "spare")
	a, b := e.enrollHost("workload"), e.enrollHost("other")
	organise(t, e)
	s := e.s
	db := s.store.DB()
	for _, q := range []string{
		`INSERT INTO organisations(id,slug,title,revision) VALUES('` + vOrg + `','client-a','Client A',1)`,
		`INSERT INTO org_policies VALUES('` + vOrg + `',1,3600,86400,1,3600,86400,1)`,
		`INSERT INTO org_approvers SELECT '` + vOrg + `',id,'approver',1 FROM people WHERE owner=1`,
		`INSERT INTO services(id,org_id,slug,title,provider,revision) VALUES('` + vService + `','` + vOrg + `','paas','PaaS','application',1)`,
		`INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES('` + vSet + `','` + vService + `','application','staging','Staging env','env-set',2)`,
		`INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES('` + signEd + `','` + vService + `','application','release-ed','Release Ed25519','env-set',0)`,
		`INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES('` + signEC + `','` + vService + `','application','release-ec','Release ECDSA','env-set',0)`,
		`INSERT INTO org_hosts SELECT '` + vOrg + `',id,1,1 FROM hosts`,
	} {
		_, err := db.Exec(q)
		requireNoError(t, err)
	}
	requireNoError(t, s.store.InitEnv(ctx))
	requireNoError(t, s.store.InitVault(ctx))
	_, err := db.Exec(v041DDL)
	requireNoError(t, err)

	f := &f1{secret: []byte("owner-prf-secret-0123456789abcdef"), spare: spare, signers: map[string][]byte{}, cas: map[string][]byte{}}
	f.identity, err = age.GenerateX25519Identity()
	requireNoError(t, err)
	f.recipient = f.identity.Recipient().String()
	f.inst = seal.RandomID()
	g := seal.Generation{Installation: f.inst, Version: 1}
	mk, err := seal.RandomKey()
	requireNoError(t, err)
	defer mk.Destroy()
	inv := seal.Inventory{Generation: g, Recipient: f.recipient, ConfigHash: s.profileRevision, SSHCA: s.sshPin(), InternalCA: s.pki.CAPin()}
	inv.Check, err = g.CheckRecord(mk)
	requireNoError(t, err)
	inv.Recovery, err = g.RecoveryPacket(f.recipient, mk)
	requireNoError(t, err)
	add := func(o seal.Object, b []byte) { o.Blob = seal.RandomID(); requireNoError(t, inv.Add(mk, o, b)) }
	for _, ca := range []struct{ role, file string }{{seal.RoleSSHCA, pki.SSHCAKeyFile}, {seal.RoleInternalCA, pki.ClientCAKeyFile}} {
		path := filepath.Join(CADir(cfg.DataDir), ca.file)
		pem, err := os.ReadFile(path)
		requireNoError(t, err)
		f.cas[ca.role] = pem
		add(seal.Object{Role: ca.role, Global: ca.role, Revision: 1}, pem)
		requireNoError(t, os.Remove(path))
	}
	add(seal.Object{Role: "ntfy-topic", Global: "approval-notices", Revision: 1}, []byte(sentinelTopic))
	org, service, set, err := s.cfProxyBinding(ctx)
	requireNoError(t, err)
	for _, p := range []struct{ role, tok string }{{"cf-proxy", testProxyToken}, {"cf-minter", testMinterToken}} {
		add(seal.Object{Role: p.role, Org: org, Service: service, Set: set, Revision: 1, Issuer: "https://api.cloudflare.com/client/v4", Account: testAcct, ParentVersion: 1}, []byte(p.tok))
	}
	requireNoError(t, os.Remove(cfg.Cloudflare.ProxyTokenFile))
	requireNoError(t, os.Remove(cfg.Cloudflare.MinterTokenFile))
	for _, r := range inv.Records {
		f.ciphertext = append(f.ciphertext, r.Payload, r.WrappedDEK)
	}

	// The live env revision (2) and the nulled older one (1), as ReplaceEnv left them.
	f.entries = []envset.Entry{{Name: "APP_TOKEN", Value: sentinelValue}, {Name: "OTHER_SECRET", Value: sentinelSecond}}
	names, _ := json.Marshal(envset.Names(f.entries))
	plain, _ := json.Marshal(f.entries)
	blob := seal.RandomID()
	env, err := seal.Object{Org: vOrg, Service: vService, Set: vSet, Role: "env-revision", Revision: 2, Blob: blob}.Encrypt(g, mk, plain)
	requireNoError(t, err)
	old := seal.RandomID()
	_, err = db.Exec(`INSERT INTO env_revisions VALUES(?,1,'["APP_TOKEN"]',?,NULL,NULL),(?,2,?,?,?,?)`, vSet, old[:], vSet, string(names), blob[:], env.Payload, env.WrappedDEK)
	requireNoError(t, err)
	draft, err := seal.Object{Org: vOrg, Service: vService, Set: vSet, Role: "env-draft", Revision: 3, Blob: seal.RandomID()}.Encrypt(g, mk, []byte(`{"op":"merge"}`))
	requireNoError(t, err)
	draftBlob := seal.RandomID()
	_, err = db.Exec(`INSERT INTO env_drafts SELECT 'draft-1',?,id,?,?,NULL,'{}',?,?,? FROM hosts LIMIT 1`, mustSessionHash(e), vSet, s.now().Add(time.Hour).UnixMilli(), draftBlob[:], draft.Payload, draft.WrappedDEK)
	requireNoError(t, err)
	f.ciphertext = append(f.ciphertext, env.Payload, env.WrappedDEK, draft.Payload)

	for set, scheme := range map[string]string{signEd: "ed25519", signEC: "ecdsa-p256-sha256"} {
		sc, _ := signer.Lookup(scheme)
		priv, pub, err := sc.Generate()
		requireNoError(t, err)
		f.signers[set] = priv
		plain, _ := json.Marshal(signerSecret{Scheme: scheme, Private: priv})
		blob := seal.RandomID()
		e, err := seal.Object{Org: vOrg, Service: vService, Set: set, Role: "signer-key", Revision: 1, Blob: blob}.Encrypt(g, mk, plain)
		requireNoError(t, err)
		_, err = db.Exec(`INSERT INTO signer_keys(set_id,scheme,public_key,origin,created,blob,payload,wrap) VALUES(?,?,?,'generated',?,?,?,?)`, set, scheme, pub, s.now().UnixMilli(), blob[:], e.Payload, e.WrappedDEK)
		requireNoError(t, err)
		f.ciphertext = append(f.ciphertext, e.Payload, e.WrappedDEK)
	}

	// Unlock wraps for both passkeys under the format-1 KEK.
	keys, err := loadPasskeys(ctx, s.store.Q())
	requireNoError(t, err)
	var wraps []seal.WrappedCredential
	for _, k := range keys {
		secret := f.secret
		if bytes.Equal(k.CredentialID, spare.CredID) {
			secret = []byte("spare-prf-secret")
		}
		c := seal.Credential{Generation: g, RPID: s.rpID, RawID: k.CredentialID, Salt: seal.RandomID()}
		kek, err := seal.ImportKEK(legacyKEK(secret, c.Salt))
		requireNoError(t, err)
		w, err := c.Wrap(kek, mk)
		kek.Destroy()
		requireNoError(t, err)
		_, err = db.Exec(`INSERT INTO seal_wraps VALUES(?,?,?,1,?)`, k.ID, c.Salt[:], w, s.now().UnixMilli())
		requireNoError(t, err)
		wraps = append(wraps, seal.WrappedCredential{Credential: c, Wrapped: w, Passkey: k.ID, Tested: true})
		f.ciphertext = append(f.ciphertext, w)
	}
	m, err := inv.Manifest(wraps)
	requireNoError(t, err)
	mb, _ := json.Marshal(m)
	ib, _ := json.Marshal(inv)
	f.manifest = string(mb)
	_, err = db.Exec(`INSERT INTO seal_active VALUES(1,?,?,'{"v":3}',x'00');PRAGMA user_version=8`, string(mb), ib)
	requireNoError(t, err)
	f.ciphertext = append(f.ciphertext, inv.Check, inv.Recovery)
	e.cfg.Seal = config.Seal{Required: true, Recipient: f.recipient, Manifest: seal.Digest(mb)}
	v := &vaultEnv{env: e, logs: logs, org: vOrg, service: vService, set: vSet, agent: e.agentClient(&a), other: e.agentClient(&b)}
	return v, f
}

// startMode closes the broker and starts it again with opts on the same data directory.
func (v *vaultEnv) startMode(opts Options) {
	v.t.Helper()
	e := v.env
	e.agent.Close()
	e.web.Close()
	e.s.Close()
	opts.Config, opts.Now = e.cfg, e.clock.Now
	opts.Logger = slog.New(slog.NewTextHandler(v.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts.newCFProxy = func(cfproxy.Options) (cfProxy, error) { return &fakeProxy{}, nil }
	s, err := New(opts)
	requireNoError(v.t, err)
	e.s = s
	if s.sealSetup {
		requireNoError(v.t, s.newStage())
		e.agent = httptest.NewUnstartedServer(http.NotFoundHandler())
	} else {
		e.agent = httptest.NewUnstartedServer(s.AgentHandler())
		e.agent.TLS = s.PKI().TLSConfig()
		e.agent.StartTLS()
	}
	e.web = httptest.NewServer(s.WebHandler())
	v.t.Cleanup(func() { s.Close() })
}

type stageStatusResp struct {
	Mode         string     `json:"mode"`
	Installation string     `json:"installation"`
	Epoch        string     `json:"epoch"`
	Stage        *stageView `json:"stage"`
}

func (v *vaultEnv) stageState() stageStatusResp {
	v.t.Helper()
	var st stageStatusResp
	mustStatus(v.t, "status", v.web("GET", "/api/ui/seal/status", nil, &st), 200)
	return st
}

// stageStep runs one staging tap as the page does: check the descriptor, evaluate the PRF
// at its inputs, derive the KEKs and seal them to the descriptor's recipient.
func (v *vaultEnv) stageStep(a *vauth.Authenticator, secret []byte, step string, scopes []string) int {
	v.t.Helper()
	st := v.stageState()
	var choice *stageChoice
	for i, c := range st.Stage.Choices {
		if c.Credential == encodeID(a.CredID) {
			choice = &st.Stage.Choices[i]
		}
	}
	if choice == nil {
		v.t.Fatalf("no choice for this passkey (step %s)", step)
	}
	var r tapResp
	if code := v.web("POST", "/api/ui/seal/stage/challenge", map[string]any{"step": step, "credential": choice.ID, "scopes": scopes}, &r); code != 200 {
		return code
	}
	if r.Open == nil {
		v.t.Fatal("no descriptor")
	}
	var d struct {
		descriptor
		Legacy *legacyView `json:"legacy"`
	}
	requireNoError(v.t, json.Unmarshal([]byte(r.Open.Descriptor), &d))
	if d.Object != "scope-enrol" || d.Purpose != stagePurpose[step] || !slices.Equal(d.Scopes, scopes) || d.Credential != encodeID(a.CredID) || (step == "open-legacy") != (d.Legacy != nil) {
		v.t.Fatalf("descriptor %s", r.Open.Descriptor)
	}
	var c map[string]any
	requireNoError(v.t, json.Unmarshal([]byte(r.Canonical), &c))
	if len(c) != 9 || c["object"] != "seal-stage" || c["action"] != step || c["credential"] != choice.ID || c["id"] != st.Installation || c["epoch"] != st.Epoch {
		v.t.Fatalf("canonical %s", r.Canonical)
	}
	challenge := seal.OpenChallenge([]byte(r.Canonical), []byte(r.Open.Descriptor))
	var inst seal.ID
	requireNoError(v.t, inst.UnmarshalText([]byte(d.Installation)))
	var frames [][]byte
	if d.Legacy != nil {
		var salt seal.ID
		requireNoError(v.t, salt.UnmarshalText([]byte(d.Legacy.PRFSalt)))
		frames = append(frames, legacyKEK(secret, salt))
	}
	for i, sc := range d.Scopes {
		var salt seal.ID
		requireNoError(v.t, salt.UnmarshalText([]byte(d.Salts[i])))
		kek, err := seal.PasskeyScope{Installation: inst, RPID: v.s.rpID, RawID: a.CredID, Scope: sc, Salt: salt}.DeriveKEK(prfOut(secret, salt[:]))
		requireNoError(v.t, err)
		frames = append(frames, bytes.Clone(kek.Bytes()))
		kek.Destroy()
	}
	if len(frames) == 1 {
		frames = append(frames, nil)
	}
	var at, ep seal.ID
	requireNoError(v.t, at.UnmarshalText([]byte(d.Attempt)))
	requireNoError(v.t, ep.UnmarshalText([]byte(d.Epoch)))
	pub, _ := b64url(d.Recipient)
	enc, ct, err := seal.SealTo(pub, seal.OpenInfo(inst, d.Purpose), seal.OpenAAD(at, ep, challenge, a.CredID), seal.Frames(frames...))
	requireNoError(v.t, err)
	return v.web("POST", "/api/ui/seal/stage/finish", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: a.Assert(challenge), Open: &api.OpenPacket{AttemptID: d.Attempt, Enc: encodeID(enc), Ciphertext: encodeID(ct)}}, nil)
}

func (v *vaultEnv) stageDrill(identity string) int {
	v.t.Helper()
	st := v.stageState()
	var inst seal.ID
	requireNoError(v.t, inst.UnmarshalText([]byte(st.Installation)))
	packet, err := maint.SealPacket(st.Stage.DrillKey, DrillInfo(inst), []byte(identity+"\n"))
	requireNoError(v.t, err)
	return v.web("POST", "/api/ui/seal/drill", map[string]string{"packet": packet}, nil)
}

// stageAll creates and tests every scope (two per tap) and runs the drill.
func (v *vaultEnv) stageAll(f *f1) {
	v.t.Helper()
	for _, step := range []string{"create", "test"} {
		for {
			var todo []string
			for _, sc := range v.stageState().Stage.Scopes {
				if step == "create" && !sc.Wrapped || step == "test" && !sc.Tested {
					todo = append(todo, sc.Scope)
				}
			}
			if len(todo) == 0 {
				break
			}
			if len(todo) > 2 {
				todo = todo[:2]
			}
			mustStatus(v.t, step, v.stageStep(v.auth, f.secret, step, todo), 200)
		}
	}
	mustStatus(v.t, "drill", v.stageDrill(f.identity.String()), 200)
}

// activate signs the manifest the status shows (a plain signature) and returns it.
func (v *vaultEnv) activate() string {
	v.t.Helper()
	st := v.stageState()
	if st.Stage.Manifest == "" {
		v.t.Fatal("no manifest to activate")
	}
	var r tapResp
	mustStatus(v.t, "activate challenge", v.web("POST", "/api/ui/seal/control/challenge", map[string]any{"action": "activate"}, &r), 200)
	var c map[string]any
	requireNoError(v.t, json.Unmarshal([]byte(r.Canonical), &c))
	if r.Open != nil || len(c) != 8 || c["manifest"] != st.Stage.Manifest || c["object"] != "seal-control" || c["action"] != "activate" {
		v.t.Fatalf("activation canonical %s", r.Canonical)
	}
	mustStatus(v.t, "activate", v.web("POST", "/api/ui/seal/control/finish", api.DecideRequest{ChallengeID: r.ChallengeID, Assertion: v.auth.Assert(sha256Bytes(r.Canonical))}, nil), 200)
	select {
	case <-v.s.seal.stop:
	case <-time.After(10 * time.Second):
		v.t.Fatal("the process was not told to exit")
	}
	return st.Stage.Manifest
}

// sealedTables is a logical dump of everything activation would change.
func sealedTables(t *testing.T, db *sql.DB) string {
	t.Helper()
	var b strings.Builder
	var ver int
	requireNoError(t, db.QueryRow(`PRAGMA user_version`).Scan(&ver))
	fmt.Fprintln(&b, "version", ver)
	for _, q := range []string{`SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY name`, `SELECT manifest,inventory FROM seal_active`, `SELECT passkey,salt,wrap FROM seal_wraps ORDER BY passkey`,
		`SELECT set_id,revision,names,blob,payload,wrap FROM env_revisions ORDER BY set_id,revision`, `SELECT id,payload,wrap FROM env_drafts ORDER BY id`, `SELECT set_id,payload,wrap FROM signer_keys ORDER BY set_id`} {
		rows, err := db.Query(q)
		requireNoError(t, err)
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			requireNoError(t, rows.Scan(ptrs...))
			fmt.Fprintf(&b, "%x\n", fmt.Sprint(vals...))
		}
		rows.Close()
	}
	return b.String()
}

// openAll opens every bucket of the store with the recovery key and returns the plaintext
// of every record by kind:ref (env entries by name).
func openAll(t *testing.T, s *Server, inst seal.ID, id *age.X25519Identity, recipient string) map[string]string {
	t.Helper()
	ctx := t.Context()
	q := s.store.Q()
	out := map[string]string{}
	scopes, err := q.Scopes(ctx)
	requireNoError(t, err)
	for _, x := range scopes {
		k, err := seal.Scope{Installation: inst, Name: x.Scope, Public: x.Public}.Recover(id, recipient, x.Recovery)
		requireNoError(t, err)
		rows, err := q.ScopeBuckets(ctx, x.Scope)
		requireNoError(t, err)
		for _, row := range rows {
			b := seal.Bucket{Installation: inst, ID: bucketSealID(row), Scope: row.Scope, Kind: row.Kind, Public: row.Public}
			bk, err := b.UnwrapWith(k, x.Public, row.Wrap)
			requireNoError(t, err)
			open := func(role string, fields [][]byte, rec []byte) string {
				p, err := b.Open(bk, role, fields, rec)
				requireNoError(t, err)
				return string(p)
			}
			switch row.Kind {
			case seal.RoleSSHCA, seal.RoleInternalCA:
				out[row.Kind] = open(row.Kind, nil, row.Payload)
			case seal.RoleCFProxy:
				out[row.Kind] = open(row.Kind, s.cfRecordFields(row), row.Payload)
			case "env-set":
				rev, err := q.SetRevision(ctx, row.Ref)
				requireNoError(t, err)
				c, err := q.EnvCipher(ctx, row.Ref, rev)
				requireNoError(t, err)
				recs, err := parseRecords(c.Payload, true)
				requireNoError(t, err)
				entries, err := openEntries(b, bk, row.Ref, recs)
				requireNoError(t, err)
				for _, e := range entries {
					out["env:"+e.Name] = e.Value
				}
			case "signer":
				scheme, public, rec, err := q.SignerKey(ctx, row.Ref)
				requireNoError(t, err)
				out["signer:"+row.Ref] = open(seal.RoleSignerKey, signerFields(store.VaultTarget{SetID: row.Ref, Scheme: scheme, PublicKey: public}), rec.Payload)
			}
			bk.Destroy()
		}
		k.Destroy()
	}
	return out
}

// noSentinels fails if a value, key, identity or token appears in b.
func noSentinels(t *testing.T, where string, b []byte, f *f1, allowTopic bool) {
	t.Helper()
	needles := map[string][]byte{"env value": []byte("SENTINEL-env-value"), "env value 2": []byte(sentinelSecond), "proxy token": []byte(testProxyToken), "minter token": []byte(testMinterToken), "identity": []byte(f.identity.String())}
	if !allowTopic {
		needles["topic"] = []byte("SENTINELnoticeTOPIC")
	}
	for set, k := range f.signers {
		needles["signer "+set[:4]] = k
		needles["signer b64 "+set[:4]] = []byte(encodeID(k))
	}
	for role, pem := range f.cas {
		needles[role] = pem[40:80]
	}
	for name, n := range needles {
		if bytes.Contains(b, n) {
			t.Errorf("%s leaked into %s", name, where)
		}
	}
}

func readAll(t *testing.T, paths ...string) []byte {
	var out []byte
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			out = append(out, b...)
		}
	}
	return out
}

func TestBucketMigration(t *testing.T) {
	v, f := newFormat1(t)
	ctx := t.Context()
	dbPath := DBPath(v.cfg.DataDir)
	_, err := v.s.store.DB().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	requireNoError(t, err)

	// The format-1 store in plain serve mode: migration required, nothing secret served.
	v.startMode(Options{})
	if st := v.stageState(); st.Mode != modeMigration || st.Stage != nil {
		t.Fatalf("serve on format 1: %+v", st)
	}
	var setup setupView
	mustStatus(t, "setup", v.web("GET", "/api/ui/setup", nil, &setup), 200)
	for _, task := range setup.Tasks {
		if task.ID == maint.TaskBuckets && (task.State == "done" || task.Settled || strings.Contains(task.Blocked, "Only") || strings.Contains(task.Blocked, "Not needed")) {
			t.Fatalf("buckets task %+v", task)
		}
	}
	v.s.store.DB().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	v.s.Close()

	// Starting the stage and stopping it again changes nothing in the file.
	before := readAll(t, dbPath)
	v.startMode(Options{BucketMigrate: true})
	v.s.Close()
	if after := readAll(t, dbPath); !bytes.Equal(before, after) {
		t.Fatal("starting and abandoning the stage changed the database file")
	}

	// A stage taken through every tap and the drill, then abandoned (process killed before
	// activation), leaves every sealed table as it was.
	v.startMode(Options{BucketMigrate: true})
	logical := sealedTables(t, v.s.store.DB())
	st := v.stageState()
	if st.Mode != modeSetup || st.Stage == nil || st.Stage.Source != "format-1" || st.Stage.LegacyUnlocked || len(st.Stage.Choices) != 2 || st.Stage.Choices[0].Legacy == nil {
		t.Fatalf("stage %+v", st.Stage)
	}
	if code := v.stageStep(v.auth, f.secret, "create", []string{seal.ScopeInstallation}); code != 409 {
		t.Fatalf("create before the old store was opened: %d", code)
	}
	if code := v.stageStep(v.auth, []byte("wrong"), "open-legacy", []string{seal.ScopeInstallation}); code/100 != 4 {
		t.Fatalf("a wrong format-1 KEK opened the store: %d", code)
	}
	mustStatus(t, "open-legacy", v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}), 200)
	// Once the ceremony passkey is fixed no other passkey joins the stage.
	if code := v.web("POST", "/api/ui/seal/stage/challenge", map[string]any{"step": "create", "credential": passkeyID(f.spare.CredID), "scopes": []string{vOrg}}, nil); code != 409 {
		t.Fatalf("a second passkey joined the stage: %d", code)
	}
	v.stageAll(f)
	if st := v.stageState(); st.Stage.Manifest == "" || !st.Stage.LegacyUnlocked || !st.Stage.Drilled {
		t.Fatalf("not ready: %+v", st.Stage)
	}
	if got := sealedTables(t, v.s.store.DB()); got != logical {
		t.Fatal("staging changed the sealed tables before activation")
	}
	v.s.Close()

	// A fresh stage after the interruption runs to activation.
	v.startMode(Options{BucketMigrate: true})
	mustStatus(t, "open-legacy", v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}), 200)
	if code := v.web("POST", "/api/ui/seal/control/challenge", map[string]any{"action": "activate"}, nil); code != 409 {
		t.Fatalf("activation before every scope is tested and drilled: %d", code)
	}
	wrongID, _ := age.GenerateX25519Identity()
	if code := v.stageDrill(wrongID.String()); code != 409 {
		t.Fatalf("a wrong identity passed the drill: %d", code)
	}
	v.stageAll(f)
	manifest := v.activate()
	if st := v.stageState(); st.Mode != modeActivated {
		t.Fatalf("mode after activation %q", st.Mode)
	}
	var m BucketManifest
	requireNoError(t, json.Unmarshal([]byte(manifest), &m))
	if m.Format != 2 || m.Installation != f.inst || len(m.Scopes) != 3 || len(m.Buckets) != 6 || len(m.ApproveOnly) != 1 || m.ApproveOnly[0] != encodeID(f.spare.CredID) || !slices.Equal(m.Dropped, []string{"cf-minter"}) || len(m.Passkeys) != 3 {
		t.Fatalf("manifest %s", manifest)
	}
	stage, _ := filepath.Glob(filepath.Join(v.cfg.DataDir, "seal-stage-*", "manifest.json"))
	if len(stage) != 1 || string(readAll(t, stage[0])) != manifest {
		t.Fatal("manifest.json for the runner missing")
	}
	v.s.Close()

	// Nothing of format 1 remains, in the file or its WAL.
	raw := readAll(t, dbPath, dbPath+"-wal")
	for i, c := range f.ciphertext {
		if bytes.Contains(raw, c[len(c)-24:]) {
			t.Errorf("format-1 ciphertext %d survives in the database file", i)
		}
	}
	noSentinels(t, "database", raw, f, true)

	// Pinned and restarted: the normal format-2 boot path.
	v.cfg.Seal.Manifest = seal.Digest([]byte(manifest))
	v.startMode(Options{})
	db := v.s.store.DB()
	var ver, n int
	requireNoError(t, db.QueryRow(`PRAGMA user_version`).Scan(&ver))
	if ver != store.SchemaBuckets {
		t.Fatal("schema", ver)
	}
	for _, q := range []string{`SELECT count(*) FROM sqlite_schema WHERE name IN ('seal_wraps','seal_keep_unlock')`, `SELECT count(*) FROM env_drafts`, `SELECT count(*) FROM env_revisions WHERE set_id='` + vSet + `' AND revision!=2`} {
		requireNoError(t, db.QueryRow(q).Scan(&n))
		if n != 0 {
			t.Fatalf("%s: %d", q, n)
		}
	}
	if topic, _ := v.s.store.Q().NoticeTopic(ctx); topic != sentinelTopic || v.s.notify.TopicURL != sentinelTopic {
		t.Fatal("notice channel not carried over")
	}
	// Migrated and serving: organisations, sealing and buckets are folded away as finished.
	setup = setupView{}
	mustStatus(t, "setup after", v.web("GET", "/api/ui/setup", nil, &setup), 200)
	settled := map[string]bool{}
	for _, task := range setup.Tasks {
		settled[task.ID] = task.Settled
	}
	if !settled[maint.TaskCutover] || !settled[maint.TaskSeal] || !settled[maint.TaskBuckets] || settled[maint.TaskUpgrade] || settled[maint.TaskPins] {
		t.Fatalf("settled after migration: %v", settled)
	}
	got := openAll(t, v.s, f.inst, f.identity, f.recipient)
	want := map[string]string{seal.RoleSSHCA: string(f.cas[seal.RoleSSHCA]), seal.RoleInternalCA: string(f.cas[seal.RoleInternalCA]), seal.RoleCFProxy: testProxyToken, "env:APP_TOKEN": sentinelValue, "env:OTHER_SECRET": sentinelSecond}
	for set, k := range f.signers {
		sc := map[string]string{signEd: "ed25519", signEC: "ecdsa-p256-sha256"}[set]
		b, _ := json.Marshal(signerSecret{Scheme: sc, Private: k})
		want["signer:"+set] = string(b)
	}
	if len(got) != len(want) {
		t.Fatalf("opened %d records, want %d", len(got), len(want))
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s did not round-trip", k)
		}
	}

	// Through the normal paths: an SSH approval opens the CA, an env release the set.
	v.fix = &bucketFix{inst: f.inst, identity: f.identity, recipient: f.recipient, prf: map[string][]byte{string(v.auth.CredID): f.secret}}
	rc := ownerOnlySSH(t, v)
	mustStatus(t, "approve ssh", v.decideTap(v.auth, "/api/ui/requests/"+rc.ID, api.ChallengeRequest{Action: "approve", TTLSeconds: 300}), 200)
	if rs, _ := v.status(v.agent, rc.ID, ""); rs.Grant == nil || rs.Grant.SSH.Certificate == "" {
		t.Fatal("no certificate signed after the move")
	}
	beforeRelease := v.seen.Len() // the agent's collect carries the values, as it should
	rel := v.envRelease()
	mustStatus(t, "collect", v.collect(v.envApprove(rel)), 200)
	// The spare passkey is approve-only now: it holds no scope wrap.
	wraps, err := v.s.store.Q().ScopeWraps(ctx, 0)
	requireNoError(t, err)
	for _, w := range wraps {
		if bytes.Equal(w.RawID, f.spare.CredID) || w.Tested == nil {
			t.Fatal("unexpected or untested wrap after the move")
		}
	}

	// Offline drill on a standalone copy, without the configuration: counts only.
	backup := filepath.Join(t.TempDir(), "backup.db")
	_, err = db.Exec(`VACUUM INTO ?`, backup)
	requireNoError(t, err)
	sum := readAll(t, backup)
	out, err := DrillBackup(backup, f.recipient, []byte(f.identity.String()+"\n"), nil)
	requireNoError(t, err)
	if !strings.Contains(out, "scopes=3 buckets=6") || !strings.Contains(out, seal.Digest([]byte(manifest))) || !strings.Contains(out, "unchecked") {
		t.Fatal(out)
	}
	if out, err = DrillBackup(backup, f.recipient, []byte(f.identity.String()), &v.cfg.Cloudflare); err != nil || strings.Contains(out, "unchecked") {
		t.Fatal(out, err)
	}
	other, _ := age.GenerateX25519Identity()
	if _, err = DrillBackup(backup, f.recipient, []byte(other.String()), nil); err == nil {
		t.Fatal("another identity passed the offline drill")
	}
	if !bytes.Equal(sum, readAll(t, backup)) {
		t.Fatal("the offline drill wrote to the backup")
	}
	noSentinels(t, "drill output", []byte(out), f, false)

	// Sentinels: logs, every response, the manifest.
	noSentinels(t, "logs", []byte(v.logs.String()), f, false)
	noSentinels(t, "responses", v.seen.Bytes()[:beforeRelease], f, false)
	noSentinels(t, "manifest", []byte(manifest), f, false)
}

// A restored schema-8 store under the format-2 pin is refused, and migration is
// refused on schema 9.
func TestBucketMigrationFences(t *testing.T) {
	v, f := newFormat1(t)
	v.startMode(Options{BucketMigrate: true})
	mustStatus(t, "open-legacy", v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}), 200)
	v.stageAll(f)
	manifest := v.activate()
	v.s.Close()
	v.cfg.Seal.Manifest = seal.Digest([]byte(manifest))
	if _, err := New(Options{Config: v.cfg, BucketMigrate: true}); err == nil {
		t.Fatal("bucket-migrate started on schema 9")
	}
	if _, err := New(Options{Config: v.cfg, SealSetup: true}); err == nil {
		t.Fatal("seal-import started on schema 9")
	}
}

// Sealing an unsealed store produces format 2 directly.
func TestSealImportBuckets(t *testing.T) {
	logs := &syncBuffer{}
	cfg := cfConfig(t, true)
	e := newEnvWith(t, cfg, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		o.newCFProxy = func(cfproxy.Options) (cfProxy, error) { return &fakeProxy{}, nil }
	})
	e.setupOwner()
	organise(t, e)
	v := &vaultEnv{env: e, logs: logs}
	f := &f1{secret: []byte("owner-prf-secret-0123456789abcdef"), cas: map[string][]byte{}, signers: map[string][]byte{}}
	var err error
	f.identity, err = age.GenerateX25519Identity()
	requireNoError(t, err)
	f.recipient = f.identity.Recipient().String()
	for role, file := range map[string]string{seal.RoleSSHCA: pki.SSHCAKeyFile, seal.RoleInternalCA: pki.ClientCAKeyFile} {
		f.cas[role] = readAll(t, filepath.Join(CADir(cfg.DataDir), file))
	}
	cfg.Seal = config.Seal{Required: true, Recipient: f.recipient}
	cfg.Ntfy.TopicURL = sentinelTopic
	v.startMode(Options{SealSetup: true})
	st := v.stageState()
	if st.Stage == nil || st.Stage.Source != "unsealed" || len(st.Stage.Scopes) != 2 || !slices.Equal(st.Stage.Dropped, []string{"cf-minter"}) {
		t.Fatalf("stage %+v", st.Stage)
	}
	if code := v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}); code/100 != 4 {
		t.Fatal("open-legacy on an unsealed store", code)
	}
	v.stageAll(f)
	manifest := v.activate()
	v.s.Close()
	requireNoError(t, json.Unmarshal([]byte(manifest), new(BucketManifest)))
	// The runner retires the plaintext sources and the topic line, then pins.
	for _, p := range []string{filepath.Join(CADir(cfg.DataDir), pki.SSHCAKeyFile), filepath.Join(CADir(cfg.DataDir), pki.ClientCAKeyFile), cfg.Cloudflare.ProxyTokenFile, cfg.Cloudflare.MinterTokenFile} {
		requireNoError(t, os.Remove(p))
	}
	cfg.Ntfy.TopicURL = ""
	cfg.Seal.Manifest = seal.Digest([]byte(manifest))
	v.startMode(Options{})
	var m BucketManifest
	requireNoError(t, json.Unmarshal([]byte(manifest), &m))
	got := openAll(t, v.s, m.Installation, f.identity, f.recipient)
	if got[seal.RoleSSHCA] != string(f.cas[seal.RoleSSHCA]) || got[seal.RoleInternalCA] != string(f.cas[seal.RoleInternalCA]) || got[seal.RoleCFProxy] != testProxyToken || len(got) != 3 {
		t.Fatal("imported values do not open")
	}
	if topic, _ := v.s.store.Q().NoticeTopic(t.Context()); topic != sentinelTopic {
		t.Fatal("topic not in notice_channel")
	}
	noSentinels(t, "logs", []byte(logs.String()), f, true)
	noSentinels(t, "responses", v.seen.Bytes(), f, false)
}

// seal-recover: every scope key from the recovery key, a replacement passkey with wraps for
// all of them, the old passkeys retired.
func TestSealRecoverBuckets(t *testing.T) {
	v, f := newFormat1(t)
	v.startMode(Options{BucketMigrate: true})
	mustStatus(t, "open-legacy", v.stageStep(v.auth, f.secret, "open-legacy", []string{seal.ScopeInstallation}), 200)
	v.stageAll(f)
	manifest := v.activate()
	v.s.Close()
	v.cfg.Seal.Manifest = seal.Digest([]byte(manifest))
	v.startMode(Options{})
	// A host's proposal is waiting when the passkeys are lost.
	res, err := v.s.store.DB().Exec(`INSERT INTO env_proposals(id,host,org_id,service_id,set_id,service_slug,set_slug,new_service,new_set,expires,status,metadata,payload,wrap) SELECT 'waiting-proposal',(SELECT min(id) FROM hosts),?,?,?,'paas','staging',0,0,?,'pending','{}',x'5b5d',x'00' WHERE EXISTS(SELECT 1 FROM hosts)`, vOrg, vService, vSet, v.clock.Now().Add(time.Hour).UnixMilli())
	requireNoError(t, err)
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatal("no host to propose from")
	}
	// A standalone backup restored into a private directory.
	dir := t.TempDir()
	requireNoError(t, os.Mkdir(filepath.Join(dir, "ca"), 0700))
	for _, name := range []string{pki.SSHCAPubFile, pki.ClientCACrtFile} {
		b, err := os.ReadFile(filepath.Join(CADir(v.cfg.DataDir), name))
		requireNoError(t, err)
		requireNoError(t, os.WriteFile(filepath.Join(dir, "ca", name), b, 0600))
	}
	_, err = v.s.store.DB().Exec(`VACUUM INTO ?`, DBPath(dir))
	requireNoError(t, err)
	v.s.Close()
	cfg := *v.cfg
	cfg.DataDir = dir
	serial := int64(1000)
	cfg.Seal.RecoverySerial = &serial
	cfg.Seal.RecoveryBackupSHA256 = fmt.Sprintf("%x", sha256.Sum256(readAll(t, DBPath(dir))))
	s, err := New(Options{Config: &cfg, Recovery: true, Now: v.clock.Now, Logger: slog.New(slog.NewTextHandler(v.logs, nil))})
	requireNoError(t, err)
	defer s.Close()
	sock := filepath.Join(t.TempDir(), "rec")
	oldScopes, err := s.store.Q().Scopes(t.Context())
	requireNoError(t, err)
	oldBuckets, err := s.store.Q().Buckets(t.Context())
	requireNoError(t, err)
	values := openAll(t, s, f.inst, f.identity, f.recipient)
	done := make(chan error, 1)
	go func() { done <- s.Recover(t.Context(), sock, strings.NewReader(f.identity.String()+"\n")) }()
	var ticket []byte
	for i := 0; i < 200 && len(ticket) == 0; i++ {
		ticket, _ = os.ReadFile(filepath.Join(sock, "ticket"))
		time.Sleep(20 * time.Millisecond)
	}
	if len(ticket) == 0 {
		t.Fatal("no ticket")
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(sock, "broker.sock"))
	}}}
	var seen bytes.Buffer
	call := func(step, token string, body, out any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", "http://aqmas/recovery/"+step, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Aqmas", "1")
		req.Header.Set("Origin", testBase)
		req.Header.Set("X-Aqmas-Recovery", token)
		resp, err := client.Do(req)
		requireNoError(t, err)
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		seen.Write(rb)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", step, resp.StatusCode, rb)
		}
		if out != nil {
			requireNoError(t, json.Unmarshal(rb, out))
		}
	}
	var begin struct {
		PublicKey json.RawMessage `json:"public_key"`
		Session   string          `json:"session"`
		Scopes    []string        `json:"scopes"`
	}
	call("begin", string(ticket), map[string]string{"name": "replacement"}, &begin)
	if len(begin.Scopes) != 3 {
		t.Fatal("scopes", begin.Scopes)
	}
	repl := vauth.New(testBase)
	secret := []byte("replacement-prf-secret")
	cred, err := repl.Register(begin.PublicKey)
	requireNoError(t, err)
	call("create", begin.Session, map[string]any{"credential": cred}, nil)
	fix := &bucketFix{inst: f.inst, prf: map[string][]byte{string(repl.CredID): secret}}
	var final struct {
		Next      string          `json:"next"`
		Canonical string          `json:"canonical"`
		PublicKey json.RawMessage `json:"public_key"`
	}
	for taps := 0; final.Next != "replace"; taps++ {
		if taps > 4 {
			t.Fatal("too many taps")
		}
		var r tapResp
		call("evaluate", begin.Session, map[string]any{}, &r)
		as, pkt := fix.tapWith(t, s, repl, r)
		call("finish", begin.Session, map[string]any{"assertion": as, "open": pkt}, &final)
	}
	var c map[string]any
	requireNoError(t, json.Unmarshal([]byte(final.Canonical), &c))
	if c["manifest_sha256"] != v.cfg.Seal.Manifest || c["credential_id"] != encodeID(repl.CredID) || !strings.Contains(c["retire_credentials"].(string), encodeID(v.auth.CredID)) {
		t.Fatalf("replacement canonical %s", final.Canonical)
	}
	call("replace", begin.Session, map[string]any{"assertion": repl.Assert(sha256Bytes(final.Canonical))}, nil)
	requireNoError(t, <-done)
	// Recovery ends it and erases what it had sealed to the replaced keys.
	var ended int
	requireNoError(t, s.store.DB().QueryRow(`SELECT count(*) FROM env_proposals WHERE id='waiting-proposal' AND status='superseded' AND payload IS NULL AND bucket IS NULL`).Scan(&ended))
	if ended != 1 {
		t.Fatal("a pending proposal survived recovery")
	}
	next, err := os.ReadFile(filepath.Join(sock, "replacement-manifest.json"))
	var nm BucketManifest
	if err != nil || json.Unmarshal(next, &nm) != nil || nm.Format != 2 || !strings.Contains(string(next), "recovery_transition") {
		t.Fatal("no replacement manifest for the operator")
	}
	// The new passkey alone holds a tested wrap of every scope.
	wraps, err := s.store.Q().ScopeWraps(t.Context(), 0)
	requireNoError(t, err)
	if len(wraps) != 3 {
		t.Fatalf("%d wraps", len(wraps))
	}
	for _, w := range wraps {
		if !bytes.Equal(w.RawID, repl.CredID) || w.Tested == nil {
			t.Fatal("old passkey kept a wrap or a wrap is untested")
		}
	}
	var n int
	requireNoError(t, s.store.DB().QueryRow(`SELECT count(*) FROM passkeys`).Scan(&n))
	if n != 1 {
		t.Fatal("old passkeys not retired")
	}
	// Every scope and bucket was rekeyed: copies of the retired passkeys' wraps open
	// only the old keys. Every record still opens, with the same values.
	newScopes, err := s.store.Q().Scopes(t.Context())
	requireNoError(t, err)
	newBuckets, err := s.store.Q().Buckets(t.Context())
	requireNoError(t, err)
	if len(newScopes) != len(oldScopes) || len(newBuckets) != len(oldBuckets) {
		t.Fatal("scopes or buckets changed in number")
	}
	for i := range newScopes {
		if bytes.Equal(newScopes[i].Public, oldScopes[i].Public) || bytes.Equal(newScopes[i].Recovery, oldScopes[i].Recovery) {
			t.Fatalf("scope %s was not rekeyed", newScopes[i].Scope)
		}
	}
	for _, nb := range newBuckets {
		for _, ob := range oldBuckets {
			if bytes.Equal(nb.ID, ob.ID) && (bytes.Equal(nb.Public, ob.Public) || bytes.Equal(nb.Wrap, ob.Wrap)) {
				t.Fatalf("bucket %s was not rekeyed", nb.Label)
			}
		}
	}
	if got := openAll(t, s, f.inst, f.identity, f.recipient); !maps.Equal(got, values) || len(got) < 5 {
		t.Fatal("values changed or did not open after the recovery rekey")
	}
	if !strings.Contains(string(readAuditDetail(t, s, "recovery_replace")), "rekeyed_scopes=3") {
		t.Fatal("the rekey is not audited")
	}
	noSentinels(t, "recovery responses", seen.Bytes(), f, false)
	noSentinels(t, "logs", []byte(v.logs.String()), f, false)
}

func readAuditDetail(t *testing.T, s *Server, action string) string {
	t.Helper()
	var d string
	requireNoError(t, s.store.DB().QueryRow(`SELECT detail FROM audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&d))
	return d
}
