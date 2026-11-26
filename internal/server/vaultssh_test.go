package server

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

type sshFixture struct {
	id, slug, path, scheme, comment string
	pub                             []byte
	line, fingerprint               string
	key                             ssh.PublicKey
}

func (f sshFixture) target(v *vaultEnv) map[string]any {
	return v.setTarget(f.id, f.slug, "Deploy key", "ssh-key", 0)
}

// sshKeyChallenge asks for a new SSH key, generated or pasted, and checks the
// canonical is exactly what the owner chose, public line included.
func (v *vaultEnv) sshKeyChallenge(id, slug, scheme, comment string, handout any, private string) (vaultReviewResp, sshFixture, int) {
	v.t.Helper()
	choice := map[string]any{"action": "ssh-key-create", "id": id, "service_id": v.service, "set_slug": slug, "set_title": "Deploy key", "scheme": scheme, "source": "generate", "comment": comment}
	if handout != nil {
		choice["handout"] = handout
	}
	recipient := ""
	if private != "" {
		a, e, c := v.sealUpload("signer-import", id, []byte(`{"private_key":`+jsonString(private)+`}`))
		choice["source"], choice["attempt_id"], choice["enc"], choice["ciphertext"] = "import", a, e, c
		recipient = v.recipient
	}
	var r vaultReviewResp
	f := sshFixture{id: id, slug: slug, path: "client-a/paas/" + slug, scheme: scheme, comment: comment}
	st := v.web("POST", "/api/ui/seal/vault/challenge", choice, &r)
	if st != 200 {
		return r, f, st
	}
	var err error
	f.pub, _ = b64url(r.Facts["public_key"].(string))
	f.key, err = signer.SSHPublicKey(scheme, f.pub)
	requireNoError(v.t, err)
	f.line, _ = signer.AuthorizedKey(scheme, f.pub, comment)
	f.fingerprint = ssh.FingerprintSHA256(f.key)
	if r.Facts["authorized_key"] != f.line || r.Facts["fingerprint"] != f.fingerprint {
		v.t.Fatalf("facts are not of the public key: %v", r.Facts)
	}
	v.expect(r, "ssh-key-create", id, with(f.target(v), "scheme", scheme, "source", choice["source"], "attempt_id", r.Facts["attempt_id"], "recipient", recipient,
		"public_key", r.Facts["public_key"], "fingerprint", f.fingerprint, "authorized_key", f.line, "comment", comment, "handout", handout, "result_revision", 0))
	if r.Open != nil {
		v.t.Fatal("creating an SSH key offers to open a bucket")
	}
	return r, f, st
}
func jsonString(s string) string {
	b, _ := reviewJSON(s)
	return b
}
func (v *vaultEnv) createSSHKey(id, slug, scheme string, handout bool, private string) sshFixture {
	v.t.Helper()
	r, f, st := v.sshKeyChallenge(id, slug, scheme, "aqmas:client-a/paas/"+slug, handout, private)
	mustStatus(v.t, "ssh key challenge", st, 200)
	var out struct {
		Path, Scheme, Fingerprint, Comment string
		AuthorizedKey                      string `json:"authorized_key"`
		Handout                            bool
	}
	mustStatus(v.t, "ssh key finish", v.tap(r, &out), 200)
	if out.Path != f.path || out.AuthorizedKey != f.line || out.Fingerprint != f.fingerprint || out.Handout != handout || out.Scheme != scheme {
		v.t.Fatalf("created another key than the one signed for: %+v", out)
	}
	return f
}

// login is the data an SSH client asks its agent to sign.
func (f sshFixture) login(user string, session byte) signer.Item {
	return signer.SSHItem(sshUserAuth(bytes.Repeat([]byte{session}, 32), user, "ssh-connection", "publickey", f.key.Type(), f.key.Marshal()))
}
func sshUserAuth(session []byte, user, service, method, algo string, key []byte) []byte {
	var b bytes.Buffer
	str := func(p []byte) {
		b.Write([]byte{byte(len(p) >> 24), byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p))})
		b.Write(p)
	}
	str(session)
	b.WriteByte(50)
	str([]byte(user))
	str([]byte(service))
	str([]byte(method))
	b.WriteByte(1)
	str([]byte(algo))
	str(key)
	return b.Bytes()
}

func (v *vaultEnv) askSSH(c *http.Client, f sshFixture, use string, ttl, max int) (signer.Request, int) {
	v.t.Helper()
	var k signer.SSHKey
	if st := v.host(c, "GET", "/v2/ssh/key?path="+f.path, nil, &k); st != 200 {
		return signer.Request{}, st
	}
	if k.AuthorizedKey != f.line || k.Fingerprint != f.fingerprint || k.Comment != f.comment {
		v.t.Fatalf("the host is told another key: %+v", k)
	}
	var r signer.Request
	st := v.host(c, "POST", "/v2/ssh/requests", map[string]any{"binding": k.Binding, "reason": "clone the deploy repository", "use": use, "ttl_seconds": ttl, "max_signatures": max}, &r)
	return r, st
}

// sshDecision reviews an SSH request as the owner; the canonical names the use.
func (v *vaultEnv) sshDecision(f sshFixture, req signer.Request, action string, ttl, max int) (vaultReviewResp, int) {
	v.t.Helper()
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": action, "id": req.ID, "ttl_seconds": ttl, "max_signatures": max}, &r)
	if st == 200 {
		v.expect(r, action, req.ID, with(f.target(v),
			"request_id", req.ID, "host", req.Host, "enrollment", req.Enrollment, "address", "127.0.0.1", "scheme", f.scheme, "fingerprint", f.fingerprint, "items", []any{}, "use", req.Use,
			"requested_ttl_seconds", req.TTL, "requested_max_signatures", req.Max, "ttl_seconds", ttl, "max_signatures", max,
			"admission_generation", req.Generation, "policy_revision", req.PolicyRevision, "service_revision", req.ServiceRevision, "soft_cap_seconds", req.Soft, "beyond_soft_cap", ttl > req.Soft))
	}
	return r, st
}
func (v *vaultEnv) approveSSH(c *http.Client, f sshFixture, req signer.Request, ttl, max int) string {
	v.t.Helper()
	r, st := v.sshDecision(f, req, "sign-approve", ttl, max)
	mustStatus(v.t, "ssh approve challenge", st, 200)
	mustStatus(v.t, "ssh approve", v.tap(r, nil), 200)
	var got signer.Request
	mustStatus(v.t, "approved status", v.host(c, "GET", "/v2/sign/requests/"+req.ID, nil, &got), 200)
	if got.Status != "approved" || got.Grant == "" || got.Use != req.Use {
		v.t.Fatalf("not approved: %+v", got)
	}
	return got.Grant
}
func (v *vaultEnv) setHandout(f sshFixture, on bool) int {
	v.t.Helper()
	var r vaultReviewResp
	st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "ssh-key-handout", "id": f.id, "handout": on}, &r)
	if st != 200 {
		return st
	}
	v.expect(r, "ssh-key-handout", f.id, with(f.target(v), "fingerprint", f.fingerprint, "old_handout", !on, "handout", on))
	return v.tap(r, nil)
}

const sshID, sshID2 = "5555555555555555555555555555555a", "5555555555555555555555555555555b"

// An SSH key is created like a signer (generated on the broker or pasted,
// sealed in its own bucket) and shown by its authorized_keys line. The tap is
// bound to the public line, the comment and the hand-out setting.
func TestSSHKeyCreate(t *testing.T) {
	v := newVault(t)
	mustStatus(t, "listing on", v.setPolicy("client-a", func(p *api.DurationPolicy) { p.Discovery = true }), 200)
	for name, c := range map[string]struct {
		scheme, comment string
		handout         any
	}{
		"a signer scheme":       {"ed25519", "x", false},
		"an unknown scheme":     {"ssh-rsa", "x", false},
		"an empty comment":      {signer.SSHEd25519, "", false},
		"a comment with a tab":  {signer.SSHEd25519, "a\tb", false},
		"a non-ASCII comment":   {signer.SSHEd25519, "café", false},
		"a padded comment":      {signer.SSHEd25519, " deploy", false},
		"no hand-out choice":    {signer.SSHEd25519, "deploy", nil},
		"a two-line comment":    {signer.SSHEd25519, "a\nssh-ed25519 AAAA evil", false},
		"an over-long comment":  {signer.SSHEd25519, strings.Repeat("c", 101), false},
		"a hand-out that is 1":  {signer.SSHEd25519, "deploy", 1},
		"a hand-out that is on": {signer.SSHEd25519, "deploy", "on"},
	} {
		if _, _, st := v.sshKeyChallenge(sshID, "deploy-key", c.scheme, c.comment, c.handout, ""); st != 400 {
			t.Fatalf("%s: %d", name, st)
		}
	}
	// A signer cannot be created with an SSH scheme either.
	if st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": "signer-create", "id": sshID, "service_id": v.service, "set_slug": "deploy-key", "set_title": "Deploy key", "scheme": signer.SSHEd25519, "source": "generate"}, nil); st != 400 {
		t.Fatalf("a signer with an SSH scheme: %d", st)
	}

	gen := v.createSSHKey(sshID, "deploy-key", signer.SSHEd25519, false, "")
	if !v.audited("vault_ssh_key_create", "client-a/paas/deploy-key scheme=ssh-ed25519 origin=generated handout=false fingerprint="+gen.fingerprint) {
		t.Fatal("creation not audited")
	}
	// Pasted: an unencrypted OpenSSH private key, here an ECDSA one.
	p256, _ := signer.Lookup(signer.SSHECDSAP256)
	priv, pub, err := p256.Generate()
	requireNoError(t, err)
	file, err := signer.OpenSSHPrivate(signer.SSHECDSAP256, priv, "pasted@example.com")
	requireNoError(t, err)
	if _, _, st := v.sshKeyChallenge(sshID2, "imported-key", signer.SSHEd25519, "x", true, string(file)); st != 400 {
		t.Fatalf("an ECDSA key pasted as Ed25519: %d", st)
	}
	if _, _, st := v.sshKeyChallenge(sshID2, "imported-key", signer.SSHECDSAP256, "x", true, "not a key"); st != 400 {
		t.Fatalf("garbage pasted as a key: %d", st)
	}
	imp := v.createSSHKey(sshID2, "imported-key", signer.SSHECDSAP256, true, string(file))
	if !bytes.Equal(imp.pub, pub) {
		t.Fatal("the pasted key has another public half")
	}
	if where := v.leaked(priv); where != "" {
		t.Fatalf("the pasted private key appears in %s", where)
	}
	if _, _, st := v.sshKeyChallenge("5555555555555555555555555555555c", "deploy-key", signer.SSHEd25519, "x", false, ""); st != 409 {
		t.Fatalf("a second key with the same name: %d", st)
	}

	// The Vault shows the public line and the fingerprint as ssh-keygen prints it.
	var state struct {
		Schemes  []signer.Scheme
		SSHTypes []signer.SSHKeyType `json:"ssh_key_types"`
		Sets     []struct {
			SetID                                      string `json:"set_id"`
			Kind, Scheme, Origin, Fingerprint, Comment string
			AuthorizedKey                              string `json:"authorized_key"`
			Handout                                    bool
			Revision                                   int
			PublicPEM                                  string `json:"public_pem"`
		}
	}
	mustStatus(t, "state", v.web("GET", "/api/ui/seal/vault/state", nil, &state), 200)
	if len(state.SSHTypes) != 2 || state.SSHTypes[0].ID != signer.SSHEd25519 {
		t.Fatalf("key types: %+v", state.SSHTypes)
	}
	for _, sc := range state.Schemes {
		if sc.SSH || strings.HasPrefix(sc.ID, "ssh-") {
			t.Fatalf("the signer form offers %s", sc.ID)
		}
	}
	seen := 0
	for _, s := range state.Sets {
		for _, f := range []sshFixture{gen, imp} {
			if s.SetID != f.id {
				continue
			}
			seen++
			if s.Kind != "ssh-key" || s.Scheme != f.scheme || s.AuthorizedKey != f.line || s.Fingerprint != f.fingerprint || s.Comment != f.comment || s.Handout != (f.id == sshID2) || s.Revision != 0 || s.PublicPEM != "" {
				t.Fatalf("set view: %+v", s)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("the Vault lists %d of the two SSH keys", seen)
	}
	// An admitted host is told the public line too (it is public), never more.
	cat, raw := v.hostCatalogue(v.agent)
	found := 0
	for _, c := range cat.Credentials {
		if c.Kind != "ssh-key" {
			continue
		}
		found++
		want := gen
		if c.Path == imp.path {
			want = imp
		}
		if c.Path != want.path || c.PublicKey != want.line || c.Scheme != want.scheme || c.Handout != (want.id == sshID2) || !strings.HasPrefix(c.Use, "aqmas ssh-agent "+want.path) {
			t.Fatalf("catalogue entry: %+v", c)
		}
	}
	if found != 2 || strings.Contains(raw, "PRIVATE") {
		t.Fatalf("catalogue: %s", raw)
	}
	// An SSH key is not an env set, a secret or a signing key.
	for _, action := range []string{"commit", "reveal", "standing-cap", "secret-convert"} {
		st := v.web("POST", "/api/ui/seal/vault/challenge", map[string]any{"action": action, "id": sshID, "names": []string{"X_KEY"}, "recipient": "x", "standing_cap_seconds": 0, "attempt_id": "x", "enc": "x", "ciphertext": "x"}, nil)
		if st == 200 || st == 404 {
			t.Fatalf("%s on an SSH key: %d", action, st)
		}
	}
	if st := v.host(v.agent, "GET", "/v2/env/set?path="+gen.path, nil, nil); st != 404 {
		t.Fatalf("an SSH key resolved as an env set: %d", st)
	}
	sig := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", "")
	if st := v.host(v.agent, "GET", "/v2/ssh/key?path="+sig.path, nil, nil); st != 404 {
		t.Fatalf("a signing key resolved as an SSH key: %d", st)
	}
	if st := v.host(v.agent, "GET", "/v2/ssh/key?path=client-a/paas/staging", nil, nil); st != 404 {
		t.Fatalf("an env set resolved as an SSH key: %d", st)
	}
}

// The preferred use: the key stays in aqmas. One approval is a time-boxed
// grant of logins; each signature is over an SSH login request for exactly
// this key and nothing else, and is recorded with the remote user and session.
func TestSSHKeyAgentGrant(t *testing.T) {
	v := newVault(t)
	f := v.createSSHKey(sshID, "deploy-key", signer.SSHEd25519, false, "")
	sc, _ := signer.Lookup(f.scheme)

	// `aqmas sign` is not a way around the login check.
	var b signer.Binding
	mustStatus(t, "binding", v.host(v.agent, "GET", "/v2/sign/key?path="+f.path, nil, &b), 200)
	for name, items := range map[string][]signer.Item{"a file": {signItemFor(sc, "manifest.bin", []byte("manifest"))}, "a login request": {f.login("git", 1)}} {
		if st := v.host(v.agent, "POST", "/v2/sign/requests", map[string]any{"binding": b, "reason": "x", "ttl_seconds": 600, "max_signatures": 5, "items": items}, nil); st != 400 {
			t.Fatalf("a signing request with %s for an SSH key: %d", name, st)
		}
	}
	for name, c := range map[string][3]any{
		"no duration":      {signer.UseSSHAgent, 0, 5},
		"a short duration": {signer.UseSSHAgent, 30, 5},
		"too many logins":  {signer.UseSSHAgent, 600, 1001},
		"another use":      {"sign", 600, 5},
		"no use":           {"", 600, 5},
	} {
		if _, st := v.askSSH(v.agent, f, c[0].(string), c[1].(int), c[2].(int)); st != 400 {
			t.Fatalf("request with %s: %d", name, st)
		}
	}
	req, st := v.askSSH(v.agent, f, signer.UseSSHAgent, 600, 5)
	mustStatus(t, "request", st, 200)
	if req.Status != "pending" || req.Use != signer.UseSSHAgent || req.TTL != 600 || req.Max != 5 || len(req.Items) != 0 {
		t.Fatalf("request: %+v", req)
	}
	if !v.audited("ssh_request", f.path+" scheme=ssh-ed25519 use=ssh-agent ttl=600 max=5") {
		t.Fatal("request not audited")
	}
	// Never a single-use or unbounded approval, never more than was asked.
	for name, c := range map[string][2]int{"single use": {0, 0}, "one login, no time": {0, 1}, "longer": {601, 5}, "more": {600, 6}, "under a minute": {30, 5}} {
		if _, st := v.sshDecision(f, req, "sign-approve", c[0], c[1]); st != 400 {
			t.Fatalf("approval %s: %d", name, st)
		}
	}
	grant := v.approveSSH(v.agent, f, req, 300, 3)
	if open := openBuckets(t, v.s); len(open) != 1 || open["signer:"+f.id].Holds[0].Until.Sub(v.clock.Now()).Seconds() != 300 {
		t.Fatalf("the key's bucket should be held for the grant: %+v", open)
	}

	// A login: signed, valid for an SSH server, recorded with user and session.
	login := f.login("git", 1)
	signed, st := v.sign(v.agent, grant, login)
	mustStatus(t, "login signature", st, 200)
	wire, err := sc.SSHSignature(signed.Signatures[0].Signature)
	if err != nil || f.key.Verify(login.Message, wire) != nil {
		t.Fatalf("not a valid SSH signature: %v", err)
	}
	u, _ := signer.ParseUserAuth(login.Message)
	if !v.audited("sign", f.path+` scheme=ssh-ed25519 use=ssh-agent user="git" session=`+u.SessionDigest()) {
		t.Fatal("the login is not audited with its user and session")
	}
	// Anything that is not a login request for this key: refused, nothing signed.
	other, _ := signer.SSHPublicKey(signer.SSHEd25519, bytes.Repeat([]byte{7}, 32))
	random := make([]byte, 200)
	rand.Read(random)
	for name, it := range map[string]signer.Item{
		"arbitrary text":          signer.SSHItem([]byte("sign this release manifest")),
		"random bytes":            signer.SSHItem(random),
		"an SSHSIG blob":          signer.SSHItem(append([]byte("SSHSIG"), login.Message...)),
		"a login for another key": signer.SSHItem(sshUserAuth(bytes.Repeat([]byte{1}, 32), "git", "ssh-connection", "publickey", other.Type(), other.Marshal())),
		"host-based auth":         signer.SSHItem(sshUserAuth(bytes.Repeat([]byte{1}, 32), "git", "ssh-connection", "hostbased", f.key.Type(), f.key.Marshal())),
		"another service":         signer.SSHItem(sshUserAuth(bytes.Repeat([]byte{1}, 32), "git", "ssh-agent", "publickey", f.key.Type(), f.key.Marshal())),
	} {
		if _, st := v.sign(v.agent, grant, it); st != 400 {
			t.Fatalf("%s was not refused: %d", name, st)
		}
	}
	// Another host, even an admitted one, cannot use the grant.
	if _, st := v.sign(v.other, grant, f.login("git", 2)); st != 404 {
		t.Fatalf("another host signed under the grant: %d", st)
	}
	// Within the grant: no new tap, until the count runs out.
	if _, st := v.sign(v.agent, grant, f.login("alice", 2), f.login("alice", 3)); st != 200 {
		t.Fatalf("second and third login: %d", st)
	}
	if _, st := v.sign(v.agent, grant, f.login("git", 4)); st == 200 {
		t.Fatal("a fourth login under a grant of three")
	}
	if open := openBuckets(t, v.s); len(open) != 0 {
		t.Fatalf("a spent grant keeps the bucket open: %v", open)
	}
	if n := v.count(`SELECT signatures FROM signer_keys WHERE set_id=?`, f.id); n != 3 {
		t.Fatalf("%d logins counted", n)
	}
	// Deny and revoke work as for signing; a hand-out grant is not offered here.
	req, st = v.askSSH(v.agent, f, signer.UseSSHAgent, 600, 0)
	mustStatus(t, "second request", st, 200)
	if req.Max != signer.DefaultSignatures {
		t.Fatalf("default logins: %d", req.Max)
	}
	r, st := v.sshDecision(f, req, "sign-deny", 0, 0)
	mustStatus(t, "deny challenge", st, 200)
	mustStatus(t, "deny", v.tap(r, nil), 200)
	req, st = v.askSSH(v.agent, f, signer.UseSSHAgent, 600, 2)
	mustStatus(t, "third request", st, 200)
	grant = v.approveSSH(v.agent, f, req, 600, 2)
	r, st = v.sshDecision(f, req, "sign-revoke", 0, 0)
	mustStatus(t, "revoke challenge", st, 200)
	mustStatus(t, "revoke", v.tap(r, nil), 200)
	if _, st := v.sign(v.agent, grant, f.login("git", 5)); st == 200 {
		t.Fatal("signed under a revoked grant")
	}

	// A signing key never answers an SSH login as an SSH key would: its grants
	// carry no use, and an SSH request cannot be made for it.
	sig := v.createSigner("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "release-key", "ed25519", "")
	var sb signer.Binding
	mustStatus(t, "signer binding", v.host(v.agent, "GET", "/v2/sign/key?path="+sig.path, nil, &sb), 200)
	if st := v.host(v.agent, "POST", "/v2/ssh/requests", map[string]any{"binding": sb, "reason": "x", "use": signer.UseSSHAgent, "ttl_seconds": 600}, nil); st != 404 {
		t.Fatalf("an SSH request for a signing key: %d", st)
	}

	// Deleted: the key is gone for the host, a live grant with it.
	req, st = v.askSSH(v.agent, f, signer.UseSSHAgent, 600, 5)
	mustStatus(t, "request", st, 200)
	grant = v.approveSSH(v.agent, f, req, 600, 5)
	if out := v.delete(f.id, f.slug, "Deploy key", "ssh-key", 0, f.fingerprint); out.Ended.Grants != 1 {
		t.Fatalf("ended: %+v", out.Ended)
	}
	if _, st := v.sign(v.agent, grant, f.login("git", 6)); st != 404 {
		t.Fatalf("a login signed with a deleted key: %d", st)
	}
	if st := v.host(v.agent, "GET", "/v2/ssh/key?path="+f.path, nil, nil); st != 404 {
		t.Fatalf("a deleted key still resolves: %d", st)
	}
	if s := v.binState(); len(s.Deleted) != 1 || s.Deleted[0].Kind != "ssh-key" {
		t.Fatalf("bin: %+v", s.Deleted)
	}
}

// Hand-out is off unless the owner turned it on for that key. On, one
// approval delivers the OpenSSH private key once; off again, nothing more.
func TestSSHKeyHandout(t *testing.T) {
	v := newVault(t)
	f := v.createSSHKey(sshID, "deploy-key", signer.SSHEd25519, false, "")
	var refusal struct{ Error, Message string }
	var k signer.SSHKey
	mustStatus(t, "key", v.host(v.agent, "GET", "/v2/ssh/key?path="+f.path, nil, &k), 200)
	if k.Handout {
		t.Fatal("hand-out is on by default")
	}
	raw := func() (int, string) {
		st, body := 0, ""
		var b bytes.Buffer
		mark := v.seen.Len()
		st = v.host(v.agent, "POST", "/v2/ssh/requests", map[string]any{"binding": k.Binding, "reason": "the tool reads a key file", "use": signer.UseSSHHandout}, &refusal)
		b.Write(v.seen.Bytes()[mark:])
		body = b.String()
		return st, body
	}
	if st, body := raw(); st != 403 || !strings.Contains(body, "aqmas ssh-agent "+f.path) {
		t.Fatalf("hand-out of a key that may not be handed out: %d %s", st, body)
	}
	if st := v.setHandout(f, false); st != 409 {
		t.Fatalf("setting hand-out to the value it has: %d", st)
	}
	mustStatus(t, "allow hand-out", v.setHandout(f, true), 200)
	if !v.audited("vault_ssh_key_handout", f.path+" handout=true was=false fingerprint="+f.fingerprint) {
		t.Fatal("the setting change is not audited")
	}
	if _, st := v.askSSH(v.agent, f, signer.UseSSHHandout, 600, 1); st != 400 {
		t.Fatalf("a hand-out with a duration: %d", st)
	}
	req, st := v.askSSH(v.agent, f, signer.UseSSHHandout, 0, 0)
	mustStatus(t, "hand-out request", st, 200)
	if req.Use != signer.UseSSHHandout || req.TTL != 0 || req.Max != 1 {
		t.Fatalf("request: %+v", req)
	}
	// One delivery: never a time-boxed grant.
	for name, c := range map[string][2]int{"a duration": {300, 1}, "two deliveries": {0, 2}, "none": {0, 0}} {
		if _, st := v.sshDecision(f, req, "sign-approve", c[0], c[1]); st != 400 {
			t.Fatalf("hand-out approval with %s: %d", name, st)
		}
	}
	grant := v.approveSSH(v.agent, f, req, 0, 1)
	// The grant hands out; it does not sign.
	if _, st := v.sign(v.agent, grant, f.login("git", 1)); st != 409 {
		t.Fatalf("signed under a hand-out grant: %d", st)
	}
	if st := v.host(v.other, "POST", "/v2/ssh/grants/"+grant+"/key", map[string]any{}, nil); st != 404 {
		t.Fatalf("another host collected the key: %d", st)
	}
	var out signer.SSHHandout
	mustStatus(t, "collect", v.host(v.agent, "POST", "/v2/ssh/grants/"+grant+"/key", map[string]any{}, &out), 200)
	parsed, err := ssh.ParsePrivateKey([]byte(out.PrivateKey))
	if err != nil || !bytes.Equal(parsed.PublicKey().Marshal(), f.key.Marshal()) || out.AuthorizedKey != f.line || out.Request.Status != "used" {
		t.Fatalf("the delivered key is not the key: %v", err)
	}
	if !v.audited("ssh_key_collect", f.path+" scheme=ssh-ed25519 fingerprint="+f.fingerprint) {
		t.Fatal("the delivery is not audited")
	}
	if st := v.host(v.agent, "POST", "/v2/ssh/grants/"+grant+"/key", map[string]any{}, nil); st == 200 {
		t.Fatal("the key was delivered twice under one approval")
	}
	if open := openBuckets(t, v.s); len(open) != 0 {
		t.Fatalf("a spent hand-out keeps the bucket open: %v", open)
	}
	// Outside the one response, the private key is nowhere.
	body := strings.Join(strings.Split(strings.TrimSpace(out.PrivateKey), "\n")[1:3], "")
	rows, err := v.s.store.DB().Query(`SELECT detail FROM audit`)
	requireNoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var d string
		requireNoError(t, rows.Scan(&d))
		if strings.Contains(d, body[:40]) || strings.Contains(d, "PRIVATE KEY") {
			t.Fatal("the private key is in the audit log")
		}
	}
	if strings.Contains(v.logs.String(), body[:40]) {
		t.Fatal("the private key is in the logs")
	}

	// A login grant does not hand out.
	req, st = v.askSSH(v.agent, f, signer.UseSSHAgent, 600, 2)
	mustStatus(t, "login request", st, 200)
	grant = v.approveSSH(v.agent, f, req, 600, 2)
	if st := v.host(v.agent, "POST", "/v2/ssh/grants/"+grant+"/key", map[string]any{}, nil); st != 409 {
		t.Fatalf("a login grant handed out the key: %d", st)
	}
	// Turned off while a hand-out is approved but not collected: it ends there.
	req, st = v.askSSH(v.agent, f, signer.UseSSHHandout, 0, 0)
	mustStatus(t, "second hand-out request", st, 200)
	handout := v.approveSSH(v.agent, f, req, 0, 1)
	waiting, st := v.askSSH(v.other, f, signer.UseSSHHandout, 0, 0)
	mustStatus(t, "third hand-out request", st, 200)
	mustStatus(t, "forbid hand-out", v.setHandout(f, false), 200)
	if st := v.host(v.agent, "POST", "/v2/ssh/grants/"+handout+"/key", map[string]any{}, nil); st == 200 {
		t.Fatal("the key was handed out after the owner turned hand-out off")
	}
	if _, st := v.sshDecision(f, waiting, "sign-approve", 0, 1); st == 200 {
		t.Fatal("a hand-out request survived the setting being turned off")
	}
	// The login grant is untouched by that.
	if _, st := v.sign(v.agent, grant, f.login("git", 9)); st != 200 {
		t.Fatalf("the login grant ended with the hand-out setting: %d", st)
	}
}
