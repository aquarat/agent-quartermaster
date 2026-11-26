package signer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The keys of RFC 8032 section 7.1 (test 1) and RFC 6979 A.2.5: public test
// vectors, so the expected lines below are what `ssh-keygen -y` and
// `ssh-keygen -lf` print for them.
var sshVectors = []struct{ scheme, seed, line, fingerprint string }{
	{SSHEd25519, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea aqmas:acme/forge/deploy-key",
		"SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"},
	{SSHECDSAP256, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk= aqmas:acme/forge/deploy-key",
		"SHA256:hfuNWmjIYvsBGZ6dpCLTTAEa5LxbZABRHHVoynAxFlo"},
}

const vectorComment = "aqmas:acme/forge/deploy-key"

func TestSSHPublicLineAndFingerprint(t *testing.T) {
	keygen, _ := exec.LookPath("ssh-keygen")
	for _, v := range sshVectors {
		sc, ok := Lookup(v.scheme)
		if !ok || !sc.SSH || !IsSSH(v.scheme) {
			t.Fatal("scheme", v.scheme)
		}
		priv, _ := hex.DecodeString(v.seed)
		pub, err := sc.Public(priv)
		if err != nil {
			t.Fatal(err)
		}
		line, err := AuthorizedKey(v.scheme, pub, vectorComment)
		if err != nil || line != v.line {
			t.Fatalf("%s line %q %v", v.scheme, line, err)
		}
		if fp, err := SSHFingerprint(v.scheme, pub); err != nil || fp != v.fingerprint {
			t.Fatalf("%s fingerprint %q %v", v.scheme, fp, err)
		}
		// The hand-out file: OpenSSH reads it and derives the same public line.
		file, err := OpenSSHPrivate(v.scheme, priv, vectorComment)
		if err != nil || !bytes.HasPrefix(file, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n")) {
			t.Fatal(err)
		}
		// Pasted back, it is the same key.
		p2, pub2, err := sc.ParsePrivate(file)
		if err != nil || !bytes.Equal(p2, priv) || !bytes.Equal(pub2, pub) {
			t.Fatalf("%s round trip: %v", v.scheme, err)
		}
		if keygen == "" {
			continue
		}
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, file, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(keygen, "-y", "-f", path).Output()
		if err != nil || strings.TrimSpace(string(out)) != v.line {
			t.Fatalf("ssh-keygen -y: %q %v", out, err)
		}
		if err := os.WriteFile(path+".pub", []byte(line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err = exec.Command(keygen, "-lf", path+".pub").Output()
		if f := strings.Fields(string(out)); err != nil || len(f) < 2 || f[1] != v.fingerprint {
			t.Fatalf("ssh-keygen -lf: %q %v", out, err)
		}
	}
	// A signer scheme is not an SSH key, and the other way round.
	plain, _ := Lookup("ed25519")
	if plain.SSH || IsSSH("ed25519") {
		t.Fatal("ed25519 signer treated as an SSH key")
	}
	for _, s := range All() {
		if s.SSH {
			t.Fatalf("%s is offered for signer sets", s.ID)
		}
	}
	if _, err := AuthorizedKey("ed25519", make([]byte, 32), "x"); err == nil {
		t.Fatal("public line for a non-SSH scheme")
	}
}

func TestSSHComment(t *testing.T) {
	for _, ok := range []string{"a", vectorComment, "deploy key for the forge", strings.Repeat("x", 100)} {
		if !ValidSSHComment(ok) {
			t.Fatalf("refused %q", ok)
		}
	}
	for _, bad := range []string{"", " lead", "trail ", "new\nline", "tab\there", "café", strings.Repeat("x", 101), "nul\x00"} {
		if ValidSSHComment(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// userAuth builds the data an SSH client signs (RFC 4252 section 7).
func userAuth(session []byte, user, service, method, algo string, key, hostKey []byte) []byte {
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
	if hostKey != nil {
		str(hostKey)
	}
	return b.Bytes()
}

func TestSSHSignsLoginRequestsOnly(t *testing.T) {
	session := bytes.Repeat([]byte{0xab}, 32)
	for _, v := range sshVectors {
		sc, _ := Lookup(v.scheme)
		priv, _ := hex.DecodeString(v.seed)
		pub, _ := sc.Public(priv)
		k, err := SSHPublicKey(v.scheme, pub)
		if err != nil {
			t.Fatal(err)
		}
		blob, algo := k.Marshal(), k.Type()
		good := userAuth(session, "git", "ssh-connection", "publickey", algo, blob, nil)
		it := SSHItem(good)
		u, err := sc.SSHLogin(pub, it)
		if err != nil || u.User != "git" || u.Method != "publickey" || u.HostKeyFingerprint() != "" || !strings.HasPrefix(u.SessionDigest(), "sha256:") {
			t.Fatalf("login request refused: %+v %v", u, err)
		}
		sig, err := sc.Sign(priv, it)
		if err != nil || !sc.Verify(pub, it, sig) {
			t.Fatal("sign", err)
		}
		// The SSH library accepts it as this key's signature over that data.
		wire, err := sc.SSHSignature(sig)
		if err != nil || k.Verify(good, wire) != nil {
			t.Fatalf("%s: not a valid SSH signature: %v", v.scheme, err)
		}
		// OpenSSH's host-bound method carries the server's host key.
		other, _ := SSHPublicKey(SSHEd25519, bytes.Repeat([]byte{9}, 32))
		bound := SSHItem(userAuth(session, "alice", "ssh-connection", "publickey-hostbound-v00@openssh.com", algo, blob, other.Marshal()))
		if u, err := sc.SSHLogin(pub, bound); err != nil || u.HostKeyFingerprint() != ssh.FingerprintSHA256(other) {
			t.Fatalf("host-bound request: %+v %v", u, err)
		}
		// Everything that is not a login request for this key is refused.
		sshsig := append([]byte("SSHSIG"), userAuth(session, "x", "file", "publickey", algo, blob, nil)...)
		random := make([]byte, 96)
		rand.Read(random)
		for name, data := range map[string][]byte{
			"arbitrary bytes":  []byte("please sign this release manifest"),
			"random bytes":     random,
			"SSHSIG namespace": sshsig,
			"empty":            {},
			"trailing bytes":   append(bytes.Clone(good), 0),
			"truncated":        good[:len(good)-1],
			"other service":    userAuth(session, "git", "ssh-userauth", "publickey", algo, blob, nil),
			"host-based":       userAuth(session, "git", "ssh-connection", "hostbased", algo, blob, nil),
			"password":         userAuth(session, "git", "ssh-connection", "password", algo, blob, nil),
			"no session id":    userAuth(nil, "git", "ssh-connection", "publickey", algo, blob, nil),
			"empty user":       userAuth(session, "", "ssh-connection", "publickey", algo, blob, nil),
			"certificate algo": userAuth(session, "git", "ssh-connection", "publickey", "ssh-ed25519-cert-v01@openssh.com", blob, nil),
			"rsa algo":         userAuth(session, "git", "ssh-connection", "publickey", "rsa-sha2-256", blob, nil),
			"garbage key":      userAuth(session, "git", "ssh-connection", "publickey", algo, []byte("not a key"), nil),
			"bound, no key":    userAuth(session, "git", "ssh-connection", "publickey-hostbound-v00@openssh.com", algo, blob, nil),
			"bound, not a key": userAuth(session, "git", "ssh-connection", "publickey-hostbound-v00@openssh.com", algo, blob, []byte("arbitrary bytes to sign")),
			"plain, extra key": userAuth(session, "git", "ssh-connection", "publickey", algo, blob, other.Marshal()),
		} {
			it := SSHItem(data)
			if sc.Valid(it) == nil {
				t.Fatalf("%s: %s passed as a login request", v.scheme, name)
			}
			if _, err := sc.Sign(priv, it); err == nil {
				t.Fatalf("%s: signed %s", v.scheme, name)
			}
		}
		// A login request for another key of the same type is well-formed, so the
		// scheme's Valid accepts it; SSHLogin (the broker's check) and Verify refuse it.
		foreign := SSHItem(userAuth(session, "git", "ssh-connection", "publickey", other.Type(), other.Marshal(), nil))
		if _, err := sc.SSHLogin(pub, foreign); err == nil {
			t.Fatal("a login request for another key was accepted")
		}
		if _, err := sc.Sign(priv, foreign); err == nil {
			t.Fatal("signed a login request for another key")
		}
	}
	// A signer key's scheme has no SSH form.
	plain, _ := Lookup("ed25519")
	if _, err := plain.SSHLogin(make([]byte, 32), SSHItem([]byte("x"))); err == nil {
		t.Fatal("SSHLogin for a signer scheme")
	}
	if _, err := plain.SSHSignature(make([]byte, 64)); err == nil {
		t.Fatal("SSH signature for a signer scheme")
	}
}

func TestSSHPastedKeys(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	for typ, scheme := range map[string]string{"ed25519": SSHEd25519, "ecdsa": SSHECDSAP256} {
		path := filepath.Join(dir, typ)
		gen := func(file, passphrase string) {
			args := []string{"-q", "-t", typ, "-N", passphrase, "-C", "pasted@example.com", "-f", file}
			if typ == "ecdsa" {
				args = append(args, "-b", "256")
			}
			if out, err := exec.Command(keygen, args...).CombinedOutput(); err != nil {
				t.Fatalf("%s %v", out, err)
			}
		}
		gen(path, "")
		file, _ := os.ReadFile(path)
		pubLine, _ := os.ReadFile(path + ".pub")
		sc, _ := Lookup(scheme)
		priv, pub, err := sc.ParsePrivate(file)
		if err != nil {
			t.Fatal(typ, err)
		}
		line, _ := AuthorizedKey(scheme, pub, "pasted@example.com")
		if line != strings.TrimSpace(string(pubLine)) {
			t.Fatalf("%s: pasted key has another public line", typ)
		}
		clear(priv)
		// The other key type refuses it, without echoing input.
		wrong := SSHEd25519
		if scheme == SSHEd25519 {
			wrong = SSHECDSAP256
		}
		w, _ := Lookup(wrong)
		if _, _, err := w.ParsePrivate(file); err == nil || strings.Contains(err.Error(), "BEGIN") {
			t.Fatalf("%s accepted as %s: %v", typ, wrong, err)
		}
		// A passphrase-protected key is refused.
		enc := filepath.Join(dir, typ+"-enc")
		gen(enc, "correct horse")
		locked, _ := os.ReadFile(enc)
		if _, _, err := sc.ParsePrivate(locked); err == nil {
			t.Fatalf("%s: encrypted key accepted", typ)
		}
	}
	// A larger curve and RSA are not SSH key types aqmas holds.
	p384 := filepath.Join(dir, "p384")
	if out, err := exec.Command(keygen, "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-f", p384).CombinedOutput(); err != nil {
		t.Fatalf("%s %v", out, err)
	}
	file, _ := os.ReadFile(p384)
	ec, _ := Lookup(SSHECDSAP256)
	if _, _, err := ec.ParsePrivate(file); err == nil {
		t.Fatal("P-384 key accepted")
	}
}
