//go:build linux

package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"filippo.io/age"
)

func testPasskeyScope(t *testing.T, scope string) (PasskeyScope, *Key) {
	t.Helper()
	o := PasskeyScope{Installation: RandomID(), RPID: "aqmas.example.com", RawID: []byte("credential-1"), Scope: scope, Salt: RandomID()}
	prf := make([]byte, 32)
	rand.Read(prf)
	kek, err := o.DeriveKEK(prf)
	if err != nil {
		t.Fatal(err)
	}
	return o, kek
}

func TestScopeWrapRoundTripAndBinding(t *testing.T) {
	o, kek := testPasskeyScope(t, ScopeInstallation)
	defer kek.Destroy()
	sk, pub, _ := NewKeyPair()
	defer sk.Destroy()
	w, err := o.Wrap(kek, sk, pub)
	if err != nil || len(w) != 73 {
		t.Fatal(err, len(w))
	}
	w2, _ := o.Wrap(kek, sk, pub)
	if bytes.Equal(w[1:25], w2[1:25]) {
		t.Fatal("nonce reused across wraps")
	}
	got, err := o.Unwrap(kek, w, pub)
	if err != nil || !bytes.Equal(got.Bytes(), sk.Bytes()) {
		t.Fatal("unwrap", err)
	}
	got.Destroy()
	for name, mut := range map[string]func(*PasskeyScope){
		"scope": func(x *PasskeyScope) { x.Scope = "org-1" },
		"salt":  func(x *PasskeyScope) { x.Salt = RandomID() },
		"cred":  func(x *PasskeyScope) { x.RawID = []byte("credential-2") },
		"rp":    func(x *PasskeyScope) { x.RPID = "other.example.com" },
		"inst":  func(x *PasskeyScope) { x.Installation = RandomID() },
	} {
		x := o
		mut(&x)
		if k, err := x.Unwrap(kek, w, pub); err == nil {
			k.Destroy()
			t.Fatalf("%s: wrong context opened", name)
		}
	}
	_, other, _ := NewKeyPair()
	if _, err := o.Unwrap(kek, w, other); err == nil {
		t.Fatal("wrap opened for a substituted scope public key")
	}
	wrong, _ := RandomKey()
	defer wrong.Destroy()
	if _, err := o.Unwrap(wrong, w, pub); err == nil {
		t.Fatal("wrong KEK opened")
	}
	w[40] ^= 1
	if _, err := o.Unwrap(kek, w, pub); err == nil {
		t.Fatal("tampered wrap opened")
	}
	sk2, _, _ := NewKeyPair()
	defer sk2.Destroy()
	if _, err := o.Wrap(kek, sk2, pub); err == nil {
		t.Fatal("wrapped a scalar that does not match the scope")
	}
	// Recovery of the scope key: only the pinned identity, only this scope.
	sc := Scope{Installation: o.Installation, Name: o.Scope, Public: pub}
	id, _ := age.GenerateX25519Identity()
	rcp := id.Recipient().String()
	rw, err := sc.RecoveryWrap(rcp, sk)
	if err != nil {
		t.Fatal(err)
	}
	k, err := sc.Recover(id, rcp, rw)
	if err != nil || !bytes.Equal(k.Bytes(), sk.Bytes()) {
		t.Fatal("recovery", err)
	}
	k.Destroy()
	if _, err := (Scope{o.Installation, "org-other", pub}).Recover(id, rcp, rw); err == nil {
		t.Fatal("recovery wrap moved to another scope")
	}
	otherID, _ := age.GenerateX25519Identity()
	if _, err := sc.Recover(otherID, otherID.Recipient().String(), rw); err == nil {
		t.Fatal("other identity recovered")
	}
	forged, _, _ := NewKeyPair()
	defer forged.Destroy()
	var out bytes.Buffer
	ww, _ := age.Encrypt(&out, id.Recipient())
	ww.Write(frame(sc.recoveryPrefix(rcp), forged.Bytes()))
	ww.Close()
	if _, err := sc.Recover(id, rcp, out.Bytes()); err == nil {
		t.Fatal("forged recovery scalar accepted")
	}
}

func testBucket(t *testing.T, scope, kind string) (Bucket, *Key) {
	t.Helper()
	sk, pub, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return Bucket{Installation: RandomID(), ID: RandomID(), Scope: scope, Kind: kind, Public: pub}, sk
}

func TestBucketWrapsAndRecords(t *testing.T) {
	b, sk := testBucket(t, "org-personal", "env-set")
	defer sk.Destroy()
	ssk, spub, _ := NewKeyPair()
	defer ssk.Destroy()
	w, err := b.WrapTo(spub, sk)
	if err != nil || len(w) != 113 {
		t.Fatal(err, len(w))
	}
	k, err := b.UnwrapWith(ssk, spub, w)
	if err != nil || !bytes.Equal(k.Bytes(), sk.Bytes()) {
		t.Fatal("bucket unwrap", err)
	}
	k.Destroy()
	for name, x := range map[string]Bucket{"id": {b.Installation, RandomID(), b.Scope, b.Kind, b.Public}, "scope": {b.Installation, b.ID, "org-other", b.Kind, b.Public}, "kind": {b.Installation, b.ID, b.Scope, "signer", b.Public}} {
		if k, err := x.UnwrapWith(ssk, spub, w); err == nil {
			k.Destroy()
			t.Fatalf("%s: wrap moved", name)
		}
	}
	o2, o2pub, _ := NewKeyPair()
	defer o2.Destroy()
	if _, err := b.UnwrapWith(o2, o2pub, w); err == nil {
		t.Fatal("other scope opened the wrap")
	}
	fields := [][]byte{[]byte("set-1"), bytes.Repeat([]byte{7}, 32), []byte("APP_SECRET")}
	rec, err := b.Seal(RoleEnvEntry, fields, []byte("sentinel value"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Open(sk, RoleEnvEntry, fields, rec)
	if err != nil || string(p) != "sentinel value" {
		t.Fatal("record open", err)
	}
	if _, err := b.Open(sk, RoleEnvEntry, [][]byte{fields[0], fields[1], []byte("OTHER")}, rec); err == nil {
		t.Fatal("record moved to another name")
	}
	if _, err := b.Open(sk, RoleSignerKey, fields, rec); err == nil {
		t.Fatal("record moved to another role")
	}
	if _, err := b.Seal(RoleEnvEntry, fields[:2], nil); err == nil {
		t.Fatal("wrong field count accepted")
	}
	b2, sk2 := testBucket(t, b.Scope, b.Kind)
	defer sk2.Destroy()
	if _, err := b2.Open(sk2, RoleEnvEntry, fields, rec); err == nil {
		t.Fatal("other bucket opened a record")
	}
}

func TestOpenAttemptsAndPacket(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a := NewOpenAttempts(func() time.Time { return now })
	id, pub, err := a.Begin("sess", "approve", "challenge-1")
	if err != nil {
		t.Fatal(err)
	}
	inst := RandomID()
	ch := OpenChallenge([]byte("canonical"), []byte("descriptor"))
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	var raw [32]byte
	copy(raw[:], mustB64(t, id))
	enc, ct, err := SealTo(pub, OpenInfo(inst, "approve"), OpenAAD(raw, a.Epoch(), ch, []byte("cred")), Frames(k1, k2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Take("other", "approve", id); err == nil {
		t.Fatal("other session took the attempt")
	}
	// The failed take above consumed it: a ceremony is single-use whatever happens.
	if _, err := a.Take("sess", "approve", id); err == nil {
		t.Fatal("attempt reused")
	}
	id, pub, _ = a.Begin("sess", "approve", "challenge-1")
	copy(raw[:], mustB64(t, id))
	enc, ct, _ = SealTo(pub, OpenInfo(inst, "approve"), OpenAAD(raw, a.Epoch(), ch, []byte("cred")), Frames(k1, nil))
	at, err := a.Take("sess", "approve", id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := at.Open(inst, a.Epoch(), ch, []byte("other-cred"), enc, ct); err == nil {
		t.Fatal("packet accepted for another credential")
	}
	keys, err := at.Open(inst, a.Epoch(), ch, []byte("cred"), enc, ct)
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Bytes(), k1) {
		t.Fatal("packet", err)
	}
	keys[0].Destroy()
	// Expiry.
	id, _, _ = a.Begin("sess", "approve", "x")
	now = now.Add(3 * time.Minute)
	if _, err := a.Take("sess", "approve", id); err == nil {
		t.Fatal("expired attempt taken")
	}
	for _, bad := range [][]byte{nil, Frames(k1[:31]), Frames(k1, k2, k1), append(Frames(k1), 0, 0, 0)} {
		if _, err := SplitKEKs(bytes.Clone(bad)); err == nil {
			t.Fatalf("bad packet %x accepted", bad)
		}
	}
}

func mustB64(t *testing.T, s string) []byte {
	var id ID
	if err := id.UnmarshalText([]byte(s)); err != nil {
		t.Fatal(err)
	}
	return id[:]
}

// test/vectors/buckets.json pins the browser-side derivations: Go writes the
// expected bytes (AQMAS_UPDATE_VECTORS=1); web/test/buckets.test.ts derives the
// same and web/test/fixtures/make-open-packet.ts writes "browser_packet",
// which this test opens.
type bucketVectors struct {
	Installation, RPID, Cred, Scope, Salt, PRF, KEKInfo, KEK string
	Canonical, Descriptor, Challenge                         string
	AttemptID, Epoch, RecipientPriv, RecipientPub            string
	Info, AAD                                                string
	Browser                                                  *struct{ Enc, Ciphertext, KEK2 string } `json:"browser_packet,omitempty"`
}

func TestBucketVectors(t *testing.T) {
	const path = "../../../test/vectors/buckets.json"
	rep := func(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }
	var inst, salt, attempt, epoch ID
	copy(inst[:], rep(1))
	copy(salt[:], rep(2))
	copy(attempt[:], rep(3))
	copy(epoch[:], rep(4))
	o := PasskeyScope{Installation: inst, RPID: "aqmas.example.com", RawID: []byte("raw credential id"), Scope: ScopeInstallation, Salt: salt}
	prf := rep(5)
	kek, err := o.DeriveKEK(prf)
	if err != nil {
		t.Fatal(err)
	}
	defer kek.Destroy()
	canonical := `{"action":"approve","id":"r1","object":"request","v":2}`
	descriptor := `{"attempt_id":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","buckets":[],"object":"bucket-open","v":1}`
	ch := OpenChallenge([]byte(canonical), []byte(descriptor))
	priv := rep(6)
	rk, err := ecdh.P256().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString
	want := bucketVectors{Installation: h(inst[:]), RPID: o.RPID, Cred: h(o.RawID), Scope: o.Scope, Salt: h(salt[:]), PRF: h(prf), KEKInfo: h(o.KEKInfo()), KEK: h(kek.Bytes()),
		Canonical: canonical, Descriptor: descriptor, Challenge: h(ch), AttemptID: h(attempt[:]), Epoch: h(epoch[:]), RecipientPriv: h(priv), RecipientPub: h(rk.PublicKey().Bytes()),
		Info: h(OpenInfo(inst, "approve")), AAD: h(OpenAAD(attempt, epoch, ch, o.RawID))}
	var got bucketVectors
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &got)
	}
	if os.Getenv("AQMAS_UPDATE_VECTORS") != "" {
		want.Browser = got.Browser
		out, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	browser := got.Browser
	got.Browser = nil
	if got != want {
		t.Fatalf("vectors drifted; regenerate with AQMAS_UPDATE_VECTORS=1\n got %+v\nwant %+v", got, want)
	}
	if browser == nil {
		t.Skip("no browser packet yet (web/test/fixtures/make-open-packet.ts)")
	}
	r, _ := RecipientFromScalar(priv)
	dec := func(s string) []byte { x, _ := hex.DecodeString(s); return x }
	p, err := r.Open(OpenInfo(inst, "approve"), OpenAAD(attempt, epoch, ch, o.RawID), dec(browser.Enc), dec(browser.Ciphertext))
	if err != nil {
		t.Fatal("browser packet did not open:", err)
	}
	keys, err := SplitKEKs(p)
	if err != nil || len(keys) != 2 || !bytes.Equal(keys[0].Bytes(), kek.Bytes()) || h(keys[1].Bytes()) != browser.KEK2 {
		t.Fatal("browser packet carries other KEKs", err)
	}
	for _, k := range keys {
		k.Destroy()
	}
}

func TestBrowserScopeRoundTripAndBinding(t *testing.T) {
	inst := RandomID()
	scope, scopePub, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Destroy()
	browser, browserPub, _ := NewKeyPair()
	defer browser.Destroy()
	other, otherPub, _ := NewKeyPair()
	defer other.Destroy()
	kek, _ := ImportKEK(bytes.Repeat([]byte{9}, 32))
	defer kek.Destroy()
	o := BrowserScope{Installation: inst, RPID: "aqmas.example.com", RawID: []byte("cred-a"), Scope: ScopeInstallation, WrapID: RandomID(), Browser: browserPub}
	wrap, err := o.Wrap(kek, scope, scopePub)
	if err != nil || len(wrap) != 73 {
		t.Fatalf("wrap: %v %d", err, len(wrap))
	}
	sealed, err := o.SealKEK(kek)
	if err != nil || len(sealed) != 113 {
		t.Fatalf("seal: %v %d", err, len(sealed))
	}
	if bytes.Contains(wrap, kek.Bytes()) || bytes.Contains(sealed, kek.Bytes()) || bytes.Contains(wrap, scope.Bytes()) {
		t.Fatal("a ciphertext contains its plaintext")
	}
	// The browser's half: open the KEK, then the broker unwraps the scope key with it.
	got, err := o.OpenKEK(browser, sealed)
	if err != nil || !bytes.Equal(got.Bytes(), kek.Bytes()) {
		t.Fatal("the browser key did not open its sealed KEK")
	}
	sk, err := o.Unwrap(got, wrap, scopePub)
	got.Destroy()
	if err != nil || !sk.Matches(scopePub) {
		t.Fatal("unwrap")
	}
	sk.Destroy()
	// Every binding: another passkey, scope, wrap ID, browser key or installation opens nothing.
	for what, x := range map[string]BrowserScope{
		"passkey":      {Installation: inst, RPID: o.RPID, RawID: []byte("cred-b"), Scope: o.Scope, WrapID: o.WrapID, Browser: browserPub},
		"scope":        {Installation: inst, RPID: o.RPID, RawID: o.RawID, Scope: "org-1", WrapID: o.WrapID, Browser: browserPub},
		"wrap id":      {Installation: inst, RPID: o.RPID, RawID: o.RawID, Scope: o.Scope, WrapID: RandomID(), Browser: browserPub},
		"rp":           {Installation: inst, RPID: "other.example.com", RawID: o.RawID, Scope: o.Scope, WrapID: o.WrapID, Browser: browserPub},
		"installation": {Installation: RandomID(), RPID: o.RPID, RawID: o.RawID, Scope: o.Scope, WrapID: o.WrapID, Browser: browserPub},
	} {
		if _, err := x.OpenKEK(browser, sealed); err == nil {
			t.Fatalf("sealed KEK opened under another %s", what)
		}
		if _, err := x.Unwrap(kek, wrap, scopePub); err == nil {
			t.Fatalf("wrap opened under another %s", what)
		}
	}
	x := o
	x.Browser = otherPub
	if _, err := x.OpenKEK(other, sealed); err == nil {
		t.Fatal("sealed KEK opened by another browser key")
	}
	if _, err := x.Unwrap(kek, wrap, scopePub); err == nil {
		t.Fatal("wrap opened under another browser key")
	}
	if _, err := o.OpenKEK(other, sealed); err == nil {
		t.Fatal("sealed KEK opened with the wrong private key")
	}
	// A PRF wrap and a browser wrap are different objects under the same KEK.
	p := PasskeyScope{Installation: inst, RPID: o.RPID, RawID: o.RawID, Scope: o.Scope, Salt: o.WrapID}
	if _, err := p.Unwrap(kek, wrap, scopePub); err == nil {
		t.Fatal("a browser wrap opened as a PRF wrap")
	}
	wrap[20] ^= 1
	if _, err := o.Unwrap(kek, wrap, scopePub); err == nil {
		t.Fatal("tampered wrap opened")
	}
	if len(BrowserKeyID(browserPub)) != 32 || BrowserKeyID(browserPub) == BrowserKeyID(otherPub) {
		t.Fatal("fingerprint")
	}
}

// test/vectors/browserkey.json pins what the browser derives for a remembered
// browser (web/test/browserKey.test.ts): the HPKE info of a sealed KEK and a
// sealed KEK made here that the page's code must open.
func TestBrowserKeyVectors(t *testing.T) {
	const path = "../../../test/vectors/browserkey.json"
	rep := func(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }
	var inst, wrapID ID
	copy(inst[:], rep(1))
	copy(wrapID[:], rep(2))
	priv := rep(7)
	bk, err := ecdh.P256().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := bk.PublicKey().Bytes()
	o := BrowserScope{Installation: inst, RPID: "aqmas.example.com", RawID: []byte("raw credential id"), Scope: ScopeInstallation, WrapID: wrapID, Browser: pub}
	kek, _ := ImportKEK(rep(8))
	defer kek.Destroy()
	type vectors struct{ Installation, RPID, Cred, Scope, WrapID, BrowserPriv, BrowserPub, KeyID, KEKInfo, KEK, SealedKEK string }
	h := hex.EncodeToString
	want := vectors{Installation: h(inst[:]), RPID: o.RPID, Cred: h(o.RawID), Scope: o.Scope, WrapID: h(wrapID[:]), BrowserPriv: h(priv), BrowserPub: h(pub), KeyID: BrowserKeyID(pub), KEKInfo: h(o.KEKInfo()), KEK: h(kek.Bytes())}
	if os.Getenv("AQMAS_UPDATE_VECTORS") != "" {
		sealed, err := o.SealKEK(kek)
		if err != nil {
			t.Fatal(err)
		}
		want.SealedKEK = h(sealed)
		out, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	var got vectors
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &got)
	}
	if err != nil {
		t.Fatal(err)
	}
	want.SealedKEK = got.SealedKEK
	if got != want {
		t.Fatalf("vectors differ:\n got %+v\nwant %+v", got, want)
	}
	sealed, _ := hex.DecodeString(got.SealedKEK)
	browser, _ := ImportKEK(priv) // a P-256 scalar in a locked page
	defer browser.Destroy()
	k, err := o.OpenKEK(browser, sealed)
	if err != nil || !bytes.Equal(k.Bytes(), kek.Bytes()) {
		t.Fatal("the committed sealed KEK does not open")
	}
	k.Destroy()
}
