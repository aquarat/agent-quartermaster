//go:build linux

package seal

import (
	"bytes"
	"context"
	"crypto/hpke"
	"errors"
	"slices"
	"testing"
	"time"

	"filippo.io/age"
)

func fixture(t *testing.T) (Generation, *Key, []byte) {
	t.Helper()
	g := Generation{RandomID(), 7}
	k, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	check, err := g.CheckRecord(k)
	if err != nil {
		t.Fatal(err)
	}
	return g, k, check
}
func TestRecoveryAndWrap(t *testing.T) {
	g, mk, check := fixture(t)
	c := Credential{g, "approval.example", []byte{0, 1, 255}, RandomID()}
	_, kek, _ := fixture(t)
	w, err := c.Wrap(kek, mk)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Unwrap(kek, w, check)
	if err != nil {
		t.Fatal(err)
	}
	out.Destroy()
	again, _ := c.Wrap(kek, mk)
	if bytes.Equal(w[1:25], again[1:25]) {
		t.Fatal("reused nonce")
	}
	for _, change := range []func(*Credential){func(c *Credential) { c.RawID = []byte{0, 1} }, func(c *Credential) { c.RPID += "x" }, func(c *Credential) { c.Salt[0] ^= 1 }, func(c *Credential) { c.Version++ }, func(c *Credential) { c.Installation[7] ^= 1 }} {
		bad := c
		change(&bad)
		if k, err := bad.Unwrap(kek, w, check); err == nil {
			k.Destroy()
			t.Fatal("swapped binding")
		}
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := id.Recipient().String()
	packet, err := g.RecoveryPacket(r, mk)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := g.Recover(r, id, packet, check)
	if err != nil {
		t.Fatal(err)
	}
	rec.Destroy()
	for _, p := range [][]byte{append(slices.Clone(packet), 0), packet[:len(packet)-1], check} {
		if _, err := g.Recover(r, id, p, check); err == nil {
			t.Fatal("invalid recovery accepted")
		}
	}
	_, other, _ := fixture(t)
	fake, err := g.RecoveryPacket(r, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.Recover(r, id, fake, check); err == nil {
		t.Fatal("public recipient alone can replace MK")
	}
}
func TestPayloadBindings(t *testing.T) {
	g, mk, _ := fixture(t)
	want := []byte("sentinel, never stored as plaintext")
	o := Object{Org: "org", Service: "service", Set: "set", Role: "cf-proxy", Revision: 2, Blob: RandomID(), Issuer: "provider", Account: "account", ParentVersion: 2}
	e, err := o.Encrypt(g, mk, want)
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.Decrypt(g, mk, e)
	if err != nil || !bytes.Equal(out, want) {
		t.Fatal("failed roundtrip")
	}
	for _, f := range []func(*Object){func(b *Object) { b.Org += "!" }, func(b *Object) { b.Service += "!" }, func(b *Object) { b.Set += "!" }, func(b *Object) { b.Role = "cf-minter" }, func(b *Object) { b.Revision++ }, func(b *Object) { b.Blob[0] ^= 1 }, func(b *Object) { b.Issuer += "!" }, func(b *Object) { b.Account += "!" }, func(b *Object) { b.ParentVersion++ }} {
		bad := o
		f(&bad)
		if _, err := bad.Decrypt(g, mk, e); err == nil {
			t.Fatal("swapped object")
		}
	}
	for _, v := range [][]byte{e.Payload, e.WrappedDEK} {
		for i := range v {
			v[i] ^= 1
			if _, err := o.Decrypt(g, mk, e); err == nil {
				t.Fatal("modified record")
			}
			v[i] ^= 1
		}
	}
	e2, _ := o.Encrypt(g, mk, want)
	e.WrappedDEK = e2.WrappedDEK
	if _, err := o.Decrypt(g, mk, e); err == nil {
		t.Fatal("mixed payload and DEK")
	}
}
func TestAttempts(t *testing.T) {
	g, _, _ := fixture(t)
	c := Credential{g, "rp.example", []byte("id"), RandomID()}
	now := time.Now()
	a := NewAttempts(func() time.Time { return now })
	defer a.Close()
	start := func() (Begin, []byte, []byte) {
		t.Helper()
		b, err := a.Begin("session", "unlock", "", c)
		if err != nil {
			t.Fatal(err)
		}
		at := a.pending[b.ID]
		enc, s, err := hpke.NewSender(at.key.PublicKey(), hpke.HKDFSHA256(), hpke.AES128GCM(), tuple("hpke-finish", g.Installation[:], []byte("unlock")))
		if err != nil {
			t.Fatal(err)
		}
		ct, err := s.Seal(tuple("hpke-aad", at.id[:], a.epoch[:], at.digest[:]), frame(frame(nil, bytes.Repeat([]byte{4}, 32)), []byte("assertion")))
		if err != nil {
			t.Fatal(err)
		}
		return b, enc, ct
	}
	n := 0
	apply := func(c Credential, _ string, d [32]byte, p []byte, k *Key) error {
		n++
		if !bytes.Equal(k.page[:32], bytes.Repeat([]byte{4}, 32)) || string(p) != "assertion" {
			t.Fatal("bad plaintext")
		}
		return nil
	}
	b, enc, ct := start()
	finish := func() error { return a.FinishBound("session", "unlock", b.ID, enc, ct, apply) }
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	if finish() == nil {
		t.Fatal("replay")
	}
	b, enc, ct = start()
	ct[0] ^= 1
	if finish() == nil {
		t.Fatal("tamper")
	}
	ct[0] ^= 1
	if finish() == nil {
		t.Fatal("retry after failure")
	}
	b, enc, ct = start()
	if a.FinishBound("other", "unlock", b.ID, enc, ct, apply) == nil {
		t.Fatal("wrong session")
	}
	b, enc, ct = start()
	now = now.Add(attemptTTL)
	if finish() == nil {
		t.Fatal("expired")
	}
	b, enc, ct = start()
	a.Close()
	if finish() == nil || n != 1 {
		t.Fatal("stale epoch")
	}
}
func TestDrainWakeRestart(t *testing.T) {
	g, mk, check := fixture(t)
	gate, err := NewGate(g, check)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.WithKey(t.Context(), nil); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	ok, wake := gate.Status()
	if ok {
		t.Fatal("started unlocked")
	}
	fail := errors.New("revoked")
	if err := gate.Install(mk, func() error { return fail }); !errors.Is(err, fail) {
		t.Fatal(err)
	}
	if err := gate.Install(mk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	<-wake
	entered, end, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go gate.WithKey(t.Context(), func(ctx context.Context, k *Key) error { close(entered); <-ctx.Done(); <-end; return nil })
	<-entered
	_, wake = gate.Status()
	go func() { gate.Drain(); close(done) }()
	<-wake
	if err := gate.WithKey(t.Context(), nil); !errors.Is(err, ErrLocked) {
		t.Fatal("wake after fence")
	}
	select {
	case <-done:
		t.Fatal("did not wait for lease")
	default:
	}
	close(end)
	<-done
	if mk.page != nil {
		t.Fatal("MK handle not destroyed")
	}
	again, err := NewGate(g, check)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Drain()
	if ok, _ = again.Status(); ok {
		t.Fatal("restored unlocked")
	}
}
