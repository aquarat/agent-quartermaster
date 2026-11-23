//go:build linux

package seal

import (
	"bytes"
	"slices"
	"testing"

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
