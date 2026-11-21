//go:build linux

package seal

import (
	"bytes"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestBrowserHPKEVectors(t *testing.T) {
	var vectors []struct{ Purpose, Info, AAD, Pub, Priv, Enc, Ciphertext string }
	b, err := os.ReadFile("../../../test/vectors/hpke.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	raw := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	rep := func(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }
	for _, v := range vectors {
		k, err := kem.NewPrivateKey(raw(v.Priv))
		if err != nil {
			t.Fatal(err)
		}
		info := tuple("hpke-finish", rep(1), []byte(v.Purpose))
		aad := tuple("hpke-aad", rep(2), rep(3), rep(4))
		if !bytes.Equal(raw(v.Pub), k.PublicKey().Bytes()) || !bytes.Equal(raw(v.Info), info) || !bytes.Equal(raw(v.AAD), aad) {
			t.Fatal("wrong HPKE context")
		}
		r, err := hpke.NewRecipient(raw(v.Enc), k, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := r.Open(aad, raw(v.Ciphertext))
		if err != nil || !bytes.Equal(msg, frame(frame(nil, rep(5)), []byte("test assertion"))) {
			t.Fatal("browser packet did not authenticate")
		}
	}
}

// Reference ciphertexts are produced by libsodium, not by this package.
func TestSuite1ReferenceOpen(t *testing.T) {
	var v struct {
		KEK, Wrap, Check string
		Info             string `json:"kek_info"`
		Records          map[string]struct{ Payload, Wrap string }
	}
	b, err := os.ReadFile("../../../test/vectors/suite1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	raw := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	id := func(x byte) ID { return ID(bytes.Repeat([]byte{x}, 32)) }
	c := Credential{Generation{id(1), 7}, "example.test", []byte{255, 1}, id(2)}
	if !bytes.Equal(c.context("mk-kek"), raw(v.Info)) {
		t.Fatal("KEK info")
	}
	k, err := importKey(raw(v.KEK))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	mk, err := c.Unwrap(k, raw(v.Wrap), raw(v.Check))
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Destroy()
	for role, r := range v.Records {
		o := Object{Role: role, Revision: 2, Blob: id(5)}
		switch role {
		case "ssh-ca", "internal-ca", "ntfy-topic":
			o.Global = "global-id"
		default:
			o.Org, o.Service, o.Set = "org", "service", "set"
		}
		if role == "cf-proxy" || role == "cf-minter" {
			o.Issuer, o.Account, o.ParentVersion = "issuer", "account", 3
		}
		p, err := o.Decrypt(c.Generation, mk, Envelope{raw(r.Payload), raw(r.Wrap)})
		if err != nil || string(p) != "vector payload" {
			t.Fatalf("%s vector rejected", role)
		}
	}
}
