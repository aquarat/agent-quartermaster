package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func item(name string, msg []byte, s Scheme) Item {
	a := sha256.Sum256(msg)
	it := Item{Name: name, Size: int64(len(msg)), SHA256: hex.EncodeToString(a[:])}
	switch s.Input {
	case "message":
		it.Message = msg
		if it.Message == nil {
			it.Message = []byte{}
		}
	case "sha512":
		b := sha512.Sum512(msg)
		it.SHA512 = hex.EncodeToString(b[:])
	}
	return it
}

// RFC 8032 section 7.1 (tests 1 and 2) and 7.3 (Ed25519ph); RFC 6979 A.2.5.
func TestKnownVectors(t *testing.T) {
	pure, _ := Lookup("ed25519")
	for _, v := range [][4]string{
		{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
	} {
		priv, pub, err := pure.ParsePrivate([]byte(v[0]))
		if err != nil || hex.EncodeToString(pub) != v[1] {
			t.Fatal("public key", err)
		}
		it := item("vector.bin", unhex(t, v[2]), pure)
		sig, err := pure.Sign(priv, it)
		if err != nil || hex.EncodeToString(sig) != v[3] || !pure.Verify(pub, it, sig) {
			t.Fatalf("ed25519 vector: %x %v", sig, err)
		}
	}
	ph, _ := Lookup("ed25519ph")
	priv, pub, err := ph.ParsePrivate([]byte("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"))
	if err != nil {
		t.Fatal(err)
	}
	it := item("abc", []byte("abc"), ph)
	sig, err := ph.Sign(priv, it)
	if err != nil || hex.EncodeToString(sig) != "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406" || !ph.Verify(pub, it, sig) {
		t.Fatalf("ed25519ph vector: %x %v", sig, err)
	}
	// Pure Ed25519 over the raw digest, checked against the standard library.
	d, _ := Lookup("ed25519-sha256")
	it = item("image.bin", bytes.Repeat([]byte{7}, 100000), d)
	sig, err = d.Sign(priv, it)
	sum := sha256.Sum256(bytes.Repeat([]byte{7}, 100000))
	if err != nil || !ed25519.Verify(pub, sum[:], sig) || !d.Verify(pub, it, sig) || pure.Verify(pub, Item{Name: "x", Size: 32, SHA256: hex.EncodeToString(sum[:]), Message: sum[:]}, sig) {
		// the last check: as a *pure* item the digest bytes have a different SHA-256, so Valid refuses
		t.Fatal("ed25519-sha256", err)
	}
	ec, _ := Lookup("ecdsa-p256-sha256")
	priv, pub, err = ec.ParsePrivate([]byte("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"))
	if err != nil || !strings.EqualFold(hex.EncodeToString(pub), "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299") {
		t.Fatalf("p256 public key %x %v", pub, err)
	}
	r, _ := new(big.Int).SetString("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16)
	s, _ := new(big.Int).SetString("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 16)
	known, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	it = item("sample", []byte("sample"), ec)
	if !ec.Verify(pub, it, known) {
		t.Fatal("RFC 6979 signature refused")
	}
	sig, err = ec.Sign(priv, it)
	if err != nil || !ec.Verify(pub, it, sig) {
		t.Fatal("ecdsa round trip", err)
	}
	it.SHA256 = strings.Repeat("0", 64)
	if ec.Verify(pub, it, sig) {
		t.Fatal("signature verified for another digest")
	}
}

func TestItemsAreUnambiguous(t *testing.T) {
	msg := []byte("manifest")
	for _, s := range All() {
		good := item("m.bin", msg, s)
		if err := s.Valid(good); err != nil {
			t.Fatal(s.ID, err)
		}
		for name, f := range map[string]func(*Item){
			"path":         func(i *Item) { i.Name = "../m.bin" },
			"control":      func(i *Item) { i.Name = "m\n.bin" },
			"bidi":         func(i *Item) { i.Name = "m‮.bin" },
			"upper digest": func(i *Item) { i.SHA256 = strings.ToUpper(i.SHA256) },
			"short digest": func(i *Item) { i.SHA256 = i.SHA256[:62] },
			"extra sha512": func(i *Item) {
				if s.Input == "sha512" {
					i.SHA512 = ""
				} else {
					i.SHA512 = strings.Repeat("a", 128)
				}
			},
			"message mismatch": func(i *Item) {
				if s.Input == "message" {
					i.Message = []byte("other")
				} else {
					i.Message = msg
				}
			},
		} {
			bad := good
			f(&bad)
			if s.Valid(bad) == nil {
				t.Fatalf("%s accepted %s", s.ID, name)
			}
			if _, err := s.Sign(bytes.Repeat([]byte{1}, 32), bad); err == nil {
				t.Fatalf("%s signed %s", s.ID, name)
			}
		}
	}
	pure, _ := Lookup("ed25519")
	if pure.Valid(item("big", make([]byte, MaxMessage+1), pure)) == nil {
		t.Fatal("oversize message accepted")
	}
	if _, ok := Lookup("ed25519-sha512"); ok {
		t.Fatal("unknown scheme resolved")
	}
}

func TestKeyFormats(t *testing.T) {
	ed, _ := Lookup("ed25519")
	ec, _ := Lookup("ecdsa-p256-sha256")
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8 := func(k any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	openssh := func(k any) []byte {
		b, err := ssh.MarshalPrivateKey(k, "")
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(b)
	}
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	for _, in := range [][]byte{pkcs8(edKey), openssh(edKey), []byte(hex.EncodeToString(edKey.Seed()) + "\n"), []byte(strings.ToUpper(hex.EncodeToString(edKey)))} {
		priv, pub, err := ed.ParsePrivate(in)
		if err != nil || !bytes.Equal(priv, edKey.Seed()) || !bytes.Equal(pub, edKey[32:]) {
			t.Fatal("ed25519 import", err)
		}
	}
	scalar, _ := ecKey.Bytes()
	for _, in := range [][]byte{pkcs8(ecKey), openssh(ecKey), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}), []byte(hex.EncodeToString(scalar))} {
		priv, pub, err := ec.ParsePrivate(in)
		want, _ := ecKey.PublicKey.Bytes()
		if err != nil || !bytes.Equal(priv, scalar) || !bytes.Equal(pub, want) {
			t.Fatal("p256 import", err)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	enc, _ := ssh.MarshalPrivateKeyWithPassphrase(edKey, "", []byte("sentinel-pass"))
	for _, in := range [][]byte{pkcs8(ecKey), pkcs8(p384), nil, []byte("sentinel"), []byte(hex.EncodeToString(edKey.Seed()) + "00"), pem.EncodeToMemory(enc), []byte(hex.EncodeToString(append(bytes.Clone(edKey.Seed()), make([]byte, 32)...)))} {
		if _, _, err := ed.ParsePrivate(in); err == nil || strings.Contains(err.Error(), "sentinel") {
			t.Fatalf("ed25519 accepted or echoed a wrong key: %v", err)
		}
	}
	if _, _, err := ec.ParsePrivate(pkcs8(edKey)); err == nil {
		t.Fatal("p256 accepted an ed25519 key")
	}
	if _, _, err := ec.ParsePrivate(pkcs8(p384)); err == nil {
		t.Fatal("p256 accepted a P-384 key")
	}
	for _, s := range All() {
		priv, pub, err := s.Generate()
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.PublicPEM(pub)
		blk, _ := pem.Decode([]byte(p))
		if err != nil || blk == nil {
			t.Fatal("public PEM", err)
		}
		if _, err = x509.ParsePKIXPublicKey(blk.Bytes); err != nil {
			t.Fatal(err)
		}
		it := item("a.bin", []byte("payload"), s)
		sig, err := s.Sign(priv, it)
		if err != nil || !s.Verify(pub, it, sig) {
			t.Fatal(s.ID, err)
		}
		for _, other := range All() {
			if other.ID != s.ID && other.Key == s.Key && other.Verify(pub, item("a.bin", []byte("payload"), other), sig) {
				t.Fatalf("%s signature verifies as %s", s.ID, other.ID)
			}
		}
	}
}
