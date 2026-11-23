package server

import (
	"encoding/json"
	"testing"
)

// The open descriptor is canonical JSON (sorted keys): the page re-serialises it and refuses
// any other spelling. encoding/json writes struct fields in declaration order, so every struct
// that ends up inside a descriptor must declare its fields in sorted key order.
func TestDescriptorStructsAreCanonical(t *testing.T) {
	for name, v := range map[string]any{
		"bucket": map[string]any{"buckets": []descriptorBucket{{Hold: "instant", ID: "i", Kind: "ssh-ca", Label: "SSH user CA", Scope: "installation", Until: ""}}},
		"legacy": map[string]any{"legacy": &legacyView{Installation: "a", MKVersion: 1, PRFSalt: "b"}},
	} {
		text, err := reviewJSON(v)
		if err != nil {
			t.Fatal(err)
		}
		var generic any
		if err = json.Unmarshal([]byte(text), &generic); err != nil {
			t.Fatal(err)
		}
		canonical, err := reviewJSON(generic) // maps encode with sorted keys
		if err != nil || canonical != text {
			t.Errorf("%s: %s is not canonical (want %s)", name, text, canonical)
		}
	}
}
