package canon

import (
	"encoding/json"
	"os"
	"testing"
)

// The vectors are shared with the web UI's verifier (web/test/bastion.test.ts): what one side
// signs the other must parse, and both must refuse the same malformed or contradictory text.
func TestBastionVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../web/test/fixtures/bastion-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Valid   []struct{ Level, Text string }
		Invalid []struct{ Why, Text string }
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Valid) < 4 || len(v.Invalid) < 8 {
		t.Fatalf("vectors missing: %d valid, %d invalid", len(v.Valid), len(v.Invalid))
	}
	for _, c := range v.Valid {
		sg, err := Parse(c.Text)
		if err != nil {
			t.Errorf("valid %s vector refused: %v\n%s", c.Level, err, c.Text)
			continue
		}
		if sg.Kind != KindBastion || sg.Level != c.Level || sg.StandingHours != 0 || sg.OrgID != "" || sg.V != 1 {
			t.Errorf("parsed %+v", sg.Action)
		}
		if again, err := Build(sg.Action, sg.Nonce, sg.IssuedAt); err != nil || again != c.Text {
			t.Errorf("round trip: %v\n%s\n%s", err, c.Text, again)
		}
	}
	for _, c := range v.Invalid {
		if _, err := Parse(c.Text); err == nil {
			t.Errorf("invalid vector accepted (%s): %s", c.Why, c.Text)
		}
	}
}

func TestOpenList(t *testing.T) {
	if got := OpenList(nil); got != "[]" {
		t.Fatal(got)
	}
	if got := OpenList([]string{"b", "a<&>", "b"}); got != `["a<&>","b"]` {
		t.Fatal(got)
	}
	for _, bad := range []string{"", "null", `["b","a"]`, `["a","a"]`, `["a", "b"]`, `[1]`, `{"a":1}`, `["a"] `} {
		if _, err := ParseOpenList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
