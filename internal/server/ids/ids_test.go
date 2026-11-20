package ids

import (
	"strings"
	"testing"
	"time"
)

func TestULID(t *testing.T) {
	a, b := newAt(time.UnixMilli(1)), newAt(time.UnixMilli(2))
	if len(a) != 26 || strings.Trim(a, crockford) != "" || a >= b {
		t.Fatalf("ulids %q %q", a, b)
	}
	if New() == New() {
		t.Fatal("duplicate")
	}
	if Hash("x") == Hash("y") || len(Hash("x")) != 64 || len(Secret(32)) != 43 {
		t.Fatal("hash/secret")
	}
}
