package main

import (
	"reflect"
	"testing"
)

func TestParseFlags(t *testing.T) {
	spec := map[string]bool{"ttl": true, "why": true, "fresh": false}
	f, err := parseFlags([]string{"--ttl", "10m", "db-1", "--why=check disk", "--fresh", "--", "df", "-h", "--why"}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if f.str["ttl"] != "10m" || f.str["why"] != "check disk" || !f.bool["fresh"] {
		t.Errorf("flags %+v", f)
	}
	if !reflect.DeepEqual(f.pos, []string{"db-1"}) || !reflect.DeepEqual(f.cmd, []string{"df", "-h", "--why"}) {
		t.Errorf("pos %q cmd %q", f.pos, f.cmd)
	}
	for _, bad := range [][]string{{"--bogus"}, {"--ttl"}, {"--fresh=1"}} {
		if _, err := parseFlags(bad, spec); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if f, _ := parseFlags([]string{"db-1"}, spec); f.cmd != nil {
		t.Error("cmd should be nil without --")
	}
}
