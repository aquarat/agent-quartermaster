package config

import (
	"strings"
	"testing"
)

func TestResolveAndRejectShadowing(t *testing.T) {
	c, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	c.Targets[1].Address = c.Targets[0].Address
	c.Targets[0].Aliases = []string{"db.example.com"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ s, user, name string }{{"db.example.com", "alice", "db-1"}, {"192.0.2.61", "git", "forgejo"}, {"192.0.2.61:2222", "git", "forgejo"}} {
		r, err := c.Resolve(tc.s, tc.user)
		if err != nil || r.Name != tc.name {
			t.Fatalf("%v: %v %v", tc, r, err)
		}
	}
	c.Targets[1].Users = append(c.Targets[1].Users, "alice")
	if _, err := c.Resolve("192.0.2.61", "alice"); err == nil || !strings.Contains(err.Error(), "db-1, forgejo") {
		t.Fatal(err)
	}
	if r, err := c.Resolve("192.0.2.61:22", "alice"); err != nil || r.Name != "db-1" {
		t.Fatal(r, err)
	}
	for _, alias := range []string{"DB.EXAMPLE.COM", "DB-1", "192.0.2.61", "::ffff:192.0.2.61"} {
		c.Targets[1].Aliases = []string{alias}
		if c.Validate() == nil {
			t.Fatalf("accepted shadowing alias %q", alias)
		}
	}
}
