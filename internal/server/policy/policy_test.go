package policy

import (
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

var ttl = config.Defaults().TTL

func TestClampTTL(t *testing.T) {
	for in, want := range map[int]int{-5: 1800, 0: 1800, 1: 60, 59: 60, 60: 60, 900: 900, 28800: 28800, 28801: 28800, 1 << 30: 28800} {
		if got := ClampTTL(in, ttl); got != want {
			t.Errorf("ClampTTL(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestApproverTTL(t *testing.T) {
	if got, err := ApproverTTL(1800, 0, ttl); err != nil || got != 1800 {
		t.Fatal("0 must keep the requested ttl")
	}
	if got, err := ApproverTTL(1800, 600, ttl); err != nil || got != 600 {
		t.Fatal("shorten failed")
	}
	if _, err := ApproverTTL(1800, 1801, ttl); err == nil {
		t.Fatal("lengthened")
	}
	if _, err := ApproverTTL(1800, 10, ttl); err == nil {
		t.Fatal("below minimum")
	}
	if StandingHours(25, ttl) == nil || StandingHours(-1, ttl) == nil || StandingHours(24, ttl) != nil {
		t.Fatal("standing hours bounds")
	}
}

func TestMatches(t *testing.T) {
	now := time.Now()
	r := Rule{HostID: 1, Kind: "ssh", Target: "db-1", LoginUser: "alice", MaxTTL: 600, ExpiresAt: now.Add(time.Hour)}
	c := Candidate{HostID: 1, Kind: "ssh", Target: "db-1", LoginUser: "alice", TTL: 600}
	if !Matches(r, c, now) {
		t.Fatal("identical candidate must match")
	}
	mut := map[string]func(*Rule, *Candidate){
		"host":    func(_ *Rule, c *Candidate) { c.HostID = 2 },
		"kind":    func(_ *Rule, c *Candidate) { c.Kind = "github" },
		"target":  func(_ *Rule, c *Candidate) { c.Target = "forgejo" },
		"user":    func(_ *Rule, c *Candidate) { c.LoginUser = "root" },
		"ttl":     func(_ *Rule, c *Candidate) { c.TTL = 601 },
		"zero":    func(_ *Rule, c *Candidate) { c.TTL = 0 },
		"expired": func(r *Rule, _ *Candidate) { r.ExpiresAt = now },
		"revoked": func(r *Rule, _ *Candidate) { r.Revoked = true },
	}
	for name, f := range mut {
		r2, c2 := r, c
		f(&r2, &c2)
		if Matches(r2, c2, now) {
			t.Errorf("%s: matched", name)
		}
	}
	c.TTL = 300
	if !Matches(r, c, now) {
		t.Fatal("shorter ttl must match")
	}
}
