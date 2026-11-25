package canon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func TestScopedRoundTripAndDowngrade(t *testing.T) {
	a := Action{Object: ObjectRequest, Action: ActionApprove, ID: "request", Kind: "cloudflare", Scope: "cf.read", Mode: "proxy", TTLSeconds: 1800, Class: "agent", Address: "192.0.2.5", RequestingHost: "builder", ScopeBinding: api.ScopeBinding{OrgID: strings.Repeat("a", 32), OrgTitle: "personal", OrgSlug: "personal", ServiceID: strings.Repeat("b", 32), ServiceTitle: "dns-cdn", ServiceSlug: "dns-cdn", SetID: strings.Repeat("c", 32), SetSlug: "proxy", SetTitle: "proxy", PolicyRevision: 1, SetRevision: 1, ServiceRevision: 1, AdmissionGeneration: 3, HostID: "enrollment", AccountID: strings.Repeat("d", 32), ProfileRevision: strings.Repeat("e", 64)}}
	a.SoftCap, a.HardCap = 3600, 7200
	text, err := Build(a, NewNonce(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(text)
	if err != nil || s.V != 2 || s.Action != a {
		t.Fatal("scoped canonical did not round trip", err)
	}
	for _, bad := range []string{strings.Replace(text, `"v":2`, `"v":1`, 1), strings.Replace(text, `"kind":"cloudflare"`, `"kind":"new-provider"`, 1), strings.Replace(text, `"set_revision":1,`, "", 1), strings.Replace(text, `"policy_revision":1`, `"policy_revision":2,"policy_revision":1`, 1)} {
		if _, err := Parse(bad); err == nil {
			t.Error("accepted noncanonical scoped action")
		}
	}
}

// The 0.10.0 policy switches are omitted while false: a policy replacement
// that uses neither is the text every earlier release signed, one that turns a
// switch on round-trips, and a plan that spells a switch out as false (or puts
// it out of order) is not canonical.
func TestPolicySwitchesRoundTrip(t *testing.T) {
	org := api.CatalogueNode{ID: strings.Repeat("a", 32), Slug: "client-a", Title: "Client A", Revision: 1}
	base := api.DurationPolicy{Default: 3600, Soft: 86400, Indefinite: true, StandingDefault: 3600, StandingSoft: 86400, StandingIndefinite: true}
	rules := []api.CatalogueRule{}
	plan := func(old, next api.DurationPolicy) string {
		b, err := json.Marshal(api.CatalogueChange{Owner: strings.Repeat("b", 32), Org: org, OldPolicy: &old, Policy: &next, OldRules: &rules, Rules: &rules, ResultRevision: 2})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const before = `{"owner_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","organisation":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","slug":"client-a","title":"Client A","revision":1},"old_policy":{"default_seconds":3600,"soft_cap_seconds":86400,"indefinite":true,"standing_default_seconds":3600,"standing_soft_cap_seconds":86400,"standing_indefinite":true},"new_policy":{"default_seconds":3600,"soft_cap_seconds":86400,"indefinite":true,"standing_default_seconds":3600,"standing_soft_cap_seconds":86400,"standing_indefinite":true},"old_rules":[],"new_rules":[],"result_revision":2}`
	if got := plan(base, base); got != before {
		t.Fatalf("a policy without the switches changed its signed shape:\n%s", got)
	}
	on := base
	on.Discovery, on.DenyGet = true, true
	for _, p := range []string{before, plan(base, on), plan(on, base)} {
		text, err := Build(Action{Object: "org_policy", Action: "replace", ID: org.ID, Plan: p}, NewNonce(), time.Now())
		if err != nil {
			t.Fatalf("build: %v\n%s", err, p)
		}
		s, err := Parse(text)
		if err != nil || s.V != 2 || s.Plan != p {
			t.Fatalf("policy plan did not round trip: %v", err)
		}
	}
	if !strings.Contains(plan(base, on), `"standing_indefinite":true,"discovery":true,"deny_get":true},"old_rules"`) {
		t.Fatalf("switches are not last, in order: %s", plan(base, on))
	}
	for name, bad := range map[string]string{
		"an explicit false": strings.Replace(before, `"standing_indefinite":true},"old_rules"`, `"standing_indefinite":true,"discovery":false},"old_rules"`, 1),
		"out of order":      strings.Replace(plan(base, on), `"discovery":true,"deny_get":true`, `"deny_get":true,"discovery":true`, 1),
		"an unknown switch": strings.Replace(before, `"standing_indefinite":true},"old_rules"`, `"standing_indefinite":true,"list_values":true},"old_rules"`, 1),
	} {
		if text, err := Build(Action{Object: "org_policy", Action: "replace", ID: org.ID, Plan: bad}, NewNonce(), time.Now()); err == nil {
			if _, err = Parse(text); err == nil {
				t.Errorf("%s was accepted as canonical", name)
			}
		}
	}
}
