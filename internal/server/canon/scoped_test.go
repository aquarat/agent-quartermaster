package canon

import (
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
