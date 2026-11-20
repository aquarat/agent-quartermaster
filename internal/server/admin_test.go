package server

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func TestAdminHostIdentityBinding(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/api/ui/hosts", "/api/ui/help"} {
		mustStatus(t, path, e.webDo("GET", path, nil, nil), 401)
	}
	e.setupOwner()
	e.cfg.AgentAPIURL = "https://agent.example.com:8443"
	var help api.HelpConfig
	mustStatus(t, "help", e.webDo("GET", "/api/ui/help", nil, &help), 200)
	if help.AgentAPIURL != e.cfg.AgentAPIURL || help.CAPin != e.s.PKI().CAPin() {
		t.Fatal(help)
	}
	host := e.agentClient(ptr(e.enrollHost("a")))
	e.enrollClass("b", api.ClassOwner)
	req, _, _ := e.request(host, "192.0.2.61:22", "alice", 600)
	path := "/api/ui/requests/" + req.ID
	approve, _ := e.challenge(path, api.ChallengeRequest{Action: "approve"})
	var it api.PendingItem
	e.webDo("GET", path, nil, &it)
	if it.SSH.TargetHost != "db-1" || it.SSH.TargetAddress != "192.0.2.61" || it.SSH.RequestedTarget != "192.0.2.61:22" {
		t.Fatal(it.SSH)
	}
	list := func() []api.HostInfo {
		var hs []api.HostInfo
		mustStatus(t, "hosts", e.webDo("GET", "/api/ui/hosts", nil, &hs), 200)
		return hs
	}
	hs := list()
	if len(hs) != 2 || hs[0].LastRequestAt == nil || hs[1].LastRequestAt != nil || hs[1].Class != api.ClassOwner || hs[0].Address == "" {
		t.Fatal(hs)
	}
	a, b := "/api/ui/hosts/"+hs[0].ID, "/api/ui/hosts/"+hs[1].ID
	rev := api.ChallengeRequest{Action: "revoke"}
	ca, _ := e.challenge(a, rev)
	cb, _ := e.challenge(b, rev)
	as, _ := e.auth.AssertOptions(ca.PublicKey)
	mustStatus(t, "A assertion with B challenge", e.webDo("POST", b+"/revoke", api.DecideRequest{ChallengeID: cb.ChallengeID, Assertion: as}, nil), 403)
	mustStatus(t, "A on B path", e.decide(b, "revoke", ca, nil), 400)
	mustStatus(t, "revoke A", e.approve(a, "revoke", rev), 200)
	hs = list()
	if hs[0].RevokedAt == nil || hs[1].RevokedAt != nil {
		t.Fatal(hs)
	}
	mustStatus(t, "stale request approval", e.decide(path, "decide", approve, nil), 409)
	r, err := e.s.store.Q().GetRequest(t.Context(), req.ID)
	if err != nil || r.Status != api.StatusExpired {
		t.Fatalf("request: %+v, %v", r, err)
	}
}

func TestOwnerDevicePolicy(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	for _, tc := range []struct {
		name, class string
		ttl, hours  int
	}{{"agent", api.ClassAgent, 28800, 24}, {"owner", api.ClassOwner, 86400, 720}} {
		t.Run(tc.name, func(t *testing.T) {
			h := e.agentClient(ptr(e.enrollClass(tc.name, tc.class)))
			request := func(host *http.Client, ttl int) string {
				r, _, st := e.request(host, "db-1", "alice", ttl)
				mustStatus(t, "create", st, 201)
				return "/api/ui/requests/" + r.ID
			}
			path := request(h, 100000)
			cr, _ := e.challenge(path, api.ChallengeRequest{Action: "approve"})
			if ttl := uiCheck(t, cr)["ttl_seconds"]; fmt.Sprint(ttl) != fmt.Sprint(tc.ttl) {
				t.Fatalf("ttl %v", ttl)
			}
			mustStatus(t, "approve", e.decide(path, "decide", cr, nil), 200)
			path = request(h, 600)
			_, st := e.challenge(path, api.ChallengeRequest{Action: "approve", StandingHours: tc.hours + 1})
			mustStatus(t, "outside class limit", st, 400)
			mustStatus(t, "class limit", e.approve(path, "decide", api.ChallengeRequest{Action: "approve", StandingHours: tc.hours}), 200)
		})
	}
}
