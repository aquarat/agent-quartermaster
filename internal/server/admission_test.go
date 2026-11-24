package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// agentErr performs an agent call and returns the status and the error code of the body.
func agentErr(t *testing.T, c *http.Client, method, url string, body any) (int, api.Error) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var e api.Error
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &e)
	return resp.StatusCode, e
}

// A host enrolled after the cutover and not admitted anywhere is told about its own state
// ("not_admitted"), identically for targets that exist and targets that do not. Once it is
// admitted to some organisation, what it cannot see is the same "not_found" as a missing
// object, as it is for every admitted host.
func TestEnrolledButNotAdmitted(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	first := e.enrollHost("first")
	organise(t, e)
	late := e.enrollHost("late")
	fc, lc := e.agentClient(&first), e.agentClient(&late)
	_, line := newSSHKey(t)
	create := func(target string) api.AccessRequest {
		return api.AccessRequest{Kind: "ssh", SSH: &api.SSHRequest{TargetHost: target, LoginUser: "alice", PublicKey: line}, Reason: "test", TTLSeconds: 600, Requester: api.Requester{Tool: "other", User: "alice"}}
	}
	calls := map[string]func(c *http.Client) (int, api.Error){
		"resolve a real target": func(c *http.Client) (int, api.Error) {
			return agentErr(t, c, "GET", e.agent.URL+"/v1/ssh-target?target=db-1&user=alice", nil)
		},
		"resolve a missing target": func(c *http.Client) (int, api.Error) {
			return agentErr(t, c, "GET", e.agent.URL+"/v1/ssh-target?target=nope&user=alice", nil)
		},
		"request a real target": func(c *http.Client) (int, api.Error) {
			return agentErr(t, c, "POST", e.agent.URL+"/v1/requests", create("db-1"))
		},
		"request a missing target": func(c *http.Client) (int, api.Error) {
			return agentErr(t, c, "POST", e.agent.URL+"/v1/requests", create("nope"))
		},
		"grants": func(c *http.Client) (int, api.Error) { return agentErr(t, c, "GET", e.agent.URL+"/v1/grants", nil) },
		"a signer key": func(c *http.Client) (int, api.Error) {
			return agentErr(t, c, "GET", e.agent.URL+"/v2/sign/key?path=a/b/c", nil)
		},
	}
	expect := func(when, code string) {
		t.Helper()
		for name, call := range calls {
			st, body := call(lc)
			if st != http.StatusNotFound || body.Code != code {
				t.Fatalf("%s, %s: got %d %q (%s), want 404 %q", when, name, st, body.Code, body.Message, code)
			}
			if code == api.ErrNotAdmitted && !strings.Contains(body.Message, "not admitted to an organisation") {
				t.Fatalf("%s, %s: message %q", when, name, body.Message)
			}
		}
	}
	expect("not admitted anywhere", api.ErrNotAdmitted)

	// The admitted host keeps the indistinguishable answer for what it cannot see ...
	if st, body := calls["resolve a missing target"](fc); st != 404 || body.Code != api.ErrNotFound {
		t.Fatalf("admitted host, missing target: %d %q", st, body.Code)
	}
	if st, _ := calls["resolve a real target"](fc); st != 200 {
		t.Fatalf("admitted host, real target: %d", st)
	}

	// ... and so does the late host once it is admitted to an organisation that does not
	// hold these targets: nothing tells it whether they exist elsewhere.
	for _, q := range []string{
		`INSERT INTO organisations(id,slug,title,revision) VALUES('` + vOrg + `','client-a','Client A',1)`,
		`INSERT INTO org_policies VALUES('` + vOrg + `',1,3600,86400,1,3600,86400,1)`,
		`INSERT INTO org_hosts SELECT '` + vOrg + `',id,1,1 FROM hosts WHERE name='late'`,
	} {
		_, err := e.s.store.DB().Exec(q)
		requireNoError(t, err)
	}
	expect("admitted to another organisation", api.ErrNotFound)

	// Its admission ends: it is back to hearing about its own state.
	_, err := e.s.store.DB().Exec(`UPDATE org_hosts SET active=0,generation=generation+1 WHERE org_id=?`, vOrg)
	requireNoError(t, err)
	expect("admission ended", api.ErrNotAdmitted)
}
