package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/vauth"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestPinnedUpdateProof(t *testing.T) {
	now := time.Now()
	const origin = "https://approvals.example.com"
	a := vauth.New(origin)
	u, _ := url.Parse(origin)
	a.RPID = u.Hostname()
	x, y := a.Key.X.FillBytes(make([]byte, 32)), a.Key.Y.FillBytes(make([]byte, 32))
	pub, e := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if e != nil {
		t.Fatal(e)
	}
	pins := []keyPin{{ID: a.CredID, PublicKey: pub}}
	h := strings.Repeat("a", 64)
	sha := strings.Repeat("1", 40)
	action := canon.Action{Object: "update", Action: "approve", ID: sha, Update: canon.Update{FromVersion: "0.1.0", ToVersion: "0.2.0", FromCommit: strings.Repeat("0", 40), ToCommit: sha, DaemonHash: h, LinuxARM: h, LinuxAMD: h, DarwinARM: h}}
	text, e := canon.Build(action, canon.NewNonce(), now)
	if e != nil {
		t.Fatal(e)
	}
	req := approval{Canonical: text, Assertion: a.Assert(canon.Challenge(text))}
	if _, e = verify(req, origin, pins, now); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"from_version", "to_version", "from_commit", "to_commit", "daemon_sha256", "linux_arm64_sha256", "linux_amd64_sha256", "darwin_arm64_sha256"} {
		changed := req
		i := strings.Index(text, `"`+key+`":"`)
		if i < 0 {
			t.Fatal(key)
		}
		pos := i + len(key) + 4
		changed.Canonical = text[:pos] + "9" + text[pos+1:]
		if _, e = verify(changed, origin, pins, now); e == nil {
			t.Fatal("unbound", key)
		}
	}
	if _, e = verify(req, origin, nil, now); e == nil {
		t.Fatal("unpinned key")
	}
	if _, e = verify(req, origin, pins, now.Add(3*time.Minute)); e == nil {
		t.Fatal("expired")
	}
	req.Assertion = a.AssertWith(canon.Challenge(text), vauth.AssertOpts{Flags: vauth.FlagUP})
	if _, e = verify(req, origin, pins, now); e == nil {
		t.Fatal("missing UV")
	}
}
