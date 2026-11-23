//go:build linux

package server

import "net/http"
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/cfaccess"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"net/http/httptest"
	"testing"
	"time"
)

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func TestDelegationBoundaries(t *testing.T) {
	ctx := t.Context()
	logs := &syncBuffer{}
	e := newEnv(t)
	e.setupOwner()
	cert := e.enrollHost("workload")
	organise(t, e)
	fix := sealBuckets(t, e, logs)
	agent := e.agentClient(&cert)
	s := e.s
	one, _, status := e.request(agent, "db-1", "alice", 300)
	mustStatus(t, "first", status, 201)
	two, _, status := e.request(agent, "db-1", "alice", 300)
	mustStatus(t, "second", status, 201)
	sess := ids.Hash(e.sess)
	pk, err := s.store.Q().SessionPasskeyID(ctx, sess)
	requireNoError(t, err)
	req := func(v any) *http.Request {
		b, _ := json.Marshal(v)
		return httptest.NewRequest("POST", "/", bytes.NewReader(b))
	}
	choices := map[string]any{"items": []ordinaryChoice{{one.ID, "deny", 0}, {two.ID, "deny", 0}}}
	beg, err := s.batchBegin(ctx, req(choices), sess)
	requireNoError(t, err)
	ch := beg.(api.ChallengeResponse)
	if ch.Open != nil {
		t.Fatal("a batch of denials offered an open")
	}
	_, err = s.store.DB().Exec(`UPDATE requests SET status='cancelled' WHERE id=?`, two.ID)
	requireNoError(t, err)
	_, err = s.batchFinish(ctx, req(api.DecideRequest{ChallengeID: ch.ChallengeID, Assertion: e.auth.Assert(canon.Challenge(ch.Canonical))}), sess)
	if err == nil {
		t.Fatal("partial batch accepted")
	}
	first, err := s.store.Q().GetRequest(ctx, one.ID)
	requireNoError(t, err)
	if first.Status != "pending" {
		t.Fatal("batch leaked first decision")
	}
	profiles, err := s.windowProfiles(ctx, s.store.Q(), sess, pk)
	requireNoError(t, err)
	p := profiles[0]
	if !p.Personal || !p.Settings.Enabled || len(p.Settings.Sets) == 0 {
		t.Fatal("personal defaults missing")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	requireNoError(t, err)
	public, err := key.PublicKey.Bytes()
	requireNoError(t, err)
	input := windowOpen{p.Org, 300, encodeID(public), encodeID(e.auth.CredID)}
	if _, err = s.windowTerms(ctx, s.store.Q(), sess, pk, ids.Secret(32), input); err == nil {
		t.Fatal("window without Access")
	}
	ctx = context.WithValue(ctx, ctxAccessSub, "verified-owner")
	s.access = &cfaccess.Verifier{}
	_, err = s.store.DB().Exec(`UPDATE web_sessions SET access_sub=? WHERE hash=?`, "verified-owner", sess)
	requireNoError(t, err)
	terms, err := s.windowTerms(ctx, s.store.Q(), sess, pk, ids.Secret(32), input)
	requireNoError(t, err)
	w, rec, err := s.stageWindow(ctx, s.store.Q(), sess, pk, terms, "test")
	requireNoError(t, err)
	s.seal.windows.publish(w)
	in := windowClick{ID: rec.ID, Token: rec.Token, Choice: ordinaryChoice{one.ID, "deny", 0}}
	prep, err := s.windowPrepare(ctx, req(in), sess)
	requireNoError(t, err)
	prop := prep.(map[string]string)
	in.Proposal = prop["proposal_id"]
	sigHash := sha256.Sum256(windowMessage(fix.inst[:], rec.ID, in.Proposal, canon.Challenge(prop["canonical"])))
	rr, ss, err := ecdsa.Sign(rand.Reader, key, sigHash[:])
	requireNoError(t, err)
	in.Proof = encodeID(append(rr.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...))
	_, err = s.windowConfirm(ctx, req(in), sess)
	requireNoError(t, err)
	if _, err = s.windowConfirm(ctx, req(in), sess); err == nil {
		t.Fatal("proposal replay")
	}
	for range 5 {
		e.clock.Advance(25 * time.Second)
		_, err = s.windowPresence(ctx, req(in), sess)
	}
	if err == nil {
		t.Fatal("heartbeat extended idle")
	}
}
func TestAlwaysTap(t *testing.T) {
	a := canon.Action{Kind: "ssh", LoginUser: "alice", TTLSeconds: 60, ScopeBinding: api.ScopeBinding{SoftCap: 300, HardCap: 300}}
	r := store.Request{TTLRequested: 60, LoginUser: "alice"}
	if !ordinaryRisk(a, &r, false) {
		t.Fatal("ordinary")
	}
	for _, f := range []func(*canon.Action, *store.Request){func(x *canon.Action, _ *store.Request) { x.StandingHours = 1 }, func(x *canon.Action, _ *store.Request) { x.StandingSeconds = 1 }, func(x *canon.Action, _ *store.Request) { x.Indefinite = true }, func(x *canon.Action, _ *store.Request) { x.LoginUser = "root" }, func(_ *canon.Action, r *store.Request) { r.TTLRequested = 301 }, func(x *canon.Action, _ *store.Request) { x.Kind = "env" }, func(x *canon.Action, _ *store.Request) { x.Kind = "cloudflare"; x.Mode = "token"; x.Scope = "cf.read" }, func(x *canon.Action, _ *store.Request) {
		x.Kind = "cloudflare"
		x.Mode = "proxy"
		x.Scope = "cf.read.private"
	}} {
		b, rr := a, r
		f(&b, &rr)
		if ordinaryRisk(b, &rr, false) {
			t.Fatal("always-tap decision eligible")
		}
	}
}
