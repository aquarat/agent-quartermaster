//go:build linux

package server

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
)

// Synchronize at the poll select, after ownership and pending-state checks,
// rather than hoping a sleep puts a handler on the vulnerable side of a lock.
type pollBarrier struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *pollBarrier) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}
func TestSealedPollFencesAfterWake(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	cert := e.enrollHost("pollhost")
	client := e.agentClient(&cert)
	req, _, code := e.request(client, "db-1", "alice", 180)
	mustStatus(t, "create", code, 201)
	ctx := t.Context()
	host, err := e.s.store.Q().ActiveHostByName(ctx, "pollhost")
	if err != nil {
		t.Fatal(err)
	}
	g := seal.Generation{Installation: seal.RandomID(), Version: 1}
	mk, err := seal.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	check, err := g.CheckRecord(mk)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := seal.NewGate(g, check)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Install(mk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	e.s.seal = &sealRuntime{gate: gate, attempts: seal.NewAttempts(nil), stop: make(chan struct{})}
	barrier := &pollBarrier{Context: ctx, waiting: make(chan struct{})}
	r := httptest.NewRequestWithContext(barrier, "GET", "/v1/requests/"+req.ID+"?wait=20s", nil)
	r.SetPathValue("id", req.ID)
	out := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { e.s.handleRequestStatus(out, r, host); close(done) }()
	select {
	case <-barrier.waiting:
	case <-time.After(3 * time.Second):
		t.Fatal("poll did not reach wait")
	}
	gate.Drain()
	if _, err = e.s.store.DB().Exec(`UPDATE requests SET status='approved' WHERE id=?`, req.ID); err != nil {
		t.Fatal(err)
	}
	e.s.bcast.notify()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("poll remained asleep")
	}
	if out.Code != 423 || !strings.Contains(out.Body.String(), `"locked"`) {
		t.Fatalf("poll not fenced: %d", out.Code)
	}
}

func TestUnknownFormatNeverCreatesCA(t *testing.T) {
	e := newEnv(t)
	if _, err := e.s.store.DB().Exec(`PRAGMA user_version=99`); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(CADir(e.cfg.DataDir), pki.SSHCAKeyFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if s, err := New(Options{Config: e.cfg}); err == nil {
		s.Close()
		t.Fatal("opened unknown format")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("generated CA before checking database format")
	}
}
