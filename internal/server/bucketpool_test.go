//go:build linux

package server

import (
	"sync"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/seal"
)

func TestBucketPoolHoldsAndWipe(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := newBucketPool(func() time.Time { return now })
	changes := 0
	p.onChange = func() { changes++ }
	a, b := seal.RandomID(), seal.RandomID()
	ka, _, _ := seal.NewKeyPair()
	kb, _, _ := seal.NewKeyPair()
	p.install(a, ka, bucketHold{Kind: "grant", Ref: "grant:1", Until: now.Add(time.Minute)}, bucketHold{Kind: "window", Ref: "window:w"})
	p.install(b, kb, bucketHold{Kind: "instant", Ref: "tap:x"})
	if !p.isOpen(a) || !p.isOpen(b) || p.count() != 2 || changes != 2 {
		t.Fatal("install")
	}
	// A second install of an open bucket keeps the first key and adds holds.
	dup, _, _ := seal.NewKeyPair()
	p.install(a, dup, bucketHold{Kind: "env", Ref: "env:1"})
	if dup.Bytes() != nil {
		t.Fatal("duplicate key not wiped")
	}
	p.release("tap:x")
	if p.isOpen(b) || kb.Bytes() != nil {
		t.Fatal("bucket without holds not wiped")
	}
	if err := p.use(b, func(*seal.Key) error { return nil }); err != errBucketClosed {
		t.Fatal("closed bucket used")
	}
	now = now.Add(2 * time.Minute)
	p.expire(now)
	if !p.isOpen(a) || len(p.snapshot()[a].Holds) != 2 {
		t.Fatal("expiry dropped the wrong holds")
	}
	p.release("window:w", "env:1")
	if p.isOpen(a) || ka.Bytes() != nil {
		t.Fatal("not wiped after the last hold")
	}
}

func TestBucketPoolUseOutlivesRelease(t *testing.T) {
	p := newBucketPool(time.Now)
	id := seal.RandomID()
	k, _, _ := seal.NewKeyPair()
	p.install(id, k, bucketHold{Kind: "instant", Ref: "tap:1"})
	started, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = p.use(id, func(k *seal.Key) error {
			close(started)
			<-release
			if k.Bytes() == nil {
				t.Error("key wiped during use")
			}
			return nil
		})
	}()
	<-started
	p.closeAll()
	if p.use(id, func(*seal.Key) error { return nil }) == nil || p.isOpen(id) || p.hold(id, bucketHold{Ref: "late"}) {
		t.Error("a closed bucket accepted a new use or hold while an old use ran")
	}
	close(release)
	wg.Wait()
	if p.isOpen(id) || k.Bytes() != nil {
		t.Fatal("closed bucket survived its last use")
	}
}
