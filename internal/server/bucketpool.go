package server

import (
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/seal"
)

// bucketPool is the only place an opened bucket key lives (docs/BUCKETS.md
// §5): bucket ID → scalar in a locked page plus the holds that justify it.
// The key is wiped as soon as the last hold is gone and no operation is using
// it. Nothing here is persisted: a restart starts empty.
type bucketPool struct {
	mu   sync.Mutex
	open map[seal.ID]*openBucket
	now  func() time.Time
	// onChange is called (outside the lock) after a bucket opens or closes.
	onChange func()
}

type openBucket struct {
	key     *seal.Key
	users   int
	closing bool // no holds left: no new use; wiped when the last use ends
	holds   map[string]bucketHold
	opened  time.Time
}

// bucketHold is one reason to keep a bucket open. Ref is "<kind>:<id>" and
// unique per bucket; Until zero means "until an event" (revoke, collect…).
type bucketHold struct {
	Kind   string    `json:"kind"`
	Ref    string    `json:"ref"`
	Reason string    `json:"reason"`
	Until  time.Time `json:"until,omitzero"`
	Since  time.Time `json:"since"`
}

var errBucketClosed = errors.New("bucket closed")

func newBucketPool(now func() time.Time) *bucketPool {
	return &bucketPool{open: map[seal.ID]*openBucket{}, now: now}
}

func (p *bucketPool) changed() {
	if p.onChange != nil {
		p.onChange()
	}
}

// install takes ownership of k. If the bucket is already open the new copy is
// wiped and the holds are added to the open one.
func (p *bucketPool) install(id seal.ID, k *seal.Key, holds ...bucketHold) {
	p.mu.Lock()
	ob := p.open[id]
	opened := ob == nil
	if ob == nil {
		ob = &openBucket{key: k, holds: map[string]bucketHold{}, opened: p.now()}
		p.open[id] = ob
	} else {
		k.Destroy()
		ob.closing = false
	}
	for _, h := range holds {
		if h.Since.IsZero() {
			h.Since = p.now()
		}
		ob.holds[h.Ref] = h
	}
	p.mu.Unlock()
	if opened {
		p.changed()
	}
}

// hold adds holds to an open bucket; false if it is closed.
func (p *bucketPool) hold(id seal.ID, holds ...bucketHold) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	ob := p.open[id]
	if ob == nil || ob.closing {
		return false
	}
	for _, h := range holds {
		if h.Since.IsZero() {
			h.Since = p.now()
		}
		ob.holds[h.Ref] = h
	}
	return true
}

func (p *bucketPool) isOpen(id seal.ID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	ob := p.open[id]
	return ob != nil && !ob.closing
}

// use lends the key for the dynamic extent of fn. fn must not retain it.
func (p *bucketPool) use(id seal.ID, fn func(*seal.Key) error) error {
	p.mu.Lock()
	ob := p.open[id]
	if ob == nil || ob.closing {
		p.mu.Unlock()
		return errBucketClosed
	}
	ob.users++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		ob.users--
		closed := p.reap(id, ob)
		if p.open[id] != ob && ob.users == 0 && ob.key != nil {
			ob.key.Destroy() // evicted while in use
			ob.key = nil
		}
		p.mu.Unlock()
		if closed {
			p.changed()
		}
	}()
	return fn(ob.key)
}

// evict closes these buckets at once, whatever their holds (rekey replaced
// their keys). A use in flight keeps its key until it ends, then it is wiped;
// a later open installs the new key.
func (p *bucketPool) evict(ids ...seal.ID) {
	p.mu.Lock()
	closed := false
	for _, id := range ids {
		ob := p.open[id]
		if ob == nil {
			continue
		}
		delete(p.open, id)
		clear(ob.holds)
		ob.closing = true
		if ob.users == 0 {
			ob.key.Destroy()
			ob.key = nil
		}
		closed = true
	}
	p.mu.Unlock()
	if closed {
		p.changed()
	}
}

// reap wipes an idle bucket with no holds. Caller holds mu.
func (p *bucketPool) reap(id seal.ID, ob *openBucket) bool {
	if len(ob.holds) > 0 || p.open[id] != ob {
		return false
	}
	ob.closing = true
	if ob.users > 0 {
		return false
	}
	ob.key.Destroy()
	delete(p.open, id)
	return true
}

// release drops every hold with one of these refs, in every bucket.
func (p *bucketPool) release(refs ...string) {
	p.drop(func(_ seal.ID, h bucketHold) bool { return slices.Contains(refs, h.Ref) })
}

// drop removes the holds for which gone returns true and wipes buckets left
// without a reason. An in-flight use finishes first (its key is wiped after).
func (p *bucketPool) drop(gone func(seal.ID, bucketHold) bool) {
	p.mu.Lock()
	closed := false
	for id, ob := range p.open {
		for ref, h := range ob.holds {
			if gone(id, h) {
				delete(ob.holds, ref)
			}
		}
		closed = p.reap(id, ob) || closed
	}
	p.mu.Unlock()
	if closed {
		p.changed()
	}
}

// expire drops holds whose Until has passed.
func (p *bucketPool) expire(now time.Time) {
	p.drop(func(_ seal.ID, h bucketHold) bool { return !h.Until.IsZero() && !now.Before(h.Until) })
}

// closeAll drops every hold; keys in use are wiped when their use ends.
func (p *bucketPool) closeAll() {
	p.drop(func(seal.ID, bucketHold) bool { return true })
}

// openBucketView is what Admin shows: never the key.
type openBucketView struct {
	ID     seal.ID      `json:"id"`
	Opened time.Time    `json:"opened_at"`
	Holds  []bucketHold `json:"holds"`
}

func (p *bucketPool) snapshot() map[seal.ID]openBucketView {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[seal.ID]openBucketView{}
	for id, ob := range p.open {
		if ob.closing {
			continue
		}
		v := openBucketView{ID: id, Opened: ob.opened}
		for _, h := range ob.holds {
			v.Holds = append(v.Holds, h)
		}
		sort.Slice(v.Holds, func(i, j int) bool { return v.Holds[i].Ref < v.Holds[j].Ref })
		out[id] = v
	}
	return out
}

// holds returns every (bucket, hold) pair, for the reconcile pass.
func (p *bucketPool) allHolds() map[seal.ID][]bucketHold {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[seal.ID][]bucketHold{}
	for id, ob := range p.open {
		for _, h := range ob.holds {
			out[id] = append(out[id], h)
		}
	}
	return out
}

// held counts every key still in memory, including buckets that are closing while an
// operation finishes with them.
func (p *bucketPool) held() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.open)
}

func (p *bucketPool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, ob := range p.open {
		if !ob.closing {
			n++
		}
	}
	return n
}
