package seal

import (
	"context"
	"errors"
	"slices"
	"sync"
)

var ErrLocked = errors.New("seal: waiting for owner unlock")

// Publish serializes the start of a bounded response write with the fence.
// Caller must already hold a lease; fn must not acquire another gate lock.
func (g *Gate) Publish(fn func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.mk == nil {
		return ErrLocked
	}
	return fn()
}

// Gate belongs to one process. Drain is terminal (explicit lock requires a
// process restart). Idle long-polls must not hold leases. On wake, acquire a
// new lease and keep it through the final payload write.
type Gate struct {
	mu      sync.Mutex
	gen     Generation
	check   []byte
	mk      *Key
	work    context.Context
	cancel  context.CancelFunc
	active  sync.WaitGroup
	closed  bool
	changed chan struct{}
}

func NewGate(g Generation, check []byte) (*Gate, error) {
	if !g.valid() || len(check) != 41+len(marker) || check[0] != 1 {
		return nil, errRecord
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Gate{gen: g, check: slices.Clone(check), work: ctx, cancel: cancel, changed: make(chan struct{})}, nil
}

// Install takes ownership only on success. commit performs the caller's final
// transaction (recheck owner, signer, session and wrap; audit the unlock).
func (g *Gate) Install(k *Key, commit func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.mk != nil {
		return errAttempt
	}
	if err := g.gen.Verify(k, g.check); err != nil {
		return err
	}
	if err := commit(); err != nil {
		return err
	}
	g.mk = k
	close(g.changed)
	g.changed = make(chan struct{})
	return nil
}
func (g *Gate) Status() (unlocked bool, changed <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mk != nil && !g.closed, g.changed
}

// WithKey never lends the master outside the operation's dynamic extent. The
// worker is responsible for respecting cancellation, bounded I/O and clearing
// derived secrets before returning. Do not call Drain from inside a lease.
func (g *Gate) WithKey(ctx context.Context, op func(context.Context, *Key) error) error {
	g.mu.Lock()
	if g.closed || g.mk == nil {
		g.mu.Unlock()
		return ErrLocked
	}
	g.active.Add(1)
	mk := g.mk
	worker, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.work, cancel)
	g.mu.Unlock()
	defer g.active.Done()
	defer cancel()
	defer stop()
	if err := worker.Err(); err != nil {
		return err
	}
	return op(worker, mk)
}
func (g *Gate) Drain() {
	g.mu.Lock()
	if !g.closed {
		g.closed = true
		g.cancel()
		close(g.changed)
	}
	g.mu.Unlock()
	g.active.Wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mk.Destroy()
	g.mk = nil
}
