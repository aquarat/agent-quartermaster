package cfproxy

import (
	"math"
	"sync"
	"time"
)

// limiter: per-host token buckets (capacity = the per-minute rate, refilled continuously).
type limiter struct {
	mu      sync.Mutex
	buckets map[limKey]*bucket
}

type limKey struct {
	host  int64
	write bool
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter { return &limiter{buckets: map[limKey]*bucket{}} }

// take consumes one token; it returns ok, or the seconds until a token is available.
func (l *limiter) take(host int64, write bool, perMinute int, now time.Time) (bool, int) {
	if perMinute <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := limKey{host, write}
	b := l.buckets[k]
	capacity := float64(perMinute)
	rate := capacity / 60 // tokens per second
	if b == nil {
		b = &bucket{tokens: capacity, last: now}
		l.buckets[k] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(capacity, b.tokens+el*rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := int(math.Ceil((1 - b.tokens) / rate))
	if wait < 1 {
		wait = 1
	}
	return false, wait
}
