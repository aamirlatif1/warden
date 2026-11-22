package ratelimit_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/ratelimit"
)

// Integration tests: they need Redis (make test-db sets the address).

func redisClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("WARDEN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("WARDEN_TEST_REDIS_ADDR not set; run make test-db")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// clock is a fake, settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func uniq(t *testing.T) string {
	t.Helper()
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "it:" + hex.EncodeToString(b[:]) + ":"
}

func newLimiter(t *testing.T, rdb *redis.Client, prefix string, limit int, window time.Duration, clk *clock) *ratelimit.Limiter {
	t.Helper()
	l, err := ratelimit.New(rdb, ratelimit.Config{Prefix: prefix, Limit: limit, Window: window, Now: clk.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func allow(t *testing.T, l *ratelimit.Limiter, key string) ratelimit.Decision {
	t.Helper()
	d, err := l.Allow(context.Background(), key)
	if err != nil {
		t.Fatalf("Allow(%q): %v", key, err)
	}
	return d
}

func TestNewRejectsBadConfig(t *testing.T) {
	rdb := redisClient(t)
	for name, cfg := range map[string]ratelimit.Config{
		"empty prefix":   {Limit: 5, Window: time.Minute},
		"zero limit":     {Prefix: "p:", Limit: 0, Window: time.Minute},
		"negative limit": {Prefix: "p:", Limit: -1, Window: time.Minute},
		"zero window":    {Prefix: "p:", Limit: 5},
		"sub-ms window":  {Prefix: "p:", Limit: 5, Window: 500 * time.Microsecond},
	} {
		if _, err := ratelimit.New(rdb, cfg); err == nil {
			t.Errorf("%s: New accepted %+v", name, cfg)
		}
	}
}

func TestEmptyKeyIsAnError(t *testing.T) {
	rdb := redisClient(t)
	l := newLimiter(t, rdb, uniq(t), 5, time.Minute, newClock())
	if _, err := l.Allow(context.Background(), ""); err == nil {
		t.Fatal("empty key allowed: every caller would share one bucket")
	}
}

func TestAllowsUpToLimitThenRefuses(t *testing.T) {
	rdb := redisClient(t)
	clk := newClock()
	l := newLimiter(t, rdb, uniq(t), 3, time.Minute, clk)

	for i := 1; i <= 3; i++ {
		d := allow(t, l, "ip-1")
		if !d.Allowed || d.Limit != 3 || d.Remaining != 3-i || d.RetryAfter != 0 {
			t.Fatalf("call %d: %+v, want allowed, remaining %d, retry 0", i, d, 3-i)
		}
		clk.Advance(time.Second)
	}
	d := allow(t, l, "ip-1")
	if d.Allowed || d.Remaining != 0 {
		t.Fatalf("4th call: %+v, want refused with remaining 0", d)
	}
	// Oldest event at t0; now t0+3s; it leaves the window at t0+60s.
	if d.RetryAfter != 57*time.Second {
		t.Fatalf("RetryAfter = %v, want 57s (oldest event + window - now)", d.RetryAfter)
	}
}

func TestWindowBoundaryIsExclusive(t *testing.T) {
	rdb := redisClient(t)
	clk := newClock()
	l := newLimiter(t, rdb, uniq(t), 1, time.Minute, clk)

	if !allow(t, l, "k").Allowed {
		t.Fatal("first call refused")
	}
	clk.Advance(time.Minute - time.Millisecond)
	if d := allow(t, l, "k"); d.Allowed || d.RetryAfter != time.Millisecond {
		t.Fatalf("at t0+window-1ms: %+v, want refused with RetryAfter 1ms", d)
	}
	clk.Advance(time.Millisecond)
	if d := allow(t, l, "k"); !d.Allowed {
		t.Fatalf("at t0+window: %+v, want allowed (event at t0 has left (t-W, t])", d)
	}
}

func TestSlidesRatherThanResetting(t *testing.T) {
	// A fixed-window counter would allow 2*Limit across a bucket edge.
	rdb := redisClient(t)
	clk := newClock()
	l := newLimiter(t, rdb, uniq(t), 4, 10*time.Second, clk)

	clk.Advance(8 * time.Second) // t0+8s: late in a would-be fixed bucket
	for range 4 {
		if !allow(t, l, "k").Allowed {
			t.Fatal("burst refused below the limit")
		}
	}
	clk.Advance(3 * time.Second) // t0+11s: a fixed window would have reset
	if d := allow(t, l, "k"); d.Allowed {
		t.Fatalf("allowed at t0+11s: %+v; 4 events at t0+8s are still in the window", d)
	}
	clk.Advance(7 * time.Second) // t0+18s: they left at t0+18s
	if d := allow(t, l, "k"); !d.Allowed || d.Remaining != 3 {
		t.Fatalf("at t0+18s: %+v, want allowed with remaining 3", d)
	}
}

func TestRefusedCallsAreNotRecorded(t *testing.T) {
	rdb := redisClient(t)
	clk := newClock()
	l := newLimiter(t, rdb, uniq(t), 2, 10*time.Second, clk)

	allow(t, l, "k")
	allow(t, l, "k")
	for range 20 { // hammering while blocked
		clk.Advance(100 * time.Millisecond)
		if allow(t, l, "k").Allowed {
			t.Fatal("allowed over the limit")
		}
	}
	// Now t0+2s. The two allowed events (both at t0) leave at t0+10s; the
	// refused ones must not keep the key locked beyond that.
	clk.Advance(8 * time.Second)
	if d := allow(t, l, "k"); !d.Allowed || d.Remaining != 1 {
		t.Fatalf("after the window: %+v, want allowed with remaining 1 (refused calls counted?)", d)
	}
}

func TestSameMillisecondCountsTwice(t *testing.T) {
	rdb := redisClient(t)
	clk := newClock() // never advanced
	l := newLimiter(t, rdb, uniq(t), 3, time.Minute, clk)

	for i := 1; i <= 3; i++ {
		if d := allow(t, l, "k"); !d.Allowed || d.Remaining != 3-i {
			t.Fatalf("call %d: %+v", i, d)
		}
	}
	if allow(t, l, "k").Allowed {
		t.Fatal("4th call in the same ms allowed: events with equal timestamps collapsed into one")
	}
}

func TestKeysAndPrefixesAreIsolated(t *testing.T) {
	rdb := redisClient(t)
	clk := newClock()
	p := uniq(t)
	a := newLimiter(t, rdb, p+"a:", 1, time.Minute, clk)
	b := newLimiter(t, rdb, p+"b:", 1, time.Minute, clk)

	if !allow(t, a, "x").Allowed || allow(t, a, "x").Allowed {
		t.Fatal("limit 1 not enforced")
	}
	if !allow(t, a, "y").Allowed {
		t.Fatal("key y shares key x's budget")
	}
	if !allow(t, b, "x").Allowed {
		t.Fatal("prefix b shares prefix a's budget")
	}
}

func TestConcurrentCallersNeverExceedLimit(t *testing.T) {
	rdb := redisClient(t)
	clk := newClock()
	prefix := uniq(t)
	// Two limiter values on the same prefix stand in for two replicas.
	r1 := newLimiter(t, rdb, prefix, 10, time.Minute, clk)
	r2 := newLimiter(t, rdb, prefix, 10, time.Minute, clk)

	var allowed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 60 {
		l := r1
		if i%2 == 1 {
			l = r2
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, err := l.Allow(context.Background(), "hot")
			if err != nil {
				t.Error(err)
				return
			}
			if d.Allowed {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := allowed.Load(); got != 10 {
		t.Fatalf("allowed %d of 60 concurrent calls, want exactly 10 (check and add must be atomic)", got)
	}
}

func TestKeyExpiresAndIsTrimmed(t *testing.T) {
	rdb := redisClient(t)
	clk := newClock()
	prefix := uniq(t)
	l := newLimiter(t, rdb, prefix, 100, 2*time.Second, clk)
	ctx := context.Background()

	for range 5 {
		allow(t, l, "k")
		clk.Advance(time.Second)
	}
	keys, err := rdb.Keys(ctx, prefix+"*").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys under prefix = %v, want exactly one (prefix + key)", keys)
	}
	if keys[0] != prefix+"k" {
		t.Fatalf("key = %q, want %q", keys[0], prefix+"k")
	}
	ttl := rdb.PTTL(ctx, keys[0]).Val()
	if ttl <= 0 || ttl > 2*time.Second {
		t.Fatalf("PTTL = %v, want 0 < ttl <= window (2s)", ttl)
	}
	// Events at t0..t0+4s; one more call at t0+5s trims everything <= t0+3s.
	allow(t, l, "k")
	n, err := rdb.ZCard(ctx, keys[0]).Result()
	if err != nil {
		t.Fatalf("ZCARD: %v (expected a sorted set of events)", err)
	}
	if n != 2 {
		t.Fatalf("events kept = %d, want 2 (t0+4s and t0+5s); old events not trimmed", n)
	}
}

func TestRedisErrorIsReturned(t *testing.T) {
	rdb := redisClient(t)
	l := newLimiter(t, rdb, uniq(t), 5, time.Minute, newClock())
	_ = rdb.Close()
	d, err := l.Allow(context.Background(), "k")
	if err == nil {
		t.Fatal("no error with Redis closed")
	}
	if d.Allowed {
		t.Fatal("Allowed=true alongside an error: callers might fail open")
	}
}
