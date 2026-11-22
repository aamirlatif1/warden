// Package ratelimit is a sliding-window rate limiter backed by Redis, shared
// by every replica (REQUIREMENTS §2 "Rate limiting, abuse mitigation"). It
// guards partner-sts /token (per IP and per client_id) and BFF /login (per
// IP). Keycloak's brute-force detection is the second layer for passwords.
package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// HAND-BUILD (S7). Semantics the tests pin down:
//
//   - Sliding log, not fixed buckets: a call at time t is allowed iff fewer
//     than Limit ALLOWED calls for the same key happened in (t-Window, t].
//     An event at t0 stops counting at exactly t0+Window.
//   - Refused calls are not recorded, so a client that keeps hammering
//     gets through again as soon as old events leave the window (no
//     self-extending lockout).
//   - Atomic across replicas: N concurrent callers never get more than
//     Limit allowed in total (check-and-add in one Lua script or MULTI).
//   - Two calls in the same millisecond are two events (unique members).
//   - Remaining = Limit - (allowed events in the window, this one included
//     when allowed). Never negative.
//   - RetryAfter = 0 when allowed; when refused, the time until the oldest
//     counted event leaves the window (> 0, <= Window).
//   - Storage: one Redis sorted set per key (score = event time in ms).
//     Memory is bounded: the key expires at most Window after the last
//     allowed event, and events older than the window are trimmed.
//   - Keys are Config.Prefix + key, so two limiters never share budgets.
//   - Redis errors are returned as errors (never "allowed"); the caller
//     decides to fail closed.
//   - Times come from Config.Now (tests use a fake clock), in milliseconds.

// Decision is the outcome of one Allow call.
type Decision struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
}

// Config configures a Limiter.
type Config struct {
	Prefix string        // Redis key namespace, e.g. "warden:rl:sts-token-ip:"; required
	Limit  int           // allowed events per Window; > 0
	Window time.Duration // >= 1 ms
	Now    func() time.Time
}

// Limiter is safe for concurrent use.
type Limiter struct {
	// yours
}

// New refuses an empty Prefix, Limit <= 0 and Window < 1 ms.
func New(rdb redis.UniversalClient, cfg Config) (*Limiter, error) {
	panic("TODO(S7 hand-build): ratelimit.New")
}

// Allow records one event for key if the window has room. An empty key is
// an error (it would put every caller in one bucket).
func (l *Limiter) Allow(ctx context.Context, key string) (Decision, error) {
	panic("TODO(S7 hand-build): Limiter.Allow")
}
