// Package jwks is a driven adapter: it fetches and caches an issuer's JSON
// Web Key Set and implements authn.KeySource.
package jwks

import (
	"context"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// HAND-BUILD (S2). Requirements (REQUIREMENTS FR-2, drill D4):
//
//   - Key on a known kid: no network call.
//   - Key on an unknown kid: at most one refetch, shared by all concurrent
//     callers (singleflight), and at most one miss-triggered refetch per
//     MinRefetchInterval. Otherwise → authn reason kid_unknown.
//     Refresh/Run do not consume that miss budget: a new kid right after a
//     scheduled refresh may still refetch once.
//   - A successful fetch replaces the key set (removed keys stop working).
//   - A failed fetch (network, non-200, bad JSON, body > 1 MiB) keeps the
//     last-known-good set. Staleness() keeps growing until a fetch succeeds.
//   - Never fetched successfully and the fetch fails → jwks_unavailable.
//   - Only public signing keys with a kid are kept (skip use=enc, no kid,
//     and strip/skip private material).
//   - Run refreshes every RefreshInterval plus jitter until ctx is done
//     (honouring Cache-Control max-age is a nice-to-have).
//
// Errors returned by Key must be *authn.Error so ReasonOf works.

// Options tune a Cache. Zero values mean the defaults.
type Options struct {
	Client             *http.Client     // default: 5 s timeout
	MinRefetchInterval time.Duration    // default 10 s
	RefreshInterval    time.Duration    // default 10 min
	Now                func() time.Time // default time.Now
}

// Cache holds one issuer's keys. It is safe for concurrent use.
type Cache struct {
	// yours
}

// New returns a cache for the JWKS at url. It does not fetch.
func New(url string, opts Options) *Cache {
	panic("TODO(S2 hand-build): jwks.New")
}

// Key returns the public key for kid. See the requirements above.
func (c *Cache) Key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	panic("TODO(S2 hand-build): Cache.Key")
}

// Refresh fetches the key set now, regardless of the miss rate limit.
func (c *Cache) Refresh(ctx context.Context) error {
	panic("TODO(S2 hand-build): Cache.Refresh")
}

// Run refreshes in the background until ctx is cancelled.
func (c *Cache) Run(ctx context.Context) {
	panic("TODO(S2 hand-build): Cache.Run")
}

// Staleness is the time since the last successful fetch (0 if never).
// Exported as the jwks_stale_seconds gauge in S8.
func (c *Cache) Staleness() time.Duration {
	panic("TODO(S2 hand-build): Cache.Staleness")
}
