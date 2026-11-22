package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authn/jwks"
)

// ---- fakes ----

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
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// idp is a fake JWKS endpoint whose key set, status and latency can change.
type idp struct {
	srv   *httptest.Server
	hits  atomic.Int64
	mu    sync.Mutex
	body  []byte
	code  int
	delay time.Duration
}

func newIDP(t *testing.T, keys ...jose.JSONWebKey) *idp {
	t.Helper()
	f := &idp{code: http.StatusOK}
	f.setKeys(keys...)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		body, code, delay := f.body, f.code, f.delay
		f.mu.Unlock()
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *idp) setKeys(keys ...jose.JSONWebKey) {
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		panic(err)
	}
	f.setBody(http.StatusOK, body)
}

func (f *idp) setBody(code int, body []byte) {
	f.mu.Lock()
	f.code, f.body = code, body
	f.mu.Unlock()
}

func (f *idp) setDelay(d time.Duration) {
	f.mu.Lock()
	f.delay = d
	f.mu.Unlock()
}

func ecKey(t *testing.T, kid string) (jose.JSONWebKey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}, priv
}

func newCache(f *idp, c *clock) *jwks.Cache {
	return jwks.New(f.srv.URL, jwks.Options{
		MinRefetchInterval: 10 * time.Second,
		RefreshInterval:    time.Hour, // Run is tested separately
		Now:                c.Now,
	})
}

var ctx = context.Background()

func wantReason(t *testing.T, err error, want authn.Reason) {
	t.Helper()
	if got := authn.ReasonOf(err); got != want {
		t.Fatalf("reason = %q, want %q (err: %v)", got, want, err)
	}
}

// ---- tests ----

func TestColdCacheFetchesOnFirstKey(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	f := newIDP(t, k1)
	c := newCache(f, newClock())

	got, err := c.Key(ctx, "k1")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if got.KeyID != "k1" || !got.IsPublic() {
		t.Fatalf("got %+v, want public key k1", got)
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestKnownKidIsServedFromCache(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	f := newIDP(t, k1)
	c := newCache(f, newClock())
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		if _, err := c.Key(ctx, "k1"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (hot path must not hit the network)", n)
	}
}

// Rotation: the IdP publishes a new key; the first token signed with it
// triggers one refetch, shared by every concurrent caller (singleflight).
func TestUnknownKidRefetchIsSharedByConcurrentCallers(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	k2, _ := ecKey(t, "k2")
	f := newIDP(t, k1)
	c := newCache(f, newClock())
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	f.setKeys(k1, k2)
	f.setDelay(100 * time.Millisecond) // keep the fetch in flight while callers pile up

	const callers = 50
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			if _, err := c.Key(ctx, "k2"); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("caller failed: %v (every waiter must get the refetched key)", err)
	}
	if n := f.hits.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (initial + one shared refetch)", n)
	}
}

// Drill D4: a flood of random kids costs at most one fetch per interval.
func TestKidFloodIsRateLimited(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	f := newIDP(t, k1)
	clk := newClock()
	c := newCache(f, clk)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	for i := range 1000 {
		_, err := c.Key(ctx, fmt.Sprintf("random-%d", i))
		wantReason(t, err, authn.ReasonKidUnknown)
	}
	if n := f.hits.Load(); n > 2 {
		t.Fatalf("fetches = %d after a 1000-kid flood, want <= 2", n)
	}

	// Known keys keep working during the flood.
	if _, err := c.Key(ctx, "k1"); err != nil {
		t.Fatalf("known kid failed during flood: %v", err)
	}

	// After the interval, one more miss may refetch.
	clk.Advance(11 * time.Second)
	before := f.hits.Load()
	_, err := c.Key(ctx, "random-after")
	wantReason(t, err, authn.ReasonKidUnknown)
	if n := f.hits.Load() - before; n != 1 {
		t.Fatalf("fetches after interval = %d, want 1", n)
	}
}

func TestConcurrentKidFloodIsRateLimited(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	f := newIDP(t, k1)
	c := newCache(f, newClock())
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 200 {
		wg.Go(func() { _, _ = c.Key(ctx, fmt.Sprintf("flood-%d", i)) })
	}
	wg.Wait()
	if n := f.hits.Load(); n > 2 {
		t.Fatalf("fetches = %d, want <= 2", n)
	}
}

func TestRefreshDropsRemovedKeys(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	k2, _ := ecKey(t, "k2")
	f := newIDP(t, k1, k2)
	c := newCache(f, newClock())
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	f.setKeys(k2) // k1 retired (or compromised)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := c.Key(ctx, "k1")
	wantReason(t, err, authn.ReasonKidUnknown)
	if _, err := c.Key(ctx, "k2"); err != nil {
		t.Fatalf("k2: %v", err)
	}
}

func TestLastKnownGoodWhenIdPFails(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	failures := []struct {
		name string
		code int
		body []byte
	}{
		{"500", http.StatusInternalServerError, []byte(`{"error":"down"}`)},
		{"200 with HTML", http.StatusOK, []byte("<html>maintenance</html>")},
		{"200 with an empty key set", http.StatusOK, []byte(`{"keys":[]}`)},
		{"body over 1 MiB (otherwise valid)", http.StatusOK, oversizedJWKS(t, k1)},
	}
	for _, fc := range failures {
		t.Run(fc.name, func(t *testing.T) {
			f := newIDP(t, k1)
			clk := newClock()
			c := newCache(f, clk)
			if err := c.Refresh(ctx); err != nil {
				t.Fatal(err)
			}
			if s := c.Staleness(); s != 0 {
				t.Fatalf("Staleness right after a fetch = %v, want 0", s)
			}

			f.setBody(fc.code, fc.body)
			clk.Advance(3 * time.Minute)
			if err := c.Refresh(ctx); err == nil {
				t.Fatal("Refresh reported success on a bad response")
			}
			if _, err := c.Key(ctx, "k1"); err != nil {
				t.Fatalf("last-known-good key not served: %v", err)
			}
			if s := c.Staleness(); s != 3*time.Minute {
				t.Fatalf("Staleness = %v, want 3m", s)
			}
		})
	}
}

// oversizedJWKS is a valid key set padded past 1 MiB, so only a size cap
// can reject it.
func oversizedJWKS(t *testing.T, k jose.JSONWebKey) []byte {
	t.Helper()
	kj, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"keys":[` + string(kj) + `],"pad":"` + strings.Repeat("a", 2<<20) + `"}`)
}

func TestColdCacheWithIdPDown(t *testing.T) {
	f := newIDP(t)
	f.setBody(http.StatusServiceUnavailable, nil)
	c := newCache(f, newClock())
	_, err := c.Key(ctx, "k1")
	wantReason(t, err, authn.ReasonJWKSUnavailable)
}

func TestOnlyPublicSigningKeysWithKidAreKept(t *testing.T) {
	sig, _ := ecKey(t, "sig")
	enc, _ := ecKey(t, "enc")
	enc.Use = "enc"
	noKid, _ := ecKey(t, "")
	_, priv := ecKey(t, "private")
	private := jose.JSONWebKey{Key: priv, KeyID: "private", Algorithm: "ES256", Use: "sig"}

	f := newIDP(t, sig, enc, noKid, private)
	c := newCache(f, newClock())
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Key(ctx, "sig"); err != nil {
		t.Fatalf("sig: %v", err)
	}
	_, err := c.Key(ctx, "enc")
	wantReason(t, err, authn.ReasonKidUnknown)

	// A private key published by mistake must never come back as private.
	got, err := c.Key(ctx, "private")
	if err == nil && !got.IsPublic() {
		t.Fatal("cache returned private key material")
	}
}

func TestKeyRespectsContextCancellation(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	f := newIDP(t, k1)
	f.setDelay(2 * time.Second)
	c := newCache(f, newClock())

	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Key(cctx, "k1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Key blocked %v after its context was cancelled", d)
	}
}

func TestRunRefreshesInBackground(t *testing.T) {
	k1, _ := ecKey(t, "k1")
	f := newIDP(t, k1)
	c := jwks.New(f.srv.URL, jwks.Options{RefreshInterval: 20 * time.Millisecond})

	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { c.Run(rctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for f.hits.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("fetches = %d after 2s with a 20ms interval, want >= 3", f.hits.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ctx was cancelled")
	}
}

// The cache satisfies the validator's consumer-side interface.
var _ authn.KeySource = (*jwks.Cache)(nil)
