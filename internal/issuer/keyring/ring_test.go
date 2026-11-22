package keyring_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/issuer"
	"github.com/aamirlatif1/warden/internal/issuer/keyring"
)

const (
	lead   = 10 * time.Minute
	retire = 5*time.Minute + 30*time.Second
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// ---- fakes ----

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time)         { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fakeSigner struct {
	kid string
	pub *ecdsa.PublicKey
}

func newFakeSigner(kid string) *fakeSigner {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &fakeSigner{kid: kid, pub: &k.PublicKey}
}

func (f *fakeSigner) KeyID() string                      { return f.kid }
func (f *fakeSigner) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (f *fakeSigner) PublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{Key: f.pub, KeyID: f.kid, Algorithm: "ES256", Use: "sig"}
}
func (f *fakeSigner) SignDigest(context.Context, []byte) ([]byte, error) {
	return make([]byte, 64), nil
}

type factory struct {
	n     atomic.Int64
	calls atomic.Int64
	err   error
	block chan struct{} // if non-nil, NewSigner waits for it
}

func (f *factory) NewSigner(ctx context.Context) (issuer.Signer, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return newFakeSigner(fmt.Sprintf("k%d", f.n.Add(1)+1)), nil // k2, k3, ...
}

func newRing(t *testing.T) (*keyring.Ring, *clock, *factory) {
	t.Helper()
	c := &clock{t: t0}
	f := &factory{}
	r, err := keyring.New(keyring.Config{PublishLead: lead, RetireAfter: retire, Factory: f, Now: c.Now}, newFakeSigner("k1"))
	if err != nil {
		t.Fatal(err)
	}
	return r, c, f
}

func kids(keys []jose.JSONWebKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.KeyID)
	}
	slices.Sort(out)
	return out
}

func states(r *keyring.Ring) map[string]keyring.State {
	out := map[string]keyring.State{}
	for _, k := range r.Keys() {
		out[k.KID] = k.State
	}
	return out
}

func want(t *testing.T, r *keyring.Ring, signing string, published ...string) {
	t.Helper()
	if got := r.Signing().KeyID(); got != signing {
		t.Fatalf("Signing = %s, want %s", got, signing)
	}
	slices.Sort(published)
	if got := kids(r.Published()); !slices.Equal(got, published) {
		t.Fatalf("Published = %v, want %v", got, published)
	}
}

// ---- timeline ----

func TestInitialState(t *testing.T) {
	r, _, _ := newRing(t)
	want(t, r, "k1", "k1")
	keys := r.Keys()
	if len(keys) != 1 || keys[0].KID != "k1" || keys[0].State != keyring.StateCurrent {
		t.Fatalf("Keys = %+v", keys)
	}
}

func TestRotationTimeline(t *testing.T) {
	r, c, _ := newRing(t)

	info, err := r.Rotate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.KID != "k2" || info.State != keyring.StateNext || !info.ActivatesAt.Equal(t0.Add(lead)) {
		t.Fatalf("Rotate = %+v", info)
	}
	// Published immediately, not signing yet.
	want(t, r, "k1", "k1", "k2")

	c.Set(t0.Add(lead - time.Nanosecond))
	want(t, r, "k1", "k1", "k2")

	// Activation instant: k2 signs, k1 retires but stays published.
	c.Set(t0.Add(lead))
	want(t, r, "k2", "k1", "k2")
	st := states(r)
	if st["k1"] != keyring.StateRetiring || st["k2"] != keyring.StateCurrent {
		t.Fatalf("states = %v", st)
	}
	for _, k := range r.Keys() {
		if k.KID == "k1" && (!k.RetiredAt.Equal(t0.Add(lead)) || !k.DropsAt.Equal(t0.Add(lead+retire))) {
			t.Fatalf("k1 retirement = %+v", k)
		}
	}

	// Tokens k1 signed just before activation still verify until DropsAt.
	c.Set(t0.Add(lead + retire - time.Nanosecond))
	want(t, r, "k2", "k1", "k2")

	c.Set(t0.Add(lead + retire))
	want(t, r, "k2", "k2")
	if len(r.Keys()) != 1 {
		t.Fatalf("Keys = %+v", r.Keys())
	}
}

// Transitions apply even if nobody looked in between.
func TestTransitionsAreLazy(t *testing.T) {
	r, c, _ := newRing(t)
	if _, err := r.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Advance(24 * time.Hour)
	want(t, r, "k2", "k2")
}

func TestRotateWhileNextPending(t *testing.T) {
	r, c, f := newRing(t)
	if _, err := r.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Advance(lead / 2)
	if _, err := r.Rotate(context.Background()); !errors.Is(err, keyring.ErrRotationInProgress) {
		t.Fatalf("err = %v, want ErrRotationInProgress", err)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("factory called %d times, want 1", f.calls.Load())
	}
}

// After k2 activates, rotating again is allowed while k1 is still retiring:
// three keys are published at once.
func TestRotateAgainWhileRetiring(t *testing.T) {
	r, c, _ := newRing(t)
	if _, err := r.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Set(t0.Add(lead + time.Minute))
	if _, err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	want(t, r, "k2", "k1", "k2", "k3")
	st := states(r)
	if st["k1"] != keyring.StateRetiring || st["k2"] != keyring.StateCurrent || st["k3"] != keyring.StateNext {
		t.Fatalf("states = %v", st)
	}
}

func TestFactoryErrorLeavesStateUnchanged(t *testing.T) {
	r, _, f := newRing(t)
	f.err = errors.New("kms: throttled")
	if _, err := r.Rotate(context.Background()); err == nil {
		t.Fatal("Rotate succeeded with a failing factory")
	}
	want(t, r, "k1", "k1")
	f.err = nil
	if _, err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	want(t, r, "k1", "k1", "k2")
}

// ---- concurrency ----

// A slow KMS CreateKey must not block token signing.
func TestSlowFactoryDoesNotBlockSigning(t *testing.T) {
	r, _, f := newRing(t)
	f.block = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := r.Rotate(context.Background()); done <- err }()

	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	got := make(chan string, 1)
	go func() { got <- r.Signing().KeyID(); _ = r.Published() }()
	select {
	case kid := <-got:
		if kid != "k1" {
			t.Fatalf("Signing = %s during rotation", kid)
		}
	case <-time.After(time.Second):
		t.Fatal("Signing blocked while the factory was running")
	}
	close(f.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Two admins press rotate at once: one key is created, the other call gets
// ErrRotationInProgress (the pending slot is claimed before the factory runs).
func TestConcurrentRotateCreatesOneKey(t *testing.T) {
	r, _, f := newRing(t)
	f.block = make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() { _, err := r.Rotate(context.Background()); errs <- err }()
	}
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(f.block)
	e1, e2 := <-errs, <-errs
	inProgress := 0
	for _, e := range []error{e1, e2} {
		if errors.Is(e, keyring.ErrRotationInProgress) {
			inProgress++
		} else if e != nil {
			t.Fatalf("unexpected error: %v", e)
		}
	}
	if inProgress != 1 || f.calls.Load() != 1 {
		t.Fatalf("in-progress errors = %d, factory calls = %d; want 1 and 1", inProgress, f.calls.Load())
	}
}

func TestConcurrentUseIsRaceFree(t *testing.T) {
	r, c, _ := newRing(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					// Separate calls are not atomic while the clock moves,
					// so this test only exercises the race detector; the
					// invariants are checked in the sequential property test.
					_ = r.Signing()
					_ = r.Published()
					_ = r.Keys()
				}
			}
		})
	}
	for range 20 {
		_, _ = r.Rotate(context.Background())
		c.Advance(lead / 3)
	}
	close(stop)
	wg.Wait()
}

// ---- the safety property, over random timelines ----

// For every token signed at time s with key K:
//  1. K was published at least PublishLead before s (except the initial
//     key), so a verifier whose JWKS cache is up to PublishLead old has it;
//  2. K stays published at every instant before s + RetireAfter, so the
//     token verifies for its whole life.
//
// And at every instant: exactly one current, at most one next, Signing in
// Published, no duplicate kids. Observations happen right after each
// Rotate at the same clock reading, so publish times are exact.
func TestSafetyPropertyOverRandomTimelines(t *testing.T) {
	for seed := range uint64(30) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := mrand.New(mrand.NewPCG(seed, seed))
			r, c, _ := newRing(t)

			firstPublished := map[string]time.Time{}
			type signing struct {
				kid string
				at  time.Time
			}
			var signings []signing

			for range 400 {
				if rng.IntN(6) == 0 {
					_, _ = r.Rotate(context.Background())
				}
				now := c.Now()

				pub := map[string]bool{}
				for _, k := range r.Published() {
					if pub[k.KeyID] {
						t.Fatalf("duplicate kid %s", k.KeyID)
					}
					pub[k.KeyID] = true
					if _, ok := firstPublished[k.KeyID]; !ok {
						firstPublished[k.KeyID] = now
					}
				}

				// (2) every token still alive must still verify.
				for _, sg := range signings {
					if now.Before(sg.at.Add(retire)) && !pub[sg.kid] {
						t.Fatalf("at %v: %s dropped, but a token it signed at %v lives until %v",
							now, sg.kid, sg.at, sg.at.Add(retire))
					}
				}

				s := r.Signing().KeyID()
				if !pub[s] {
					t.Fatalf("signing key %s not published", s)
				}
				// (1) published long enough before first use.
				if s != "k1" && now.Sub(firstPublished[s]) < lead {
					t.Fatalf("%s signs at %v, published only at %v (< lead)", s, now, firstPublished[s])
				}
				signings = append(signings, signing{s, now})

				cur, next := 0, 0
				for _, k := range r.Keys() {
					switch k.State {
					case keyring.StateCurrent:
						cur++
					case keyring.StateNext:
						next++
					}
				}
				if cur != 1 || next > 1 {
					t.Fatalf("current = %d, next = %d", cur, next)
				}

				c.Advance(time.Duration(rng.Int64N(int64(3 * time.Minute))))
			}
		})
	}
}

func TestNewValidatesConfig(t *testing.T) {
	f := &factory{}
	if _, err := keyring.New(keyring.Config{Factory: f}, nil); err == nil {
		t.Error("accepted a nil initial key")
	}
	if _, err := keyring.New(keyring.Config{}, newFakeSigner("k1")); err == nil {
		t.Error("accepted a nil factory")
	}
	if _, err := keyring.New(keyring.Config{Factory: f, PublishLead: -time.Second}, newFakeSigner("k1")); err == nil {
		t.Error("accepted a negative PublishLead")
	}
}
