package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

type tokenFixture struct {
	ts       *app.TokenSource
	oidc     *fakeOIDC
	sessions *memSessions
	locks    *memLocker
	clk      *clock
}

// newTokens stores session "s1" whose access token has `left` remaining.
func newTokens(t *testing.T, left time.Duration) tokenFixture {
	t.Helper()
	clk := &clock{t: t0}
	o := &fakeOIDC{clk: clk}
	s := newMemSessions()
	l := newMemLocker()
	_ = s.Create(context.Background(), domain.Session{
		ID: "s1", Subject: "sub-anna", AccessToken: "at-old", RefreshToken: "rt-old",
		AccessExpiry: t0.Add(left), CreatedAt: t0,
	})
	return tokenFixture{
		ts:   app.NewTokenSource(s, o, l, quiet, app.TokenSourceConfig{Now: clk.Now}),
		oidc: o, sessions: s, locks: l, clk: clk,
	}
}

func TestFreshTokenNoRefresh(t *testing.T) {
	f := newTokens(t, 4*time.Minute)
	tok, err := f.ts.AccessToken(context.Background(), "s1")
	if err != nil || tok != "at-old" {
		t.Fatalf("got %q, %v", tok, err)
	}
	if f.oidc.refreshCalls.Load() != 0 || f.locks.acquired.Load() != 0 {
		t.Fatal("refreshed or locked a fresh token")
	}
}

func TestStaleTokenRefreshes(t *testing.T) {
	f := newTokens(t, 30*time.Second) // inside the 60 s skew
	tok, err := f.ts.AccessToken(context.Background(), "s1")
	if err != nil || tok != "at-1" {
		t.Fatalf("got %q, %v", tok, err)
	}
	s, _ := f.sessions.Get(context.Background(), "s1")
	if s.AccessToken != "at-1" || s.RefreshToken != "rt-1" || !s.AccessExpiry.Equal(t0.Add(5*time.Minute)) {
		t.Fatalf("session after refresh = %+v (rotated refresh token must be stored)", s)
	}
	if f.locks.isHeld("refresh:s1") {
		t.Fatal("lock not released")
	}
}

func TestRefreshWithoutNewRefreshTokenKeepsOld(t *testing.T) {
	f := newTokens(t, 0)
	f.oidc.refreshNoRT = true
	if _, err := f.ts.AccessToken(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.sessions.Get(context.Background(), "s1"); s.RefreshToken != "rt-old" {
		t.Fatalf("refresh token = %q, want rt-old kept", s.RefreshToken)
	}
}

// The core property: parallel requests on one session refresh once.
// Refresh tokens rotate, so a second refresh with rt-old would be reuse
// and Keycloak would kill the session.
func TestConcurrentRequestsRefreshOnce(t *testing.T) {
	f := newTokens(t, 10*time.Second)
	f.oidc.refreshDelay = 50 * time.Millisecond

	const n = 20
	var wg sync.WaitGroup
	got := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { got[i], errs[i] = f.ts.AccessToken(context.Background(), "s1") })
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || got[i] != "at-1" {
			t.Fatalf("request %d: %q, %v", i, got[i], errs[i])
		}
	}
	if c := f.oidc.refreshCalls.Load(); c != 1 {
		t.Fatalf("refresh called %d times, want 1 (double refresh = refresh-token reuse)", c)
	}
}

func TestInvalidGrantEndsSession(t *testing.T) {
	f := newTokens(t, 0)
	f.oidc.refreshErr = app.ErrInvalidGrant
	_, err := f.ts.AccessToken(context.Background(), "s1")
	if !errors.Is(err, app.ErrSessionEnded) {
		t.Fatalf("err = %v, want ErrSessionEnded", err)
	}
	if _, err := f.sessions.Get(context.Background(), "s1"); !errors.Is(err, domain.ErrNoSession) {
		t.Fatal("D8: session survived a refused refresh token")
	}
	if f.locks.isHeld("refresh:s1") {
		t.Fatal("lock not released")
	}
}

func TestTransientRefreshErrorKeepsSession(t *testing.T) {
	f := newTokens(t, 0)
	f.oidc.refreshErr = errors.New("keycloak: 503")
	_, err := f.ts.AccessToken(context.Background(), "s1")
	if err == nil || errors.Is(err, app.ErrSessionEnded) {
		t.Fatalf("err = %v, want a plain error", err)
	}
	if _, err := f.sessions.Get(context.Background(), "s1"); err != nil {
		t.Fatal("transient error deleted the session")
	}
	f.oidc.refreshErr = nil
	if tok, err := f.ts.AccessToken(context.Background(), "s1"); err != nil || tok == "at-old" {
		t.Fatalf("retry after transient error: %q, %v (lock released?)", tok, err)
	}
}

func TestUnknownSession(t *testing.T) {
	f := newTokens(t, time.Hour)
	if _, err := f.ts.AccessToken(context.Background(), "nope"); !errors.Is(err, domain.ErrNoSession) {
		t.Fatalf("err = %v", err)
	}
}

func TestLockErrorNoRefresh(t *testing.T) {
	f := newTokens(t, 0)
	f.locks.err = errors.New("redis down")
	if _, err := f.ts.AccessToken(context.Background(), "s1"); err == nil {
		t.Fatal("refreshed without the lock")
	}
	if f.oidc.refreshCalls.Load() != 0 {
		t.Fatal("refresh called without holding the lock")
	}
}
