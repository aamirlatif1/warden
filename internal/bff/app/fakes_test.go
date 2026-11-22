package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// ---- fake IdP: enforces PKCE like Keycloak does ----

type fakeOIDC struct {
	mu        sync.Mutex
	clk       *clock
	auth      []app.AuthParams // every authorization request
	verifiers []string         // every verifier presented at the token endpoint

	claims        app.IDClaims // returned by VerifyIDToken (Nonce auto-filled from the last AuthURL unless overrideNonce)
	overrideNonce bool
	idTokenErr    error
	exchangeErr   error

	refreshCalls atomic.Int64
	refreshDelay time.Duration
	refreshErr   error
	refreshNoRT  bool // response without a new refresh token
}

func (f *fakeOIDC) AuthURL(p app.AuthParams) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, p)
	return "http://kc/auth?state=" + p.State
}

func (f *fakeOIDC) lastAuth() app.AuthParams {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auth[len(f.auth)-1]
}

func s256(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func (f *fakeOIDC) Exchange(_ context.Context, code, verifier string) (app.Tokens, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifiers = append(f.verifiers, verifier)
	if f.exchangeErr != nil {
		return app.Tokens{}, f.exchangeErr
	}
	if code != "good-code" {
		return app.Tokens{}, errors.New("invalid_grant: bad code")
	}
	// PKCE: the IdP only accepts the verifier whose S256 it saw at /auth.
	if len(f.auth) == 0 || s256(verifier) != f.auth[len(f.auth)-1].CodeChallenge {
		return app.Tokens{}, errors.New("invalid_grant: PKCE verification failed")
	}
	return app.Tokens{AccessToken: "at-0", RefreshToken: "rt-0", IDToken: "id-0", Expiry: f.clk.Now().Add(5 * time.Minute)}, nil
}

func (f *fakeOIDC) VerifyIDToken(context.Context, string) (app.IDClaims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idTokenErr != nil {
		return app.IDClaims{}, f.idTokenErr
	}
	c := f.claims
	if !f.overrideNonce && len(f.auth) > 0 {
		c.Nonce = f.auth[len(f.auth)-1].Nonce
	}
	return c, nil
}

func (f *fakeOIDC) Refresh(_ context.Context, rt string) (app.Tokens, error) {
	n := f.refreshCalls.Add(1)
	time.Sleep(f.refreshDelay)
	if f.refreshErr != nil {
		return app.Tokens{}, f.refreshErr
	}
	out := app.Tokens{AccessToken: fmt.Sprintf("at-%d", n), Expiry: f.clk.Now().Add(5 * time.Minute)}
	if !f.refreshNoRT {
		out.RefreshToken = fmt.Sprintf("rt-%d", n)
	}
	return out, nil
}

func (f *fakeOIDC) EndSessionURL(hint, post string) string {
	return "http://kc/logout?hint=" + hint + "&post=" + post
}

// ---- in-memory stores ----

type memSessions struct {
	mu sync.Mutex
	m  map[string]domain.Session
}

func newMemSessions() *memSessions { return &memSessions{m: map[string]domain.Session{}} }

func (s *memSessions) Create(_ context.Context, x domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[x.ID]; ok || x.ID == "" {
		return errors.New("session id collision or empty")
	}
	s.m[x.ID] = x
	return nil
}

func (s *memSessions) Get(_ context.Context, id string) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[id]
	if !ok {
		return domain.Session{}, domain.ErrNoSession
	}
	return x, nil
}

func (s *memSessions) Save(_ context.Context, x domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[x.ID]; !ok {
		return domain.ErrNoSession
	}
	s.m[x.ID] = x
	return nil
}

func (s *memSessions) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

func (s *memSessions) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.m) }

type memTxs struct {
	mu sync.Mutex
	m  map[string]domain.LoginTx
}

func newMemTxs() *memTxs { return &memTxs{m: map[string]domain.LoginTx{}} }

func (t *memTxs) Put(_ context.Context, tx domain.LoginTx, _ time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[tx.ID] = tx
	return nil
}

func (t *memTxs) Take(_ context.Context, id string) (domain.LoginTx, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tx, ok := t.m[id]
	if !ok {
		return domain.LoginTx{}, app.ErrNoTx
	}
	delete(t.m, id)
	return tx, nil
}

// ---- locker ----

type memLocker struct {
	mu       sync.Mutex
	held     map[string]chan struct{}
	acquired atomic.Int64
	err      error
}

func newMemLocker() *memLocker { return &memLocker{held: map[string]chan struct{}{}} }

func (l *memLocker) Acquire(ctx context.Context, key string, _ time.Duration) (func(), error) {
	if l.err != nil {
		return nil, l.err
	}
	for {
		l.mu.Lock()
		ch, busy := l.held[key]
		if !busy {
			done := make(chan struct{})
			l.held[key] = done
			l.mu.Unlock()
			l.acquired.Add(1)
			var once sync.Once
			return func() {
				once.Do(func() {
					l.mu.Lock()
					delete(l.held, key)
					l.mu.Unlock()
					close(done)
				})
			}, nil
		}
		l.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (l *memLocker) isHeld(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.held[key]
	return ok
}
