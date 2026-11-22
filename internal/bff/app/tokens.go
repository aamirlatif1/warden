package app

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ErrSessionEnded: the refresh token was refused (D8: reuse detected, or
// revoked); the session has been deleted and the user must log in again.
var ErrSessionEnded = errors.New("session ended")

type TokenSourceConfig struct {
	Skew    time.Duration    // refresh when less than this is left; 0 means 60 s
	LockTTL time.Duration    // per-session refresh lock; 0 means 10 s
	Now     func() time.Time // nil means time.Now
}

// TokenSource hands out a valid access token for a session.
type TokenSource struct {
	sessions SessionStore
	oidc     OIDC
	locks    Locker
	log      *slog.Logger
	cfg      TokenSourceConfig
}

func NewTokenSource(s SessionStore, o OIDC, l Locker, log *slog.Logger, cfg TokenSourceConfig) *TokenSource {
	if cfg.Skew == 0 {
		cfg.Skew = 60 * time.Second
	}
	if cfg.LockTTL == 0 {
		cfg.LockTTL = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &TokenSource{sessions: s, oidc: o, locks: l, log: log, cfg: cfg}
}

// HAND-BUILD (S6). AccessToken: refresh under a per-session lock.
//
//   - Fresh (more than Skew left): return it, no lock, no refresh.
//   - Otherwise Acquire("refresh:"+sid), then RE-READ the session: another
//     request may have refreshed while we waited. Still stale → Refresh.
//   - N concurrent requests for one session → exactly one Refresh call,
//     and all of them get the new token (refresh tokens rotate: a second
//     refresh with the old one would be reuse and kill the session).
//   - ErrInvalidGrant → delete the session, return ErrSessionEnded.
//   - Other refresh error → keep the session, return the error.
//   - Store the new access token, expiry and refresh token (keep the old
//     refresh token only if the response has none). Always release the lock.
//   - Unknown session → domain.ErrNoSession.
func (t *TokenSource) AccessToken(ctx context.Context, sid string) (string, error) {
	panic("TODO(S6 hand-build): TokenSource.AccessToken")
}
