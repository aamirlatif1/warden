// Package app holds the BFF's use cases: login, callback, logout, token
// refresh, and the portal actions that call policy-api.
package app

import (
	"context"
	"errors"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/domain"
)

// ---- OpenID Provider (Keycloak) ----

// AuthParams build the authorization request.
type AuthParams struct {
	State         string
	Nonce         string
	CodeChallenge string // S256(verifier), base64url
	ACRValues     string // "" or "gold"
	MaxAge        time.Duration
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Expiry       time.Time // access token expiry
}

// IDClaims are what the BFF needs from a verified ID token.
type IDClaims struct {
	Subject  string
	Username string
	Nonce    string
	ACR      string
	SID      string
	AuthTime time.Time
}

// ErrInvalidGrant: the IdP refused a refresh token (expired, revoked, or
// reused, which with refresh-token rotation ends the Keycloak session: D8).
var ErrInvalidGrant = errors.New("invalid_grant")

type OIDC interface {
	AuthURL(p AuthParams) string
	Exchange(ctx context.Context, code, verifier string) (Tokens, error)
	// VerifyIDToken checks signature, iss, aud, azp, exp. It does NOT check
	// the nonce: the callback compares it with the login transaction.
	VerifyIDToken(ctx context.Context, raw string) (IDClaims, error)
	Refresh(ctx context.Context, refreshToken string) (Tokens, error)
	EndSessionURL(idTokenHint, postLogoutRedirect string) string
}

// ---- storage ----

type SessionStore interface {
	Create(ctx context.Context, s domain.Session) error
	// Get enforces the idle and absolute timeouts and slides the idle one.
	Get(ctx context.Context, id string) (domain.Session, error)
	Save(ctx context.Context, s domain.Session) error
	Delete(ctx context.Context, id string) error
}

type TxStore interface {
	Put(ctx context.Context, tx domain.LoginTx, ttl time.Duration) error
	// Take returns and deletes the transaction atomically (single use).
	Take(ctx context.Context, id string) (domain.LoginTx, error)
}

var ErrNoTx = errors.New("no login transaction")

// Locker is a distributed mutex (Redis SET NX PX). Acquire blocks until the
// lock is held or ctx is done.
type Locker interface {
	Acquire(ctx context.Context, key string, ttl time.Duration) (release func(), err error)
}
