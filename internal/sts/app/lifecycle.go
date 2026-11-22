package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/issuer"
	"github.com/aamirlatif1/warden/internal/issuer/keyring"
	"github.com/aamirlatif1/warden/internal/revocation"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

const ErrUnauthorizedClient = "unauthorized_client"

type TokenInspector interface {
	Inspect(raw string) (issuer.Claims, error)
	TTL() time.Duration
	Issuer() string
}

type Revoker interface {
	Revoke(ctx context.Context, e revocation.Event) error
	IsRevoked(ctx context.Context, t authn.TokenRef) (bool, error)
}

type PartnerAdmin interface {
	Partner(ctx context.Context, clientID string) (domain.Partner, error)
	SetStatus(ctx context.Context, clientID string, s domain.PartnerStatus) error
}

type Rotator interface {
	Rotate(ctx context.Context) (keyring.KeyInfo, error)
	Keys() []keyring.KeyInfo
}

// Lifecycle handles everything after issuance: revoke, introspect,
// suspend/resume, key rotation.
type Lifecycle struct {
	verifier AssertionVerifier
	tokens   TokenInspector
	revoker  Revoker
	partners PartnerAdmin
	keys     Rotator
	log      *slog.Logger
	now      func() time.Time
}

func NewLifecycle(v AssertionVerifier, t TokenInspector, r Revoker, p PartnerAdmin, k Rotator, log *slog.Logger) *Lifecycle {
	return &Lifecycle{verifier: v, tokens: t, revoker: r, partners: p, keys: k, log: log, now: time.Now}
}

type RevokeRequest struct {
	ClientAssertionType string
	ClientAssertion     string
	ClientID            string
	Token               string
}

// Revoke implements RFC 7009 for access tokens. The client authenticates
// with private_key_jwt and may revoke only its own tokens. An invalid or
// expired token is not an error (§2.2: respond 200 either way, so the
// endpoint is no oracle for token validity).
func (l *Lifecycle) Revoke(ctx context.Context, req RevokeRequest) error {
	if req.ClientAssertionType != clientauth.AssertionType || req.ClientAssertion == "" {
		return oauthErr(ErrInvalidClient, "private_key_jwt client authentication required")
	}
	if req.Token == "" {
		return oauthErr(ErrInvalidRequest, "token is required")
	}
	a, err := authenticate(ctx, l.verifier, l.log, req.ClientAssertion, req.ClientID)
	if err != nil {
		return err
	}
	c, err := l.tokens.Inspect(req.Token)
	if err != nil {
		l.log.InfoContext(ctx, "revoke: not our token, ignored", "client_id", a.ClientID)
		return nil
	}
	if c.ClientID != a.ClientID {
		l.log.WarnContext(ctx, "revoke: token belongs to another client", "client_id", a.ClientID, "token_client_id", c.ClientID)
		return oauthErr(ErrUnauthorizedClient, "the token was not issued to this client")
	}
	if !c.ExpiresAt.After(l.now()) {
		return nil
	}
	if err := l.revoker.Revoke(ctx, revocation.Event{Kind: revocation.KindJTI, Issuer: c.Issuer, Value: c.JTI, ExpiresAt: c.ExpiresAt.Unix()}); err != nil {
		l.log.ErrorContext(ctx, "revoke failed", "jti", c.JTI, "err", err)
		return oauthErr(ErrServerError, "temporarily unavailable")
	}
	l.log.InfoContext(ctx, "token revoked", "client_id", a.ClientID, "jti", c.JTI)
	return nil
}

// Introspection is the RFC 7662 response. Inactive tokens get only
// {"active": false}: nothing else may leak.
type Introspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Sub       string `json:"sub,omitempty"`
	PartnerID string `json:"partner_id,omitempty"`
	Iss       string `json:"iss,omitempty"`
	JTI       string `json:"jti,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
}

// Introspect answers active = our signature + not expired + not revoked +
// partner still active. The caller (a resource server) is authenticated
// by the adapter. A dependency error is returned, not reported inactive,
// so the resource server fails closed and logs the real cause.
func (l *Lifecycle) Introspect(ctx context.Context, raw string) (Introspection, error) {
	c, err := l.tokens.Inspect(raw)
	if err != nil || !c.ExpiresAt.After(l.now()) {
		return Introspection{Active: false}, nil
	}
	revoked, err := l.revoker.IsRevoked(ctx, authn.TokenRef{Issuer: c.Issuer, JTI: c.JTI, ClientID: c.ClientID, IssuedAt: c.IssuedAt})
	if err != nil {
		return Introspection{}, err
	}
	if revoked {
		return Introspection{Active: false}, nil
	}
	p, err := l.partners.Partner(ctx, c.ClientID)
	if errors.Is(err, domain.ErrNotFound) {
		return Introspection{Active: false}, nil
	}
	if err != nil {
		return Introspection{}, err
	}
	if !p.Active() {
		return Introspection{Active: false}, nil
	}
	return Introspection{
		Active: true, Scope: c.Scope, ClientID: c.ClientID, Sub: c.Subject, PartnerID: c.PartnerID,
		Iss: c.Issuer, JTI: c.JTI, TokenType: "Bearer", Exp: c.ExpiresAt.Unix(), Iat: c.IssuedAt.Unix(),
	}, nil
}

// SuspendPartner stops issuance (status) and kills tokens already issued
// (client-level revocation with cut-off = now, kept for one token lifetime).
func (l *Lifecycle) SuspendPartner(ctx context.Context, clientID string) error {
	if err := l.partners.SetStatus(ctx, clientID, domain.PartnerSuspended); err != nil {
		return err
	}
	now := l.now()
	err := l.revoker.Revoke(ctx, revocation.Event{
		Kind: revocation.KindClient, Issuer: l.tokens.Issuer(), Value: clientID,
		NotBefore: now.Unix(), ExpiresAt: now.Add(l.tokens.TTL() + 30*time.Second).Unix(),
	})
	if err != nil {
		return err
	}
	l.log.InfoContext(ctx, "partner suspended", "client_id", clientID)
	return nil
}

// ResumePartner re-enables issuance. Tokens from before the suspension stay
// revoked until the client entry expires.
func (l *Lifecycle) ResumePartner(ctx context.Context, clientID string) error {
	if err := l.partners.SetStatus(ctx, clientID, domain.PartnerActive); err != nil {
		return err
	}
	l.log.InfoContext(ctx, "partner resumed", "client_id", clientID)
	return nil
}

func (l *Lifecycle) Rotate(ctx context.Context) (keyring.KeyInfo, error) {
	info, err := l.keys.Rotate(ctx)
	if err != nil {
		return keyring.KeyInfo{}, err
	}
	l.log.InfoContext(ctx, "key rotation started", "next_kid", info.KID, "activates_at", info.ActivatesAt)
	return info, nil
}

func (l *Lifecycle) Keys() []keyring.KeyInfo { return l.keys.Keys() }
