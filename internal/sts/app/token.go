// Package app holds partner-sts's token use case: authenticate the client
// with private_key_jwt, check the partner, downscope, mint.
package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/aamirlatif1/warden/internal/issuer"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

// OAuth error codes (RFC 6749 §5.2).
const (
	ErrInvalidRequest       = "invalid_request"
	ErrInvalidClient        = "invalid_client"
	ErrUnsupportedGrantType = "unsupported_grant_type"
	ErrInvalidScope         = "invalid_scope"
	ErrServerError          = "server_error"
)

// OAuthError is returned to the client as {"error", "error_description"}.
// Description is generic on purpose: the real reason goes to the log only.
type OAuthError struct {
	Code        string
	Description string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func oauthErr(code, desc string) *OAuthError { return &OAuthError{Code: code, Description: desc} }

type AssertionVerifier interface {
	Verify(ctx context.Context, raw string) (clientauth.Assertion, error)
}

type PartnerStore interface {
	Partner(ctx context.Context, clientID string) (domain.Partner, error)
}

type TokenMinter interface {
	Mint(ctx context.Context, g issuer.Grant) (issuer.Token, error)
}

type TokenRequest struct {
	GrantType           string
	ClientAssertionType string
	ClientAssertion     string
	ClientID            string // optional; if present must match the assertion
	Scope               string // space-separated
}

type TokenResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
}

type TokenService struct {
	verifier AssertionVerifier
	partners PartnerStore
	minter   TokenMinter
	log      *slog.Logger
	ttl      int
}

func NewTokenService(v AssertionVerifier, p PartnerStore, m TokenMinter, log *slog.Logger) *TokenService {
	return &TokenService{verifier: v, partners: p, minter: m, log: log, ttl: 300}
}

// Token implements the client_credentials grant with private_key_jwt.
func (s *TokenService) Token(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	if req.GrantType != "client_credentials" {
		return TokenResponse{}, oauthErr(ErrUnsupportedGrantType, "only client_credentials is supported")
	}
	if req.ClientAssertionType != clientauth.AssertionType || req.ClientAssertion == "" {
		return TokenResponse{}, oauthErr(ErrInvalidClient, "private_key_jwt client authentication required")
	}

	a, err := s.verifier.Verify(ctx, req.ClientAssertion)
	if err != nil {
		reason := clientauth.ReasonOf(err)
		var ce *clientauth.Error
		claimed := ""
		if errors.As(err, &ce) {
			claimed = ce.ClientID
		}
		s.log.WarnContext(ctx, "client authentication failed", "reason", string(reason), "claimed_client_id", claimed)
		if reason == clientauth.ReasonReplayUnavailable || reason == clientauth.ReasonInternal {
			return TokenResponse{}, oauthErr(ErrServerError, "temporarily unavailable")
		}
		return TokenResponse{}, oauthErr(ErrInvalidClient, "client authentication failed")
	}
	if req.ClientID != "" && req.ClientID != a.ClientID {
		s.log.WarnContext(ctx, "client authentication failed", "reason", "client_id_mismatch", "claimed_client_id", a.ClientID)
		return TokenResponse{}, oauthErr(ErrInvalidClient, "client authentication failed")
	}

	p, err := s.partners.Partner(ctx, a.ClientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return TokenResponse{}, oauthErr(ErrInvalidClient, "client authentication failed")
		}
		s.log.ErrorContext(ctx, "partner lookup failed", "client_id", a.ClientID, "err", err)
		return TokenResponse{}, oauthErr(ErrServerError, "temporarily unavailable")
	}
	if !p.Active() {
		s.log.WarnContext(ctx, "client authentication failed", "reason", "partner_suspended", "client_id", a.ClientID)
		return TokenResponse{}, oauthErr(ErrInvalidClient, "client authentication failed")
	}

	scopes := p.Downscope(strings.Fields(req.Scope))
	if len(scopes) == 0 {
		return TokenResponse{}, oauthErr(ErrInvalidScope, "no requested scope is allowed for this client")
	}

	tok, err := s.minter.Mint(ctx, issuer.Grant{ClientID: p.ClientID, PartnerID: p.PartnerID, Scopes: scopes})
	if err != nil {
		s.log.ErrorContext(ctx, "mint failed", "client_id", p.ClientID, "err", err)
		return TokenResponse{}, oauthErr(ErrServerError, "temporarily unavailable")
	}
	s.log.InfoContext(ctx, "token issued",
		"client_id", p.ClientID, "partner_id", p.PartnerID, "scope", strings.Join(scopes, " "),
		"jti", tok.JTI, "kid", tok.KeyID, "assertion_jti", a.JTI)

	return TokenResponse{AccessToken: tok.Value, TokenType: "Bearer", ExpiresIn: s.ttl, Scope: strings.Join(scopes, " ")}, nil
}
