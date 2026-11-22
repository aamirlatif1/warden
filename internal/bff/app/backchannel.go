package app

import (
	"context"
	"log/slog"

	"github.com/aamirlatif1/warden/internal/bff/logouttoken"
)

// LogoutTokenValidator is implemented by logouttoken.Validator.
type LogoutTokenValidator interface {
	Validate(ctx context.Context, raw string) (logouttoken.Claims, error)
}

// SessionsBySID ends every BFF session bound to one Keycloak SSO session.
type SessionsBySID interface {
	DeleteByKeycloakSID(ctx context.Context, kcSID string) (int, error)
}

// Backchannel handles OIDC Back-Channel Logout: Keycloak tells the BFF an
// SSO session ended (admin "sign out", logout in another app, expiry).
type Backchannel struct {
	tokens   LogoutTokenValidator
	sessions SessionsBySID
	log      *slog.Logger
}

func NewBackchannel(v LogoutTokenValidator, s SessionsBySID, log *slog.Logger) *Backchannel {
	return &Backchannel{tokens: v, sessions: s, log: log}
}

// Logout validates the logout token and deletes the sessions for its sid.
// Rejections are *logouttoken.Error; anything else is a storage failure.
func (b *Backchannel) Logout(ctx context.Context, raw string) error {
	cl, err := b.tokens.Validate(ctx, raw)
	if err != nil {
		b.log.WarnContext(ctx, "backchannel logout rejected", "reason", string(logouttoken.ReasonOf(err)))
		return err
	}
	n, err := b.sessions.DeleteByKeycloakSID(ctx, cl.SID)
	if err != nil {
		return err
	}
	b.log.InfoContext(ctx, "backchannel logout", "sub", cl.Subject, "sessions_ended", n)
	return nil
}
