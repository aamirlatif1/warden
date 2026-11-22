package app

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/domain"
)

type AuthConfig struct {
	TxTTL time.Duration    // login transaction lifetime; 0 means 10 min
	Now   func() time.Time // nil means time.Now
}

// AuthService runs the authorization code + PKCE flow and the session
// lifecycle around it.
type AuthService struct {
	oidc     OIDC
	sessions SessionStore
	txs      TxStore
	log      *slog.Logger
	cfg      AuthConfig
}

func NewAuthService(o OIDC, s SessionStore, t TxStore, log *slog.Logger, cfg AuthConfig) *AuthService {
	if cfg.TxTTL == 0 {
		cfg.TxTTL = 10 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &AuthService{oidc: o, sessions: s, txs: t, log: log, cfg: cfg}
}

type LoginRequest struct {
	ReturnTo       string
	ACRValues      string
	MaxAge         time.Duration
	Pending        *domain.PendingAction
	PendingSubject string
	IDPHint        string // skip Keycloak's login page and go to this broker
}

// Login creates the single-use login transaction (state, nonce, PKCE
// verifier) and returns its ID (the __Host-preauth cookie) and the
// authorization URL to redirect to.
func (a *AuthService) Login(ctx context.Context, req LoginRequest) (txID, redirectURL string, err error) {
	tx := domain.LoginTx{
		ID:             randomToken(),
		State:          randomToken(),
		Nonce:          randomToken(),
		Verifier:       randomToken(), // 43 chars: within RFC 7636's 43..128
		ReturnTo:       SafeReturnTo(req.ReturnTo),
		ACRValues:      req.ACRValues,
		MaxAge:         req.MaxAge,
		CreatedAt:      a.cfg.Now(),
		Pending:        req.Pending,
		PendingSubject: req.PendingSubject,
	}
	if err := a.txs.Put(ctx, tx, a.cfg.TxTTL); err != nil {
		return "", "", err
	}
	url := a.oidc.AuthURL(AuthParams{
		State: tx.State, Nonce: tx.Nonce, CodeChallenge: pkceChallenge(tx.Verifier),
		ACRValues: tx.ACRValues, MaxAge: tx.MaxAge, IDPHint: req.IDPHint,
	})
	return tx.ID, url, nil
}

// SafeReturnTo keeps only local absolute paths, so /login?return_to= can't
// become an open redirect ("//evil", "/\evil", "https://evil" → "/").
func SafeReturnTo(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") ||
		strings.ContainsAny(p, "\\\r\n") || strings.Contains(p, "://") {
		return "/"
	}
	return p
}

// Logout deletes the session and returns Keycloak's end-session URL
// (RP-initiated logout) so the SSO session ends too.
func (a *AuthService) Logout(ctx context.Context, sid, postLogoutRedirect string) (string, error) {
	s, err := a.sessions.Get(ctx, sid)
	if err != nil {
		return postLogoutRedirect, nil // nothing to end
	}
	if err := a.sessions.Delete(ctx, sid); err != nil {
		return "", err
	}
	a.log.InfoContext(ctx, "logout", "sub", s.Subject)
	return a.oidc.EndSessionURL(s.IDToken, postLogoutRedirect), nil
}
