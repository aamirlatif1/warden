package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/domain"
)

// Policy as the portal shows it.
type Policy struct {
	ID               string
	Product          string
	Status           string
	PayoutIBANMasked string
}

// StepUpRequired: policy-api answered 401 insufficient_user_authentication
// (RFC 9470) with these parameters.
type StepUpRequired struct {
	ACR    string
	MaxAge time.Duration
}

func (e *StepUpRequired) Error() string {
	return fmt.Sprintf("step-up required: acr_values=%s max_age=%s", e.ACR, e.MaxAge)
}

var (
	ErrAPIUnauthorized = errors.New("policy-api rejected the access token")
	ErrAPIForbidden    = errors.New("policy-api: forbidden")
	ErrAPINotFound     = errors.New("policy-api: not found")
	ErrAPIInvalid      = errors.New("policy-api: invalid input")
)

type PolicyAPI interface {
	ListPolicies(ctx context.Context, accessToken string) ([]Policy, error)
	UpdatePayout(ctx context.Context, accessToken, policyID, iban string) (Policy, error)
}

type AccessTokens interface {
	AccessToken(ctx context.Context, sid string) (string, error)
}

// StepUpNeeded tells the web layer to start a step-up login with Login.
type StepUpNeeded struct{ Login LoginRequest }

func (e *StepUpNeeded) Error() string { return "step-up login needed" }

// Portal is what a logged-in policyholder can do.
type Portal struct {
	tokens   AccessTokens
	api      PolicyAPI
	sessions SessionStore
	log      *slog.Logger
}

func NewPortal(t AccessTokens, api PolicyAPI, s SessionStore, log *slog.Logger) *Portal {
	return &Portal{tokens: t, api: api, sessions: s, log: log}
}

type Dashboard struct {
	Session  domain.Session
	Policies []Policy
}

func (p *Portal) Dashboard(ctx context.Context, sid string) (Dashboard, error) {
	s, err := p.sessions.Get(ctx, sid)
	if err != nil {
		return Dashboard{}, err
	}
	tok, err := p.tokens.AccessToken(ctx, sid)
	if err != nil {
		return Dashboard{}, err
	}
	pols, err := p.api.ListPolicies(ctx, tok)
	if err != nil {
		return Dashboard{}, p.apiErr(ctx, sid, err)
	}
	return Dashboard{Session: s, Policies: pols}, nil
}

// UpdatePayout changes the payout IBAN. If policy-api demands step-up, it
// returns *StepUpNeeded carrying the intent to replay after re-auth.
func (p *Portal) UpdatePayout(ctx context.Context, sid, policyID, iban string) (Policy, error) {
	s, err := p.sessions.Get(ctx, sid)
	if err != nil {
		return Policy{}, err
	}
	tok, err := p.tokens.AccessToken(ctx, sid)
	if err != nil {
		return Policy{}, err
	}
	pol, err := p.api.UpdatePayout(ctx, tok, policyID, iban)
	var su *StepUpRequired
	if errors.As(err, &su) {
		p.log.InfoContext(ctx, "step-up required", "sub", s.Subject, "acr_values", su.ACR, "max_age", su.MaxAge.String())
		return Policy{}, &StepUpNeeded{Login: LoginRequest{
			ReturnTo:       "/",
			ACRValues:      su.ACR,
			MaxAge:         su.MaxAge,
			Pending:        &domain.PendingAction{Kind: domain.PendingUpdatePayout, PolicyID: policyID, IBAN: iban},
			PendingSubject: s.Subject,
		}}
	}
	if err != nil {
		return Policy{}, p.apiErr(ctx, sid, err)
	}
	return pol, nil
}

// apiErr: a plain 401 means the token is dead (revoked, user disabled):
// end the session so the user logs in again.
func (p *Portal) apiErr(ctx context.Context, sid string, err error) error {
	if errors.Is(err, ErrAPIUnauthorized) {
		_ = p.sessions.Delete(ctx, sid)
		return ErrSessionEnded
	}
	return err
}
