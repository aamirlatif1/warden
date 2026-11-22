// Package app holds policy-api's use cases. It depends on domain, on the
// pure authz engine and authn.Principal, and on the small interfaces
// declared here; adapters implement them.
//
// Every use case authorizes in the same order: load the resource, call
// authz.Decide, log the decision, and only then validate input and act.
// Input is validated after authz so an unauthorized caller learns nothing
// from validation errors.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authz"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

var (
	// ErrUnavailable: a dependency needed to decide safely is down (e.g.
	// introspection). The request fails closed.
	ErrUnavailable = errors.New("dependency unavailable")
	// ErrTokenInactive: online introspection says the token is no longer
	// active (revoked or suspended).
	ErrTokenInactive = errors.New("token inactive")
)

type PolicyStore interface {
	ListPoliciesByHolder(ctx context.Context, subject string) ([]domain.Policy, error)
	GetPolicy(ctx context.Context, id string) (domain.Policy, error)
	SetPayoutIBAN(ctx context.Context, policyID, iban string) (domain.Policy, error)
}

type QuoteStore interface {
	SaveQuote(ctx context.Context, q domain.Quote) error
}

type ClaimStore interface {
	GetClaim(ctx context.Context, id string) (domain.Claim, error)
	// GetClaimForUpdate locks the row until the surrounding InTx ends.
	GetClaimForUpdate(ctx context.Context, id string) (domain.Claim, error)
	SaveClaim(ctx context.Context, c domain.Claim) error
}

// ApprovalLimits returns an underwriter's approval limit in euro cents, or
// 0 when the subject has none.
type ApprovalLimits interface {
	ApprovalLimit(ctx context.Context, subject string) (int64, error)
}

// Introspector checks online that the caller's token is still active
// (RFC 7662). Wired in S5; until then high-value approvals fail closed.
type Introspector interface {
	Active(ctx context.Context, p authn.Principal) (bool, error)
}

// TxRunner runs fn in one transaction; stores called with the ctx passed
// to fn take part in it.
type TxRunner interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type Deps struct {
	Policies     PolicyStore
	Quotes       QuoteStore
	Claims       ClaimStore
	Limits       ApprovalLimits
	Tx           TxRunner
	Introspector Introspector // nil: introspection unavailable, fail closed
	Log          *slog.Logger
	Now          func() time.Time // nil: time.Now
	// Decide is the authorization engine; nil means authz.Decide. Tests
	// replace it to observe what the use cases pass in.
	Decide func(authn.Principal, authz.Action, authz.Resource, authz.Env) authz.Decision
}

type Service struct {
	d Deps
}

func NewService(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Decide == nil {
		d.Decide = authz.Decide
	}
	return &Service{d: d}
}

// authorize calls the engine and writes the decision log line. Tokens are
// never logged; the subject and issuer are.
func (s *Service) authorize(ctx context.Context, p authn.Principal, a authz.Action, r authz.Resource, env authz.Env) authz.Decision {
	env.Now = s.d.Now()
	d := s.d.Decide(p, a, r, env)
	s.d.Log.InfoContext(ctx, "authz decision",
		"action", string(a),
		"effect", d.Effect.String(),
		"reason", string(d.Reason),
		"sub", p.Subject,
		"iss", p.Issuer,
		"client_id", p.ClientID,
		"resource_id", r.ID,
		"introspect", d.Introspect,
	)
	return d
}

type CreateQuoteInput struct {
	PartnerID    string
	Product      string
	InsuredValue domain.Money
}

func (s *Service) CreateQuote(ctx context.Context, p authn.Principal, in CreateQuoteInput) (domain.Quote, error) {
	d := s.authorize(ctx, p, authz.ActionCreateQuote, authz.Resource{PartnerID: in.PartnerID}, authz.Env{})
	if err := d.Err(); err != nil {
		return domain.Quote{}, err
	}
	if strings.TrimSpace(in.Product) == "" {
		return domain.Quote{}, fmt.Errorf("product is required: %w", domain.ErrInvalidArgument)
	}
	premium, err := domain.PriceQuote(in.InsuredValue)
	if err != nil {
		return domain.Quote{}, fmt.Errorf("insured value: %w", err)
	}
	q := domain.Quote{
		ID:        newID("q"),
		PartnerID: in.PartnerID,
		Product:   in.Product,
		Premium:   premium,
		CreatedAt: s.d.Now().UTC(),
	}
	if err := s.d.Quotes.SaveQuote(ctx, q); err != nil {
		return domain.Quote{}, fmt.Errorf("save quote: %w", err)
	}
	return q, nil
}

func (s *Service) ListPolicies(ctx context.Context, p authn.Principal) ([]domain.Policy, error) {
	d := s.authorize(ctx, p, authz.ActionListPolicies, authz.Resource{}, authz.Env{})
	if err := d.Err(); err != nil {
		return nil, err
	}
	return s.d.Policies.ListPoliciesByHolder(ctx, p.Subject)
}

func (s *Service) GetPolicy(ctx context.Context, p authn.Principal, id string) (domain.Policy, error) {
	pol, err := s.d.Policies.GetPolicy(ctx, id)
	if err != nil {
		return domain.Policy{}, err
	}
	d := s.authorize(ctx, p, authz.ActionGetPolicy, authz.Resource{ID: id, OwnerSubject: pol.HolderSubject}, authz.Env{})
	if err := d.Err(); err != nil {
		return domain.Policy{}, err
	}
	return pol, nil
}

func (s *Service) UpdatePayoutAccount(ctx context.Context, p authn.Principal, policyID, iban string) (domain.Policy, error) {
	pol, err := s.d.Policies.GetPolicy(ctx, policyID)
	if err != nil {
		return domain.Policy{}, err
	}
	d := s.authorize(ctx, p, authz.ActionUpdatePayoutAccount, authz.Resource{ID: policyID, OwnerSubject: pol.HolderSubject}, authz.Env{})
	if err := d.Err(); err != nil {
		return domain.Policy{}, err
	}
	norm, err := domain.NormalizeIBAN(iban)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("iban: %w", err)
	}
	return s.d.Policies.SetPayoutIBAN(ctx, policyID, norm)
}

func (s *Service) ApproveClaim(ctx context.Context, p authn.Principal, claimID string) (domain.Claim, error) {
	c, err := s.d.Claims.GetClaim(ctx, claimID)
	if err != nil {
		return domain.Claim{}, err
	}
	limit, err := s.d.Limits.ApprovalLimit(ctx, p.Subject)
	if err != nil {
		return domain.Claim{}, fmt.Errorf("approval limit: %w", err)
	}
	d := s.authorize(ctx, p, authz.ActionApproveClaim,
		authz.Resource{ID: claimID, AmountMinor: c.Amount.AmountMinor},
		authz.Env{ApprovalLimitMinor: limit})
	if err := d.Err(); err != nil {
		return domain.Claim{}, err
	}
	if d.Introspect {
		if err := s.introspect(ctx, p); err != nil {
			return domain.Claim{}, err
		}
	}

	// Network calls are done; now lock the row and change state.
	var approved domain.Claim
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		locked, err := s.d.Claims.GetClaimForUpdate(ctx, claimID)
		if err != nil {
			return err
		}
		approved, err = locked.Approve()
		if err != nil {
			return err
		}
		return s.d.Claims.SaveClaim(ctx, approved)
	})
	if err != nil {
		return domain.Claim{}, err
	}
	return approved, nil
}

func (s *Service) introspect(ctx context.Context, p authn.Principal) error {
	if s.d.Introspector == nil {
		s.d.Log.WarnContext(ctx, "introspection required but not configured; failing closed", "sub", p.Subject)
		return ErrUnavailable
	}
	active, err := s.d.Introspector.Active(ctx, p)
	if err != nil {
		s.d.Log.WarnContext(ctx, "introspection failed; failing closed", "sub", p.Subject, "err", err)
		return ErrUnavailable
	}
	if !active {
		return ErrTokenInactive
	}
	return nil
}

func newID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}
