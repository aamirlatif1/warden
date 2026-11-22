// Package app holds policy-api's use cases. It depends on domain and on the
// small store interfaces declared here; adapters implement them.
//
// Authorization is not done here: authz.Decide runs in the driving adapters
// (S3). Until then every authenticated caller reaches these use cases.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aamirlatif1/warden/internal/policy/domain"
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
	SaveClaim(ctx context.Context, c domain.Claim) error
}

type Service struct {
	policies PolicyStore
	quotes   QuoteStore
	claims   ClaimStore
	now      func() time.Time
}

func NewService(p PolicyStore, q QuoteStore, c ClaimStore) *Service {
	return &Service{policies: p, quotes: q, claims: c, now: time.Now}
}

type CreateQuoteInput struct {
	PartnerID    string
	Product      string
	InsuredValue domain.Money
}

func (s *Service) CreateQuote(ctx context.Context, in CreateQuoteInput) (domain.Quote, error) {
	if strings.TrimSpace(in.PartnerID) == "" || strings.TrimSpace(in.Product) == "" {
		return domain.Quote{}, fmt.Errorf("partner_id and product are required: %w", domain.ErrInvalidArgument)
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
		CreatedAt: s.now().UTC(),
	}
	if err := s.quotes.SaveQuote(ctx, q); err != nil {
		return domain.Quote{}, fmt.Errorf("save quote: %w", err)
	}
	return q, nil
}

func (s *Service) ListPolicies(ctx context.Context, holderSubject string) ([]domain.Policy, error) {
	if holderSubject == "" {
		return nil, domain.ErrInvalidArgument
	}
	return s.policies.ListPoliciesByHolder(ctx, holderSubject)
}

func (s *Service) GetPolicy(ctx context.Context, id string) (domain.Policy, error) {
	return s.policies.GetPolicy(ctx, id)
}

func (s *Service) UpdatePayoutAccount(ctx context.Context, policyID, iban string) (domain.Policy, error) {
	norm, err := domain.NormalizeIBAN(iban)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("iban: %w", err)
	}
	return s.policies.SetPayoutIBAN(ctx, policyID, norm)
}

// ApproveClaim is read-modify-write without a transaction; S3 moves it to
// Postgres behind a transaction.
func (s *Service) ApproveClaim(ctx context.Context, claimID string) (domain.Claim, error) {
	c, err := s.claims.GetClaim(ctx, claimID)
	if err != nil {
		return domain.Claim{}, err
	}
	approved, err := c.Approve()
	if err != nil {
		return domain.Claim{}, err
	}
	if err := s.claims.SaveClaim(ctx, approved); err != nil {
		return domain.Claim{}, fmt.Errorf("save claim: %w", err)
	}
	return approved, nil
}

func newID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}
