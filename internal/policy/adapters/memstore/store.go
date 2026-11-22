// Package memstore is an in-memory driven adapter for the app stores, used
// by unit tests. policy-api itself runs on pgstore (Postgres).
package memstore

import (
	"context"
	"sort"
	"sync"

	"github.com/aamirlatif1/warden/internal/policy/domain"
)

type Store struct {
	txMu     sync.Mutex
	mu       sync.RWMutex
	policies map[string]domain.Policy
	quotes   map[string]domain.Quote
	claims   map[string]domain.Claim
	limits   map[string]int64
}

func New() *Store {
	return &Store{
		policies: map[string]domain.Policy{},
		quotes:   map[string]domain.Quote{},
		claims:   map[string]domain.Claim{},
		limits:   map[string]int64{},
	}
}

// AddPolicy and AddClaim seed the store (tests, local runs).
func (s *Store) AddPolicy(p domain.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = p
}

func (s *Store) AddClaim(c domain.Claim) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims[c.ID] = c
}

func (s *Store) ListPoliciesByHolder(_ context.Context, subject string) ([]domain.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []domain.Policy{}
	for _, p := range s.policies {
		if p.HolderSubject == subject {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) GetPolicy(_ context.Context, id string) (domain.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return domain.Policy{}, domain.ErrNotFound
	}
	return p, nil
}

func (s *Store) SetPayoutIBAN(_ context.Context, policyID, iban string) (domain.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[policyID]
	if !ok {
		return domain.Policy{}, domain.ErrNotFound
	}
	p.PayoutIBAN = iban
	s.policies[policyID] = p
	return p, nil
}

func (s *Store) SaveQuote(_ context.Context, q domain.Quote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotes[q.ID] = q
	return nil
}

func (s *Store) GetClaim(_ context.Context, id string) (domain.Claim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.claims[id]
	if !ok {
		return domain.Claim{}, domain.ErrNotFound
	}
	return c, nil
}

func (s *Store) SaveClaim(_ context.Context, c domain.Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims[c.ID] = c
	return nil
}

// GetClaimForUpdate has no locking here; InTx serialises instead.
func (s *Store) GetClaimForUpdate(ctx context.Context, id string) (domain.Claim, error) {
	return s.GetClaim(ctx, id)
}

func (s *Store) SetApprovalLimit(subject string, limitMinor int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits[subject] = limitMinor
}

func (s *Store) ApprovalLimit(_ context.Context, subject string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.limits[subject], nil
}

// InTx runs fn while holding a store-wide transaction lock, so concurrent
// InTx calls are serialised (enough for tests).
func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	return fn(ctx)
}
