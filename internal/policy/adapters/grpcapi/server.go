// Package grpcapi is the gRPC driving adapter for policy-api.
package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/aamirlatif1/warden/gen/warden/policy/v1"
	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

// PolicyService is the part of *app.Service this adapter calls.
type PolicyService interface {
	CreateQuote(ctx context.Context, in app.CreateQuoteInput) (domain.Quote, error)
	ListPolicies(ctx context.Context, holderSubject string) ([]domain.Policy, error)
	GetPolicy(ctx context.Context, id string) (domain.Policy, error)
	UpdatePayoutAccount(ctx context.Context, policyID, iban string) (domain.Policy, error)
	ApproveClaim(ctx context.Context, claimID string) (domain.Claim, error)
}

type Server struct {
	policyv1.UnimplementedPolicyServiceServer
	svc PolicyService
	log *slog.Logger
}

func NewServer(svc PolicyService, log *slog.Logger) *Server {
	return &Server{svc: svc, log: log}
}

func (s *Server) CreateQuote(ctx context.Context, req *policyv1.CreateQuoteRequest) (*policyv1.CreateQuoteResponse, error) {
	q, err := s.svc.CreateQuote(ctx, app.CreateQuoteInput{
		PartnerID:    req.GetPartnerId(),
		Product:      req.GetProduct(),
		InsuredValue: moneyFromPB(req.GetInsuredValue()),
	})
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &policyv1.CreateQuoteResponse{Quote: &policyv1.Quote{
		Id:        q.ID,
		PartnerId: q.PartnerID,
		Product:   q.Product,
		Premium:   moneyToPB(q.Premium),
		CreatedAt: timestamppb.New(q.CreatedAt),
	}}, nil
}

func (s *Server) ListPolicies(ctx context.Context, _ *policyv1.ListPoliciesRequest) (*policyv1.ListPoliciesResponse, error) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	ps, err := s.svc.ListPolicies(ctx, p.Subject)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	out := make([]*policyv1.Policy, 0, len(ps))
	for _, pol := range ps {
		out = append(out, policyToPB(pol))
	}
	return &policyv1.ListPoliciesResponse{Policies: out}, nil
}

func (s *Server) GetPolicy(ctx context.Context, req *policyv1.GetPolicyRequest) (*policyv1.GetPolicyResponse, error) {
	pol, err := s.svc.GetPolicy(ctx, req.GetId())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &policyv1.GetPolicyResponse{Policy: policyToPB(pol)}, nil
}

func (s *Server) UpdatePayoutAccount(ctx context.Context, req *policyv1.UpdatePayoutAccountRequest) (*policyv1.UpdatePayoutAccountResponse, error) {
	pol, err := s.svc.UpdatePayoutAccount(ctx, req.GetPolicyId(), req.GetIban())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &policyv1.UpdatePayoutAccountResponse{Policy: policyToPB(pol)}, nil
}

func (s *Server) ApproveClaim(ctx context.Context, req *policyv1.ApproveClaimRequest) (*policyv1.ApproveClaimResponse, error) {
	c, err := s.svc.ApproveClaim(ctx, req.GetClaimId())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &policyv1.ApproveClaimResponse{Claim: &policyv1.Claim{
		Id:       c.ID,
		PolicyId: c.PolicyID,
		Amount:   moneyToPB(c.Amount),
		Status:   string(c.Status),
	}}, nil
}

func (s *Server) toStatus(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, domain.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrConflict):
		return status.Error(codes.FailedPrecondition, "conflict")
	default:
		s.log.ErrorContext(ctx, "policy-api internal error", "err", err)
		return status.Error(codes.Internal, "internal error")
	}
}

func moneyFromPB(m *policyv1.Money) domain.Money {
	return domain.Money{AmountMinor: m.GetAmountMinor(), Currency: m.GetCurrency()}
}

func moneyToPB(m domain.Money) *policyv1.Money {
	return &policyv1.Money{AmountMinor: m.AmountMinor, Currency: m.Currency}
}

func policyToPB(p domain.Policy) *policyv1.Policy {
	return &policyv1.Policy{
		Id:               p.ID,
		HolderSubject:    p.HolderSubject,
		Product:          p.Product,
		Status:           p.Status,
		PayoutIbanMasked: p.MaskedIBAN(),
	}
}
