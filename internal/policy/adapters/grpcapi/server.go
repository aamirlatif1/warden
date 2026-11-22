// Package grpcapi is the gRPC driving adapter for policy-api.
package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/aamirlatif1/warden/gen/warden/policy/v1"
	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authz"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

// PolicyService is the part of *app.Service this adapter calls.
type PolicyService interface {
	CreateQuote(ctx context.Context, p authn.Principal, in app.CreateQuoteInput) (domain.Quote, error)
	ListPolicies(ctx context.Context, p authn.Principal) ([]domain.Policy, error)
	GetPolicy(ctx context.Context, p authn.Principal, id string) (domain.Policy, error)
	UpdatePayoutAccount(ctx context.Context, p authn.Principal, policyID, iban string) (domain.Policy, error)
	ApproveClaim(ctx context.Context, p authn.Principal, claimID string) (domain.Claim, error)
}

var errUnauthenticated = status.Error(codes.Unauthenticated, "unauthenticated")

type Server struct {
	policyv1.UnimplementedPolicyServiceServer
	svc PolicyService
	log *slog.Logger
}

func NewServer(svc PolicyService, log *slog.Logger) *Server {
	return &Server{svc: svc, log: log}
}

func (s *Server) CreateQuote(ctx context.Context, req *policyv1.CreateQuoteRequest) (*policyv1.CreateQuoteResponse, error) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	q, err := s.svc.CreateQuote(ctx, p, app.CreateQuoteInput{
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
		return nil, errUnauthenticated
	}
	ps, err := s.svc.ListPolicies(ctx, p)
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
	p, ok := authn.FromContext(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	pol, err := s.svc.GetPolicy(ctx, p, req.GetId())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &policyv1.GetPolicyResponse{Policy: policyToPB(pol)}, nil
}

func (s *Server) UpdatePayoutAccount(ctx context.Context, req *policyv1.UpdatePayoutAccountRequest) (*policyv1.UpdatePayoutAccountResponse, error) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	pol, err := s.svc.UpdatePayoutAccount(ctx, p, req.GetPolicyId(), req.GetIban())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &policyv1.UpdatePayoutAccountResponse{Policy: policyToPB(pol)}, nil
}

func (s *Server) ApproveClaim(ctx context.Context, req *policyv1.ApproveClaimRequest) (*policyv1.ApproveClaimResponse, error) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	c, err := s.svc.ApproveClaim(ctx, p, req.GetClaimId())
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

// toStatus maps app errors to gRPC status. Step-up is Unauthenticated
// with the RFC 9470 challenge in the "www-authenticate" trailer, the gRPC
// equivalent of the HTTP header.
func (s *Server) toStatus(ctx context.Context, err error) error {
	var denied *authz.DeniedError
	var stepUp *authz.StepUpError
	switch {
	case errors.As(err, &stepUp):
		_ = grpc.SetTrailer(ctx, metadata.Pairs("www-authenticate", stepUp.Challenge()))
		return status.Error(codes.Unauthenticated, "insufficient_user_authentication")
	case errors.As(err, &denied):
		return status.Error(codes.PermissionDenied, "forbidden: "+string(denied.Reason))
	case errors.Is(err, app.ErrTokenInactive):
		return status.Error(codes.Unauthenticated, "token inactive")
	case errors.Is(err, app.ErrUnavailable):
		return status.Error(codes.Unavailable, "temporarily unavailable")
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
