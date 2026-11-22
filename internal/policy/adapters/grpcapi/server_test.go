package grpcapi_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	policyv1 "github.com/aamirlatif1/warden/gen/warden/policy/v1"
	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authz"
	"github.com/aamirlatif1/warden/internal/policy/adapters/grpcapi"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

type stubService struct {
	err  error
	seen authn.Principal
}

func (s *stubService) CreateQuote(_ context.Context, p authn.Principal, in app.CreateQuoteInput) (domain.Quote, error) {
	s.seen = p
	return domain.Quote{ID: "q1", PartnerID: in.PartnerID, CreatedAt: time.Unix(0, 0)}, s.err
}
func (s *stubService) ListPolicies(_ context.Context, p authn.Principal) ([]domain.Policy, error) {
	s.seen = p
	return []domain.Policy{{ID: "p1", PayoutIBAN: "DE89370400440532013000"}}, s.err
}
func (s *stubService) GetPolicy(_ context.Context, p authn.Principal, id string) (domain.Policy, error) {
	s.seen = p
	return domain.Policy{ID: id}, s.err
}
func (s *stubService) UpdatePayoutAccount(_ context.Context, p authn.Principal, id, _ string) (domain.Policy, error) {
	s.seen = p
	return domain.Policy{ID: id}, s.err
}
func (s *stubService) ApproveClaim(_ context.Context, p authn.Principal, id string) (domain.Claim, error) {
	s.seen = p
	return domain.Claim{ID: id}, s.err
}

// dial starts a real gRPC server over bufconn. The interceptor injects the
// principal from the "x-test-sub" metadata (standing in for grpcauth).
func dial(t *testing.T, svc *stubService) policyv1.PolicyServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	fakeAuth := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if v := md.Get("x-test-sub"); len(v) == 1 {
			ctx = authn.WithPrincipal(ctx, authn.Principal{Subject: v[0]})
		}
		return h(ctx, req)
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(fakeAuth))
	policyv1.RegisterPolicyServiceServer(srv, grpcapi.NewServer(svc, slog.New(slog.NewTextHandler(io.Discard, nil))))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return policyv1.NewPolicyServiceClient(conn)
}

func as(sub string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "x-test-sub", sub)
}

func TestPrincipalIsPassedToUseCases(t *testing.T) {
	svc := &stubService{}
	c := dial(t, svc)
	resp, err := c.ListPolicies(as("sub-anna"), &policyv1.ListPoliciesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if svc.seen.Subject != "sub-anna" {
		t.Fatalf("principal = %+v", svc.seen)
	}
	if got := resp.Policies[0].PayoutIbanMasked; got != "******************3000" {
		t.Fatalf("IBAN not masked: %q", got)
	}
}

func TestNoPrincipalIsUnauthenticated(t *testing.T) {
	c := dial(t, &stubService{})
	ctx := context.Background()
	calls := map[string]error{}
	_, calls["CreateQuote"] = c.CreateQuote(ctx, &policyv1.CreateQuoteRequest{})
	_, calls["ListPolicies"] = c.ListPolicies(ctx, &policyv1.ListPoliciesRequest{})
	_, calls["GetPolicy"] = c.GetPolicy(ctx, &policyv1.GetPolicyRequest{Id: "p1"})
	_, calls["UpdatePayoutAccount"] = c.UpdatePayoutAccount(ctx, &policyv1.UpdatePayoutAccountRequest{PolicyId: "p1"})
	_, calls["ApproveClaim"] = c.ApproveClaim(ctx, &policyv1.ApproveClaimRequest{ClaimId: "c1"})
	for name, err := range calls {
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s: code = %v", name, status.Code(err))
		}
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
	}{
		{"deny", &authz.DeniedError{Reason: authz.ReasonNotOwner}, codes.PermissionDenied},
		{"step-up", &authz.StepUpError{Reason: authz.ReasonACRTooLow, ACR: "gold", MaxAge: 5 * time.Minute}, codes.Unauthenticated},
		{"inactive token", app.ErrTokenInactive, codes.Unauthenticated},
		{"dependency down", app.ErrUnavailable, codes.Unavailable},
		{"not found", domain.ErrNotFound, codes.NotFound},
		{"invalid", domain.ErrInvalidArgument, codes.InvalidArgument},
		{"conflict", domain.ErrConflict, codes.FailedPrecondition},
		{"other", errors.New("db exploded at 10.0.0.5"), codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dial(t, &stubService{err: tc.err})
			var trailer metadata.MD
			_, err := c.UpdatePayoutAccount(as("sub-anna"), &policyv1.UpdatePayoutAccountRequest{PolicyId: "p1"}, grpc.Trailer(&trailer))
			if status.Code(err) != tc.code {
				t.Fatalf("code = %v, want %v", status.Code(err), tc.code)
			}
			if strings.Contains(status.Convert(err).Message(), "10.0.0.5") {
				t.Fatal("internal detail leaked")
			}
			www := trailer.Get("www-authenticate")
			if tc.name == "step-up" {
				if len(www) != 1 || !strings.Contains(www[0], `error="insufficient_user_authentication"`) || !strings.Contains(www[0], `acr_values="gold"`) || !strings.Contains(www[0], "max_age=300") {
					t.Fatalf("www-authenticate trailer = %q", www)
				}
			} else if len(www) != 0 {
				t.Fatalf("unexpected www-authenticate trailer %q", www)
			}
		})
	}
}
