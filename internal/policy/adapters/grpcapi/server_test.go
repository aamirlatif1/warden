package grpcapi_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	policyv1 "github.com/aamirlatif1/warden/gen/warden/policy/v1"
	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/policy/adapters/grpcapi"
	"github.com/aamirlatif1/warden/internal/policy/adapters/memstore"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

func newServer() *grpcapi.Server {
	st := memstore.New()
	st.AddPolicy(domain.Policy{ID: "p1", HolderSubject: "anna", Product: "travel", Status: "active", PayoutIBAN: "DE89370400440532013000"})
	st.AddPolicy(domain.Policy{ID: "p2", HolderSubject: "bob", Product: "phone", Status: "active"})
	return grpcapi.NewServer(app.NewService(st, st, st), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func as(sub string) context.Context {
	return authn.WithPrincipal(context.Background(), authn.Principal{Subject: sub})
}

func TestListPoliciesUsesTokenSubject(t *testing.T) {
	s := newServer()
	resp, err := s.ListPolicies(as("anna"), &policyv1.ListPoliciesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Policies) != 1 || resp.Policies[0].Id != "p1" {
		t.Fatalf("got %v", resp.Policies)
	}
	if got := resp.Policies[0].PayoutIbanMasked; got != "******************3000" {
		t.Fatalf("IBAN not masked: %q", got)
	}
}

func TestListPoliciesWithoutPrincipal(t *testing.T) {
	_, err := newServer().ListPolicies(context.Background(), &policyv1.ListPoliciesRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v", status.Code(err))
	}
}

func TestErrorMapping(t *testing.T) {
	s := newServer()
	_, err := s.GetPolicy(as("anna"), &policyv1.GetPolicyRequest{Id: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("unknown policy: %v", err)
	}
	_, err = s.UpdatePayoutAccount(as("anna"), &policyv1.UpdatePayoutAccountRequest{PolicyId: "p1", Iban: "bad"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad iban: %v", err)
	}
}

func TestCreateQuote(t *testing.T) {
	resp, err := newServer().CreateQuote(as("shopr"), &policyv1.CreateQuoteRequest{
		PartnerId: "shopr", Product: "phone",
		InsuredValue: &policyv1.Money{AmountMinor: 80_000, Currency: "EUR"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Quote.GetPremium().GetAmountMinor() != 1200 || resp.Quote.GetCreatedAt() == nil {
		t.Fatalf("got %v", resp.Quote)
	}
}
