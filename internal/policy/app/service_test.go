package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aamirlatif1/warden/internal/policy/adapters/memstore"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

func newSvc() (*app.Service, *memstore.Store) {
	st := memstore.New()
	st.AddPolicy(domain.Policy{ID: "p1", HolderSubject: "anna", Product: "travel", Status: "active"})
	st.AddPolicy(domain.Policy{ID: "p2", HolderSubject: "bob", Product: "phone", Status: "active"})
	st.AddClaim(domain.Claim{ID: "c1", PolicyID: "p1", Amount: domain.Money{AmountMinor: 50_000, Currency: "EUR"}, Status: domain.ClaimOpen})
	return app.NewService(st, st, st), st
}

var ctx = context.Background()

func TestCreateQuote(t *testing.T) {
	svc, _ := newSvc()
	q, err := svc.CreateQuote(ctx, app.CreateQuoteInput{PartnerID: "shopr", Product: "phone", InsuredValue: domain.Money{AmountMinor: 80_000, Currency: "EUR"}})
	if err != nil {
		t.Fatal(err)
	}
	if q.ID == "" || q.PartnerID != "shopr" || q.Premium.AmountMinor != 1200 {
		t.Fatalf("got %+v", q)
	}
	_, err = svc.CreateQuote(ctx, app.CreateQuoteInput{Product: "phone", InsuredValue: domain.Money{AmountMinor: 1, Currency: "EUR"}})
	if !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("missing partner_id: err = %v", err)
	}
}

func TestListPoliciesOnlyReturnsHolders(t *testing.T) {
	svc, _ := newSvc()
	ps, err := svc.ListPolicies(ctx, "anna")
	if err != nil || len(ps) != 1 || ps[0].ID != "p1" {
		t.Fatalf("got %v, %v", ps, err)
	}
	if _, err := svc.ListPolicies(ctx, ""); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("empty subject: err = %v", err)
	}
}

func TestUpdatePayoutAccount(t *testing.T) {
	svc, _ := newSvc()
	p, err := svc.UpdatePayoutAccount(ctx, "p1", "de89 3704 0044 0532 0130 00")
	if err != nil || p.PayoutIBAN != "DE89370400440532013000" {
		t.Fatalf("got %+v, %v", p, err)
	}
	if _, err := svc.UpdatePayoutAccount(ctx, "p1", "DE00"); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("bad IBAN: err = %v", err)
	}
	if _, err := svc.UpdatePayoutAccount(ctx, "nope", "DE89370400440532013000"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown policy: err = %v", err)
	}
}

func TestApproveClaim(t *testing.T) {
	svc, _ := newSvc()
	c, err := svc.ApproveClaim(ctx, "c1")
	if err != nil || c.Status != domain.ClaimApproved {
		t.Fatalf("got %+v, %v", c, err)
	}
	if _, err := svc.ApproveClaim(ctx, "c1"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("re-approve: err = %v", err)
	}
	if _, err := svc.ApproveClaim(ctx, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: err = %v", err)
	}
}
