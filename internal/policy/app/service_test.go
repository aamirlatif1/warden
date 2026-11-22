package app_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authz"
	"github.com/aamirlatif1/warden/internal/policy/adapters/memstore"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

var (
	ctx  = context.Background()
	now  = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	anna = authn.Principal{Subject: "sub-anna", Issuer: "kc", Roles: []string{"policyholder"}}
	ben  = authn.Principal{Subject: "sub-ben", Issuer: "kc", Roles: []string{"underwriter"}}
)

// fakeEngine records every call and returns the configured decision.
type fakeEngine struct {
	calls    []call
	decision authz.Decision
}

type call struct {
	p   authn.Principal
	a   authz.Action
	r   authz.Resource
	env authz.Env
}

func (f *fakeEngine) Decide(p authn.Principal, a authz.Action, r authz.Resource, env authz.Env) authz.Decision {
	f.calls = append(f.calls, call{p, a, r, env})
	return f.decision
}

var (
	allow = authz.Decision{Effect: authz.EffectAllow, Reason: authz.ReasonAllowed}
	deny  = authz.Decision{Effect: authz.EffectDeny, Reason: authz.ReasonNotOwner}
	step  = authz.Decision{Effect: authz.EffectStepUp, Reason: authz.ReasonACRTooLow, ACR: "gold", MaxAge: 5 * time.Minute}
)

type fakeIntrospector struct {
	active bool
	err    error
	calls  int
}

func (f *fakeIntrospector) Active(context.Context, authn.Principal) (bool, error) {
	f.calls++
	return f.active, f.err
}

type fixture struct {
	svc    *app.Service
	store  *memstore.Store
	engine *fakeEngine
	logs   *bytes.Buffer
}

func newFixture(d authz.Decision, intro app.Introspector) fixture {
	st := memstore.New()
	st.AddPolicy(domain.Policy{ID: "p_anna", HolderSubject: "sub-anna", Product: "travel", Status: "active"})
	st.AddPolicy(domain.Policy{ID: "p_bob", HolderSubject: "sub-bob", Product: "phone", Status: "active"})
	st.AddClaim(domain.Claim{ID: "c_small", PolicyID: "p_anna", Amount: domain.Money{AmountMinor: 50_000, Currency: "EUR"}, Status: domain.ClaimOpen})
	st.AddClaim(domain.Claim{ID: "c_large", PolicyID: "p_anna", Amount: domain.Money{AmountMinor: 1_500_000, Currency: "EUR"}, Status: domain.ClaimOpen})
	st.SetApprovalLimit("sub-ben", 2_000_000)

	eng := &fakeEngine{decision: d}
	logs := &bytes.Buffer{}
	svc := app.NewService(app.Deps{
		Policies: st, Quotes: st, Claims: st, Limits: st, Tx: st,
		Introspector: intro,
		Log:          slog.New(slog.NewJSONHandler(logs, nil)),
		Now:          func() time.Time { return now },
		Decide:       eng.Decide,
	})
	return fixture{svc, st, eng, logs}
}

func (f fixture) onlyCall(t *testing.T) call {
	t.Helper()
	if len(f.engine.calls) != 1 {
		t.Fatalf("Decide called %d times, want 1", len(f.engine.calls))
	}
	return f.engine.calls[0]
}

// ---- what each use case passes to the engine ----

func TestCreateQuotePassesRequestTenant(t *testing.T) {
	f := newFixture(allow, nil)
	shopr := authn.Principal{Subject: "shopr", PartnerID: "shopr"}
	_, err := f.svc.CreateQuote(ctx, shopr, app.CreateQuoteInput{PartnerID: "nordbank", Product: "phone", InsuredValue: domain.Money{AmountMinor: 100, Currency: "EUR"}})
	if err != nil {
		t.Fatal(err)
	}
	c := f.onlyCall(t)
	if c.a != authz.ActionCreateQuote || c.r.PartnerID != "nordbank" || c.p.PartnerID != "shopr" {
		t.Fatalf("engine got %+v", c)
	}
	if !c.env.Now.Equal(now) {
		t.Fatalf("env.Now = %v, want the service clock", c.env.Now)
	}
}

func TestGetPolicyPassesStoredOwner(t *testing.T) {
	f := newFixture(allow, nil)
	if _, err := f.svc.GetPolicy(ctx, anna, "p_bob"); err != nil {
		t.Fatal(err)
	}
	c := f.onlyCall(t)
	if c.a != authz.ActionGetPolicy || c.r.OwnerSubject != "sub-bob" || c.r.ID != "p_bob" {
		t.Fatalf("engine got %+v; owner must come from the store, not the request", c)
	}
}

func TestUpdatePayoutPassesStoredOwner(t *testing.T) {
	f := newFixture(allow, nil)
	if _, err := f.svc.UpdatePayoutAccount(ctx, anna, "p_anna", "DE89370400440532013000"); err != nil {
		t.Fatal(err)
	}
	c := f.onlyCall(t)
	if c.a != authz.ActionUpdatePayoutAccount || c.r.OwnerSubject != "sub-anna" {
		t.Fatalf("engine got %+v", c)
	}
}

func TestApproveClaimPassesAmountAndLimit(t *testing.T) {
	f := newFixture(allow, nil)
	if _, err := f.svc.ApproveClaim(ctx, ben, "c_small"); err != nil {
		t.Fatal(err)
	}
	c := f.onlyCall(t)
	if c.a != authz.ActionApproveClaim || c.r.AmountMinor != 50_000 || c.env.ApprovalLimitMinor != 2_000_000 {
		t.Fatalf("engine got %+v", c)
	}
}

func TestListPoliciesUsesTokenSubject(t *testing.T) {
	f := newFixture(allow, nil)
	ps, err := f.svc.ListPolicies(ctx, anna)
	if err != nil || len(ps) != 1 || ps[0].ID != "p_anna" {
		t.Fatalf("got %v, %v", ps, err)
	}
	if f.onlyCall(t).a != authz.ActionListPolicies {
		t.Fatal("wrong action")
	}
}

// ---- deny and step-up stop the use case ----

func TestDenyStopsEveryUseCase(t *testing.T) {
	f := newFixture(deny, nil)
	iban := "DE89370400440532013000"
	errs := map[string]error{}
	_, errs["CreateQuote"] = f.svc.CreateQuote(ctx, anna, app.CreateQuoteInput{PartnerID: "x", Product: "p", InsuredValue: domain.Money{AmountMinor: 1, Currency: "EUR"}})
	_, errs["ListPolicies"] = f.svc.ListPolicies(ctx, anna)
	_, errs["GetPolicy"] = f.svc.GetPolicy(ctx, anna, "p_bob")
	_, errs["UpdatePayoutAccount"] = f.svc.UpdatePayoutAccount(ctx, anna, "p_bob", iban)
	_, errs["ApproveClaim"] = f.svc.ApproveClaim(ctx, anna, "c_small")
	for name, err := range errs {
		var d *authz.DeniedError
		if !errors.As(err, &d) || d.Reason != authz.ReasonNotOwner {
			t.Errorf("%s: err = %v, want DeniedError(not_owner)", name, err)
		}
	}
	if p, _ := f.store.GetPolicy(ctx, "p_bob"); p.PayoutIBAN != "" {
		t.Error("denied payout change was written")
	}
	if c, _ := f.store.GetClaim(ctx, "c_small"); c.Status != domain.ClaimOpen {
		t.Error("denied approval was written")
	}
}

func TestStepUpIsReturnedAndNothingIsWritten(t *testing.T) {
	f := newFixture(step, nil)
	_, err := f.svc.UpdatePayoutAccount(ctx, anna, "p_anna", "DE89370400440532013000")
	var su *authz.StepUpError
	if !errors.As(err, &su) || su.ACR != "gold" || su.MaxAge != 5*time.Minute {
		t.Fatalf("err = %v, want StepUpError", err)
	}
	if p, _ := f.store.GetPolicy(ctx, "p_anna"); p.PayoutIBAN != "" {
		t.Fatal("payout changed without step-up")
	}
}

// Validation runs after authz: a denied caller must not learn whether the
// IBAN was valid.
func TestValidationRunsAfterAuthz(t *testing.T) {
	f := newFixture(deny, nil)
	_, err := f.svc.UpdatePayoutAccount(ctx, anna, "p_bob", "not-an-iban")
	var d *authz.DeniedError
	if !errors.As(err, &d) {
		t.Fatalf("err = %v, want DeniedError before IBAN validation", err)
	}
}

func TestUnknownResourceIsNotFoundBeforeAuthz(t *testing.T) {
	f := newFixture(allow, nil)
	if _, err := f.svc.GetPolicy(ctx, anna, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if len(f.engine.calls) != 0 {
		t.Fatal("engine called for a missing resource")
	}
}

// ---- introspection obligation ----

func TestIntrospectionObligation(t *testing.T) {
	allowIntrospect := authz.Decision{Effect: authz.EffectAllow, Reason: authz.ReasonAllowed, Introspect: true}

	cases := []struct {
		name    string
		intro   *fakeIntrospector
		wantErr error
	}{
		{"not configured fails closed", nil, app.ErrUnavailable},
		{"introspector error fails closed", &fakeIntrospector{err: errors.New("timeout")}, app.ErrUnavailable},
		{"inactive token", &fakeIntrospector{active: false}, app.ErrTokenInactive},
		{"active token", &fakeIntrospector{active: true}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var intro app.Introspector
			if tc.intro != nil {
				intro = tc.intro
			}
			f := newFixture(allowIntrospect, intro)
			_, err := f.svc.ApproveClaim(ctx, ben, "c_large")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			c, _ := f.store.GetClaim(ctx, "c_large")
			if (c.Status == domain.ClaimApproved) != (tc.wantErr == nil) {
				t.Fatalf("claim status = %s", c.Status)
			}
		})
	}
}

func TestNoIntrospectionWhenNotRequired(t *testing.T) {
	intro := &fakeIntrospector{active: true}
	f := newFixture(allow, intro)
	if _, err := f.svc.ApproveClaim(ctx, ben, "c_small"); err != nil {
		t.Fatal(err)
	}
	if intro.calls != 0 {
		t.Fatalf("introspected %d times for a low-risk approval", intro.calls)
	}
}

func TestApproveTwiceConflicts(t *testing.T) {
	f := newFixture(allow, nil)
	if _, err := f.svc.ApproveClaim(ctx, ben, "c_small"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApproveClaim(ctx, ben, "c_small"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

// ---- decision log ----

func TestEveryDecisionIsLoggedWithReason(t *testing.T) {
	f := newFixture(deny, nil)
	_, _ = f.svc.GetPolicy(ctx, anna, "p_bob")
	line := f.logs.String()
	for _, want := range []string{`"msg":"authz decision"`, `"action":"policy.get"`, `"effect":"deny"`, `"reason":"not_owner"`, `"sub":"sub-anna"`, `"resource_id":"p_bob"`} {
		if !strings.Contains(line, want) {
			t.Errorf("decision log missing %s:\n%s", want, line)
		}
	}
}

// ---- domain behaviour behind an allow ----

func TestCreateQuoteValidation(t *testing.T) {
	f := newFixture(allow, nil)
	q, err := f.svc.CreateQuote(ctx, anna, app.CreateQuoteInput{PartnerID: "shopr", Product: "phone", InsuredValue: domain.Money{AmountMinor: 80_000, Currency: "EUR"}})
	if err != nil || q.Premium.AmountMinor != 1200 || !q.CreatedAt.Equal(now) {
		t.Fatalf("got %+v, %v", q, err)
	}
	_, err = f.svc.CreateQuote(ctx, anna, app.CreateQuoteInput{PartnerID: "shopr", InsuredValue: domain.Money{AmountMinor: 1, Currency: "EUR"}})
	if !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("missing product: err = %v", err)
	}
}

func TestUpdatePayoutNormalizesIBAN(t *testing.T) {
	f := newFixture(allow, nil)
	p, err := f.svc.UpdatePayoutAccount(ctx, anna, "p_anna", "de89 3704 0044 0532 0130 00")
	if err != nil || p.PayoutIBAN != "DE89370400440532013000" {
		t.Fatalf("got %+v, %v", p, err)
	}
	if _, err := f.svc.UpdatePayoutAccount(ctx, anna, "p_anna", "DE00"); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("bad IBAN: err = %v", err)
	}
}
