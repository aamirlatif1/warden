package authz_test

import (
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authz"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	kc        = "http://localhost:8080/realms/insurance"
	sts       = "http://localhost:8083"
	annaSub   = "0f9c1d2e-anna"
	bobSub    = "7a3b5c6d-bob"
	benSub    = "c4d5e6f7-ben"
	limit2k   = 200_000   // 2 000 €
	limit20k  = 2_000_000 // 20 000 €
	introOver = authz.IntrospectAboveMinor
)

// ---- personas ----

func anna(acr string, authAgo time.Duration) authn.Principal {
	p := authn.Principal{Subject: annaSub, Issuer: kc, ClientID: "portal-bff",
		Roles: []string{"policyholder", "default-roles-insurance"}, Scopes: []string{"openid", "policies"}, ACR: acr}
	if authAgo >= 0 {
		p.AuthTime = now.Add(-authAgo)
	}
	return p
}

func bob() authn.Principal {
	return authn.Principal{Subject: bobSub, Issuer: kc, Roles: []string{"policyholder"}, ACR: "1", AuthTime: now.Add(-time.Minute)}
}

func ben() authn.Principal {
	return authn.Principal{Subject: benSub, Issuer: kc, Roles: []string{"underwriter"}, ACR: "gold", AuthTime: now.Add(-time.Minute)}
}

func shopr() authn.Principal {
	return authn.Principal{Subject: "shopr", Issuer: sts, ClientID: "shopr", PartnerID: "shopr", Scopes: []string{"quotes:write"}}
}

func with(p authn.Principal, f func(*authn.Principal)) authn.Principal { f(&p); return p }

const noAuthTime = -1

// ---- table ----

type tc struct {
	name       string
	p          authn.Principal
	action     authz.Action
	res        authz.Resource
	limit      int64
	effect     authz.Effect
	reason     authz.Reason
	introspect bool
}

func TestDecide(t *testing.T) {
	annaPolicy := authz.Resource{ID: "pol_anna", OwnerSubject: annaSub}
	bobPolicy := authz.Resource{ID: "pol_bob", OwnerSubject: bobSub}
	claim := func(amount int64) authz.Resource { return authz.Resource{ID: "clm", AmountMinor: amount} }

	allow, deny, stepUp := authz.EffectAllow, authz.EffectDeny, authz.EffectStepUp

	cases := []tc{
		// ---- CreateQuote: scope + tenant (D5) ----
		{"partner quotes for itself", shopr(), authz.ActionCreateQuote, authz.Resource{PartnerID: "shopr"}, 0, allow, authz.ReasonAllowed, false},
		{"D5 partner quotes for another tenant", shopr(), authz.ActionCreateQuote, authz.Resource{PartnerID: "nordbank"}, 0, deny, authz.ReasonTenantMismatch, false},
		{"partner tenant differs only in case", shopr(), authz.ActionCreateQuote, authz.Resource{PartnerID: "Shopr"}, 0, deny, authz.ReasonTenantMismatch, false},
		{"partner without quotes:write", with(shopr(), func(p *authn.Principal) { p.Scopes = []string{"quotes:read"} }),
			authz.ActionCreateQuote, authz.Resource{PartnerID: "shopr"}, 0, deny, authz.ReasonMissingScope, false},
		{"scope but no partner_id in token", with(shopr(), func(p *authn.Principal) { p.PartnerID = "" }),
			authz.ActionCreateQuote, authz.Resource{PartnerID: "shopr"}, 0, deny, authz.ReasonTenantMismatch, false},
		{"empty partner_id on both sides", with(shopr(), func(p *authn.Principal) { p.PartnerID = "" }),
			authz.ActionCreateQuote, authz.Resource{PartnerID: ""}, 0, deny, authz.ReasonTenantMismatch, false},
		{"bank customer (no quotes:write) for own bank", with(anna("1", time.Minute), func(p *authn.Principal) { p.PartnerID = "nordbank" }),
			authz.ActionCreateQuote, authz.Resource{PartnerID: "nordbank"}, 0, deny, authz.ReasonMissingScope, false},

		// ---- ListPolicies: role ----
		{"policyholder lists", anna("1", time.Minute), authz.ActionListPolicies, authz.Resource{}, 0, allow, authz.ReasonAllowed, false},
		{"partner token lists policies", shopr(), authz.ActionListPolicies, authz.Resource{}, 0, deny, authz.ReasonMissingRole, false},
		{"underwriter only lists policies", ben(), authz.ActionListPolicies, authz.Resource{}, 0, deny, authz.ReasonMissingRole, false},
		{"no roles at all", authn.Principal{Subject: "svc"}, authz.ActionListPolicies, authz.Resource{}, 0, deny, authz.ReasonMissingRole, false},
		{"role name differs in case", with(anna("1", time.Minute), func(p *authn.Principal) { p.Roles = []string{"Policyholder"} }),
			authz.ActionListPolicies, authz.Resource{}, 0, deny, authz.ReasonMissingRole, false},

		// ---- GetPolicy: owner or underwriter (D6) ----
		{"owner reads own policy", anna("1", time.Minute), authz.ActionGetPolicy, annaPolicy, 0, allow, authz.ReasonAllowed, false},
		{"D6 policyholder reads another's policy", anna("1", time.Minute), authz.ActionGetPolicy, bobPolicy, 0, deny, authz.ReasonNotOwner, false},
		{"underwriter reads any policy", ben(), authz.ActionGetPolicy, bobPolicy, 0, allow, authz.ReasonAllowed, false},
		{"partner reads a policy", shopr(), authz.ActionGetPolicy, annaPolicy, 0, deny, authz.ReasonNotOwner, false},
		{"empty sub vs empty owner", authn.Principal{Roles: []string{"policyholder"}}, authz.ActionGetPolicy, authz.Resource{}, 0, deny, authz.ReasonNotOwner, false},
		{"role Underwriter (case) is not underwriter", with(bob(), func(p *authn.Principal) { p.Roles = []string{"Underwriter"} }),
			authz.ActionGetPolicy, annaPolicy, 0, deny, authz.ReasonNotOwner, false},

		// ---- UpdatePayoutAccount: owner, then step-up (D7) ----
		{"owner with gold, fresh auth", anna("gold", time.Minute), authz.ActionUpdatePayoutAccount, annaPolicy, 0, allow, authz.ReasonAllowed, false},
		{"owner with acr 2, fresh auth", anna("2", time.Minute), authz.ActionUpdatePayoutAccount, annaPolicy, 0, allow, authz.ReasonAllowed, false},
		{"auth exactly 5 min ago", anna("gold", 5*time.Minute), authz.ActionUpdatePayoutAccount, annaPolicy, 0, allow, authz.ReasonAllowed, false},
		{"D7 owner with acr 1", anna("1", time.Minute), authz.ActionUpdatePayoutAccount, annaPolicy, 0, stepUp, authz.ReasonACRTooLow, false},
		{"owner with acr silver", anna("silver", time.Minute), authz.ActionUpdatePayoutAccount, annaPolicy, 0, stepUp, authz.ReasonACRTooLow, false},
		{"owner with no acr", anna("", time.Minute), authz.ActionUpdatePayoutAccount, annaPolicy, 0, stepUp, authz.ReasonACRTooLow, false},
		{"owner with an unknown acr value", anna("platinum", time.Minute), authz.ActionUpdatePayoutAccount, annaPolicy, 0, stepUp, authz.ReasonACRTooLow, false},
		{"gold but auth 5m1s ago", anna("gold", 5*time.Minute+time.Second), authz.ActionUpdatePayoutAccount, annaPolicy, 0, stepUp, authz.ReasonAuthTooOld, false},
		{"gold but no auth_time", anna("gold", noAuthTime), authz.ActionUpdatePayoutAccount, annaPolicy, 0, stepUp, authz.ReasonAuthTooOld, false},
		{"non-owner is denied, not sent to MFA", anna("1", time.Minute), authz.ActionUpdatePayoutAccount, bobPolicy, 0, deny, authz.ReasonNotOwner, false},
		{"underwriter cannot change a payout account", ben(), authz.ActionUpdatePayoutAccount, annaPolicy, 0, deny, authz.ReasonNotOwner, false},

		// ---- ApproveClaim: role + ABAC limit + introspection ----
		{"underwriter within limit", ben(), authz.ActionApproveClaim, claim(50_000), limit2k, allow, authz.ReasonAllowed, false},
		{"amount equals limit", ben(), authz.ActionApproveClaim, claim(limit2k), limit2k, allow, authz.ReasonAllowed, false},
		{"amount one cent over limit", ben(), authz.ActionApproveClaim, claim(limit2k + 1), limit2k, deny, authz.ReasonOverApprovalLimit, false},
		{"underwriter with no limit row", ben(), authz.ActionApproveClaim, claim(100), 0, deny, authz.ReasonOverApprovalLimit, false},
		{"exactly 10 000 € needs no introspection", ben(), authz.ActionApproveClaim, claim(introOver), limit20k, allow, authz.ReasonAllowed, false},
		{"above 10 000 € must introspect", ben(), authz.ActionApproveClaim, claim(introOver + 1), limit20k, allow, authz.ReasonAllowed, true},
		{"policyholder approves (limit set by mistake)", anna("gold", time.Minute), authz.ActionApproveClaim, claim(100), limit20k, deny, authz.ReasonMissingRole, false},
		{"partner approves", shopr(), authz.ActionApproveClaim, claim(100), limit20k, deny, authz.ReasonMissingRole, false},

		// ---- default deny ----
		{"unknown action", ben(), authz.Action("policy.delete"), annaPolicy, limit20k, deny, authz.ReasonUnknownAction, false},
		{"empty action", ben(), authz.Action(""), annaPolicy, limit20k, deny, authz.ReasonUnknownAction, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := authz.Decide(c.p, c.action, c.res, authz.Env{Now: now, ApprovalLimitMinor: c.limit})
			if got.Effect != c.effect || got.Reason != c.reason {
				t.Fatalf("Decide = %v/%q, want %v/%q", got.Effect, got.Reason, c.effect, c.reason)
			}
			if got.Introspect != c.introspect {
				t.Errorf("Introspect = %v, want %v", got.Introspect, c.introspect)
			}
			if c.effect == authz.EffectStepUp {
				if got.ACR != authz.StepUpACR || got.MaxAge != authz.StepUpMaxAge {
					t.Errorf("step-up challenge = acr %q max_age %v, want %q %v", got.ACR, got.MaxAge, authz.StepUpACR, authz.StepUpMaxAge)
				}
			} else if got.ACR != "" || got.MaxAge != 0 {
				t.Errorf("non-step-up decision carries a challenge: %+v", got)
			}
			if c.effect != authz.EffectAllow && got.Introspect {
				t.Errorf("non-allow decision carries an introspection obligation")
			}
		})
	}
}

// Decide is pure: the same input gives the same output and the input is
// not modified.
func TestDecideIsPure(t *testing.T) {
	p := anna("gold", time.Minute)
	roles := append([]string(nil), p.Roles...)
	env := authz.Env{Now: now}
	r := authz.Resource{OwnerSubject: annaSub}
	first := authz.Decide(p, authz.ActionUpdatePayoutAccount, r, env)
	for range 10 {
		if got := authz.Decide(p, authz.ActionUpdatePayoutAccount, r, env); got != first {
			t.Fatalf("non-deterministic: %+v vs %+v", got, first)
		}
	}
	for i := range roles {
		if p.Roles[i] != roles[i] {
			t.Fatal("Decide modified the principal's roles")
		}
	}
}
