package authz

import "github.com/aamirlatif1/warden/internal/authn"

// HAND-BUILD (S3). Rules (REQUIREMENTS FR-2):
//
//	CreateQuote          scope quotes:write AND p.PartnerID != "" AND p.PartnerID == r.PartnerID
//	ListPolicies         role policyholder (the store filters by sub)
//	GetPolicy            owner (p.Subject == r.OwnerSubject) OR role underwriter
//	UpdatePayoutAccount  owner, THEN acr level >= 2 AND auth_time within StepUpMaxAge
//	                     → otherwise StepUp{ACR: StepUpACR, MaxAge: StepUpMaxAge}
//	ApproveClaim         role underwriter AND r.AmountMinor <= env.ApprovalLimitMinor;
//	                     Allow.Introspect = r.AmountMinor > IntrospectAboveMinor
//	anything else        Deny(unknown_action)
//
// acr levels: "gold" or "2" → 2, "silver" or "1" → 1, anything else → 0.
// Check ownership before step-up: a non-owner must never be sent to MFA.
// Empty strings never match (an empty sub does not own an empty owner).
func Decide(p authn.Principal, a Action, r Resource, env Env) Decision {
	panic("TODO(S3 hand-build): authz.Decide")
}
