// Package authz is the authorization engine. Decide is a pure function: no
// I/O, no clock, no globals. The caller (policy-api's app layer) loads the
// resource and the subject's business attributes and passes them in.
package authz

import (
	"fmt"
	"time"
)

// Action is what the caller wants to do. Values are log/metric labels.
type Action string

const (
	ActionCreateQuote         Action = "quote.create"
	ActionListPolicies        Action = "policy.list"
	ActionGetPolicy           Action = "policy.get"
	ActionUpdatePayoutAccount Action = "policy.update_payout_account"
	ActionApproveClaim        Action = "claim.approve"
)

// Resource holds the attributes of the target that rules need. Only the
// fields relevant to the action are set.
type Resource struct {
	ID           string // for the decision log only
	PartnerID    string // CreateQuote: partner_id from the request
	OwnerSubject string // GetPolicy, UpdatePayoutAccount: the policy holder's sub
	AmountMinor  int64  // ApproveClaim: claim amount in euro cents
}

// Env is the context of the request that is not part of the token.
type Env struct {
	Now                time.Time
	ApprovalLimitMinor int64 // the caller's approval limit in euro cents (Postgres); 0 = no authority
}

// Effect is the outcome kind.
type Effect int

const (
	EffectDeny Effect = iota // zero value: an empty Decision denies
	EffectAllow
	EffectStepUp
)

func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "allow"
	case EffectStepUp:
		return "step_up"
	default:
		return "deny"
	}
}

// Reason is a stable, low-cardinality label for the decision. It is logged
// with every decision and asserted by tests and drills; never rename one.
type Reason string

const (
	// Allow
	ReasonAllowed Reason = "allowed"

	// Deny
	ReasonUnknownAction     Reason = "unknown_action"      // default deny
	ReasonMissingScope      Reason = "missing_scope"       // e.g. no quotes:write
	ReasonTenantMismatch    Reason = "tenant_mismatch"     // token partner_id != request partner_id (D5)
	ReasonMissingRole       Reason = "missing_role"        // e.g. not a policyholder / underwriter
	ReasonNotOwner          Reason = "not_owner"           // BOLA (D6)
	ReasonOverApprovalLimit Reason = "over_approval_limit" // ABAC: amount > limit

	// Step-up (D7)
	ReasonACRTooLow  Reason = "acr_too_low"  // acr below gold (level 2)
	ReasonAuthTooOld Reason = "auth_too_old" // auth_time missing or older than MaxAge
)

// Thresholds from REQUIREMENTS FR-2.
const (
	StepUpACR            = "gold"          // acr_values in the RFC 9470 challenge
	StepUpMaxAge         = 5 * time.Minute // max_age in the challenge
	IntrospectAboveMinor = 1_000_000       // 10 000 € in cents: above this, verify the token online
	RoleUnderwriter      = "underwriter"
	RolePolicyholder     = "policyholder"
	ScopeQuotesWrite     = "quotes:write"
)

// Decision is the result of Decide.
type Decision struct {
	Effect Effect
	Reason Reason

	// StepUp only: what the client must come back with.
	ACR    string
	MaxAge time.Duration

	// Allow only: an obligation to check the token online (RFC 7662) before
	// acting, for high-risk actions.
	Introspect bool
}

func (d Decision) Allowed() bool { return d.Effect == EffectAllow }

// Err turns a non-allow decision into an error the adapters can map:
// *DeniedError → 403 / PermissionDenied, *StepUpError → 401 + RFC 9470
// challenge / Unauthenticated. It returns nil for Allow.
func (d Decision) Err() error {
	switch d.Effect {
	case EffectAllow:
		return nil
	case EffectStepUp:
		return &StepUpError{Reason: d.Reason, ACR: d.ACR, MaxAge: d.MaxAge}
	default:
		return &DeniedError{Reason: d.Reason}
	}
}

type DeniedError struct{ Reason Reason }

func (e *DeniedError) Error() string { return "authz: denied: " + string(e.Reason) }

type StepUpError struct {
	Reason Reason
	ACR    string
	MaxAge time.Duration
}

func (e *StepUpError) Error() string {
	return fmt.Sprintf("authz: step-up required (%s): acr=%s max_age=%s", e.Reason, e.ACR, e.MaxAge)
}

// Challenge is the RFC 9470 WWW-Authenticate value for this step-up.
func (e *StepUpError) Challenge() string {
	return fmt.Sprintf(`Bearer error="insufficient_user_authentication", error_description="%s", acr_values="%s", max_age=%d`,
		e.Reason, e.ACR, int(e.MaxAge.Seconds()))
}
