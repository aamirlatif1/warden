package authz

import (
	"errors"
	"testing"
)

func TestDecisionErr(t *testing.T) {
	if err := (Decision{Effect: EffectAllow, Reason: ReasonAllowed}).Err(); err != nil {
		t.Fatalf("allow: %v", err)
	}

	var denied *DeniedError
	if err := (Decision{}).Err(); !errors.As(err, &denied) || denied.Reason != "" {
		t.Fatalf("zero Decision must deny, got %v", err)
	}
	if err := (Decision{Effect: EffectDeny, Reason: ReasonNotOwner}).Err(); !errors.As(err, &denied) || denied.Reason != ReasonNotOwner {
		t.Fatalf("deny: %v", err)
	}

	var su *StepUpError
	err := Decision{Effect: EffectStepUp, Reason: ReasonACRTooLow, ACR: StepUpACR, MaxAge: StepUpMaxAge}.Err()
	if !errors.As(err, &su) {
		t.Fatalf("step-up: %v", err)
	}
	want := `Bearer error="insufficient_user_authentication", error_description="acr_too_low", acr_values="gold", max_age=300`
	if got := su.Challenge(); got != want {
		t.Fatalf("Challenge() =\n  %s\nwant\n  %s", got, want)
	}
}
