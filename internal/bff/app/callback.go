package app

import (
	"context"
	"fmt"

	"github.com/aamirlatif1/warden/internal/bff/domain"
)

// LoginReason is a stable label for a failed callback (logged, drilled).
type LoginReason string

const (
	ReasonIdPError        LoginReason = "idp_error"        // ?error= from the IdP (e.g. access_denied)
	ReasonTxMissing       LoginReason = "tx_missing"       // no/unknown/used __Host-preauth transaction
	ReasonTxExpired       LoginReason = "tx_expired"       // older than TxTTL
	ReasonStateMismatch   LoginReason = "state_mismatch"   // login CSRF / mix-up
	ReasonCodeMissing     LoginReason = "code_missing"     //
	ReasonExchangeFailed  LoginReason = "exchange_failed"  // code invalid, used, or PKCE verifier wrong
	ReasonIDTokenInvalid  LoginReason = "id_token_invalid" // signature, iss, aud, azp, exp
	ReasonNonceMismatch   LoginReason = "nonce_mismatch"   // ID token replay / injection
	ReasonACRInsufficient LoginReason = "acr_insufficient" // step-up asked for gold and did not get it (or auth too old)
)

// LoginError is a failed callback. The user sees a generic message.
type LoginError struct{ Reason LoginReason }

func (e *LoginError) Error() string { return fmt.Sprintf("login failed: %s", e.Reason) }

type CallbackRequest struct {
	TxID     string // __Host-preauth cookie
	State    string // ?state=
	Code     string // ?code=
	Error    string // ?error=
	PriorSID string // __Host-sid cookie present before login, if any
}

type CallbackResult struct {
	Session  domain.Session        // the NEW session (already stored)
	ReturnTo string                //
	Pending  *domain.PendingAction // replay this, if set
}

// HAND-BUILD (S6). Callback finishes the login. Rules the tests check:
//
//  1. ?error= present → idp_error (the transaction is still consumed).
//  2. Take the transaction (single use: a second callback with the same
//     cookie fails tx_missing). Older than TxTTL → tx_expired.
//  3. state == tx.State in constant time, else state_mismatch.
//  4. Exchange the code WITH tx.Verifier (PKCE). Error → exchange_failed.
//  5. VerifyIDToken; error → id_token_invalid. nonce == tx.Nonce in
//     constant time, else nonce_mismatch.
//  6. If tx.ACRValues == "gold": claims ACR must be "gold" or "2", and if
//     tx.MaxAge > 0 auth_time must be within it → else acr_insufficient.
//  7. Session fixation (D10): delete the prior session if any, create a
//     session with a FRESH ID (NewSessionID) and a fresh CSRF token. Never
//     reuse PriorSID or the tx ID.
//  8. Pending action only if tx.PendingSubject == claims.Subject; a
//     different user logging in must not run someone else's intent.
//  9. Never log tokens, codes or the verifier.
func (a *AuthService) Callback(ctx context.Context, req CallbackRequest) (CallbackResult, error) {
	panic("TODO(S6 hand-build): AuthService.Callback")
}
