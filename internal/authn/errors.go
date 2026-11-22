package authn

import (
	"errors"
	"fmt"
)

// Reason is a stable, low-cardinality label for why a token was rejected.
// It is the reason label of authn_validations_total{issuer,result,reason}
// and drills assert on it, so never rename a value.
type Reason string

const (
	ReasonMalformed         Reason = "malformed"          // not a compact JWS, bad base64/JSON, too large, bad claim types
	ReasonAlgNotAllowed     Reason = "alg_not_allowed"    // header alg differs from the issuer profile's pinned alg (incl. none, HS*)
	ReasonIssuerUnknown     Reason = "iss_unknown"        // iss missing or not an exact match for a configured profile
	ReasonKidUnknown        Reason = "kid_unknown"        // kid missing, or not in the issuer's JWKS after the (rate-limited) refetch
	ReasonSignatureInvalid  Reason = "signature_invalid"  // signature does not verify with the issuer's key
	ReasonExpired           Reason = "expired"            // now > exp + leeway
	ReasonNotYetValid       Reason = "nbf_future"         // now < nbf - leeway
	ReasonIssuedInFuture    Reason = "iat_future"         // now < iat - leeway
	ReasonClaimMissing      Reason = "claim_missing"      // a claim the profile requires (exp, sub, jti, ...) is absent
	ReasonAudienceMismatch  Reason = "aud_mismatch"       // aud (or Cognito client_id) not accepted
	ReasonTokenUseInvalid   Reason = "token_use_invalid"  // Cognito token_use != "access"
	ReasonTypeInvalid       Reason = "typ_invalid"        // typ header differs from the profile's required type (RFC 9068 at+jwt)
	ReasonRevoked           Reason = "revoked"            // jti is on the denylist
	ReasonJWKSUnavailable   Reason = "jwks_unavailable"   // no keys have ever been fetched for this issuer
	ReasonMissingCredential Reason = "missing_credential" // no bearer token in the request (set by the adapters)
	ReasonInternal          Reason = "internal"           // anything that is not an *Error
)

// Error is a rejected token. It never contains the token itself.
type Error struct {
	Reason Reason
	Issuer string // issuer profile Name when known, else ""; metric label
	Err    error  // optional cause, for logs only
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("authn: %s: %v", e.Reason, e.Err)
	}
	return "authn: " + string(e.Reason)
}

func (e *Error) Unwrap() error { return e.Err }

// Reject builds an *Error. cause may be nil.
func Reject(reason Reason, issuer string, cause error) *Error {
	return &Error{Reason: reason, Issuer: issuer, Err: cause}
}

// ReasonOf extracts the Reason from err. It returns "" for nil and
// ReasonInternal for errors that are not an *Error.
func ReasonOf(err error) Reason {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonInternal
}
