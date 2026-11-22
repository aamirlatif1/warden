package authn

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// HAND-BUILD (S2). The pipeline (REQUIREMENTS FR-2):
//
//  1. Reject oversized input (cap it; tests send 32 KiB and expect malformed).
//  2. Parse the compact JWS; read the header without trusting it.
//  3. Select the profile by exact iss. Unknown → iss_unknown.
//  4. Header alg must equal profile.Alg (none, HS*, other asym → alg_not_allowed).
//  5. Key by kid from that issuer's KeySource only — ignore jku, x5u, jwk headers.
//  6. Verify the signature.
//  7. exp (required), nbf, iat with Leeway.
//  8. Audience rule (aud / Cognito client_id + token_use), then typ.
//  9. Denylist.Revoked(TokenRef{iss, jti, client id, iat}).
// 10. Map claims → Principal per profile.
//
// Every rejection is an *Error with a Reason (see errors.go).

// KeySource returns the verification key for kid. It is consumed here and
// implemented by jwks.Cache (and by static maps in tests). An unknown kid
// must yield an error whose ReasonOf is ReasonKidUnknown.
type KeySource interface {
	Key(ctx context.Context, kid string) (jose.JSONWebKey, error)
}

// Denylist reports revoked tokens. Implemented by revocation.Set, fed by
// Redis pub/sub. A token is revoked if its (issuer, jti) is listed, or if
// its client is revoked for tokens issued at or before a cut-off (partner
// suspension).
type Denylist interface {
	Revoked(t TokenRef) bool
}

// TokenRef identifies a token for the denylist. IssuedAt is the iat claim;
// zero when absent (a client-level revocation then applies, fail closed).
type TokenRef struct {
	Issuer   string
	JTI      string
	ClientID string
	IssuedAt time.Time
}

// Issuer pairs a profile with the keys it may sign with.
type Issuer struct {
	Profile IssuerProfile
	Keys    KeySource
}

// Config configures a Validator.
type Config struct {
	Issuers  []Issuer
	Denylist Denylist         // nil: nothing is revoked
	Leeway   time.Duration    // clock skew for exp/nbf/iat; 0 means the default, 30s
	Now      func() time.Time // nil means time.Now
}

// Validator checks bearer tokens. It is safe for concurrent use.
type Validator struct {
	// yours
}

// NewValidator checks cfg and builds a Validator. It must refuse configs
// that would weaken validation: no issuers, a duplicate iss, a nil
// KeySource, a profile alg that is none or symmetric (HS*), or a profile
// with no audience rule (empty Audience and no ClientIDs).
func NewValidator(cfg Config) (*Validator, error) {
	panic("TODO(S2 hand-build): NewValidator")
}

// Validate checks raw (the token without the "Bearer " prefix) and returns
// the principal. Errors are *Error; the token is never part of the error.
func (v *Validator) Validate(ctx context.Context, raw string) (Principal, error) {
	panic("TODO(S2 hand-build): Validate")
}
