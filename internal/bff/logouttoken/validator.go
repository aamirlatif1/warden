package logouttoken

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// HAND-BUILD (S7). Validate checks a logout token (Back-Channel Logout
// 1.0 §2.6), in this order:
//
//  1. Size cap (tests send 16 KiB → malformed); compact JWS; header alg ==
//     Config.Alg only.
//  2. kid required; KeySource.Key(kid) (any error → kid_unknown); verify the
//     signature. Nothing below is trusted before this passes.
//  3. iss == Config.Issuer exactly; aud contains Config.ClientID (a string,
//     or an array where it is one of the values).
//  4. iat and jti required; iat not in the future (Leeway); not older than
//     MaxAge (+Leeway); if exp is present, not expired (Leeway).
//  5. events is a JSON object with the member EventBackchannelLogout whose
//     value is a JSON object (usually {}); other members are allowed. This
//     is what stops an ID token or access token from the same issuer being
//     replayed here.
//  6. nonce must be absent; sid required.
//  7. LAST: FirstUse on key iss + "|" + jti, with ttl at least as long as the
//     token stays acceptable (iat + MaxAge + Leeway - now). A forged token
//     must never burn a real jti. Store error → fail closed.

// Config configures a Validator.
type Config struct {
	Issuer   string                  // e.g. http://localhost:8080/realms/insurance
	ClientID string                  // this BFF's client_id; must appear in aud
	Alg      jose.SignatureAlgorithm // 0 means RS256 (Keycloak's realm default)
	MaxAge   time.Duration           // 0 means 2 min
	Leeway   time.Duration           // 0 means 30 s
	Now      func() time.Time        // nil means time.Now
	Keys     KeySource
	Replay   ReplayCache
}

// Validator is safe for concurrent use.
type Validator struct {
	// yours
}

// NewValidator refuses configs that would weaken validation: empty Issuer
// or ClientID, nil Keys or Replay, alg none or symmetric (HS*).
func NewValidator(cfg Config) (*Validator, error) {
	panic("TODO(S7 hand-build): logouttoken.NewValidator")
}

// Validate returns the token's claims or an *Error.
func (v *Validator) Validate(ctx context.Context, raw string) (Claims, error) {
	panic("TODO(S7 hand-build): Validator.Validate")
}
