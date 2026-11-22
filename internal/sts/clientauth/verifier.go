package clientauth

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// HAND-BUILD (S4). Verify checks a client assertion:
//
//  1. Size cap (tests send 16 KiB → malformed), compact JWS, header alg ==
//     Config.Alg only.
//  2. iss present; sub == iss (that is the client_id); client registered.
//  3. aud is exactly Config.Audience — the STS issuer identifier — as a
//     string or a one-element array. Token endpoint URL, extra values or a
//     trailing slash → aud_invalid (rfc7523bis, audience injection).
//  4. kid required and among this client's keys only; verify the signature.
//  5. exp required; not expired (Leeway); exp <= now + MaxLifetime (+Leeway);
//     if iat present, exp - iat <= MaxLifetime; nbf/iat not in the future.
//  6. jti required. LAST, after everything else passed: FirstUse on
//     key client_id + ":" + jti with ttl >= exp - now. A forged or expired
//     assertion must never burn a legitimate jti. Store error → fail closed.

// Config configures a Verifier.
type Config struct {
	Audience    string                  // the STS issuer identifier; the only accepted aud
	Alg         jose.SignatureAlgorithm // 0 means ES256
	MaxLifetime time.Duration           // 0 means 5 min
	Leeway      time.Duration           // 0 means 30 s
	Now         func() time.Time        // nil means time.Now
	Clients     ClientLookup
	Replay      ReplayCache
}

// Verifier is safe for concurrent use.
type Verifier struct {
	// yours
}

// NewVerifier refuses configs that would weaken verification: empty
// Audience, nil Clients or Replay, alg none or symmetric (HS*).
func NewVerifier(cfg Config) (*Verifier, error) {
	panic("TODO(S4 hand-build): clientauth.NewVerifier")
}

// Verify returns the verified assertion or an *Error.
func (v *Verifier) Verify(ctx context.Context, raw string) (Assertion, error) {
	panic("TODO(S4 hand-build): Verifier.Verify")
}
