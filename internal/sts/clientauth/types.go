// Package clientauth authenticates partners at partner-sts's token endpoint
// with private_key_jwt (RFC 7523 §2.2, OIDC Core §9): the client proves
// possession of its registered private key by signing a short-lived JWT.
package clientauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// AssertionType is the only client_assertion_type accepted (RFC 7523).
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Client is a registered client and its public verification keys.
type Client struct {
	ID   string
	Keys []jose.JSONWebKey
}

// ErrUnknownClient is returned by ClientLookup for an unregistered client.
var ErrUnknownClient = errors.New("unknown client")

// ClientLookup finds a registered client. Implemented by the partner
// registry (pgstore).
type ClientLookup interface {
	Client(ctx context.Context, clientID string) (Client, error)
}

// ReplayCache remembers assertion IDs. FirstUse must be atomic (Redis
// SET NX): it records key for ttl and reports whether this was the first
// time key was seen.
type ReplayCache interface {
	FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// Assertion is a verified client assertion.
type Assertion struct {
	ClientID  string
	JTI       string
	ExpiresAt time.Time
}

// Reason is a stable label for why an assertion was rejected. Logged and
// asserted by drill D12; never rename one. The token endpoint answers every
// one of them with the same invalid_client, so the reason never reaches the
// client.
type Reason string

const (
	ReasonMalformed         Reason = "malformed"          // not a compact JWS, bad JSON, too large, bad claim types
	ReasonAlgNotAllowed     Reason = "alg_not_allowed"    // header alg != Config.Alg (none, HS*, RS*, ES384, ...)
	ReasonClaimMissing      Reason = "claim_missing"      // iss, exp or jti absent
	ReasonIssSubMismatch    Reason = "iss_sub_mismatch"   // sub missing or != iss (RFC 7523 §3: both are the client_id)
	ReasonClientUnknown     Reason = "client_unknown"     // iss is not a registered client
	ReasonAudInvalid        Reason = "aud_invalid"        // aud is not exactly the STS issuer identifier (single value)
	ReasonKidUnknown        Reason = "kid_unknown"        // kid missing or not among this client's keys
	ReasonSignatureInvalid  Reason = "signature_invalid"  //
	ReasonExpired           Reason = "expired"            // now > exp + leeway
	ReasonLifetimeTooLong   Reason = "lifetime_too_long"  // exp > now + MaxLifetime + leeway, or exp - iat > MaxLifetime
	ReasonNotYetValid       Reason = "nbf_future"         // now < nbf - leeway
	ReasonIssuedInFuture    Reason = "iat_future"         // now < iat - leeway
	ReasonJTIReplayed       Reason = "jti_replayed"       // (client_id, jti) seen before (D12)
	ReasonReplayUnavailable Reason = "replay_unavailable" // replay store error: fail closed
	ReasonInternal          Reason = "internal"           // not an *Error
)

// Error is a rejected assertion. It never contains the assertion.
type Error struct {
	Reason   Reason
	ClientID string // the claimed client_id when parsed, for logs; may be unverified
	Err      error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("clientauth: %s: %v", e.Reason, e.Err)
	}
	return "clientauth: " + string(e.Reason)
}

func (e *Error) Unwrap() error { return e.Err }

func Reject(reason Reason, clientID string, cause error) *Error {
	return &Error{Reason: reason, ClientID: clientID, Err: cause}
}

// ReasonOf returns the Reason of err, "" for nil, ReasonInternal otherwise.
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
