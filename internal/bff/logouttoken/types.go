// Package logouttoken validates OIDC Back-Channel Logout tokens (OpenID
// Connect Back-Channel Logout 1.0, §2.4 and §2.6): Keycloak POSTs one to
// the BFF's /backchannel-logout when an SSO session ends (admin logout,
// logout from another client, session expiry), and the BFF deletes every
// session bound to that Keycloak sid.
package logouttoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// EventBackchannelLogout is the member the events claim must contain.
const EventBackchannelLogout = "http://schemas.openid.net/event/backchannel-logout"

// KeySource returns the issuer's public key for a kid. authn/jwks.Cache
// implements it. Any error means the key can't be used (kid_unknown).
type KeySource interface {
	Key(ctx context.Context, kid string) (jose.JSONWebKey, error)
}

// ReplayCache remembers logout token IDs. FirstUse must be atomic (Redis
// SET NX): it records key for ttl and reports whether key was new.
type ReplayCache interface {
	FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// Claims is a validated logout token.
type Claims struct {
	Issuer   string
	Subject  string // may be empty; sid is what the BFF acts on
	SID      string // Keycloak session ID; required here
	JTI      string
	IssuedAt time.Time
}

// Reason is a stable label for why a logout token was rejected, used in
// logs and drills. Never rename one. The endpoint answers all of them with
// the same 400 invalid_request.
type Reason string

const (
	ReasonMalformed         Reason = "malformed"          // not a compact JWS, bad JSON, too large, bad claim types
	ReasonAlgNotAllowed     Reason = "alg_not_allowed"    // header alg != Config.Alg (none, HS256, ES256, ...)
	ReasonKidUnknown        Reason = "kid_unknown"        // kid missing, or KeySource returned an error
	ReasonSignatureInvalid  Reason = "signature_invalid"  //
	ReasonIssuerMismatch    Reason = "iss_mismatch"       // iss != Config.Issuer exactly
	ReasonAudienceMismatch  Reason = "aud_mismatch"       // aud (string or array) does not contain Config.ClientID
	ReasonClaimMissing      Reason = "claim_missing"      // iat or jti absent
	ReasonEventsInvalid     Reason = "events_invalid"     // events absent, not an object, or lacks the logout member as an object
	ReasonNoncePresent      Reason = "nonce_present"      // §2.6: a logout token must not contain nonce
	ReasonSIDMissing        Reason = "sid_missing"        // no sid (the client requires one: backchannel_logout_session_required)
	ReasonExpired           Reason = "expired"            // exp present and now > exp + leeway
	ReasonIssuedInFuture    Reason = "iat_future"         // now < iat - leeway
	ReasonTooOld            Reason = "too_old"            // now > iat + MaxAge + leeway
	ReasonJTIReplayed       Reason = "jti_replayed"       // jti seen before
	ReasonReplayUnavailable Reason = "replay_unavailable" // replay store error: fail closed
	ReasonInternal          Reason = "internal"           // not an *Error
)

// Error is a rejected logout token. It never contains the token.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("logouttoken: %s: %v", e.Reason, e.Err)
	}
	return "logouttoken: " + string(e.Reason)
}

func (e *Error) Unwrap() error { return e.Err }

func Reject(reason Reason, cause error) *Error { return &Error{Reason: reason, Err: cause} }

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
