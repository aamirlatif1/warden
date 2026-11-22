// Package domain holds the BFF's entities. Pure Go.
package domain

import (
	"errors"
	"time"
)

// ErrNoSession: unknown, expired (idle or absolute) or deleted session.
var ErrNoSession = errors.New("no session")

// Session is a logged-in browser. Only its ID leaves the server (as the
// __Host- cookie); tokens stay in Redis, encrypted.
type Session struct {
	ID           string // 256-bit random, base64url; the cookie value
	Subject      string // Keycloak sub
	Username     string // preferred_username, for display
	KeycloakSID  string // "sid" claim: back-channel logout finds sessions by it
	ACR          string
	AuthTime     time.Time
	AccessToken  string
	RefreshToken string
	IDToken      string // id_token_hint for RP-initiated logout
	AccessExpiry time.Time
	CSRFToken    string // synchroniser token for state-changing forms
	CreatedAt    time.Time
}

// PendingAction is an intent the user must step up for, replayed after
// re-authentication (REQUIREMENTS FR-3 step-up).
type PendingAction struct {
	Kind     string `json:"kind"` // "update_payout"
	PolicyID string `json:"policy_id"`
	IBAN     string `json:"iban"`
}

const PendingUpdatePayout = "update_payout"

// LoginTx is the pre-authentication record between /login and /callback,
// keyed by the __Host-preauth cookie. Single use.
type LoginTx struct {
	ID        string // cookie value
	State     string // echoed by the IdP; binds the callback to this browser
	Nonce     string // must come back inside the ID token
	Verifier  string // PKCE code_verifier; only its S256 hash went to the IdP
	ReturnTo  string // local path to land on after login
	ACRValues string // "" or e.g. "gold" (step-up)
	MaxAge    time.Duration
	CreatedAt time.Time

	// Step-up replay: the action, and who asked for it. Replayed only if
	// the same subject logs back in.
	Pending        *PendingAction
	PendingSubject string
}
