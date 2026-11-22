// Package keyring is partner-sts's signing-key rotation state machine
// (ADR-004). Each key moves through:
//
//	next ──(PublishLead elapsed)──▶ current ──(next key activates)──▶ retiring ──(RetireAfter elapsed)──▶ dropped
//	published, not signing          signing + published              published, not signing           gone from JWKS
//
// Why: a verifier caches the JWKS (policy-api: up to Cache-Control
// max-age). If a key signed the moment it was created, verifiers with a
// stale cache would reject its tokens. Publishing it PublishLead (2x the
// JWKS cache TTL) before it signs means every verifier has it by then.
// Likewise the old key stays published RetireAfter (max token TTL +
// leeway) after it stops signing, so tokens it already signed still verify.
package keyring

import (
	"context"
	"errors"
	"time"

	"github.com/aamirlatif1/warden/internal/issuer"
)

// KeyFactory creates a new signing key (a new KMS key, or a local one).
type KeyFactory interface {
	NewSigner(ctx context.Context) (issuer.Signer, error)
}

type State string

const (
	StateNext     State = "next"     // published, not yet signing
	StateCurrent  State = "current"  // the one signing key
	StateRetiring State = "retiring" // published, no longer signing
)

// KeyInfo describes a key for /admin/keys and logs.
type KeyInfo struct {
	KID         string    `json:"kid"`
	State       State     `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	ActivatesAt time.Time `json:"activates_at,omitzero"` // next: when it becomes current
	RetiredAt   time.Time `json:"retired_at,omitzero"`   // retiring: when it stopped signing
	DropsAt     time.Time `json:"drops_at,omitzero"`     // retiring: when it leaves JWKS
}

// ErrRotationInProgress: a next key already exists (or is being created).
var ErrRotationInProgress = errors.New("keyring: rotation already in progress")

// Config tunes the timeline. Zero durations mean the defaults.
type Config struct {
	PublishLead time.Duration    // default 10 min (2 x the 5 min JWKS cache TTL)
	RetireAfter time.Duration    // default 5 min 30 s (5 min token TTL + 30 s leeway)
	Factory     KeyFactory       // required
	Now         func() time.Time // default time.Now
}
