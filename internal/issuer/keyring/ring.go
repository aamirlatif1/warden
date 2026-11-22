package keyring

import (
	"context"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/issuer"
)

// HAND-BUILD (S5). Rules the tests check:
//
//   - Transitions are driven by the clock: every call evaluates Now() and
//     applies any due transition (no background goroutine needed).
//   - A next key becomes current when now >= ActivatesAt; at that instant
//     the old current becomes retiring with RetiredAt = ActivatesAt and
//     DropsAt = RetiredAt + RetireAfter. A key is dropped when now >= DropsAt.
//   - Exactly one current key; at most one next key; Signing() is always
//     in Published(); Published() never has duplicates.
//   - Rotate while a next key exists, or while one is being created →
//     ErrRotationInProgress, and the factory is not called.
//   - Never hold the lock while calling the factory (a KMS CreateKey can
//     take seconds); Signing/Published must not block meanwhile.
//   - Factory error → no state change, and a later Rotate may try again.
//
// Ring implements issuer.KeyRing and is safe for concurrent use.
type Ring struct {
	// yours
}

var _ issuer.KeyRing = (*Ring)(nil)

// New starts a ring whose only key, initial, is current.
func New(cfg Config, initial issuer.Signer) (*Ring, error) {
	panic("TODO(S5 hand-build): keyring.New")
}

// Signing returns the current key.
func (r *Ring) Signing() issuer.Signer {
	panic("TODO(S5 hand-build): Ring.Signing")
}

// Published returns every key verifiers must know: next, current, retiring.
func (r *Ring) Published() []jose.JSONWebKey {
	panic("TODO(S5 hand-build): Ring.Published")
}

// Rotate creates a next key that becomes current after PublishLead.
func (r *Ring) Rotate(ctx context.Context) (KeyInfo, error) {
	panic("TODO(S5 hand-build): Ring.Rotate")
}

// Keys reports every key and its state, for /admin/keys.
func (r *Ring) Keys() []KeyInfo {
	panic("TODO(S5 hand-build): Ring.Keys")
}
