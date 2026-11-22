// Package domain holds partner-sts's entities. Pure Go.
package domain

import (
	"errors"
	"slices"
)

var ErrNotFound = errors.New("not found")

type PartnerStatus string

const (
	PartnerActive    PartnerStatus = "active"
	PartnerSuspended PartnerStatus = "suspended"
)

// Partner is a registered partner backend (an OAuth client of partner-sts).
type Partner struct {
	ClientID      string // OAuth client_id, the assertion's iss/sub
	PartnerID     string // tenant, copied into tokens as partner_id
	Name          string
	Status        PartnerStatus
	AllowedScopes []string
	JWKS          []byte // the partner's public JWK Set (JSON), for private_key_jwt
}

func (p Partner) Active() bool { return p.Status == PartnerActive }

// Downscope returns allowed ∩ requested, in allowed order. An empty request
// means "everything allowed" (RFC 6749 §3.3 default scope).
func (p Partner) Downscope(requested []string) []string {
	if len(requested) == 0 {
		return slices.Clone(p.AllowedScopes)
	}
	var out []string
	for _, s := range p.AllowedScopes {
		if slices.Contains(requested, s) {
			out = append(out, s)
		}
	}
	return out
}
