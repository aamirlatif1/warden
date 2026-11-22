// Package revocation fans revocations out from partner-sts to every
// resource server: a Redis denylist (durable until the token would expire
// anyway) plus pub/sub on warden.revocations for sub-second propagation,
// into a local in-memory Set that the validator consults with no network
// call on the hot path (ADR-003, ADR-007).
package revocation

import (
	"sync"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
)

// Kind of revocation.
const (
	KindJTI    = "jti"    // one token
	KindClient = "client" // every token of a client issued at or before NotBefore (partner suspended)
)

// Event is one revocation, as stored in Redis and published.
type Event struct {
	Kind      string `json:"kind"`
	Issuer    string `json:"iss"`
	Value     string `json:"value"`                // the jti, or the client_id
	NotBefore int64  `json:"not_before,omitempty"` // client: tokens with iat <= this are revoked (unix s)
	ExpiresAt int64  `json:"exp"`                  // entry is useless after this: every affected token has expired (unix s)
	RevokedAt int64  `json:"revoked_at_ms"`        // for propagation-lag measurement (unix ms)
}

func (e Event) key() string { return e.Issuer + "|" + e.Value }

// Set is the in-memory denylist. It implements authn.Denylist.
type Set struct {
	mu      sync.RWMutex
	jtis    map[string]int64 // iss|jti → exp
	clients map[string]Event // iss|client → event
	now     func() time.Time
}

var _ authn.Denylist = (*Set)(nil)

func NewSet(now func() time.Time) *Set {
	if now == nil {
		now = time.Now
	}
	return &Set{jtis: map[string]int64{}, clients: map[string]Event{}, now: now}
}

// Apply adds an event. Expired events are ignored. For a client, the later
// NotBefore wins (a second suspension extends the cut-off).
func (s *Set) Apply(e Event) {
	if e.ExpiresAt <= s.now().Unix() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch e.Kind {
	case KindJTI:
		if e.ExpiresAt > s.jtis[e.key()] {
			s.jtis[e.key()] = e.ExpiresAt
		}
	case KindClient:
		if old, ok := s.clients[e.key()]; !ok || e.NotBefore >= old.NotBefore {
			s.clients[e.key()] = e
		}
	}
}

// Revoked implements authn.Denylist.
func (s *Set) Revoked(t authn.TokenRef) bool {
	now := s.now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if exp, ok := s.jtis[t.Issuer+"|"+t.JTI]; ok && t.JTI != "" && exp > now {
		return true
	}
	if t.ClientID == "" {
		return false
	}
	if e, ok := s.clients[t.Issuer+"|"+t.ClientID]; ok && e.ExpiresAt > now {
		return t.IssuedAt.IsZero() || t.IssuedAt.Unix() <= e.NotBefore
	}
	return false
}

// Purge drops expired entries.
func (s *Set) Purge() {
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.jtis {
		if exp <= now {
			delete(s.jtis, k)
		}
	}
	for k, e := range s.clients {
		if e.ExpiresAt <= now {
			delete(s.clients, k)
		}
	}
}

// Len is the number of live entries (a gauge in S8).
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.jtis) + len(s.clients)
}
