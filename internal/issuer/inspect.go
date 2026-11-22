package issuer

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims are the claims of a token this issuer minted.
type Claims struct {
	Issuer    string
	Subject   string
	ClientID  string
	PartnerID string
	Scope     string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// ErrNotOurs: the token was not signed by a key this issuer publishes, or
// is not a well-formed at+jwt from this issuer.
var ErrNotOurs = errors.New("issuer: not a token from this issuer")

// Inspect verifies a token this STS minted (signature against the
// published keys, typ, iss) and returns its claims. It does NOT check
// expiry or revocation: /revoke and /introspect decide what to do with
// those. This is the issuer checking its own output, not the resource
// server's validator.
func (m *Minter) Inspect(raw string) (Claims, error) {
	if len(raw) > 8<<10 {
		return Claims{}, ErrNotOurs
	}
	obj, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(obj.Signatures) != 1 {
		return Claims{}, ErrNotOurs
	}
	h := obj.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders["typ"].(string); typ != "at+jwt" {
		return Claims{}, ErrNotOurs
	}
	var key *jose.JSONWebKey
	for _, k := range m.cfg.Keys.Published() {
		if k.KeyID == h.KeyID {
			key = &k
			break
		}
	}
	if key == nil {
		return Claims{}, ErrNotOurs
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return Claims{}, ErrNotOurs
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil || c.Iss != m.cfg.Issuer || c.Jti == "" {
		return Claims{}, ErrNotOurs
	}
	return Claims{
		Issuer: c.Iss, Subject: c.Sub, ClientID: c.ClientID, PartnerID: c.PartnerID, Scope: c.Scope,
		JTI: c.Jti, IssuedAt: time.Unix(c.Iat, 0), ExpiresAt: time.Unix(c.Exp, 0),
	}, nil
}

// TTL is the lifetime of minted tokens.
func (m *Minter) TTL() time.Duration { return m.cfg.TTL }

// Issuer is the iss of minted tokens.
func (m *Minter) Issuer() string { return m.cfg.Issuer }
