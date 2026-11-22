// Package issuer mints partner-sts access tokens (RFC 9068 JWT profile).
// It assembles the compact JWS itself and delegates only the signature to
// a Signer (KMS or local), so the private key never has to be in process.
package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Signer signs a SHA-256 digest and returns a JOSE (R||S) signature.
// Implemented by kms.KMSSigner and kms.LocalSigner.
type Signer interface {
	KeyID() string
	Algorithm() jose.SignatureAlgorithm
	PublicJWK() jose.JSONWebKey
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}

// KeyRing decides which key signs now and which keys are published in
// JWKS. S4 has one static key (SingleKey); the rotation state machine in
// S5 implements this interface.
type KeyRing interface {
	Signing() Signer
	Published() []jose.JSONWebKey
}

// SingleKey is a KeyRing with one key that signs and is published.
type SingleKey struct{ S Signer }

func (k SingleKey) Signing() Signer              { return k.S }
func (k SingleKey) Published() []jose.JSONWebKey { return []jose.JSONWebKey{k.S.PublicJWK()} }

type Config struct {
	Issuer   string        // iss, e.g. http://localhost:8083
	Audience string        // aud of every token, e.g. policy-api
	TTL      time.Duration // default 5 min
	Keys     KeyRing
	Now      func() time.Time
}

type Minter struct {
	cfg Config
}

func New(cfg Config) (*Minter, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.Keys == nil {
		return nil, errors.New("issuer: Issuer, Audience and Keys are required")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Minter{cfg: cfg}, nil
}

// Grant is what the token is for: an authenticated, downscoped client.
type Grant struct {
	ClientID  string
	PartnerID string
	Scopes    []string
}

type Token struct {
	Value     string
	JTI       string
	KeyID     string
	ExpiresAt time.Time
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type claims struct {
	Iss       string `json:"iss"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	ClientID  string `json:"client_id"`
	PartnerID string `json:"partner_id"`
	Scope     string `json:"scope,omitempty"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	Jti       string `json:"jti"`
}

// Mint builds header.payload, hashes it, has the Signer sign the digest,
// and appends the base64url signature.
func (m *Minter) Mint(ctx context.Context, g Grant) (Token, error) {
	if g.ClientID == "" || g.PartnerID == "" {
		return Token{}, errors.New("issuer: grant needs ClientID and PartnerID")
	}
	signer := m.cfg.Keys.Signing()
	now := m.cfg.Now().UTC().Truncate(time.Second)
	exp := now.Add(m.cfg.TTL)
	jti := newJTI()

	h, err := json.Marshal(header{Alg: string(signer.Algorithm()), Typ: "at+jwt", Kid: signer.KeyID()})
	if err != nil {
		return Token{}, err
	}
	p, err := json.Marshal(claims{
		Iss: m.cfg.Issuer, Sub: g.ClientID, Aud: m.cfg.Audience,
		ClientID: g.ClientID, PartnerID: g.PartnerID, Scope: strings.Join(g.Scopes, " "),
		Iat: now.Unix(), Exp: exp.Unix(), Jti: jti,
	})
	if err != nil {
		return Token{}, err
	}
	signingInput := b64(h) + "." + b64(p)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := signer.SignDigest(ctx, digest[:])
	if err != nil {
		return Token{}, fmt.Errorf("issuer: sign: %w", err)
	}
	return Token{Value: signingInput + "." + b64(sig), JTI: jti, KeyID: signer.KeyID(), ExpiresAt: exp}, nil
}

// JWKS is the public key set for /jwks.json.
func (m *Minter) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: m.cfg.Keys.Published()}
}

// SelfTest signs a probe and verifies it against the published key. Run it
// at startup: a signer that returns DER instead of R||S, or a key that is
// not in JWKS, fails here instead of on every partner request.
func (m *Minter) SelfTest(ctx context.Context) error {
	s := m.cfg.Keys.Signing()
	digest := sha256.Sum256([]byte("warden-issuer-selftest"))
	sig, err := s.SignDigest(ctx, digest[:])
	if err != nil {
		return fmt.Errorf("issuer self-test: sign: %w", err)
	}
	var pub *ecdsa.PublicKey
	for _, k := range m.cfg.Keys.Published() {
		if k.KeyID == s.KeyID() {
			pub, _ = k.Key.(*ecdsa.PublicKey)
		}
	}
	if pub == nil {
		return errors.New("issuer self-test: signing key is not published in JWKS")
	}
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("issuer self-test: signature does not verify (DER instead of JOSE R||S?)")
	}
	return nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
