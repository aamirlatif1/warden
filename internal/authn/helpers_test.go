package authn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/authn"
)

// Fixed test clock. Every token is built relative to it.
var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	kcIss      = "http://localhost:8080/realms/insurance"
	stsIss     = "http://localhost:8083"
	cognitoIss = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_TEST"
	audience   = "policy-api"
	cognitoApp = "cognito-app-client"

	kcKid      = "kc-1"
	stsKid     = "sts-1"
	cognitoKid = "cognito-1"
)

// Keys are generated once per test binary (RSA keygen is slow).
type testKeys struct {
	kc       *rsa.PrivateKey // Keycloak realm key
	sts      *ecdsa.PrivateKey
	cognito  *rsa.PrivateKey
	attacker *rsa.PrivateKey // never published in any JWKS
	attackEC *ecdsa.PrivateKey
}

var (
	keysOnce sync.Once
	keys     testKeys
)

func k(t testing.TB) testKeys {
	t.Helper()
	keysOnce.Do(func() {
		keys.kc = mustRSA()
		keys.cognito = mustRSA()
		keys.attacker = mustRSA()
		keys.sts = mustEC()
		keys.attackEC = mustEC()
	})
	return keys
}

func mustRSA() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func mustEC() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func pubJWK(key any, kid string, alg jose.SignatureAlgorithm) jose.JSONWebKey {
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	default:
		panic("unsupported key")
	}
	return jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: string(alg), Use: "sig"}
}

// staticKeys is an in-memory authn.KeySource that counts lookups.
type staticKeys struct {
	keys  map[string]jose.JSONWebKey
	calls atomic.Int64
}

func newStaticKeys(ks ...jose.JSONWebKey) *staticKeys {
	s := &staticKeys{keys: map[string]jose.JSONWebKey{}}
	for _, key := range ks {
		s.keys[key.KeyID] = key
	}
	return s
}

func (s *staticKeys) Key(_ context.Context, kid string) (jose.JSONWebKey, error) {
	s.calls.Add(1)
	key, ok := s.keys[kid]
	if !ok {
		return jose.JSONWebKey{}, authn.Reject(authn.ReasonKidUnknown, "", nil)
	}
	return key, nil
}

// denylist revokes jti "revoked-jti" from any issuer, and every token of
// client "suspended-client" issued at or before now-1m.
type denylist struct{}

func (denylist) Revoked(t authn.TokenRef) bool {
	if t.JTI == "revoked-jti" {
		return true
	}
	if t.ClientID == "suspended-client" {
		return t.IssuedAt.IsZero() || !t.IssuedAt.After(now.Add(-time.Minute))
	}
	return false
}

// recordingDenylist records what the validator asked.
type recordingDenylist struct{ got []authn.TokenRef }

func (r *recordingDenylist) Revoked(t authn.TokenRef) bool { r.got = append(r.got, t); return false }

// newTestValidator trusts Keycloak, partner-sts and Cognito, each with
// only its own key, with the denylist above.
func newTestValidator(t testing.TB) *authn.Validator {
	t.Helper()
	ks := k(t)
	v, err := authn.NewValidator(authn.Config{
		Issuers: []authn.Issuer{
			{Profile: authn.KeycloakProfile(kcIss, audience), Keys: newStaticKeys(pubJWK(ks.kc, kcKid, jose.RS256))},
			{Profile: authn.PartnerSTSProfile(stsIss, audience), Keys: newStaticKeys(pubJWK(ks.sts, stsKid, jose.ES256))},
			{Profile: authn.CognitoProfile(cognitoIss, cognitoApp), Keys: newStaticKeys(pubJWK(ks.cognito, cognitoKid, jose.RS256))},
		},
		Denylist: denylist{},
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// ---- token building ----

type claims = map[string]any

func unix(d time.Duration) int64 { return now.Add(d).Unix() }

func kcClaims() claims {
	return claims{
		"iss":          kcIss,
		"sub":          "user-anna",
		"aud":          []string{audience, "account"},
		"azp":          "portal-bff",
		"exp":          unix(5 * time.Minute),
		"iat":          unix(-10 * time.Second),
		"auth_time":    unix(-60 * time.Second),
		"jti":          "kc-jti-1",
		"scope":        "openid profile policies",
		"acr":          "gold",
		"partner_id":   "nordbank",
		"realm_access": map[string]any{"roles": []string{"policyholder", "default-roles-insurance"}},
	}
}

func stsClaims() claims {
	return claims{
		"iss":        stsIss,
		"sub":        "shopr",
		"client_id":  "shopr",
		"aud":        audience,
		"exp":        unix(5 * time.Minute),
		"iat":        unix(0),
		"jti":        "sts-jti-1",
		"scope":      "quotes:write",
		"partner_id": "shopr",
	}
}

func cognitoClaims() claims {
	return claims{
		"iss":            cognitoIss,
		"sub":            "8f0c-cognito-user",
		"client_id":      cognitoApp,
		"token_use":      "access",
		"exp":            unix(5 * time.Minute),
		"iat":            unix(-5 * time.Second),
		"auth_time":      unix(-5 * time.Second),
		"jti":            "cognito-jti-1",
		"scope":          "warden/quotes.read",
		"cognito:groups": []string{"underwriter"},
	}
}

// with returns a copy of c with the given overrides; a nil value deletes.
func with(c claims, kv ...any) claims {
	out := maps.Clone(c)
	for i := 0; i < len(kv); i += 2 {
		key := kv[i].(string)
		if kv[i+1] == nil {
			delete(out, key)
		} else {
			out[key] = kv[i+1]
		}
	}
	return out
}

type spec struct {
	alg     jose.SignatureAlgorithm
	key     any    // signing key: *rsa.PrivateKey, *ecdsa.PrivateKey or []byte
	kid     string // "" = no kid header
	typ     string // "" = no typ header
	headers map[jose.HeaderKey]any
	embed   bool // embed the public JWK in the header
}

func kcSpec(t testing.TB) spec { return spec{alg: jose.RS256, key: k(t).kc, kid: kcKid, typ: "JWT"} }
func stsSpec(t testing.TB) spec {
	return spec{alg: jose.ES256, key: k(t).sts, kid: stsKid, typ: "at+jwt"}
}
func cognitoSpec(t testing.TB) spec {
	return spec{alg: jose.RS256, key: k(t).cognito, kid: cognitoKid}
}

func sign(t testing.TB, s spec, c claims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(t, s, payload)
}

func signRaw(t testing.TB, s spec, payload []byte) string {
	t.Helper()
	opts := &jose.SignerOptions{EmbedJWK: s.embed}
	if s.kid != "" {
		opts = opts.WithHeader("kid", s.kid)
	}
	if s.typ != "" {
		opts = opts.WithType(jose.ContentType(s.typ))
	}
	for hk, hv := range s.headers {
		opts = opts.WithHeader(hk, hv)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: s.key}, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return tok
}

var b64 = base64.RawURLEncoding

// unsigned builds header.payload. with an arbitrary header (alg none etc.).
func unsigned(t testing.TB, header map[string]any, c claims) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(c)
	return b64.EncodeToString(h) + "." + b64.EncodeToString(p) + "."
}

// swapPayload replaces the payload of a signed token, keeping header and
// signature (tampering).
func swapPayload(t testing.TB, tok string, c claims) string {
	t.Helper()
	parts := splitJWS(t, tok)
	p, _ := json.Marshal(c)
	return parts[0] + "." + b64.EncodeToString(p) + "." + parts[2]
}

func stripSignature(t testing.TB, tok string) string {
	t.Helper()
	parts := splitJWS(t, tok)
	return parts[0] + "." + parts[1] + "."
}

func splitJWS(t testing.TB, tok string) [3]string {
	t.Helper()
	var out [3]string
	i := 0
	start := 0
	for j := 0; j < len(tok); j++ {
		if tok[j] == '.' {
			if i == 2 {
				t.Fatal("too many segments")
			}
			out[i] = tok[start:j]
			i++
			start = j + 1
		}
	}
	out[2] = tok[start:]
	return out
}

// rsaPublicPEM is what an attacker uses as an HMAC secret in alg confusion.
func rsaPublicPEM(t testing.TB, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
