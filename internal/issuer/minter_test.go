package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/issuer"
	"github.com/aamirlatif1/warden/internal/kms"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func newMinter(t *testing.T, s issuer.Signer) *issuer.Minter {
	t.Helper()
	m, err := issuer.New(issuer.Config{
		Issuer: "http://localhost:8083", Audience: "policy-api",
		Keys: issuer.SingleKey{S: s}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func localSigner(t *testing.T) *kms.LocalSigner {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := kms.NewLocalSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The minted token must verify with an independent JOSE library against
// the published JWKS, and carry the claims policy-api's STS profile needs.
func TestMintVerifiesWithJWKS(t *testing.T) {
	m := newMinter(t, localSigner(t))
	tok, err := m.Mint(context.Background(), issuer.Grant{ClientID: "shopr", PartnerID: "shopr", Scopes: []string{"quotes:write"}})
	if err != nil {
		t.Fatal(err)
	}

	obj, err := jose.ParseSigned(tok.Value, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	h := obj.Signatures[0].Protected
	if h.KeyID != tok.KeyID || h.ExtraHeaders["typ"] != "at+jwt" {
		t.Fatalf("header = kid %q typ %v", h.KeyID, h.ExtraHeaders["typ"])
	}
	set := m.JWKS()
	keys := set.Key(h.KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %q not in JWKS", h.KeyID)
	}
	payload, err := obj.Verify(keys[0])
	if err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"iss": "http://localhost:8083", "sub": "shopr", "aud": "policy-api",
		"client_id": "shopr", "partner_id": "shopr", "scope": "quotes:write",
		"iat": float64(now.Unix()), "exp": float64(now.Add(5 * time.Minute).Unix()),
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}
	if jti, _ := c["jti"].(string); jti == "" || jti != tok.JTI {
		t.Errorf("jti = %v, token.JTI = %q", c["jti"], tok.JTI)
	}
	if !tok.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("ExpiresAt = %v", tok.ExpiresAt)
	}
}

func TestJTIsAreUnique(t *testing.T) {
	m := newMinter(t, localSigner(t))
	seen := map[string]bool{}
	for range 100 {
		tok, err := m.Mint(context.Background(), issuer.Grant{ClientID: "shopr", PartnerID: "shopr"})
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.JTI] {
			t.Fatal("duplicate jti")
		}
		seen[tok.JTI] = true
		if strings.Contains(tok.Value, `"scope"`) {
			t.Fatal("unexpected")
		}
	}
}

func TestMintRequiresClientAndPartner(t *testing.T) {
	m := newMinter(t, localSigner(t))
	if _, err := m.Mint(context.Background(), issuer.Grant{ClientID: "shopr"}); err == nil {
		t.Fatal("minted a token without partner_id")
	}
}

// derSigner returns DER instead of JOSE: the self-test must catch it.
type derSigner struct{ *kms.LocalSigner }

func (d derSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	sig, err := d.LocalSigner.SignDigest(ctx, digest)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x30, 0x44}, sig...), nil // DER-shaped, wrong length
}

// unpublished signs with one key but publishes another.
type unpublished struct {
	issuer.Signer
	other jose.JSONWebKey
}

func (u unpublished) PublicJWK() jose.JSONWebKey { return u.other }

func TestSelfTest(t *testing.T) {
	ctx := context.Background()
	if err := newMinter(t, localSigner(t)).SelfTest(ctx); err != nil {
		t.Fatalf("good signer: %v", err)
	}
	if err := newMinter(t, derSigner{localSigner(t)}).SelfTest(ctx); err == nil {
		t.Fatal("self-test passed a DER signer")
	}
	other := localSigner(t).PublicJWK()
	if err := newMinter(t, unpublished{localSigner(t), other}).SelfTest(ctx); err == nil {
		t.Fatal("self-test passed a key that is not in JWKS")
	}
}
