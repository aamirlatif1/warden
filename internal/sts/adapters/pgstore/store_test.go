package pgstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/sts/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

var ctx = context.Background()

func jwks(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k
}

func TestParsePublicJWKS(t *testing.T) {
	k := ecKey(t)
	sig := jose.JSONWebKey{Key: &k.PublicKey, KeyID: "s1", Algorithm: "ES256", Use: "sig"}
	enc := jose.JSONWebKey{Key: &k.PublicKey, KeyID: "e1", Use: "enc"}
	noKid := jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256"}
	private := jose.JSONWebKey{Key: k, KeyID: "p1", Algorithm: "ES256"}

	got, err := pgstore.ParsePublicJWKS(jwks(t, sig, enc, noKid))
	if err != nil || len(got) != 1 || got[0].KeyID != "s1" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := pgstore.ParsePublicJWKS(jwks(t, sig, private)); err == nil {
		t.Fatal("accepted a set with private key material")
	}
	if _, err := pgstore.ParsePublicJWKS(jwks(t, enc)); err == nil {
		t.Fatal("accepted a set with no signing key")
	}
	if _, err := pgstore.ParsePublicJWKS([]byte("nope")); err == nil {
		t.Fatal("accepted garbage")
	}
}

func open(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("WARDEN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("WARDEN_TEST_DATABASE_URL not set; run make test-db")
	}
	s, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPartnerRegistry(t *testing.T) {
	s := open(t)
	k := ecKey(t)
	p := domain.Partner{
		ClientID: "it-shopr", PartnerID: "shopr", Name: "Shopr", Status: domain.PartnerActive,
		AllowedScopes: []string{"quotes:read", "quotes:write"},
		JWKS:          jwks(t, jose.JSONWebKey{Key: &k.PublicKey, KeyID: "it-1", Algorithm: "ES256", Use: "sig"}),
	}
	if err := s.UpsertPartner(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := s.Partner(ctx, "it-shopr")
	if err != nil || got.PartnerID != "shopr" || !got.Active() || len(got.AllowedScopes) != 2 {
		t.Fatalf("Partner = %+v, %v", got, err)
	}
	c, err := s.Client(ctx, "it-shopr")
	if err != nil || c.ID != "it-shopr" || len(c.Keys) != 1 || c.Keys[0].KeyID != "it-1" {
		t.Fatalf("Client = %+v, %v", c, err)
	}

	if err := s.SetStatus(ctx, "it-shopr", domain.PartnerSuspended); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Partner(ctx, "it-shopr"); got.Active() {
		t.Fatal("SetStatus did not suspend")
	}
	if err := s.SetStatus(ctx, "it-ghost", domain.PartnerActive); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetStatus on missing partner: %v", err)
	}

	if _, err := s.Partner(ctx, "it-ghost"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing partner: %v", err)
	}
	if _, err := s.Client(ctx, "it-ghost"); !errors.Is(err, clientauth.ErrUnknownClient) {
		t.Fatalf("missing client: %v", err)
	}

	bad := p
	bad.ClientID = "it-bad"
	bad.JWKS = jwks(t, jose.JSONWebKey{Key: k, KeyID: "x", Algorithm: "ES256"})
	if err := s.UpsertPartner(ctx, bad); err == nil {
		t.Fatal("stored a partner whose JWKS holds a private key")
	}
}
