package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/go-jose/go-jose/v4"
)

func verifyJOSE(t *testing.T, jwk jose.JSONWebKey, digest, sig []byte) {
	t.Helper()
	if len(sig) != 64 {
		t.Fatalf("signature length %d, want 64", len(sig))
	}
	pub := jwk.Key.(*ecdsa.PublicKey)
	if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify against the published JWK")
	}
}

func TestLocalSigner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k", "sts.pem")
	s1, err := LoadOrCreateLocalSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", fi.Mode().Perm())
	}
	s2, err := LoadOrCreateLocalSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if s1.KeyID() != s2.KeyID() || s1.KeyID() == "" {
		t.Fatalf("kid not stable across loads: %q vs %q", s1.KeyID(), s2.KeyID())
	}
	jwk := s1.PublicJWK()
	if !jwk.IsPublic() || jwk.Algorithm != "ES256" || jwk.Use != "sig" {
		t.Fatalf("published JWK = %+v", jwk)
	}
	d := sha256.Sum256([]byte("x.y"))
	sig, err := s1.SignDigest(context.Background(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	verifyJOSE(t, jwk, d[:], sig)
	if _, err := s1.SignDigest(context.Background(), []byte("short")); err == nil {
		t.Fatal("accepted a non-SHA-256 digest")
	}
}

// fakeKMS mimics KMS: DER signatures from a P-256 key.
type fakeKMS struct {
	key   *ecdsa.PrivateKey
	spec  types.KeySpec
	input *awskms.SignInput
}

func (f *fakeKMS) GetPublicKey(context.Context, *awskms.GetPublicKeyInput, ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	return &awskms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.spec, KeyUsage: types.KeyUsageTypeSignVerify}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *awskms.SignInput, _ ...func(*awskms.Options)) (*awskms.SignOutput, error) {
	f.input = in
	der, err := ecdsa.SignASN1(rand.Reader, f.key, in.Message)
	return &awskms.SignOutput{Signature: der}, err
}

func TestKMSSignerWithFake(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fakeKMS{key: key, spec: types.KeySpecEccNistP256}
	s, err := NewKMSSigner(context.Background(), f, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("a.b"))
	sig, err := s.SignDigest(context.Background(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	verifyJOSE(t, s.PublicJWK(), d[:], sig)
	if f.input.MessageType != types.MessageTypeDigest || f.input.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		t.Fatalf("Sign called with %s / %s", f.input.MessageType, f.input.SigningAlgorithm)
	}

	f.spec = types.KeySpecRsa2048
	if _, err := NewKMSSigner(context.Background(), f, "alias/test"); err == nil {
		t.Fatal("accepted a non-P-256 key spec")
	}
}
