package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v4"
)

// LocalSigner signs with a P-256 key held in process memory. It is the
// fallback when KMS is unavailable (WARDEN_SIGNER=local). The private key
// never leaves the process, but unlike KMS it is in process memory and on
// disk: dev only.
type LocalSigner struct {
	key *ecdsa.PrivateKey
	jwk jose.JSONWebKey
}

// NewLocalSigner wraps an existing P-256 key.
func NewLocalSigner(key *ecdsa.PrivateKey) (*LocalSigner, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("local signer: key must be P-256")
	}
	jwk, err := publicJWK(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &LocalSigner{key: key, jwk: jwk}, nil
}

// LoadOrCreateLocalSigner reads a PEM (PKCS#8) P-256 key from path, or
// creates one with mode 0600 if the file does not exist.
func LoadOrCreateLocalSigner(path string) (*LocalSigner, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := WritePrivateKeyPEM(path, key); err != nil {
			return nil, err
		}
		return NewLocalSigner(key)
	}
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKeyPEM(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return NewLocalSigner(key)
}

func (s *LocalSigner) KeyID() string                      { return s.jwk.KeyID }
func (s *LocalSigner) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (s *LocalSigner) PublicJWK() jose.JSONWebKey         { return s.jwk }

// SignDigest signs a SHA-256 digest and returns the JOSE R||S signature.
// It goes through DER like the KMS path, so both signers share the
// conversion code.
func (s *LocalSigner) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("local signer: digest must be SHA-256 (32 bytes)")
	}
	der, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		return nil, err
	}
	return DERToJOSE(der)
}

// publicJWK builds the public JWK with kid = RFC 7638 thumbprint, so the
// kid is derived from the key itself and stable across restarts.
func publicJWK(pub *ecdsa.PublicKey) (jose.JSONWebKey, error) {
	jwk := jose.JSONWebKey{Key: pub, Algorithm: string(jose.ES256), Use: "sig"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	return jwk, nil
}

// ---- PEM helpers (also used by cmd/partnercli) ----

func ParsePrivateKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected a PKCS#8 PRIVATE KEY PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("expected a P-256 ECDSA key")
	}
	return ec, nil
}

func WritePrivateKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}
