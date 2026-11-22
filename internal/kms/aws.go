package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/go-jose/go-jose/v4"
)

// KMSAPI is the part of the AWS KMS client this adapter calls.
type KMSAPI interface {
	GetPublicKey(ctx context.Context, in *awskms.GetPublicKeyInput, opts ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *awskms.SignInput, opts ...func(*awskms.Options)) (*awskms.SignOutput, error)
}

// KMSSigner signs with an ECC_NIST_P256 key in AWS KMS. The private key
// never leaves KMS; we send a SHA-256 digest and get back DER.
type KMSSigner struct {
	api   KMSAPI
	keyID string // key ID, ARN or alias
	jwk   jose.JSONWebKey
}

// NewKMSSigner fetches the public key once and checks it is a P-256
// signing key.
func NewKMSSigner(ctx context.Context, api KMSAPI, keyID string) (*KMSSigner, error) {
	out, err := api.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("kms GetPublicKey %s: %w", keyID, err)
	}
	if out.KeySpec != types.KeySpecEccNistP256 || out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kms key %s: want ECC_NIST_P256 / SIGN_VERIFY, got %s / %s", keyID, out.KeySpec, out.KeyUsage)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("kms public key is not P-256")
	}
	jwk, err := publicJWK(ec)
	if err != nil {
		return nil, err
	}
	return &KMSSigner{api: api, keyID: keyID, jwk: jwk}, nil
}

func (s *KMSSigner) KeyID() string                      { return s.jwk.KeyID }
func (s *KMSSigner) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (s *KMSSigner) PublicJWK() jose.JSONWebKey         { return s.jwk }

// SignDigest asks KMS to sign a precomputed SHA-256 digest
// (MessageType=DIGEST, so the JWS signing input never leaves the process
// and has no 4 KiB limit) and converts the DER result to JOSE R||S.
func (s *KMSSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("kms signer: digest must be SHA-256 (32 bytes)")
	}
	out, err := s.api.Sign(ctx, &awskms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	return DERToJOSE(out.Signature)
}
