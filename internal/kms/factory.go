package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aamirlatif1/warden/internal/issuer"
)

// KMSCreateAPI adds CreateKey to what the signer needs.
type KMSCreateAPI interface {
	KMSAPI
	CreateKey(ctx context.Context, in *awskms.CreateKeyInput, opts ...func(*awskms.Options)) (*awskms.CreateKeyOutput, error)
}

// KMSFactory creates a new ECC_NIST_P256 signing key in KMS per rotation.
// It implements keyring.KeyFactory.
type KMSFactory struct {
	API         KMSCreateAPI
	Description string
}

func (f KMSFactory) NewSigner(ctx context.Context) (issuer.Signer, error) {
	out, err := f.API.CreateKey(ctx, &awskms.CreateKeyInput{
		KeySpec:     types.KeySpecEccNistP256,
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Description: aws.String(f.Description),
	})
	if err != nil {
		return nil, fmt.Errorf("kms CreateKey: %w", err)
	}
	return NewKMSSigner(ctx, f.API, aws.ToString(out.KeyMetadata.KeyId))
}

// LocalFactory creates in-memory P-256 keys (WARDEN_SIGNER=local). Rotated
// keys are not persisted: a restart falls back to the key file.
type LocalFactory struct{}

func (LocalFactory) NewSigner(context.Context) (issuer.Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewLocalSigner(k)
}
