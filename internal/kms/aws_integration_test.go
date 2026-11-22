package kms

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Against LocalStack KMS: run with `make test-db` (needs `make up`).
func TestKMSSignerAgainstLocalStack(t *testing.T) {
	endpoint := os.Getenv("WARDEN_TEST_KMS_ENDPOINT")
	if endpoint == "" {
		t.Skip("WARDEN_TEST_KMS_ENDPOINT not set")
	}
	ctx := context.Background()
	client := awskms.New(awskms.Options{
		Region:       "eu-central-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
	})
	created, err := client.CreateKey(ctx, &awskms.CreateKeyInput{
		KeySpec:  types.KeySpecEccNistP256,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID := aws.ToString(created.KeyMetadata.KeyId)
	t.Cleanup(func() {
		_, _ = client.ScheduleKeyDeletion(ctx, &awskms.ScheduleKeyDeletionInput{KeyId: aws.String(keyID), PendingWindowInDays: aws.Int32(7)})
	})

	s, err := NewKMSSigner(ctx, client, keyID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		d := sha256.Sum256([]byte{byte(i)})
		sig, err := s.SignDigest(ctx, d[:])
		if err != nil {
			t.Fatal(err)
		}
		verifyJOSE(t, s.PublicJWK(), d[:], sig)
	}
}
