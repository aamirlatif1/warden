// Command partner-sts is Warden's token issuer for partner backends
// (private_key_jwt → ES256 at+jwt). Composition root only.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/issuer"
	"github.com/aamirlatif1/warden/internal/kms"
	"github.com/aamirlatif1/warden/internal/sts/adapters/httpapi"
	"github.com/aamirlatif1/warden/internal/sts/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/sts/adapters/redisreplay"
	"github.com/aamirlatif1/warden/internal/sts/app"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
)

type cfg struct {
	addr, issuer, audience string
	signer                 string // kms | local
	kmsKeyID, kmsEndpoint  string
	region, localKeyFile   string
	databaseURL, redisAddr string
}

func loadConfig() cfg {
	return cfg{
		addr:         env("WARDEN_STS_ADDR", ":8083"),
		issuer:       env("WARDEN_STS_ISSUER", "http://localhost:8083"),
		audience:     env("WARDEN_API_AUDIENCE", "policy-api"),
		signer:       env("WARDEN_SIGNER", "kms"),
		kmsKeyID:     env("WARDEN_KMS_KEY_ID", "alias/warden-sts"),
		kmsEndpoint:  env("WARDEN_KMS_ENDPOINT", "http://localhost:4566"), // LocalStack; empty = real AWS
		region:       env("AWS_REGION", "eu-central-1"),
		localKeyFile: env("WARDEN_LOCAL_KEY_FILE", ".local/sts-signing.key.pem"),
		databaseURL:  env("WARDEN_DATABASE_URL", "postgres://warden:warden@localhost:5434/warden?sslmode=disable"),
		redisAddr:    env("WARDEN_REDIS_ADDR", "localhost:6379"),
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("partner-sts stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := loadConfig()

	signer, err := newSigner(ctx, c)
	if err != nil {
		return err
	}
	minter, err := issuer.New(issuer.Config{Issuer: c.issuer, Audience: c.audience, Keys: issuer.SingleKey{S: signer}})
	if err != nil {
		return err
	}
	if err := minter.SelfTest(ctx); err != nil {
		return err
	}

	store, err := pgstore.Open(c.databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: c.redisAddr})
	defer func() { _ = rdb.Close() }()

	verifier, err := clientauth.NewVerifier(clientauth.Config{
		Audience: c.issuer, // rfc7523bis: the assertion's aud is our issuer identifier
		Clients:  store,
		Replay:   redisreplay.New(rdb),
	})
	if err != nil {
		return fmt.Errorf("client auth config: %w", err)
	}

	tokens := app.NewTokenService(verifier, store, minter, log)

	gin.SetMode(gin.ReleaseMode)
	srv := &http.Server{
		Addr:              c.addr,
		Handler:           httpapi.NewRouter(httpapi.Config{Issuer: c.issuer, JWKSMaxAge: 300}, tokens, minter, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	log.Info("partner-sts listening", "addr", c.addr, "issuer", c.issuer, "signer", c.signer, "kid", signer.KeyID())

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func newSigner(ctx context.Context, c cfg) (issuer.Signer, error) {
	switch c.signer {
	case "local":
		return kms.LoadOrCreateLocalSigner(c.localKeyFile)
	case "kms":
		opts := []func(*config.LoadOptions) error{config.WithRegion(c.region)}
		if c.kmsEndpoint != "" && os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			// LocalStack accepts any credentials.
			opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, err
		}
		client := awskms.NewFromConfig(awsCfg, func(o *awskms.Options) {
			if c.kmsEndpoint != "" {
				o.BaseEndpoint = aws.String(c.kmsEndpoint)
			}
		})
		s, err := kms.NewKMSSigner(ctx, client, c.kmsKeyID)
		if err != nil {
			return nil, fmt.Errorf("%w (run `make kms-key`, or set WARDEN_SIGNER=local)", err)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("WARDEN_SIGNER must be kms or local, got %q", c.signer)
	}
}
