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
	"github.com/aamirlatif1/warden/internal/issuer/keyring"
	"github.com/aamirlatif1/warden/internal/kms"
	"github.com/aamirlatif1/warden/internal/ratelimit"
	"github.com/aamirlatif1/warden/internal/revocation"
	"github.com/aamirlatif1/warden/internal/sts/adapters/httpapi"
	"github.com/aamirlatif1/warden/internal/sts/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/sts/adapters/redisreplay"
	"github.com/aamirlatif1/warden/internal/sts/app"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
)

// tokenTTL is the lifetime of every access token partner-sts issues.
const tokenTTL = 5 * time.Minute

type cfg struct {
	addr, adminAddr        string
	issuer, audience       string
	publishLead            time.Duration
	introspectSecret       string
	signer                 string // kms | local
	kmsKeyID, kmsEndpoint  string
	region, localKeyFile   string
	databaseURL, redisAddr string
	ipRate, clientRate     string // /token budgets, "LIMIT/WINDOW"
}

func loadConfig() cfg {
	return cfg{
		addr:        env("WARDEN_STS_ADDR", ":8083"),
		adminAddr:   env("WARDEN_STS_ADMIN_ADDR", "127.0.0.1:9083"),
		issuer:      env("WARDEN_STS_ISSUER", "http://localhost:8083"),
		audience:    env("WARDEN_API_AUDIENCE", "policy-api"),
		publishLead: durationEnv("WARDEN_STS_PUBLISH_LEAD", 10*time.Minute),
		// policy-api's credentials for /introspect; empty disables the endpoint.
		introspectSecret: os.Getenv("WARDEN_STS_INTROSPECT_SECRET"),
		ipRate:           env("WARDEN_STS_TOKEN_RATE_IP", "60/1m"),
		clientRate:       env("WARDEN_STS_TOKEN_RATE_CLIENT", "30/1m"),
		signer:           env("WARDEN_SIGNER", "kms"),
		kmsKeyID:         env("WARDEN_KMS_KEY_ID", "alias/warden-sts"),
		kmsEndpoint:      env("WARDEN_KMS_ENDPOINT", "http://localhost:4566"), // LocalStack; empty = real AWS
		region:           env("AWS_REGION", "eu-central-1"),
		localKeyFile:     env("WARDEN_LOCAL_KEY_FILE", ".local/sts-signing.key.pem"),
		databaseURL:      env("WARDEN_DATABASE_URL", "postgres://warden:warden@localhost:5434/warden?sslmode=disable"),
		redisAddr:        env("WARDEN_REDIS_ADDR", "localhost:6379"),
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func durationEnv(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
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

	// ---- keys: KMS (or local) signer inside the rotation state machine ----
	signer, factory, err := newSigner(ctx, c)
	if err != nil {
		return err
	}
	// ADR-004: a new key is published publishLead before it signs, and JWKS
	// is cacheable for half of that, so every verifier has it in time. An
	// old key stays published for one token lifetime (+ leeway) after.
	ring, err := keyring.New(keyring.Config{
		PublishLead: c.publishLead,
		RetireAfter: tokenTTL + 30*time.Second,
		Factory:     factory,
	}, signer)
	if err != nil {
		return err
	}
	minter, err := issuer.New(issuer.Config{Issuer: c.issuer, Audience: c.audience, TTL: tokenTTL, Keys: ring})
	if err != nil {
		return err
	}
	if err := minter.SelfTest(ctx); err != nil {
		return err
	}

	// ---- storage ----
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

	// ---- use cases ----
	verifier, err := clientauth.NewVerifier(clientauth.Config{
		Audience: c.issuer, // rfc7523bis: the assertion's aud is our issuer identifier
		Clients:  store,
		Replay:   redisreplay.New(rdb),
	})
	if err != nil {
		return fmt.Errorf("client auth config: %w", err)
	}
	tokens := app.NewTokenService(verifier, store, minter, log)
	limits, err := tokenLimits(rdb, c)
	if err != nil {
		return err
	}
	lifecycle := app.NewLifecycle(verifier, minter, revocation.NewStore(rdb), store, ring, log)

	introspectors := map[string]string{}
	if c.introspectSecret != "" {
		introspectors["policy-api"] = c.introspectSecret
	}

	// ---- HTTP: public listener + loopback-only admin listener ----
	gin.SetMode(gin.ReleaseMode)
	public := &http.Server{
		Addr: c.addr,
		Handler: httpapi.NewRouter(httpapi.Config{
			Issuer:               c.issuer,
			JWKSMaxAge:           int((c.publishLead / 2).Seconds()),
			IntrospectionClients: introspectors,
		}, httpapi.Services{Tokens: tokens, Lifecycle: lifecycle, Keys: minter, Limits: limits}, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	admin := &http.Server{
		Addr:              c.adminAddr,
		Handler:           httpapi.NewAdminRouter(lifecycle, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second, // a KMS CreateKey can be slow
	}
	errc := make(chan error, 2)
	for _, s := range []*http.Server{public, admin} {
		go func() {
			if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	log.Info("partner-sts listening",
		"addr", c.addr, "admin", c.adminAddr, "issuer", c.issuer, "signer", c.signer,
		"kid", signer.KeyID(), "publish_lead", c.publishLead.String(), "introspection", c.introspectSecret != "")

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = admin.Shutdown(shutdownCtx)
	return public.Shutdown(shutdownCtx)
}

// newSigner returns the initial signing key and the factory that creates
// rotated ones. Rotation state is in memory: after a restart the STS signs
// with the configured key again (ADR-004 material: persist the ring, or
// move the KMS alias when a key activates).
func newSigner(ctx context.Context, c cfg) (issuer.Signer, keyring.KeyFactory, error) {
	switch c.signer {
	case "local":
		s, err := kms.LoadOrCreateLocalSigner(c.localKeyFile)
		return s, kms.LocalFactory{}, err
	case "kms":
		opts := []func(*config.LoadOptions) error{config.WithRegion(c.region)}
		if c.kmsEndpoint != "" && os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			// LocalStack accepts any credentials.
			opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, nil, err
		}
		client := awskms.NewFromConfig(awsCfg, func(o *awskms.Options) {
			if c.kmsEndpoint != "" {
				o.BaseEndpoint = aws.String(c.kmsEndpoint)
			}
		})
		s, err := kms.NewKMSSigner(ctx, client, c.kmsKeyID)
		if err != nil {
			return nil, nil, fmt.Errorf("%w (run `make kms-key`, or set WARDEN_SIGNER=local)", err)
		}
		return s, kms.KMSFactory{API: client, Description: "warden partner-sts signing key (rotated)"}, nil
	default:
		return nil, nil, fmt.Errorf("WARDEN_SIGNER must be kms or local, got %q", c.signer)
	}
}

// tokenLimits builds /token's per-IP and per-client sliding windows.
func tokenLimits(rdb *redis.Client, c cfg) (httpapi.TokenLimits, error) {
	build := func(name, rate string) (*ratelimit.Limiter, error) {
		n, w, err := ratelimit.ParseRate(rate)
		if err != nil {
			return nil, err
		}
		return ratelimit.New(rdb, ratelimit.Config{Prefix: "warden:rl:sts-token-" + name + ":", Limit: n, Window: w})
	}
	ip, err := build("ip", c.ipRate)
	if err != nil {
		return httpapi.TokenLimits{}, err
	}
	client, err := build("client", c.clientRate)
	if err != nil {
		return httpapi.TokenLimits{}, err
	}
	return httpapi.TokenLimits{PerIP: ip, PerClient: client}, nil
}
