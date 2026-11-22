// Command policy-api is the resource server: gRPC on :9090 and REST (Gin)
// on :8081. This file is the composition root: it builds adapters, injects
// them into the app service and starts the servers. No business logic.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	policyv1 "github.com/aamirlatif1/warden/gen/warden/policy/v1"
	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authn/ginauth"
	"github.com/aamirlatif1/warden/internal/authn/grpcauth"
	"github.com/aamirlatif1/warden/internal/authn/jwks"
	"github.com/aamirlatif1/warden/internal/policy/adapters/grpcapi"
	"github.com/aamirlatif1/warden/internal/policy/adapters/httpapi"
	"github.com/aamirlatif1/warden/internal/policy/adapters/introspect"
	"github.com/aamirlatif1/warden/internal/policy/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/revocation"
)

type config struct {
	grpcAddr        string
	httpAddr        string
	audience        string
	keycloakIssuer  string
	keycloakJWKSURL string
	stsIssuer       string
	stsJWKSURL      string
	databaseURL     string
	redisAddr       string
	// RFC 7662 credentials (policy-api's client secret at each issuer);
	// empty disables introspection for that issuer.
	keycloakIntrospectSecret string
	stsIntrospectSecret      string
}

func loadConfig() config {
	issuer := env("WARDEN_KEYCLOAK_ISSUER", "http://localhost:8080/realms/insurance")
	stsIssuer := env("WARDEN_STS_ISSUER", "http://localhost:8083")
	return config{
		grpcAddr:        env("WARDEN_GRPC_ADDR", ":9090"),
		httpAddr:        env("WARDEN_HTTP_ADDR", ":8081"),
		audience:        env("WARDEN_API_AUDIENCE", "policy-api"),
		keycloakIssuer:  issuer,
		keycloakJWKSURL: env("WARDEN_KEYCLOAK_JWKS_URL", issuer+"/protocol/openid-connect/certs"),
		stsIssuer:       stsIssuer,
		stsJWKSURL:      env("WARDEN_STS_JWKS_URL", stsIssuer+"/jwks.json"),
		databaseURL:     env("WARDEN_DATABASE_URL", "postgres://warden:warden@localhost:5434/warden?sslmode=disable"),
		redisAddr:       env("WARDEN_REDIS_ADDR", "localhost:6379"),

		keycloakIntrospectSecret: os.Getenv("WARDEN_KEYCLOAK_INTROSPECT_SECRET"),
		stsIntrospectSecret:      os.Getenv("WARDEN_STS_INTROSPECT_SECRET"),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("policy-api stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := loadConfig()

	// ---- authn: one validator shared by REST and gRPC ----
	// One JWKS cache per issuer: keys are never shared across issuers.
	kcKeys := startJWKS(ctx, log, "keycloak", cfg.keycloakJWKSURL)
	stsKeys := startJWKS(ctx, log, "partner-sts", cfg.stsJWKSURL)

	// Revocation: a local set fed by Redis pub/sub, so the hot path makes
	// no network call. If Redis is down the set keeps its last state:
	// tokens are short-lived, and high-risk calls are introspected online.
	rdb := redis.NewClient(&redis.Options{Addr: cfg.redisAddr})
	defer func() { _ = rdb.Close() }()
	denylist := revocation.NewSet(nil)
	go revocation.NewSubscriber(rdb, denylist, log).Run(ctx)

	validator, err := authn.NewValidator(authn.Config{
		Issuers: []authn.Issuer{
			{Profile: authn.KeycloakProfile(cfg.keycloakIssuer, cfg.audience), Keys: kcKeys},
			{Profile: authn.PartnerSTSProfile(cfg.stsIssuer, cfg.audience), Keys: stsKeys},
		},
		Denylist: denylist,
	})
	if err != nil {
		return fmt.Errorf("authn config: %w", err)
	}

	// ---- storage ----
	store, err := pgstore.Open(cfg.databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// ---- app ----
	svc := app.NewService(app.Deps{
		Policies:     store,
		Quotes:       store,
		Claims:       store,
		Limits:       store,
		Tx:           store,
		Introspector: newIntrospector(cfg, log),
		Log:          log,
	})

	// ---- gRPC ----
	grpcSrv := grpc.NewServer(grpc.ChainUnaryInterceptor(grpcauth.UnaryServerInterceptor(validator)))
	policyv1.RegisterPolicyServiceServer(grpcSrv, grpcapi.NewServer(svc, log))
	lis, err := net.Listen("tcp", cfg.grpcAddr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}

	// ---- REST ----
	gin.SetMode(gin.ReleaseMode)
	httpSrv := &http.Server{
		Addr:              cfg.httpAddr,
		Handler:           httpapi.NewRouter(svc, ginauth.Middleware(validator), log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	errc := make(chan error, 2)
	go func() { errc <- grpcSrv.Serve(lis) }()
	go func() {
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	log.Info("policy-api listening", "grpc", cfg.grpcAddr, "http", cfg.httpAddr,
		"keycloak_issuer", cfg.keycloakIssuer, "sts_issuer", cfg.stsIssuer)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
	return nil
}

// startJWKS warms an issuer's key cache and starts its background refresh.
// A failed first fetch is not fatal: the issuer may start later, and the
// first token with an unknown kid triggers a (rate-limited) fetch.
func startJWKS(ctx context.Context, log *slog.Logger, name, url string) *jwks.Cache {
	c := jwks.New(url, jwks.Options{})
	if err := c.Refresh(ctx); err != nil {
		log.Warn("initial JWKS fetch failed", "issuer", name, "url", url, "err", err)
	}
	go c.Run(ctx)
	return c
}

// newIntrospector routes RFC 7662 calls by token issuer. With no
// credentials configured it returns nil, and approvals above 10 000 EUR
// fail closed (503).
func newIntrospector(cfg config, log *slog.Logger) app.Introspector {
	eps := map[string]introspect.Endpoint{}
	if cfg.keycloakIntrospectSecret != "" {
		eps[cfg.keycloakIssuer] = introspect.Endpoint{
			URL:      cfg.keycloakIssuer + "/protocol/openid-connect/token/introspect",
			ClientID: "policy-api",
			Secret:   cfg.keycloakIntrospectSecret,
		}
	}
	if cfg.stsIntrospectSecret != "" {
		eps[cfg.stsIssuer] = introspect.Endpoint{URL: cfg.stsIssuer + "/introspect", ClientID: "policy-api", Secret: cfg.stsIntrospectSecret}
	}
	if len(eps) == 0 {
		log.Warn("no introspection credentials: approvals above 10 000 EUR fail closed")
		return nil
	}
	return introspect.New(eps, nil)
}
