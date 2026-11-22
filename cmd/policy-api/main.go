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
	"google.golang.org/grpc"

	policyv1 "github.com/aamirlatif1/warden/gen/warden/policy/v1"
	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authn/ginauth"
	"github.com/aamirlatif1/warden/internal/authn/grpcauth"
	"github.com/aamirlatif1/warden/internal/authn/jwks"
	"github.com/aamirlatif1/warden/internal/policy/adapters/grpcapi"
	"github.com/aamirlatif1/warden/internal/policy/adapters/httpapi"
	"github.com/aamirlatif1/warden/internal/policy/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/policy/app"
)

type config struct {
	grpcAddr        string
	httpAddr        string
	audience        string
	keycloakIssuer  string
	keycloakJWKSURL string
	databaseURL     string
}

func loadConfig() config {
	issuer := env("WARDEN_KEYCLOAK_ISSUER", "http://localhost:8080/realms/insurance")
	return config{
		grpcAddr:        env("WARDEN_GRPC_ADDR", ":9090"),
		httpAddr:        env("WARDEN_HTTP_ADDR", ":8081"),
		audience:        env("WARDEN_API_AUDIENCE", "policy-api"),
		keycloakIssuer:  issuer,
		keycloakJWKSURL: env("WARDEN_KEYCLOAK_JWKS_URL", issuer+"/protocol/openid-connect/certs"),
		databaseURL:     env("WARDEN_DATABASE_URL", "postgres://warden:warden@localhost:5434/warden?sslmode=disable"),
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
	kcKeys := jwks.New(cfg.keycloakJWKSURL, jwks.Options{})
	if err := kcKeys.Refresh(ctx); err != nil {
		// Not fatal: the first token triggers a fetch, and Run keeps trying.
		log.Warn("initial JWKS fetch failed", "issuer", "keycloak", "err", err)
	}
	go kcKeys.Run(ctx)

	validator, err := authn.NewValidator(authn.Config{
		Issuers: []authn.Issuer{
			{Profile: authn.KeycloakProfile(cfg.keycloakIssuer, cfg.audience), Keys: kcKeys},
			// S4: partner-sts profile.
		},
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
		Policies: store,
		Quotes:   store,
		Claims:   store,
		Limits:   store,
		Tx:       store,
		// S5: introspection client for partner-sts / Keycloak. Until then,
		// approvals above 10 000 EUR fail closed (503).
		Introspector: nil,
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
	log.Info("policy-api listening", "grpc", cfg.grpcAddr, "http", cfg.httpAddr, "keycloak_issuer", cfg.keycloakIssuer)

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
