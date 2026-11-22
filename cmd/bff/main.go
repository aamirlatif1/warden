// Command bff is the policyholder portal's backend-for-frontend: OIDC code
// flow with PKCE against Keycloak, server-side sessions, step-up, and
// calls to policy-api over mTLS. A second instance with another client ID
// runs as claims-app to show SSO. Composition root only.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/authn/jwks"
	"github.com/aamirlatif1/warden/internal/bff/adapters/oidcclient"
	"github.com/aamirlatif1/warden/internal/bff/adapters/policyclient"
	"github.com/aamirlatif1/warden/internal/bff/adapters/redisstore"
	"github.com/aamirlatif1/warden/internal/bff/adapters/web"
	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/logouttoken"
	"github.com/aamirlatif1/warden/internal/ratelimit"
	"github.com/aamirlatif1/warden/internal/tlsutil"
)

type config struct {
	instance, title, addr, baseURL string
	clientID, clientSecret         string
	issuer                         string
	sessionKeyFile, redisAddr      string
	policyAPIURL, pkiDir           string
	idps                           string // "alias:Label,alias2:Label2"
	adaptive                       bool
	loginRate                      string // per IP, "LIMIT/WINDOW"
}

func loadConfig() config {
	return config{
		instance:       env("WARDEN_BFF_INSTANCE", "portal"), // portal | claims
		title:          env("WARDEN_BFF_TITLE", "Policyholder portal"),
		addr:           env("WARDEN_BFF_ADDR", ":8082"),
		baseURL:        env("WARDEN_BFF_BASE_URL", "http://localhost:8082"),
		clientID:       env("WARDEN_BFF_CLIENT_ID", "portal-bff"),
		clientSecret:   os.Getenv("WARDEN_BFF_CLIENT_SECRET"),
		issuer:         env("WARDEN_KEYCLOAK_ISSUER", "http://localhost:8080/realms/insurance"),
		sessionKeyFile: env("WARDEN_BFF_SESSION_KEY_FILE", ".local/bff-session.key"),
		redisAddr:      env("WARDEN_REDIS_ADDR", "localhost:6379"),
		policyAPIURL:   env("WARDEN_POLICY_API_URL", "https://localhost:8444"),
		pkiDir:         env("WARDEN_PKI_DIR", "deploy/pki"),
		idps:           env("WARDEN_BFF_IDPS", "nordbank:Log in with Nordbank"),
		adaptive:       env("WARDEN_BFF_ADAPTIVE", "on") == "on",
		loginRate:      env("WARDEN_BFF_LOGIN_RATE", "20/1m"),
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
		log.Error("bff stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := loadConfig()
	log = log.With("instance", c.instance)
	if c.clientSecret == "" {
		return errors.New("WARDEN_BFF_CLIENT_SECRET is required (make run-bff reads it from Tofu)")
	}

	// ---- driven adapters ----
	key, err := loadOrCreateKey(c.sessionKeyFile)
	if err != nil {
		return err
	}
	sealer, err := redisstore.NewSealer(key)
	if err != nil {
		return err
	}
	rdb := redis.NewClient(&redis.Options{Addr: c.redisAddr})
	defer func() { _ = rdb.Close() }()
	prefix := "bff:" + c.instance + ":"
	sessions := redisstore.NewSessions(rdb, sealer, redisstore.SessionConfig{Prefix: prefix})
	txs := redisstore.NewTxs(rdb, sealer, prefix)
	locks := redisstore.NewLocker(rdb, prefix)

	op, err := oidcclient.New(ctx, oidcclient.Config{
		Issuer: c.issuer, ClientID: c.clientID, ClientSecret: c.clientSecret,
		RedirectURL: c.baseURL + "/callback",
	})
	if err != nil {
		return fmt.Errorf("%w (is Keycloak up? make up && make infra)", err)
	}

	mtls, err := tlsutil.ClientMTLS(filepath.Join(c.pkiDir, "ca.pem"), filepath.Join(c.pkiDir, "bff.pem"), filepath.Join(c.pkiDir, "bff.key"))
	if err != nil {
		return fmt.Errorf("mTLS client: %w (run make pki)", err)
	}
	api := policyclient.New(c.policyAPIURL, &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: mtls, ForceAttemptHTTP2: true},
	})

	// Keycloak's signing keys for logout tokens: the same cache policy-api
	// uses for access tokens.
	kcKeys := jwks.New(c.issuer+"/protocol/openid-connect/certs", jwks.Options{})
	if err := kcKeys.Refresh(ctx); err != nil {
		log.Warn("keycloak JWKS not fetched yet; will retry on demand", "err", err)
	}
	go kcKeys.Run(ctx)
	logoutTokens, err := logouttoken.NewValidator(logouttoken.Config{
		Issuer: c.issuer, ClientID: c.clientID,
		Keys: kcKeys, Replay: redisstore.NewReplay(rdb, prefix),
	})
	if err != nil {
		return err
	}

	// ---- use cases ----
	auth := app.NewAuthService(op, sessions, txs, log, app.AuthConfig{})
	tokens := app.NewTokenSource(sessions, op, locks, log, app.TokenSourceConfig{})
	portal := app.NewPortal(tokens, api, sessions, log)
	opts := []web.Option{web.WithBackchannel(app.NewBackchannel(logoutTokens, sessions, log))}
	if c.adaptive {
		// Shared prefix: one browser is one device for every instance.
		opts = append(opts, web.WithLoginRisk(app.NewLoginRisk(redisstore.NewDevices(rdb, "bff:", 0), log)))
	}
	limit, window, err := ratelimit.ParseRate(c.loginRate)
	if err != nil {
		return err
	}
	loginLimit, err := ratelimit.New(rdb, ratelimit.Config{Prefix: "warden:rl:" + prefix + "login-ip:", Limit: limit, Window: window})
	if err != nil {
		return err
	}
	opts = append(opts, web.WithLoginLimit(loginLimit))

	// ---- HTTP ----
	idp, _ := url.Parse(c.issuer)
	srv, err := web.New(web.Config{
		Title: c.title, BaseURL: c.baseURL,
		CookiePrefix: "__Host-" + c.instance + "-",
		IdPOrigin:    idp.Scheme + "://" + idp.Host,
		IdPs:         parseIdPs(c.idps),
	}, auth, portal, sessions, log, opts...)
	if err != nil {
		return err
	}
	gin.SetMode(gin.ReleaseMode)
	httpSrv := &http.Server{
		Addr: c.addr, Handler: srv.Router(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	log.Info("bff listening", "addr", c.addr, "base_url", c.baseURL, "client_id", c.clientID, "policy_api", c.policyAPIURL)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

// parseIdPs reads "alias:Label,alias2:Label2"; "" or "none" offers none.
func parseIdPs(s string) []web.IdP {
	var out []web.IdP
	if s == "none" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		alias, label, ok := strings.Cut(strings.TrimSpace(part), ":")
		if ok && alias != "" && label != "" {
			out = append(out, web.IdP{Alias: alias, Label: label})
		}
	}
	return out
}

// loadOrCreateKey reads a base64 32-byte AES key, creating one (0600) for
// local dev. Production would fetch it from a secret manager and rotate it.
func loadOrCreateKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
			return nil, err
		}
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
}
