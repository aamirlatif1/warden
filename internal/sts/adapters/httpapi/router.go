// Package httpapi is partner-sts's HTTP (Gin) driving adapter: the token
// endpoint, discovery and JWKS.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/sts/app"
)

type TokenService interface {
	Token(ctx context.Context, req app.TokenRequest) (app.TokenResponse, error)
}

type KeySet interface {
	JWKS() jose.JSONWebKeySet
}

type LifecycleService interface {
	Revoke(ctx context.Context, req app.RevokeRequest) error
	Introspect(ctx context.Context, raw string) (app.Introspection, error)
}

// Services are the use cases behind the public router.
type Services struct {
	Tokens    TokenService
	Lifecycle LifecycleService
	Keys      KeySet
}

type Config struct {
	Issuer        string // e.g. http://localhost:8083
	JWKSMaxAge    int    // seconds, Cache-Control on /jwks.json (rotation lead time is 2x this)
	MaxBodyBytes  int64  // token request body cap
	SupportedAlgs []string
	// IntrospectionClients are the resource servers allowed to call
	// /introspect, as client_id → secret (HTTP Basic). Empty disables it.
	IntrospectionClients map[string]string
}

// Metadata is the RFC 8414 / OIDC discovery document.
type Metadata struct {
	Issuer                       string   `json:"issuer"`
	TokenEndpoint                string   `json:"token_endpoint"`
	JWKSURI                      string   `json:"jwks_uri"`
	GrantTypesSupported          []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods     []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgs []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpoint           string   `json:"revocation_endpoint"`
	IntrospectionEndpoint        string   `json:"introspection_endpoint"`
	ResponseTypesSupported       []string `json:"response_types_supported"`
}

func NewRouter(cfg Config, svc Services, log *slog.Logger) *gin.Engine {
	tokens, keys := svc.Tokens, svc.Keys
	if cfg.JWKSMaxAge == 0 {
		cfg.JWKSMaxAge = 300
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 16 << 10
	}
	if len(cfg.SupportedAlgs) == 0 {
		cfg.SupportedAlgs = []string{"ES256"}
	}
	meta := Metadata{
		Issuer:                       cfg.Issuer,
		TokenEndpoint:                cfg.Issuer + "/token",
		JWKSURI:                      cfg.Issuer + "/jwks.json",
		GrantTypesSupported:          []string{"client_credentials"},
		TokenEndpointAuthMethods:     []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgs: cfg.SupportedAlgs,
		RevocationEndpoint:           cfg.Issuer + "/revoke",
		IntrospectionEndpoint:        cfg.Issuer + "/introspect",
		// Required by RFC 8414 but meaningless here: no authorization
		// endpoint, so no response types. "token" would advertise implicit.
		ResponseTypesSupported: []string{},
	}

	r := gin.New()
	r.Use(gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, rec any) {
		log.ErrorContext(c.Request.Context(), "panic in handler", "path", c.FullPath(), "panic", rec)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": app.ErrServerError})
	}))

	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	discovery := func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=3600")
		c.JSON(http.StatusOK, meta)
	}
	r.GET("/.well-known/openid-configuration", discovery)
	r.GET("/.well-known/oauth-authorization-server", discovery)

	r.GET("/jwks.json", func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age="+strconv.Itoa(cfg.JWKSMaxAge))
		c.JSON(http.StatusOK, keys.JWKS())
	})

	r.POST("/token", func(c *gin.Context) {
		// RFC 6749 §5.1: token responses must not be cached.
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		if !readForm(c, cfg.MaxBodyBytes, "grant_type", "client_assertion", "client_assertion_type", "client_id", "scope") {
			return
		}
		resp, err := tokens.Token(c.Request.Context(), app.TokenRequest{
			GrantType:           c.PostForm("grant_type"),
			ClientAssertionType: c.PostForm("client_assertion_type"),
			ClientAssertion:     c.PostForm("client_assertion"),
			ClientID:            c.PostForm("client_id"),
			Scope:               c.PostForm("scope"),
		})
		if err != nil {
			oauthError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token": resp.AccessToken,
			"token_type":   resp.TokenType,
			"expires_in":   resp.ExpiresIn,
			"scope":        resp.Scope,
		})
	})
	// RFC 7009. Always 200 for a well-formed, authenticated request, even
	// for an unknown token.
	r.POST("/revoke", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if !readForm(c, cfg.MaxBodyBytes, "token", "token_type_hint", "client_assertion", "client_assertion_type", "client_id") {
			return
		}
		err := svc.Lifecycle.Revoke(c.Request.Context(), app.RevokeRequest{
			ClientAssertionType: c.PostForm("client_assertion_type"),
			ClientAssertion:     c.PostForm("client_assertion"),
			ClientID:            c.PostForm("client_id"),
			Token:               c.PostForm("token"),
		})
		if err != nil {
			oauthError(c, err)
			return
		}
		c.Status(http.StatusOK)
	})

	// RFC 7662, for resource servers (HTTP Basic).
	r.POST("/introspect", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if !resourceServerAuth(c, cfg.IntrospectionClients) {
			c.Header("WWW-Authenticate", `Basic realm="warden-introspection"`)
			c.JSON(http.StatusUnauthorized, gin.H{"error": app.ErrInvalidClient})
			return
		}
		if !readForm(c, cfg.MaxBodyBytes, "token", "token_type_hint") {
			return
		}
		resp, err := svc.Lifecycle.Introspect(c.Request.Context(), c.PostForm("token"))
		if err != nil {
			log.ErrorContext(c.Request.Context(), "introspection failed", "err", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": app.ErrServerError})
			return
		}
		c.JSON(http.StatusOK, resp)
	})
	return r
}

// readForm caps the body, requires a form content type, parses the body
// (never the query string: RFC 6749 §2.3.1) and rejects repeated
// parameters (RFC 6749 §3.2). It writes the error response itself.
func readForm(c *gin.Context, maxBytes int64, single ...string) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
	if c.ContentType() != "application/x-www-form-urlencoded" {
		oauthError(c, &app.OAuthError{Code: app.ErrInvalidRequest, Description: "body must be application/x-www-form-urlencoded"})
		return false
	}
	if err := c.Request.ParseForm(); err != nil {
		oauthError(c, &app.OAuthError{Code: app.ErrInvalidRequest, Description: "malformed form body"})
		return false
	}
	for _, p := range single {
		if len(c.Request.PostForm[p]) > 1 {
			oauthError(c, &app.OAuthError{Code: app.ErrInvalidRequest, Description: "repeated parameter: " + p})
			return false
		}
	}
	return true
}

// resourceServerAuth checks HTTP Basic credentials in constant time
// (comparing SHA-256 digests, so lengths don't leak either).
func resourceServerAuth(c *gin.Context, clients map[string]string) bool {
	id, secret, ok := c.Request.BasicAuth()
	if !ok || len(clients) == 0 {
		return false
	}
	want, known := clients[id]
	a, b := sha256.Sum256([]byte(secret)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1 && known && want != ""
}

// oauthError writes an RFC 6749 §5.2 error. invalid_client is 400 here,
// not 401: the client authenticated with an assertion in the body, not an
// Authorization header, so there is no WWW-Authenticate scheme to send.
func oauthError(c *gin.Context, err error) {
	var oe *app.OAuthError
	if !errors.As(err, &oe) {
		oe = &app.OAuthError{Code: app.ErrServerError, Description: "temporarily unavailable"}
	}
	status := http.StatusBadRequest
	switch oe.Code {
	case app.ErrServerError:
		status = http.StatusInternalServerError
	case app.ErrUnauthorizedClient:
		status = http.StatusForbidden
	}
	c.JSON(status, gin.H{"error": oe.Code, "error_description": oe.Description})
}
