// Package httpapi is partner-sts's HTTP (Gin) driving adapter: the token
// endpoint, discovery and JWKS.
package httpapi

import (
	"context"
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

type Config struct {
	Issuer        string // e.g. http://localhost:8083
	JWKSMaxAge    int    // seconds, Cache-Control on /jwks.json (rotation lead time is 2x this)
	MaxBodyBytes  int64  // token request body cap
	SupportedAlgs []string
}

// Metadata is the RFC 8414 / OIDC discovery document.
type Metadata struct {
	Issuer                       string   `json:"issuer"`
	TokenEndpoint                string   `json:"token_endpoint"`
	JWKSURI                      string   `json:"jwks_uri"`
	GrantTypesSupported          []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods     []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgs []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ResponseTypesSupported       []string `json:"response_types_supported"`
}

func NewRouter(cfg Config, tokens TokenService, keys KeySet, log *slog.Logger) *gin.Engine {
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
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, cfg.MaxBodyBytes)

		if ct := c.ContentType(); ct != "application/x-www-form-urlencoded" {
			oauthError(c, &app.OAuthError{Code: app.ErrInvalidRequest, Description: "body must be application/x-www-form-urlencoded"})
			return
		}
		if err := c.Request.ParseForm(); err != nil {
			oauthError(c, &app.OAuthError{Code: app.ErrInvalidRequest, Description: "malformed form body"})
			return
		}
		// Credentials only from the body, never the query string (RFC 6749
		// §2.3.1): PostForm reads the body only. Repeated parameters are
		// ambiguous and rejected (RFC 6749 §3.2).
		for _, p := range []string{"grant_type", "client_assertion", "client_assertion_type", "client_id", "scope"} {
			if len(c.Request.PostForm[p]) > 1 {
				oauthError(c, &app.OAuthError{Code: app.ErrInvalidRequest, Description: "repeated parameter: " + p})
				return
			}
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
	return r
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
	if oe.Code == app.ErrServerError {
		status = http.StatusInternalServerError
	}
	c.JSON(status, gin.H{"error": oe.Code, "error_description": oe.Description})
}
