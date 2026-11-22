// Package oidcclient is the BFF's driven adapter to the OpenID Provider
// (Keycloak): authorization URL, code exchange with PKCE, ID token
// verification, refresh, and RP-initiated logout.
package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/aamirlatif1/warden/internal/bff/app"
)

type Config struct {
	Issuer       string // e.g. http://localhost:8080/realms/insurance
	ClientID     string
	ClientSecret string
	RedirectURL  string   // exact, as registered (open-redirect defence)
	Scopes       []string // default: openid profile
	HTTPClient   *http.Client
}

type Client struct {
	conf       oauth2.Config
	verifier   *oidc.IDTokenVerifier
	clientID   string
	endSession string
	hc         *http.Client
}

// New fetches the provider's discovery document.
func New(ctx context.Context, cfg Config) (*Client, error) {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	ctx = oidc.ClientContext(ctx, hc)
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&meta)
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile"}
	}
	return &Client{
		conf: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
			Endpoint: p.Endpoint(), Scopes: scopes,
		},
		verifier:   p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		clientID:   cfg.ClientID,
		endSession: meta.EndSession,
		hc:         hc,
	}, nil
}

func (c *Client) ctx(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, c.hc)
}

func (c *Client) AuthURL(p app.AuthParams) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", p.Nonce),
		oauth2.SetAuthURLParam("code_challenge", p.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if p.ACRValues != "" {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", p.ACRValues))
	}
	if p.MaxAge > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(p.MaxAge.Seconds()))))
	}
	return c.conf.AuthCodeURL(p.State, opts...)
}

func (c *Client) Exchange(ctx context.Context, code, verifier string) (app.Tokens, error) {
	t, err := c.conf.Exchange(c.ctx(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return app.Tokens{}, sanitize(err)
	}
	return toTokens(t), nil
}

func (c *Client) VerifyIDToken(ctx context.Context, raw string) (app.IDClaims, error) {
	tok, err := c.verifier.Verify(oidc.ClientContext(ctx, c.hc), raw)
	if err != nil {
		return app.IDClaims{}, err
	}
	var cl struct {
		Nonce    string `json:"nonce"`
		ACR      string `json:"acr"`
		SID      string `json:"sid"`
		AZP      string `json:"azp"`
		AuthTime int64  `json:"auth_time"`
		Username string `json:"preferred_username"`
	}
	if err := tok.Claims(&cl); err != nil {
		return app.IDClaims{}, err
	}
	// OIDC Core §3.1.3.7: if azp is present it must be our client_id.
	if cl.AZP != "" && cl.AZP != c.clientID {
		return app.IDClaims{}, errors.New("id token: azp is not this client")
	}
	out := app.IDClaims{Subject: tok.Subject, Username: cl.Username, Nonce: cl.Nonce, ACR: cl.ACR, SID: cl.SID}
	if cl.AuthTime > 0 {
		out.AuthTime = time.Unix(cl.AuthTime, 0)
	}
	return out, nil
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (app.Tokens, error) {
	src := c.conf.TokenSource(c.ctx(ctx), &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Unix(1, 0)})
	t, err := src.Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
			return app.Tokens{}, app.ErrInvalidGrant
		}
		return app.Tokens{}, sanitize(err)
	}
	return toTokens(t), nil
}

func (c *Client) EndSessionURL(idTokenHint, postLogoutRedirect string) string {
	if c.endSession == "" {
		return postLogoutRedirect
	}
	q := url.Values{"client_id": {c.clientID}, "post_logout_redirect_uri": {postLogoutRedirect}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	return c.endSession + "?" + q.Encode()
}

func toTokens(t *oauth2.Token) app.Tokens {
	idt, _ := t.Extra("id_token").(string)
	return app.Tokens{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, IDToken: idt, Expiry: t.Expiry}
}

// sanitize drops the response body from oauth2 errors: it can echo tokens.
func sanitize(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return fmt.Errorf("token endpoint: HTTP %d %s", re.Response.StatusCode, re.ErrorCode)
	}
	return err
}

var _ app.OIDC = (*Client)(nil)
