// Package introspect is policy-api's RFC 7662 client: for high-risk
// actions the app asks the token's issuer whether it is still active.
// Keycloak tokens go to Keycloak, partner-sts tokens to partner-sts.
package introspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
)

// Endpoint is one issuer's introspection endpoint and policy-api's
// credentials for it (HTTP Basic, client_secret_basic).
type Endpoint struct {
	URL      string
	ClientID string
	Secret   string
}

// Client implements app.Introspector.
type Client struct {
	hc       *http.Client
	byIssuer map[string]Endpoint
}

func New(byIssuer map[string]Endpoint, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Second}
	}
	return &Client{hc: hc, byIssuer: byIssuer}
}

// Active asks the issuer about the token in ctx (authn.WithRawToken). Any
// failure is an error, never "active", so the caller fails closed.
func (c *Client) Active(ctx context.Context, p authn.Principal) (bool, error) {
	raw, ok := authn.RawTokenFrom(ctx)
	if !ok {
		return false, errors.New("introspect: no raw token in context")
	}
	ep, ok := c.byIssuer[p.Issuer]
	if !ok || ep.URL == "" {
		return false, fmt.Errorf("introspect: no endpoint configured for issuer %q", p.Issuer)
	}
	form := url.Values{"token": {raw}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(ep.ClientID), url.QueryEscape(ep.Secret))

	resp, err := c.hc.Do(req)
	if err != nil {
		return false, fmt.Errorf("introspect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("introspect: HTTP %d from %s", resp.StatusCode, ep.URL)
	}
	var body struct {
		Active bool   `json:"active"`
		Sub    string `json:"sub"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return false, fmt.Errorf("introspect: decode: %w", err)
	}
	if body.Active && body.Sub != "" && body.Sub != p.Subject {
		return false, errors.New("introspect: subject mismatch between token and introspection response")
	}
	return body.Active, nil
}
