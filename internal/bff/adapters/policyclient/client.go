// Package policyclient is the BFF's driven adapter to policy-api's REST API
// (over mTLS in the composition root). It turns an RFC 9470 challenge into
// app.StepUpRequired.
package policyclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/app"
)

type Client struct {
	base string
	hc   *http.Client
}

func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), hc: hc}
}

type policyJSON struct {
	ID               string `json:"id"`
	Product          string `json:"product"`
	Status           string `json:"status"`
	PayoutIBANMasked string `json:"payout_iban_masked"`
}

func (p policyJSON) toApp() app.Policy {
	return app.Policy{ID: p.ID, Product: p.Product, Status: p.Status, PayoutIBANMasked: p.PayoutIBANMasked}
}

func (c *Client) ListPolicies(ctx context.Context, token string) ([]app.Policy, error) {
	var out struct {
		Policies []policyJSON `json:"policies"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/policies", token, nil, &out); err != nil {
		return nil, err
	}
	pols := make([]app.Policy, 0, len(out.Policies))
	for _, p := range out.Policies {
		pols = append(pols, p.toApp())
	}
	return pols, nil
}

func (c *Client) UpdatePayout(ctx context.Context, token, policyID, iban string) (app.Policy, error) {
	var out struct {
		Policy policyJSON `json:"policy"`
	}
	path := "/v1/policies/" + url.PathEscape(policyID) + "/payout-account"
	if err := c.do(ctx, http.MethodPut, path, token, map[string]string{"iban": iban}, &out); err != nil {
		return app.Policy{}, err
	}
	return out.Policy.toApp(), nil
}

func (c *Client) do(ctx context.Context, method, path, token string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("policy-api: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	case http.StatusUnauthorized:
		if su := ParseStepUp(resp.Header.Get("WWW-Authenticate")); su != nil {
			return su
		}
		return app.ErrAPIUnauthorized
	case http.StatusForbidden:
		return app.ErrAPIForbidden
	case http.StatusNotFound:
		return app.ErrAPINotFound
	case http.StatusBadRequest:
		return app.ErrAPIInvalid
	default:
		return fmt.Errorf("policy-api: HTTP %d", resp.StatusCode)
	}
}

var authParam = regexp.MustCompile(`([a-zA-Z_]+)=(?:"([^"]*)"|([^\s,]+))`)

// ParseStepUp reads an RFC 9470 challenge:
//
//	Bearer error="insufficient_user_authentication", acr_values="gold", max_age=300
//
// It returns nil for any other challenge.
func ParseStepUp(header string) *app.StepUpRequired {
	scheme, params, _ := strings.Cut(strings.TrimSpace(header), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return nil
	}
	kv := map[string]string{}
	for _, m := range authParam.FindAllStringSubmatch(params, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		kv[strings.ToLower(m[1])] = v
	}
	if kv["error"] != "insufficient_user_authentication" {
		return nil
	}
	su := &app.StepUpRequired{ACR: kv["acr_values"]}
	if n, err := strconv.Atoi(kv["max_age"]); err == nil && n > 0 {
		su.MaxAge = time.Duration(n) * time.Second
	}
	return su
}

var _ app.PolicyAPI = (*Client)(nil)
