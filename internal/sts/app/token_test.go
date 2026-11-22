package app_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/aamirlatif1/warden/internal/issuer"
	"github.com/aamirlatif1/warden/internal/sts/app"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

type fakeVerifier struct {
	assertion clientauth.Assertion
	err       error
}

func (f fakeVerifier) Verify(context.Context, string) (clientauth.Assertion, error) {
	return f.assertion, f.err
}

type fakePartners map[string]domain.Partner

func (f fakePartners) Partner(_ context.Context, id string) (domain.Partner, error) {
	if id == "boom" {
		return domain.Partner{}, errors.New("db down")
	}
	p, ok := f[id]
	if !ok {
		return domain.Partner{}, domain.ErrNotFound
	}
	return p, nil
}

type fakeMinter struct {
	got issuer.Grant
	err error
}

func (f *fakeMinter) Mint(_ context.Context, g issuer.Grant) (issuer.Token, error) {
	f.got = g
	return issuer.Token{Value: "minted.token.sig", JTI: "at-1", KeyID: "k1"}, f.err
}

var partners = fakePartners{
	"shopr": {ClientID: "shopr", PartnerID: "shopr", Status: domain.PartnerActive, AllowedScopes: []string{"quotes:read", "quotes:write"}},
	"gone":  {ClientID: "gone", PartnerID: "gone", Status: domain.PartnerSuspended, AllowedScopes: []string{"quotes:write"}},
}

func good(scope string) app.TokenRequest {
	return app.TokenRequest{GrantType: "client_credentials", ClientAssertionType: clientauth.AssertionType, ClientAssertion: "a.b.c", Scope: scope}
}

func run(t *testing.T, v fakeVerifier, m *fakeMinter, req app.TokenRequest) (app.TokenResponse, error, string) {
	t.Helper()
	logs := &bytes.Buffer{}
	svc := app.NewTokenService(v, partners, m, slog.New(slog.NewJSONHandler(logs, nil)))
	resp, err := svc.Token(context.Background(), req)
	return resp, err, logs.String()
}

func code(err error) string {
	var oe *app.OAuthError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return "<not an OAuthError: " + err.Error() + ">"
}

func TestTokenIssued(t *testing.T) {
	m := &fakeMinter{}
	v := fakeVerifier{assertion: clientauth.Assertion{ClientID: "shopr", JTI: "as-1"}}
	resp, err, logs := run(t, v, m, good("quotes:write admin"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken != "minted.token.sig" || resp.TokenType != "Bearer" || resp.ExpiresIn != 300 || resp.Scope != "quotes:write" {
		t.Fatalf("resp = %+v", resp)
	}
	if m.got.ClientID != "shopr" || m.got.PartnerID != "shopr" || strings.Join(m.got.Scopes, " ") != "quotes:write" {
		t.Fatalf("grant = %+v (scope must be downscoped)", m.got)
	}
	if !strings.Contains(logs, `"msg":"token issued"`) || strings.Contains(logs, "minted.token.sig") {
		t.Fatalf("issuance log wrong or leaks the token:\n%s", logs)
	}
}

func TestEmptyScopeGetsAllAllowed(t *testing.T) {
	m := &fakeMinter{}
	resp, err, _ := run(t, fakeVerifier{assertion: clientauth.Assertion{ClientID: "shopr"}}, m, good(""))
	if err != nil || resp.Scope != "quotes:read quotes:write" {
		t.Fatalf("resp = %+v, %v", resp, err)
	}
}

func TestTokenErrors(t *testing.T) {
	ok := fakeVerifier{assertion: clientauth.Assertion{ClientID: "shopr"}}
	cases := []struct {
		name string
		v    fakeVerifier
		m    *fakeMinter
		req  app.TokenRequest
		want string
	}{
		{"wrong grant type", ok, &fakeMinter{}, func() app.TokenRequest { r := good(""); r.GrantType = "password"; return r }(), app.ErrUnsupportedGrantType},
		{"no assertion", ok, &fakeMinter{}, func() app.TokenRequest { r := good(""); r.ClientAssertion = ""; return r }(), app.ErrInvalidClient},
		{"wrong assertion type", ok, &fakeMinter{}, func() app.TokenRequest { r := good(""); r.ClientAssertionType = "urn:x"; return r }(), app.ErrInvalidClient},
		{"D12 replayed assertion", fakeVerifier{err: clientauth.Reject(clientauth.ReasonJTIReplayed, "shopr", nil)}, &fakeMinter{}, good(""), app.ErrInvalidClient},
		{"bad signature", fakeVerifier{err: clientauth.Reject(clientauth.ReasonSignatureInvalid, "shopr", nil)}, &fakeMinter{}, good(""), app.ErrInvalidClient},
		{"replay store down", fakeVerifier{err: clientauth.Reject(clientauth.ReasonReplayUnavailable, "shopr", nil)}, &fakeMinter{}, good(""), app.ErrServerError},
		{"client_id param differs from assertion", ok, &fakeMinter{}, func() app.TokenRequest { r := good(""); r.ClientID = "acme"; return r }(), app.ErrInvalidClient},
		{"partner not registered", fakeVerifier{assertion: clientauth.Assertion{ClientID: "ghost"}}, &fakeMinter{}, good(""), app.ErrInvalidClient},
		{"partner suspended", fakeVerifier{assertion: clientauth.Assertion{ClientID: "gone"}}, &fakeMinter{}, good(""), app.ErrInvalidClient},
		{"partner store down", fakeVerifier{assertion: clientauth.Assertion{ClientID: "boom"}}, &fakeMinter{}, good(""), app.ErrServerError},
		{"no allowed scope", ok, &fakeMinter{}, good("policies:admin"), app.ErrInvalidScope},
		{"minting fails", ok, &fakeMinter{err: errors.New("kms throttled")}, good(""), app.ErrServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err, logs := run(t, tc.v, tc.m, tc.req)
			if code(err) != tc.want {
				t.Fatalf("code = %s, want %s", code(err), tc.want)
			}
			var oe *app.OAuthError
			errors.As(err, &oe)
			for _, leak := range []string{"jti_replayed", "signature", "suspended", "kms", "db down"} {
				if strings.Contains(oe.Description, leak) {
					t.Fatalf("error_description leaks %q: %q", leak, oe.Description)
				}
			}
			if tc.name == "D12 replayed assertion" && !strings.Contains(logs, `"reason":"jti_replayed"`) {
				t.Fatalf("reason not logged:\n%s", logs)
			}
		})
	}
}
