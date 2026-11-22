package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/issuer/keyring"
	"github.com/aamirlatif1/warden/internal/sts/adapters/httpapi"
	"github.com/aamirlatif1/warden/internal/sts/app"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

type stubTokens struct {
	got app.TokenRequest
	err error
}

func (s *stubTokens) Token(_ context.Context, r app.TokenRequest) (app.TokenResponse, error) {
	s.got = r
	return app.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 300, Scope: "quotes:write"}, s.err
}

type stubKeys struct{}

func (stubKeys) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
}

type stubLifecycle struct {
	revoked    string
	revokeErr  error
	introspect app.Introspection
	introErr   error
}

func (s *stubLifecycle) Revoke(_ context.Context, r app.RevokeRequest) error {
	s.revoked = r.Token
	return s.revokeErr
}

func (s *stubLifecycle) Introspect(context.Context, string) (app.Introspection, error) {
	return s.introspect, s.introErr
}

func newRouterWith(tokens *stubTokens, lc *stubLifecycle) http.Handler {
	gin.SetMode(gin.TestMode)
	return httpapi.NewRouter(
		httpapi.Config{Issuer: "http://localhost:8083", JWKSMaxAge: 300, IntrospectionClients: map[string]string{"policy-api": "s3cret"}},
		httpapi.Services{Tokens: tokens, Lifecycle: lc, Keys: stubKeys{}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func newRouter(tokens *stubTokens) http.Handler { return newRouterWith(tokens, &stubLifecycle{}) }

func form(kv ...string) string {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v.Encode()
}

func post(h http.Handler, path, ctype, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

const formCT = "application/x-www-form-urlencoded"

func TestDiscovery(t *testing.T) {
	h := newRouter(&stubTokens{})
	for _, p := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || w.Code != 200 {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body)
		}
		if m["issuer"] != "http://localhost:8083" || m["token_endpoint"] != "http://localhost:8083/token" || m["jwks_uri"] != "http://localhost:8083/jwks.json" {
			t.Fatalf("%s: %v", p, m)
		}
		if am, _ := m["token_endpoint_auth_methods_supported"].([]any); len(am) != 1 || am[0] != "private_key_jwt" {
			t.Fatalf("auth methods = %v", m["token_endpoint_auth_methods_supported"])
		}
	}
}

func TestJWKSIsCacheable(t *testing.T) {
	w := httptest.NewRecorder()
	newRouter(&stubTokens{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "public, max-age=300" || !strings.Contains(w.Body.String(), `"keys"`) {
		t.Fatalf("%d %q %s", w.Code, w.Header().Get("Cache-Control"), w.Body)
	}
}

func TestTokenSuccess(t *testing.T) {
	st := &stubTokens{}
	w := post(newRouter(st), "/token", formCT, form(
		"grant_type", "client_credentials",
		"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion", "a.b.c", "client_id", "shopr", "scope", "quotes:write"))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatal("token response is cacheable")
	}
	if st.got.ClientAssertion != "a.b.c" || st.got.ClientID != "shopr" || st.got.Scope != "quotes:write" || st.got.GrantType != "client_credentials" {
		t.Fatalf("request = %+v", st.got)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["access_token"] != "at" || body["token_type"] != "Bearer" || body["expires_in"] != float64(300) {
		t.Fatalf("body = %v", body)
	}
}

func TestTokenRequestErrors(t *testing.T) {
	cases := []struct {
		name, path, ctype, body string
		err                     error
		status                  int
		code                    string
	}{
		{"JSON body", "/token", "application/json", `{"grant_type":"client_credentials"}`, nil, 400, "invalid_request"},
		{"assertion in the query string only", "/token?client_assertion=a.b.c", formCT, form("grant_type", "client_credentials"), &app.OAuthError{Code: "invalid_client", Description: "x"}, 400, "invalid_client"},
		{"repeated parameter", "/token", formCT, form("grant_type", "client_credentials", "grant_type", "password"), nil, 400, "invalid_request"},
		{"body too large", "/token", formCT, form("client_assertion", strings.Repeat("a", 20<<10)), nil, 400, "invalid_request"},
		{"invalid_client is 400", "/token", formCT, form("grant_type", "client_credentials"), &app.OAuthError{Code: "invalid_client", Description: "client authentication failed"}, 400, "invalid_client"},
		{"server_error is 500", "/token", formCT, form("grant_type", "client_credentials"), &app.OAuthError{Code: "server_error", Description: "temporarily unavailable"}, 500, "server_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &stubTokens{err: tc.err}
			w := post(newRouter(st), tc.path, tc.ctype, tc.body)
			var body map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v, want %d %s", w.Code, body, tc.status, tc.code)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("error response is cacheable")
			}
			if tc.name == "assertion in the query string only" && st.got.ClientAssertion != "" {
				t.Fatal("assertion was read from the query string")
			}
		})
	}
}

func TestRevokeEndpoint(t *testing.T) {
	lc := &stubLifecycle{}
	h := newRouterWith(&stubTokens{}, lc)
	w := post(h, "/revoke", formCT, form("token", "tok", "client_assertion_type", "x", "client_assertion", "a"))
	if w.Code != 200 || lc.revoked != "tok" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %q", w.Code, lc.revoked)
	}
	lc.revokeErr = &app.OAuthError{Code: app.ErrUnauthorizedClient, Description: "x"}
	if w := post(h, "/revoke", formCT, form("token", "tok")); w.Code != 403 {
		t.Fatalf("unauthorized_client: %d", w.Code)
	}
}

func TestIntrospectEndpoint(t *testing.T) {
	lc := &stubLifecycle{introspect: app.Introspection{Active: true, ClientID: "shopr"}}
	h := newRouterWith(&stubTokens{}, lc)
	do := func(user, pass string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form("token", "tok")))
		req.Header.Set("Content-Type", formCT)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := do("policy-api", "s3cret"); w.Code != 200 || !strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatalf("authorized: %d %s", w.Code, w.Body)
	}
	for name, creds := range map[string][2]string{"no auth": {"", ""}, "wrong secret": {"policy-api", "nope"}, "unknown client": {"shopr", "s3cret"}} {
		if w := do(creds[0], creds[1]); w.Code != 401 || strings.Contains(w.Body.String(), "active") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	lc.introErr = errors.New("redis down")
	if w := do("policy-api", "s3cret"); w.Code != 503 {
		t.Fatalf("store down: %d (must not answer active=false)", w.Code)
	}
}

type stubAdmin struct{ rotateErr, partnerErr error }

func (s stubAdmin) Rotate(context.Context) (keyring.KeyInfo, error) {
	return keyring.KeyInfo{KID: "k2", State: keyring.StateNext}, s.rotateErr
}
func (stubAdmin) Keys() []keyring.KeyInfo {
	return []keyring.KeyInfo{{KID: "k1", State: keyring.StateCurrent}}
}
func (s stubAdmin) SuspendPartner(context.Context, string) error { return s.partnerErr }
func (s stubAdmin) ResumePartner(context.Context, string) error  { return s.partnerErr }

func TestAdminRouter(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	req := func(h http.Handler, method, path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w.Code
	}
	h := httpapi.NewAdminRouter(stubAdmin{}, quiet)
	if c := req(h, "GET", "/admin/keys"); c != 200 {
		t.Errorf("keys: %d", c)
	}
	if c := req(h, "POST", "/admin/rotate"); c != 202 {
		t.Errorf("rotate: %d", c)
	}
	if c := req(h, "POST", "/admin/partners/shopr/suspend"); c != 204 {
		t.Errorf("suspend: %d", c)
	}
	if c := req(httpapi.NewAdminRouter(stubAdmin{rotateErr: keyring.ErrRotationInProgress}, quiet), "POST", "/admin/rotate"); c != 409 {
		t.Errorf("rotate in progress: %d", c)
	}
	if c := req(httpapi.NewAdminRouter(stubAdmin{partnerErr: domain.ErrNotFound}, quiet), "POST", "/admin/partners/x/resume"); c != 404 {
		t.Errorf("unknown partner: %d", c)
	}
}
