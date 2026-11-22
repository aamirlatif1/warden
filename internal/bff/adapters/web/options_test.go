package web_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/bff/adapters/web"
	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
	"github.com/aamirlatif1/warden/internal/bff/logouttoken"
	"github.com/aamirlatif1/warden/internal/ratelimit"
)

// ---- fakes for S7 options ----

type fakeBackchannel struct {
	got []string
	err error
}

func (f *fakeBackchannel) Logout(_ context.Context, tok string) error {
	f.got = append(f.got, tok)
	return f.err
}

type fakeRisk struct {
	acr        string
	gotDevice  string
	gotCountry string
	remembered map[string]string
}

func (f *fakeRisk) ACRValues(_ context.Context, dev, country string) string {
	f.gotDevice, f.gotCountry = dev, country
	return f.acr
}

func (f *fakeRisk) Remember(_ context.Context, dev, country string) error {
	if f.remembered == nil {
		f.remembered = map[string]string{}
	}
	f.remembered[dev] = country
	return nil
}

type budget struct{ left int }

func (b *budget) Allow(context.Context, string) (ratelimit.Decision, error) {
	if b.left > 0 {
		b.left--
		return ratelimit.Decision{Allowed: true}, nil
	}
	return ratelimit.Decision{RetryAfter: 30e9}, nil
}

func newServerWith(t *testing.T, a *fakeAuth, opts ...web.Option) http.Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s, err := web.New(web.Config{
		Title: "Portal", BaseURL: base, CookiePrefix: "__Host-portal-", IdPOrigin: "http://localhost:8080",
		IdPs: []web.IdP{{Alias: "nordbank", Label: "Log in with Nordbank"}},
	}, a, &fakePortal{}, fakeSessions{}, slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s.Router()
}

// ---- back-channel logout ----

func TestBackchannelLogout(t *testing.T) {
	cases := []struct {
		name     string
		form     url.Values
		err      error
		want     int
		wantBody string
	}{
		{"valid", url.Values{"logout_token": {"tok"}}, nil, 200, ""},
		{"missing token", url.Values{}, nil, 400, `{"error":"invalid_request"}`},
		{"rejected token", url.Values{"logout_token": {"tok"}}, logouttoken.Reject(logouttoken.ReasonSIDMissing, nil), 400, `{"error":"invalid_request"}`},
		{"replay store down", url.Values{"logout_token": {"tok"}}, logouttoken.Reject(logouttoken.ReasonReplayUnavailable, nil), 503, `{"error":"temporarily_unavailable"}`},
		{"session store down", url.Values{"logout_token": {"tok"}}, errors.New("redis down"), 500, `{"error":"server_error"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBackchannel{err: tc.err}
			w := do(newServerWith(t, &fakeAuth{}, web.WithBackchannel(b)), req{method: "POST", path: "/backchannel-logout", form: tc.form})
			if w.Code != tc.want || w.Body.String() != tc.wantBody {
				t.Fatalf("got %d %q, want %d %q", w.Code, w.Body, tc.want, tc.wantBody)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("response cacheable")
			}
		})
	}
}

func TestBackchannelNeedsNoCSRFButIsOffWithoutOption(t *testing.T) {
	b := &fakeBackchannel{}
	// Keycloak sends no Origin, no cookie and no CSRF token.
	w := do(newServerWith(t, &fakeAuth{}, web.WithBackchannel(b)), req{method: "POST", path: "/backchannel-logout",
		form: url.Values{"logout_token": {"tok"}}, headers: map[string]string{"Origin": "http://keycloak:8080"}})
	if w.Code != 200 || len(b.got) != 1 || b.got[0] != "tok" {
		t.Fatalf("got %d, token %v", w.Code, b.got)
	}
	if w := do(newServerWith(t, &fakeAuth{}), req{method: "POST", path: "/backchannel-logout", form: url.Values{"logout_token": {"tok"}}}); w.Code != 404 {
		t.Fatalf("route served without WithBackchannel: %d", w.Code)
	}
}

func TestBackchannelBodyCap(t *testing.T) {
	b := &fakeBackchannel{}
	w := do(newServerWith(t, &fakeAuth{}, web.WithBackchannel(b)), req{method: "POST", path: "/backchannel-logout",
		form: url.Values{"logout_token": {strings.Repeat("a", 32<<10)}}})
	if w.Code != 400 || len(b.got) != 0 {
		t.Fatalf("oversized body: %d, validator called %d times", w.Code, len(b.got))
	}
}

// ---- brokered login ----

func TestLoginWithIdPHint(t *testing.T) {
	a := &fakeAuth{}
	h := newServerWith(t, a)
	if w := do(h, req{method: "GET", path: "/login?idp=nordbank"}); w.Code != 302 || a.loginReq.IDPHint != "nordbank" {
		t.Fatalf("got %d, hint %q", w.Code, a.loginReq.IDPHint)
	}
	a.loginReq = app.LoginRequest{}
	if w := do(h, req{method: "GET", path: "/login?idp=evilbank"}); w.Code != 400 || a.loginReq.IDPHint != "" {
		t.Fatalf("unknown alias: %d, hint %q", w.Code, a.loginReq.IDPHint)
	}
}

func TestHomeOffersConfiguredIdPs(t *testing.T) {
	w := do(newServerWith(t, &fakeAuth{}), req{method: "GET", path: "/"})
	if !strings.Contains(w.Body.String(), `href="/login?idp=nordbank"`) || !strings.Contains(w.Body.String(), "Log in with Nordbank") {
		t.Fatalf("home page lacks the Nordbank button:\n%s", w.Body)
	}
}

// ---- adaptive step-up ----

func TestAdaptiveLoginIssuesDeviceCookieAndStepsUp(t *testing.T) {
	a := &fakeAuth{}
	r := &fakeRisk{acr: "gold"}
	w := do(newServerWith(t, a, web.WithLoginRisk(r)), req{method: "GET", path: "/login", headers: map[string]string{"X-Country": " de "}})
	if a.loginReq.ACRValues != "gold" {
		t.Fatalf("ACRValues = %q, want gold", a.loginReq.ACRValues)
	}
	c := cookieNamed(w, "__Host-warden-device")
	if c == nil || len(c.Value) < 43 || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
		t.Fatalf("device cookie = %+v", c)
	}
	if r.gotDevice != c.Value || r.gotCountry != "DE" {
		t.Fatalf("risk saw device %q country %q", r.gotDevice, r.gotCountry)
	}
}

func TestAdaptiveLoginReusesDeviceCookie(t *testing.T) {
	a := &fakeAuth{}
	r := &fakeRisk{}
	w := do(newServerWith(t, a, web.WithLoginRisk(r)), req{method: "GET", path: "/login",
		cookies: map[string]string{"__Host-warden-device": "dev-known"}, headers: map[string]string{"X-Country": "Germany"}})
	if cookieNamed(w, "__Host-warden-device") != nil {
		t.Fatal("re-issued an existing device cookie")
	}
	if r.gotDevice != "dev-known" || r.gotCountry != "" || a.loginReq.ACRValues != "" {
		t.Fatalf("device %q country %q acr %q", r.gotDevice, r.gotCountry, a.loginReq.ACRValues)
	}
}

func TestAdaptiveSkippedForBrokeredLogin(t *testing.T) {
	a := &fakeAuth{}
	r := &fakeRisk{acr: "gold"}
	do(newServerWith(t, a, web.WithLoginRisk(r)), req{method: "GET", path: "/login?idp=nordbank"})
	if a.loginReq.ACRValues != "" || r.gotDevice != "" {
		t.Fatalf("brokered login stepped up: acr %q", a.loginReq.ACRValues)
	}
}

func TestCallbackRemembersDevice(t *testing.T) {
	a := &fakeAuth{cbRes: app.CallbackResult{Session: domain.Session{ID: "new-sid", Subject: "sub-anna"}, ReturnTo: "/"}}
	r := &fakeRisk{}
	do(newServerWith(t, a, web.WithLoginRisk(r)), req{method: "GET", path: "/callback?state=s&code=c",
		cookies: map[string]string{"__Host-portal-preauth": "tx", "__Host-warden-device": "dev-1"}, headers: map[string]string{"X-Country": "DE"}})
	if r.remembered["dev-1"] != "DE" {
		t.Fatalf("remembered = %v", r.remembered)
	}

	failed := &fakeAuth{cbErr: &app.LoginError{Reason: app.ReasonStateMismatch}}
	r2 := &fakeRisk{}
	do(newServerWith(t, failed, web.WithLoginRisk(r2)), req{method: "GET", path: "/callback?state=s&code=c",
		cookies: map[string]string{"__Host-portal-preauth": "tx", "__Host-warden-device": "dev-1"}})
	if len(r2.remembered) != 0 {
		t.Fatal("device remembered after a failed login")
	}
}

// ---- /login rate limit ----

func TestLoginRateLimit(t *testing.T) {
	h := newServerWith(t, &fakeAuth{}, web.WithLoginLimit(&budget{left: 2}))
	for i := range 2 {
		if w := do(h, req{method: "GET", path: "/login"}); w.Code != 302 {
			t.Fatalf("login %d: %d", i+1, w.Code)
		}
	}
	w := do(h, req{method: "GET", path: "/login"})
	if w.Code != 429 || w.Header().Get("Retry-After") != "30" || !strings.Contains(w.Body.String(), "Too many attempts") {
		t.Fatalf("3rd login: %d Retry-After %q body %q", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
	if cookieNamed(w, "__Host-portal-preauth") != nil {
		t.Fatal("refused login still created a login transaction")
	}
}
