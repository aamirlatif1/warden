package web_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/bff/adapters/web"
	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

const base = "http://localhost:8082"

// ---- fakes ----

type fakeAuth struct {
	loginReq  app.LoginRequest
	cbReq     app.CallbackRequest
	cbRes     app.CallbackResult
	cbErr     error
	logoutSID string
}

func (f *fakeAuth) Login(_ context.Context, r app.LoginRequest) (string, string, error) {
	f.loginReq = r
	return "tx-123", "http://localhost:8080/auth?state=abc", nil
}
func (f *fakeAuth) Callback(_ context.Context, r app.CallbackRequest) (app.CallbackResult, error) {
	f.cbReq = r
	return f.cbRes, f.cbErr
}
func (f *fakeAuth) Logout(_ context.Context, sid, post string) (string, error) {
	f.logoutSID = sid
	return "http://localhost:8080/logout?post=" + url.QueryEscape(post), nil
}

type fakePortal struct {
	payoutErr error
	payoutSID string
	dashErr   error
}

func (f *fakePortal) Dashboard(_ context.Context, sid string) (app.Dashboard, error) {
	return app.Dashboard{
		Session:  domain.Session{ID: sid, Username: "anna", ACR: "1", AuthTime: time.Now(), CSRFToken: "csrf-good", AccessToken: "eyJ.secret.at"},
		Policies: []app.Policy{{ID: "pol_anna_travel", Product: "travel", Status: "active", PayoutIBANMasked: "******************3000"}},
	}, f.dashErr
}
func (f *fakePortal) UpdatePayout(_ context.Context, sid, id, iban string) (app.Policy, error) {
	f.payoutSID = sid
	return app.Policy{ID: id, PayoutIBANMasked: "****" + iban[len(iban)-4:]}, f.payoutErr
}

type fakeSessions struct{}

func (fakeSessions) Get(_ context.Context, id string) (domain.Session, error) {
	if id != "sid-good" {
		return domain.Session{}, domain.ErrNoSession
	}
	return domain.Session{ID: id, Subject: "sub-anna", CSRFToken: "csrf-good"}, nil
}

func newServer(t *testing.T, a *fakeAuth, p *fakePortal) http.Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s, err := web.New(web.Config{Title: "Portal", BaseURL: base, CookiePrefix: "__Host-portal-", IdPOrigin: "http://localhost:8080"},
		a, p, fakeSessions{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s.Router()
}

type req struct {
	method, path string
	form         url.Values
	cookies      map[string]string
	headers      map[string]string
}

func do(h http.Handler, r req) *httptest.ResponseRecorder {
	var body io.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	}
	hr := httptest.NewRequest(r.method, r.path, body)
	if r.form != nil {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range r.cookies {
		hr.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hr)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ---- tests ----

func TestNewRejectsWeakCookiePrefix(t *testing.T) {
	if _, err := web.New(web.Config{BaseURL: base, CookiePrefix: "sid-"}, &fakeAuth{}, &fakePortal{}, fakeSessions{}, nil); err == nil {
		t.Fatal("accepted a cookie prefix without __Host-")
	}
}

func TestLoginSetsPreauthCookie(t *testing.T) {
	a := &fakeAuth{}
	w := do(newServer(t, a, &fakePortal{}), req{method: "GET", path: "/login?return_to=/x"})
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "http://localhost:8080/auth") {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	c := cookieNamed(w, "__Host-portal-preauth")
	if c == nil || c.Value != "tx-123" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 600 {
		t.Fatalf("preauth cookie = %+v", c)
	}
	if a.loginReq.ReturnTo != "/x" {
		t.Fatalf("return_to not passed: %+v", a.loginReq)
	}
}

func TestCallbackSetsSessionCookie(t *testing.T) {
	a := &fakeAuth{cbRes: app.CallbackResult{Session: domain.Session{ID: "sid-new", Subject: "sub-anna"}, ReturnTo: "/"}}
	w := do(newServer(t, a, &fakePortal{}), req{method: "GET", path: "/callback?state=abc&code=c1",
		cookies: map[string]string{"__Host-portal-preauth": "tx-123", "__Host-portal-sid": "attacker-planted"}})
	if w.Code != 302 {
		t.Fatalf("status %d", w.Code)
	}
	if a.cbReq.TxID != "tx-123" || a.cbReq.State != "abc" || a.cbReq.Code != "c1" || a.cbReq.PriorSID != "attacker-planted" {
		t.Fatalf("callback request = %+v", a.cbReq)
	}
	sid := cookieNamed(w, "__Host-portal-sid")
	if sid == nil || sid.Value != "sid-new" || !sid.Secure || !sid.HttpOnly || sid.SameSite != http.SameSiteLaxMode || sid.Path != "/" || sid.Domain != "" {
		t.Fatalf("sid cookie = %+v", sid)
	}
	if pre := cookieNamed(w, "__Host-portal-preauth"); pre == nil || pre.MaxAge >= 0 {
		t.Fatalf("preauth cookie not cleared: %+v", pre)
	}
}

func TestCallbackFailureIsGeneric(t *testing.T) {
	a := &fakeAuth{cbErr: &app.LoginError{Reason: app.ReasonStateMismatch}}
	w := do(newServer(t, a, &fakePortal{}), req{method: "GET", path: "/callback?state=x&code=y"})
	if w.Code != 400 || cookieNamed(w, "__Host-portal-sid") != nil {
		t.Fatalf("%d, sid cookie set: %v", w.Code, cookieNamed(w, "__Host-portal-sid"))
	}
	if strings.Contains(w.Body.String(), "state_mismatch") {
		t.Fatal("failure reason shown to the user")
	}
}

func TestCallbackReplaysPendingIntent(t *testing.T) {
	a := &fakeAuth{cbRes: app.CallbackResult{
		Session: domain.Session{ID: "sid-gold"},
		Pending: &domain.PendingAction{Kind: domain.PendingUpdatePayout, PolicyID: "pol_anna_travel", IBAN: "DE89370400440532013000"},
	}}
	p := &fakePortal{}
	w := do(newServer(t, a, p), req{method: "GET", path: "/callback?state=a&code=b", cookies: map[string]string{"__Host-portal-preauth": "tx"}})
	if w.Code != 200 || p.payoutSID != "sid-gold" || !strings.Contains(w.Body.String(), "Payout account updated") {
		t.Fatalf("%d, replayed with sid %q: %s", w.Code, p.payoutSID, w.Body)
	}
}

func TestPayoutCSRF(t *testing.T) {
	good := url.Values{"csrf_token": {"csrf-good"}, "policy_id": {"pol_anna_travel"}, "iban": {"DE89370400440532013000"}}
	noToken := url.Values{"policy_id": {"pol_anna_travel"}, "iban": {"DE89370400440532013000"}}
	badToken := url.Values{"csrf_token": {"csrf-evil"}, "policy_id": {"p"}, "iban": {"DE89370400440532013000"}}
	sid := map[string]string{"__Host-portal-sid": "sid-good"}
	cases := []struct {
		name    string
		form    url.Values
		cookies map[string]string
		headers map[string]string
		want    int
	}{
		{"valid", good, sid, map[string]string{"Origin": base}, 200},
		{"valid, no Origin header", good, sid, nil, 200},
		{"D9 no CSRF token", noToken, sid, map[string]string{"Origin": base}, 403},
		{"D9 wrong CSRF token", badToken, sid, map[string]string{"Origin": base}, 403},
		{"D9 foreign Origin", good, sid, map[string]string{"Origin": "https://evil.example"}, 403},
		{"D9 Origin of another local app (claims-app)", good, sid, map[string]string{"Origin": "http://localhost:8084"}, 403},
		{"D9 foreign Referer, no Origin", good, sid, map[string]string{"Referer": "https://evil.example/page"}, 403},
		{"no session", good, nil, map[string]string{"Origin": base}, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &fakePortal{}
			w := do(newServer(t, &fakeAuth{}, p), req{method: "POST", path: "/payout", form: tc.form, cookies: tc.cookies, headers: tc.headers})
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d", w.Code, tc.want)
			}
			if tc.want == 403 && p.payoutSID != "" {
				t.Fatal("use case ran despite CSRF failure")
			}
		})
	}
}

func TestPayoutStepUpRedirects(t *testing.T) {
	a := &fakeAuth{}
	p := &fakePortal{payoutErr: &app.StepUpNeeded{Login: app.LoginRequest{ACRValues: "gold", MaxAge: 5 * time.Minute,
		Pending: &domain.PendingAction{Kind: domain.PendingUpdatePayout, PolicyID: "p1", IBAN: "DE89370400440532013000"}}}}
	w := do(newServer(t, a, p), req{method: "POST", path: "/payout",
		form:    url.Values{"csrf_token": {"csrf-good"}, "policy_id": {"p1"}, "iban": {"DE89370400440532013000"}},
		cookies: map[string]string{"__Host-portal-sid": "sid-good"}, headers: map[string]string{"Origin": base}})
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "http://localhost:8080/auth") {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	if a.loginReq.ACRValues != "gold" || a.loginReq.Pending == nil {
		t.Fatalf("login request = %+v", a.loginReq)
	}
	if cookieNamed(w, "__Host-portal-preauth") == nil {
		t.Fatal("no preauth cookie for the step-up login")
	}
}

func TestPayoutErrors(t *testing.T) {
	cases := map[error]int{
		app.ErrAPIInvalid:   400,
		app.ErrAPIForbidden: 403,
		app.ErrSessionEnded: 401,
		errors.New("boom"):  502,
	}
	for e, want := range cases {
		p := &fakePortal{payoutErr: e}
		w := do(newServer(t, &fakeAuth{}, p), req{method: "POST", path: "/payout",
			form:    url.Values{"csrf_token": {"csrf-good"}, "policy_id": {"p1"}, "iban": {"DE89370400440532013000"}},
			cookies: map[string]string{"__Host-portal-sid": "sid-good"}})
		if w.Code != want {
			t.Errorf("%v: status %d, want %d", e, w.Code, want)
		}
	}
}

func TestLogout(t *testing.T) {
	a := &fakeAuth{}
	w := do(newServer(t, a, &fakePortal{}), req{method: "POST", path: "/logout",
		form: url.Values{"csrf_token": {"csrf-good"}}, cookies: map[string]string{"__Host-portal-sid": "sid-good"}})
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "http://localhost:8080/logout") || a.logoutSID != "sid-good" {
		t.Fatalf("%d %s sid %q", w.Code, w.Header().Get("Location"), a.logoutSID)
	}
	if c := cookieNamed(w, "__Host-portal-sid"); c == nil || c.MaxAge >= 0 {
		t.Fatal("sid cookie not cleared")
	}
	// CSRF on logout too: a cross-site POST must not log the user out.
	w = do(newServer(t, a, &fakePortal{}), req{method: "POST", path: "/logout",
		form: url.Values{}, cookies: map[string]string{"__Host-portal-sid": "sid-good"}, headers: map[string]string{"Origin": "https://evil.example"}})
	if w.Code != 403 {
		t.Fatalf("forced logout: %d", w.Code)
	}
}

func TestPagesAndHeaders(t *testing.T) {
	h := newServer(t, &fakeAuth{}, &fakePortal{})

	w := do(h, req{method: "GET", path: "/"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `href="/login"`) {
		t.Fatalf("landing: %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "form-action 'self' http://localhost:8080") ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers: %v", w.Header())
	}

	w = do(h, req{method: "GET", path: "/", cookies: map[string]string{"__Host-portal-sid": "sid-good"}})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "pol_anna_travel") || !strings.Contains(body, `name="csrf_token" value="csrf-good"`) {
		t.Fatalf("dashboard: %d\n%s", w.Code, body)
	}
	if strings.Contains(body, "eyJ") {
		t.Fatal("access token rendered into the page")
	}

	p := &fakePortal{dashErr: domain.ErrNoSession}
	w = do(newServer(t, &fakeAuth{}, p), req{method: "GET", path: "/", cookies: map[string]string{"__Host-portal-sid": "expired"}})
	if c := cookieNamed(w, "__Host-portal-sid"); w.Code != 200 || c == nil || c.MaxAge >= 0 {
		t.Fatal("expired session cookie not cleared")
	}
}
