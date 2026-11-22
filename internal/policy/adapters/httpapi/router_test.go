package httpapi_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authz"
	"github.com/aamirlatif1/warden/internal/policy/adapters/httpapi"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

// stubService records calls and returns err (or canned data).
type stubService struct {
	err   error
	calls []string
	seen  authn.Principal
}

func (s *stubService) rec(name string, p authn.Principal, args ...string) {
	s.seen = p
	s.calls = append(s.calls, strings.Join(append([]string{name}, args...), " "))
}

func (s *stubService) CreateQuote(_ context.Context, p authn.Principal, in app.CreateQuoteInput) (domain.Quote, error) {
	s.rec("CreateQuote", p, in.PartnerID)
	return domain.Quote{ID: "q1", PartnerID: in.PartnerID, Premium: domain.Money{AmountMinor: 1, Currency: "EUR"}}, s.err
}
func (s *stubService) ListPolicies(_ context.Context, p authn.Principal) ([]domain.Policy, error) {
	s.rec("ListPolicies", p)
	return []domain.Policy{{ID: "p1", PayoutIBAN: "DE89370400440532013000"}}, s.err
}
func (s *stubService) GetPolicy(_ context.Context, p authn.Principal, id string) (domain.Policy, error) {
	s.rec("GetPolicy", p, id)
	return domain.Policy{ID: id}, s.err
}
func (s *stubService) UpdatePayoutAccount(_ context.Context, p authn.Principal, id, iban string) (domain.Policy, error) {
	s.rec("UpdatePayoutAccount", p, id, iban)
	return domain.Policy{ID: id, PayoutIBAN: iban}, s.err
}
func (s *stubService) ApproveClaim(_ context.Context, p authn.Principal, id string) (domain.Claim, error) {
	s.rec("ApproveClaim", p, id)
	return domain.Claim{ID: id, Status: domain.ClaimApproved}, s.err
}

// fakeAuth stands in for ginauth: header X-Test-Sub becomes the principal.
// With X-Test-Skip-Principal it lets the request through with none, to
// prove the router does not trust a misbehaving middleware.
func fakeAuth(c *gin.Context) {
	if c.GetHeader("X-Test-Skip-Principal") != "" {
		c.Next()
		return
	}
	sub := c.GetHeader("X-Test-Sub")
	if sub == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Request = c.Request.WithContext(authn.WithPrincipal(c.Request.Context(), authn.Principal{Subject: sub}))
	c.Next()
}

func newRouter(svc *stubService) http.Handler {
	gin.SetMode(gin.TestMode)
	return httpapi.NewRouter(svc, fakeAuth, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(h http.Handler, method, path, sub, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if sub != "" {
		req.Header.Set("X-Test-Sub", sub)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestRoutesReachTheRightUseCase(t *testing.T) {
	cases := []struct {
		method, path, body string
		want               int
		call               string
	}{
		{"POST", "/v1/quotes", `{"partner_id":"shopr","product":"phone","insured_value":{"amount_minor":1,"currency":"EUR"}}`, 201, "CreateQuote shopr"},
		{"GET", "/v1/policies", "", 200, "ListPolicies"},
		{"GET", "/v1/policies/p1", "", 200, "GetPolicy p1"},
		{"PUT", "/v1/policies/p1/payout-account", `{"iban":"DE89"}`, 200, "UpdatePayoutAccount p1 DE89"},
		{"POST", "/v1/claims/c1:approve", "", 200, "ApproveClaim c1"},
		{"POST", "/v1/claims/c1:reject", "", 404, ""},
		{"POST", "/v1/claims/:approve", "", 404, ""},
		{"POST", "/v1/quotes", `{`, 400, ""},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			svc := &stubService{}
			w := do(newRouter(svc), tc.method, tc.path, "sub-anna", tc.body)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", w.Code, tc.want, w.Body)
			}
			if tc.call == "" {
				if len(svc.calls) != 0 {
					t.Fatalf("use case called: %v", svc.calls)
				}
				return
			}
			if len(svc.calls) != 1 || svc.calls[0] != tc.call {
				t.Fatalf("calls = %q, want [%q]", svc.calls, tc.call)
			}
			if svc.seen.Subject != "sub-anna" {
				t.Fatalf("principal not passed to the use case: %+v", svc.seen)
			}
		})
	}
}

func TestAuthGates(t *testing.T) {
	svc := &stubService{}
	h := newRouter(svc)
	if w := do(h, "GET", "/healthz", "", ""); w.Code != 200 {
		t.Errorf("healthz = %d", w.Code)
	}
	if w := do(h, "GET", "/v1/policies", "", ""); w.Code != 401 {
		t.Errorf("no token = %d", w.Code)
	}
	if w := do(h, "GET", "/v1/policies", "", "", "X-Test-Skip-Principal", "1"); w.Code != 401 {
		t.Errorf("middleware set no principal: status = %d, want 401", w.Code)
	}
	if len(svc.calls) != 0 {
		t.Errorf("use case reached without a principal: %v", svc.calls)
	}
}

func TestErrorMapping(t *testing.T) {
	stepUp := &authz.StepUpError{Reason: authz.ReasonACRTooLow, ACR: "gold", MaxAge: 5 * time.Minute}
	cases := []struct {
		name    string
		err     error
		status  int
		www     string // substring of WWW-Authenticate, "" = header absent
		bodyHas string
	}{
		{"deny → 403 with reason", &authz.DeniedError{Reason: authz.ReasonNotOwner}, 403, "", `"reason":"not_owner"`},
		{"step-up → 401 RFC 9470", stepUp, 401, `error="insufficient_user_authentication", error_description="acr_too_low", acr_values="gold", max_age=300`, "insufficient_user_authentication"},
		{"inactive token → 401 invalid_token", app.ErrTokenInactive, 401, `error="invalid_token"`, "token inactive"},
		{"dependency down → 503", app.ErrUnavailable, 503, "", "unavailable"},
		{"not found → 404", domain.ErrNotFound, 404, "", "not found"},
		{"invalid → 400", fmt.Errorf("iban: %w", domain.ErrInvalidArgument), 400, "", "invalid"},
		{"conflict → 409", domain.ErrConflict, 409, "", "conflict"},
		{"other → 500, no detail", errors.New("pq: connection refused at 10.0.0.5"), 500, "", "internal error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := do(newRouter(&stubService{err: tc.err}), "PUT", "/v1/policies/p1/payout-account", "sub-anna", `{"iban":"x"}`)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			www := w.Header().Get("WWW-Authenticate")
			if (tc.www == "") != (www == "") || !strings.Contains(www, tc.www) {
				t.Fatalf("WWW-Authenticate = %q, want %q", www, tc.www)
			}
			if !strings.Contains(w.Body.String(), tc.bodyHas) {
				t.Fatalf("body = %s, want it to contain %q", w.Body, tc.bodyHas)
			}
			if strings.Contains(w.Body.String(), "10.0.0.5") {
				t.Fatal("internal error detail leaked")
			}
		})
	}
}

func TestPayoutIBANIsMaskedInResponses(t *testing.T) {
	w := do(newRouter(&stubService{}), "GET", "/v1/policies", "sub-anna", "")
	if strings.Contains(w.Body.String(), "DE8937040044") || !strings.Contains(w.Body.String(), "3000") {
		t.Fatalf("IBAN not masked: %s", w.Body)
	}
}
