package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/policy/adapters/httpapi"
	"github.com/aamirlatif1/warden/internal/policy/adapters/memstore"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

// fakeAuth stands in for ginauth: header "X-Test-Sub" becomes the principal,
// no header → 401.
func fakeAuth(c *gin.Context) {
	sub := c.GetHeader("X-Test-Sub")
	if sub == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Request = c.Request.WithContext(authn.WithPrincipal(c.Request.Context(), authn.Principal{Subject: sub}))
	c.Next()
}

func newRouter() http.Handler {
	gin.SetMode(gin.TestMode)
	st := memstore.New()
	st.AddPolicy(domain.Policy{ID: "p1", HolderSubject: "anna", Product: "travel", Status: "active"})
	st.AddPolicy(domain.Policy{ID: "p2", HolderSubject: "bob", Product: "phone", Status: "active"})
	st.AddClaim(domain.Claim{ID: "c1", PolicyID: "p1", Amount: domain.Money{AmountMinor: 100, Currency: "EUR"}, Status: domain.ClaimOpen})
	return httpapi.NewRouter(app.NewService(st, st, st), fakeAuth, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(t *testing.T, h http.Handler, method, path, sub, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if sub != "" {
		req.Header.Set("X-Test-Sub", sub)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestRoutes(t *testing.T) {
	cases := []struct {
		name, method, path, sub, body string
		want                          int
	}{
		{"healthz needs no token", "GET", "/healthz", "", "", 200},
		{"v1 needs a token", "GET", "/v1/policies", "", "", 401},
		{"list policies", "GET", "/v1/policies", "anna", "", 200},
		{"get policy", "GET", "/v1/policies/p1", "anna", "", 200},
		{"get unknown policy", "GET", "/v1/policies/nope", "anna", "", 404},
		{"create quote", "POST", "/v1/quotes", "shopr", `{"partner_id":"shopr","product":"phone","insured_value":{"amount_minor":80000,"currency":"EUR"}}`, 201},
		{"create quote bad JSON", "POST", "/v1/quotes", "shopr", `{`, 400},
		{"create quote invalid value", "POST", "/v1/quotes", "shopr", `{"partner_id":"shopr","product":"phone","insured_value":{"amount_minor":-1,"currency":"EUR"}}`, 400},
		{"update payout account", "PUT", "/v1/policies/p1/payout-account", "anna", `{"iban":"DE89370400440532013000"}`, 200},
		{"update payout bad IBAN", "PUT", "/v1/policies/p1/payout-account", "anna", `{"iban":"DE00"}`, 400},
		{"approve claim", "POST", "/v1/claims/c1:approve", "ben", "", 200},
		{"unknown claim action", "POST", "/v1/claims/c1:reject", "ben", "", 404},
		{"claim action without id", "POST", "/v1/claims/:approve", "ben", "", 404},
	}
	h := newRouter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, h, tc.method, tc.path, tc.sub, tc.body)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d, body %s", w.Code, tc.want, w.Body)
			}
		})
	}
}

func TestListPoliciesReturnsOnlyCallersPolicies(t *testing.T) {
	w := do(t, newRouter(), "GET", "/v1/policies", "bob", "")
	var resp struct {
		Policies []struct {
			ID string `json:"id"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Policies) != 1 || resp.Policies[0].ID != "p2" {
		t.Fatalf("got %+v", resp.Policies)
	}
}

func TestPayoutIBANIsMaskedInResponses(t *testing.T) {
	w := do(t, newRouter(), "PUT", "/v1/policies/p1/payout-account", "anna", `{"iban":"DE89370400440532013000"}`)
	if strings.Contains(w.Body.String(), "DE8937040044") {
		t.Fatalf("full IBAN in response: %s", w.Body)
	}
}
