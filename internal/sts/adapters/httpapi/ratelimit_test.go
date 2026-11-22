package httpapi_test

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/ratelimit"
	"github.com/aamirlatif1/warden/internal/sts/adapters/httpapi"
)

// keyedBudget allows n calls per key and records the keys it saw.
type keyedBudget struct {
	mu   sync.Mutex
	n    int
	used map[string]int
	keys []string
}

func newBudget(n int) *keyedBudget { return &keyedBudget{n: n, used: map[string]int{}} }

func (b *keyedBudget) Allow(_ context.Context, key string) (ratelimit.Decision, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys = append(b.keys, key)
	if b.used[key] >= b.n {
		return ratelimit.Decision{RetryAfter: 20e9}, nil
	}
	b.used[key]++
	return ratelimit.Decision{Allowed: true}, nil
}

func limitedRouter(tokens *stubTokens, l httpapi.TokenLimits) http.Handler {
	gin.SetMode(gin.TestMode)
	return httpapi.NewRouter(httpapi.Config{Issuer: "http://localhost:8083"},
		httpapi.Services{Tokens: tokens, Lifecycle: &stubLifecycle{}, Keys: stubKeys{}, Limits: l},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func postFrom(h http.Handler, remote, xff, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", formCT)
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// assertion builds an unsigned compact JWT carrying only iss: the limiter
// keys on the claimed client before any verification.
func assertion(iss string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256"}`)) + "." + enc([]byte(`{"iss":"`+iss+`"}`)) + ".sig"
}

func tokenForm(iss string) string {
	return form("grant_type", "client_credentials",
		"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion", assertion(iss))
}

func TestTokenPerIPLimit(t *testing.T) {
	ip := newBudget(2)
	h := limitedRouter(&stubTokens{}, httpapi.TokenLimits{PerIP: ip})
	for i := range 2 {
		if w := postFrom(h, "192.0.2.1:1000", "", tokenForm("shopr")); w.Code != 200 {
			t.Fatalf("call %d: %d %s", i+1, w.Code, w.Body)
		}
	}
	// Rotating X-Forwarded-For must not buy a fresh budget.
	w := postFrom(h, "192.0.2.1:1000", "198.51.100.9", tokenForm("shopr"))
	if w.Code != 429 || w.Header().Get("Retry-After") != "20" || w.Body.String() != `{"error":"rate_limited"}` {
		t.Fatalf("3rd: %d %q %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
	if w := postFrom(h, "192.0.2.2:1000", "", tokenForm("shopr")); w.Code != 200 {
		t.Fatalf("another IP refused: %d", w.Code)
	}
}

func TestTokenPerClientLimitUsesClaimedClient(t *testing.T) {
	cl := newBudget(1)
	tokens := &stubTokens{}
	h := limitedRouter(tokens, httpapi.TokenLimits{PerClient: cl})

	if w := postFrom(h, "192.0.2.1:1", "", tokenForm("shopr")); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	tokens.got.ClientAssertion = ""
	if w := postFrom(h, "192.0.2.7:1", "", tokenForm("shopr")); w.Code != 429 {
		t.Fatalf("same client from another IP: %d, want 429", w.Code)
	}
	if tokens.got.ClientAssertion != "" {
		t.Fatal("token use case ran for a rate-limited request")
	}
	if w := postFrom(h, "192.0.2.1:1", "", tokenForm("acme")); w.Code != 200 {
		t.Fatalf("other client: %d", w.Code)
	}
	// Explicit client_id wins over the assertion's iss.
	if w := postFrom(h, "192.0.2.1:1", "", tokenForm("other")+"&client_id=nordbank"); w.Code != 200 {
		t.Fatalf("client_id form param: %d", w.Code)
	}
	if got := cl.keys[len(cl.keys)-1]; got != "nordbank" {
		t.Fatalf("keyed on %q, want nordbank", got)
	}
}

func TestTokenPerClientKeyIsBounded(t *testing.T) {
	cl := newBudget(10)
	h := limitedRouter(&stubTokens{}, httpapi.TokenLimits{PerClient: cl})
	postFrom(h, "192.0.2.1:1", "", tokenForm(strings.Repeat("x", 5000)))
	if len(cl.keys) != 1 || len(cl.keys[0]) > 64 {
		t.Fatalf("key length %d, want <= 64", len(cl.keys[0]))
	}
}

func TestTokenUnparseableAssertionSkipsClientRule(t *testing.T) {
	cl := newBudget(0) // would refuse anything it is asked about
	h := limitedRouter(&stubTokens{}, httpapi.TokenLimits{PerClient: cl})
	body := form("grant_type", "client_credentials", "client_assertion", "not-a-jwt")
	if w := postFrom(h, "192.0.2.1:1", "", body); w.Code == 429 || len(cl.keys) != 0 {
		t.Fatalf("got %d, keys %v: no claimed client means no client bucket", w.Code, cl.keys)
	}
}
