package ginlimit_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/ratelimit"
	"github.com/aamirlatif1/warden/internal/ratelimit/ginlimit"
)

type fakeLimiter struct {
	allow map[string]int // remaining budget per key
	err   error
	keys  []string
	retry time.Duration
}

func (f *fakeLimiter) Allow(_ context.Context, key string) (ratelimit.Decision, error) {
	f.keys = append(f.keys, key)
	if f.err != nil {
		return ratelimit.Decision{}, f.err
	}
	if f.allow[key] > 0 {
		f.allow[key]--
		return ratelimit.Decision{Allowed: true, Remaining: f.allow[key]}, nil
	}
	return ratelimit.Decision{RetryAfter: f.retry}, nil
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func engine(mw gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.POST("/x", mw, func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func do(r http.Handler, remote, xff string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAllowsThenRefusesWithRetryAfter(t *testing.T) {
	l := &fakeLimiter{allow: map[string]int{"10.0.0.1": 1}, retry: 1500 * time.Millisecond}
	r := engine(ginlimit.Middleware(quiet, nil, ginlimit.Rule{Name: "ip", Limiter: l, Key: ginlimit.ByIP}))

	if w := do(r, "10.0.0.1:1234", ""); w.Code != http.StatusOK {
		t.Fatalf("first: %d", w.Code)
	}
	w := do(r, "10.0.0.1:1234", "")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second: %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2 (1.5 s rounded up)", got)
	}
	if w.Body.String() != `{"error":"rate_limited"}` {
		t.Fatalf("body = %s", w.Body)
	}
}

func TestRetryAfterIsAtLeastOneSecond(t *testing.T) {
	l := &fakeLimiter{allow: map[string]int{}, retry: 0}
	r := engine(ginlimit.Middleware(quiet, nil, ginlimit.Rule{Name: "ip", Limiter: l, Key: ginlimit.ByIP}))
	if got := do(r, "10.0.0.1:1", "").Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestSpoofedForwardedForIsIgnored(t *testing.T) {
	l := &fakeLimiter{allow: map[string]int{"10.0.0.1": 1}}
	r := engine(ginlimit.Middleware(quiet, nil, ginlimit.Rule{Name: "ip", Limiter: l, Key: ginlimit.ByIP}))
	do(r, "10.0.0.1:1", "203.0.113.7")
	if w := do(r, "10.0.0.1:1", "203.0.113.8"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("new X-Forwarded-For value got a fresh budget: %d", w.Code)
	}
	for _, k := range l.keys {
		if k != "10.0.0.1" {
			t.Fatalf("keyed on %q, want the peer address", k)
		}
	}
}

func TestLimiterErrorFailsClosed(t *testing.T) {
	l := &fakeLimiter{err: errors.New("redis down")}
	r := engine(ginlimit.Middleware(quiet, nil, ginlimit.Rule{Name: "ip", Limiter: l, Key: ginlimit.ByIP}))
	w := do(r, "10.0.0.1:1", "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("got %d (Retry-After %q), want 503 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestEmptyKeySkipsRuleAndRulesRunInOrder(t *testing.T) {
	skip := &fakeLimiter{allow: map[string]int{}}
	first := &fakeLimiter{allow: map[string]int{}} // refuses
	second := &fakeLimiter{allow: map[string]int{"k": 5}}
	r := engine(ginlimit.Middleware(quiet, nil,
		ginlimit.Rule{Name: "skip", Limiter: skip, Key: func(*gin.Context) string { return "" }},
		ginlimit.Rule{Name: "first", Limiter: first, Key: func(*gin.Context) string { return "k" }},
		ginlimit.Rule{Name: "second", Limiter: second, Key: func(*gin.Context) string { return "k" }},
	))
	if w := do(r, "10.0.0.1:1", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 from the first rule", w.Code)
	}
	if len(skip.keys) != 0 {
		t.Fatal("rule with an empty key was consulted")
	}
	if len(second.keys) != 0 {
		t.Fatal("second rule spent budget after the first refused")
	}
}

func TestCustomRejecter(t *testing.T) {
	l := &fakeLimiter{allow: map[string]int{}}
	html := func(c *gin.Context, status int) { c.Data(status, "text/html", []byte("slow down")); c.Abort() }
	r := engine(ginlimit.Middleware(quiet, html, ginlimit.Rule{Name: "ip", Limiter: l, Key: ginlimit.ByIP}))
	w := do(r, "10.0.0.1:1", "")
	if w.Code != http.StatusTooManyRequests || w.Body.String() != "slow down" {
		t.Fatalf("got %d %q", w.Code, w.Body)
	}
}
