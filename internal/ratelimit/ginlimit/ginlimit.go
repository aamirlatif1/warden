// Package ginlimit applies ratelimit decisions to Gin routes: 429 with
// Retry-After when a rule's budget is spent, 503 when the limiter itself
// fails (fail closed: every route it guards needs Redis anyway).
package ginlimit

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/ratelimit"
)

// Limiter is what a rule needs from ratelimit.Limiter.
type Limiter interface {
	Allow(ctx context.Context, key string) (ratelimit.Decision, error)
}

// Rule is one budget. Key returns the bucket for this request; "" skips
// the rule (for example no client_id to key on).
type Rule struct {
	Name    string // stable label for logs and, in S8, ratelimit_rejected_total{route}
	Limiter Limiter
	Key     func(c *gin.Context) string
}

// Rejecter writes the response for a refused request. Retry-After is
// already set.
type Rejecter func(c *gin.Context, status int)

// JSON is the default Rejecter: {"error":"rate_limited"} or
// {"error":"temporarily_unavailable"}.
func JSON(c *gin.Context, status int) {
	if status == http.StatusTooManyRequests {
		c.AbortWithStatusJSON(status, gin.H{"error": "rate_limited"})
		return
	}
	c.AbortWithStatusJSON(status, gin.H{"error": "temporarily_unavailable"})
}

// ByIP keys on the client IP. It is only as good as the engine's trusted
// proxy list: routers call SetTrustedProxies(nil), so X-Forwarded-For from
// a client is ignored and this is the TCP peer address.
func ByIP(c *gin.Context) string { return c.ClientIP() }

// Middleware enforces rules in order and stops at the first refusal.
func Middleware(log *slog.Logger, reject Rejecter, rules ...Rule) gin.HandlerFunc {
	if reject == nil {
		reject = JSON
	}
	return func(c *gin.Context) {
		for _, r := range rules {
			if !Check(c, log, reject, r) {
				return
			}
		}
		c.Next()
	}
}

// Check applies one rule inside a handler (for keys only known after the
// body is parsed). It reports whether the request may continue; when it
// returns false the response has been written and the context aborted.
func Check(c *gin.Context, log *slog.Logger, reject Rejecter, r Rule) bool {
	if reject == nil {
		reject = JSON
	}
	key := r.Key(c)
	if key == "" {
		return true
	}
	ctx := c.Request.Context()
	d, err := r.Limiter.Allow(ctx, key)
	if err != nil {
		log.ErrorContext(ctx, "rate limiter unavailable", "rule", r.Name, "err", err)
		c.Header("Retry-After", "1")
		reject(c, http.StatusServiceUnavailable)
		return false
	}
	if d.Allowed {
		return true
	}
	// The key may be an IP address or a client_id: log the rule, not the key.
	log.WarnContext(ctx, "rate limited", "rule", r.Name, "path", c.FullPath(), "retry_after_ms", d.RetryAfter.Milliseconds())
	c.Header("Retry-After", strconv.Itoa(retryAfterSeconds(d)))
	reject(c, http.StatusTooManyRequests)
	return false
}

// retryAfterSeconds rounds up: telling a client "0" invites an immediate
// retry that is still refused.
func retryAfterSeconds(d ratelimit.Decision) int {
	s := int(math.Ceil(d.RetryAfter.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}
