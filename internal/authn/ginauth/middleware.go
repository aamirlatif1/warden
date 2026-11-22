// Package ginauth is the HTTP driving adapter for authn.
package ginauth

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/authn"
)

// TokenValidator is the part of *authn.Validator this adapter needs.
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (authn.Principal, error)
}

// HAND-BUILD (S2). Middleware authenticates the request (RFC 6750):
//
//   - Authorization: Bearer <token>, scheme case-insensitive.
//   - No credentials → 401, WWW-Authenticate: Bearer (no error= attribute).
//   - Wrong scheme / invalid token → 401, WWW-Authenticate: Bearer
//     error="invalid_token". Never echo the token in the body or headers.
//   - Success → principal stored with authn.WithPrincipal on
//     c.Request.Context(), then c.Next().
func Middleware(v TokenValidator) gin.HandlerFunc {
	panic("TODO(S2 hand-build): ginauth.Middleware")
}
