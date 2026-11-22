// Package grpcauth is the gRPC driving adapter for authn.
package grpcauth

import (
	"context"

	"google.golang.org/grpc"

	"github.com/aamirlatif1/warden/internal/authn"
)

// TokenValidator is the part of *authn.Validator this adapter needs.
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (authn.Principal, error)
}

// HAND-BUILD (S2). UnaryServerInterceptor authenticates every unary call:
//
//   - Exactly one "authorization" metadata value "Bearer <token>" (scheme
//     case-insensitive). Missing, repeated, or another scheme →
//     codes.Unauthenticated.
//   - Invalid token → codes.Unauthenticated; the message may carry the
//     reason but never the token.
//   - Success → handler runs with authn.WithPrincipal(ctx, p).
func UnaryServerInterceptor(v TokenValidator) grpc.UnaryServerInterceptor {
	panic("TODO(S2 hand-build): grpcauth.UnaryServerInterceptor")
}
