package grpcauth_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authn/grpcauth"
)

const goodToken = "good.token.sig"

type fakeValidator struct{ calls int }

func (f *fakeValidator) Validate(_ context.Context, raw string) (authn.Principal, error) {
	f.calls++
	if raw != goodToken {
		return authn.Principal{}, authn.Reject(authn.ReasonExpired, "keycloak", nil)
	}
	return authn.Principal{Subject: "shopr"}, nil
}

func TestUnaryServerInterceptor(t *testing.T) {
	cases := []struct {
		name     string
		md       metadata.MD // nil = no incoming metadata at all
		wantCode codes.Code
	}{
		{"no metadata", nil, codes.Unauthenticated},
		{"no authorization key", metadata.Pairs("x-other", "1"), codes.Unauthenticated},
		{"valid token", metadata.Pairs("authorization", "Bearer "+goodToken), codes.OK},
		{"scheme is case-insensitive", metadata.Pairs("authorization", "BEARER "+goodToken), codes.OK},
		{"invalid token", metadata.Pairs("authorization", "Bearer forged.token.sig"), codes.Unauthenticated},
		{"Basic scheme", metadata.Pairs("authorization", "Basic dXNlcjpwYXNz"), codes.Unauthenticated},
		{"two authorization values", metadata.Pairs("authorization", "Bearer "+goodToken, "authorization", "Bearer forged.token.sig"), codes.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fv := &fakeValidator{}
			icpt := grpcauth.UnaryServerInterceptor(fv)

			ctx := context.Background()
			if tc.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tc.md)
			}
			var handlerCalled bool
			var seen authn.Principal
			handler := func(ctx context.Context, _ any) (any, error) {
				handlerCalled = true
				seen, _ = authn.FromContext(ctx)
				return "ok", nil
			}
			_, err := icpt(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/warden.policy.v1.PolicyService/GetPolicy"}, handler)

			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("code = %v, want %v (err %v)", got, tc.wantCode, err)
			}
			if handlerCalled != (tc.wantCode == codes.OK) {
				t.Fatalf("handler called = %v", handlerCalled)
			}
			if tc.wantCode == codes.OK && seen.Subject != "shopr" {
				t.Fatalf("principal not in handler context: %+v", seen)
			}
			if err != nil && strings.Contains(status.Convert(err).Message(), "forged.token.sig") {
				t.Fatalf("status message leaks the token: %v", err)
			}
		})
	}
}
