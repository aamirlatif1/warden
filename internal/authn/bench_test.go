package authn_test

import (
	"context"
	"testing"
)

// BenchmarkValidate measures the hot path with a warm key cache.
// Target (REQUIREMENTS FR-2): < 50 µs/op. Record the number in README.
func BenchmarkValidate(b *testing.B) {
	v := newTestValidator(b)
	ctx := context.Background()

	for _, bc := range []struct {
		name string
		tok  string
	}{
		{"keycloak-RS256", sign(b, kcSpec(b), kcClaims())},
		{"partner-sts-ES256", sign(b, stsSpec(b), stsClaims())},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := v.Validate(ctx, bc.tok); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkValidateParallel(b *testing.B) {
	v := newTestValidator(b)
	tok := sign(b, kcSpec(b), kcClaims())
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := v.Validate(context.Background(), tok); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
