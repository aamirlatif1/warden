package domain

import (
	"slices"
	"testing"
)

func TestDownscope(t *testing.T) {
	p := Partner{AllowedScopes: []string{"quotes:read", "quotes:write"}}
	cases := []struct {
		req, want []string
	}{
		{nil, []string{"quotes:read", "quotes:write"}},
		{[]string{"quotes:write"}, []string{"quotes:write"}},
		{[]string{"quotes:write", "policies:admin"}, []string{"quotes:write"}},
		{[]string{"policies:admin"}, nil},
		{[]string{"QUOTES:WRITE"}, nil},
	}
	for _, tc := range cases {
		if got := p.Downscope(tc.req); !slices.Equal(got, tc.want) {
			t.Errorf("Downscope(%v) = %v, want %v", tc.req, got, tc.want)
		}
	}
}
