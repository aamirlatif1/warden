package authz_test

import (
	"slices"
	"testing"

	"github.com/aamirlatif1/warden/internal/authz"
)

func TestAssessLogin(t *testing.T) {
	cases := []struct {
		name string
		in   authz.LoginSignals
		want []authz.RiskReason
	}{
		{"new device, no country", authz.LoginSignals{}, []authz.RiskReason{authz.RiskNewDevice}},
		{"new device, country given", authz.LoginSignals{Country: "DE"}, []authz.RiskReason{authz.RiskNewDevice}},
		{"known device, same country", authz.LoginSignals{DeviceKnown: true, Country: "DE", LastCountry: "DE"}, nil},
		{"known device, new country", authz.LoginSignals{DeviceKnown: true, Country: "BR", LastCountry: "DE"}, []authz.RiskReason{authz.RiskNewCountry}},
		{"known device, header absent now", authz.LoginSignals{DeviceKnown: true, LastCountry: "DE"}, nil},
		{"known device, first country seen", authz.LoginSignals{DeviceKnown: true, Country: "DE"}, nil},
		{"known device, no signals", authz.LoginSignals{DeviceKnown: true}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := authz.AssessLogin(tc.in)
			if !slices.Equal(got.Reasons, tc.want) {
				t.Fatalf("reasons = %v, want %v", got.Reasons, tc.want)
			}
			if got.StepUp != (len(tc.want) > 0) {
				t.Fatalf("StepUp = %v with reasons %v", got.StepUp, got.Reasons)
			}
		})
	}
}
