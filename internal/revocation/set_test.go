package revocation

import (
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func TestSet(t *testing.T) {
	now := t0
	s := NewSet(func() time.Time { return now })
	exp := t0.Add(5 * time.Minute).Unix()

	s.Apply(Event{Kind: KindJTI, Issuer: "sts", Value: "j1", ExpiresAt: exp})
	s.Apply(Event{Kind: KindClient, Issuer: "sts", Value: "shopr", NotBefore: t0.Unix(), ExpiresAt: exp})
	s.Apply(Event{Kind: KindJTI, Issuer: "sts", Value: "old", ExpiresAt: t0.Add(-time.Second).Unix()}) // already expired

	cases := []struct {
		name string
		ref  authn.TokenRef
		want bool
	}{
		{"revoked jti", authn.TokenRef{Issuer: "sts", JTI: "j1"}, true},
		{"same jti, other issuer", authn.TokenRef{Issuer: "kc", JTI: "j1"}, false},
		{"other jti", authn.TokenRef{Issuer: "sts", JTI: "j2"}, false},
		{"expired event ignored", authn.TokenRef{Issuer: "sts", JTI: "old"}, false},
		{"client token issued before suspension", authn.TokenRef{Issuer: "sts", JTI: "x", ClientID: "shopr", IssuedAt: t0.Add(-time.Minute)}, true},
		{"client token issued at the cut-off second", authn.TokenRef{Issuer: "sts", JTI: "x", ClientID: "shopr", IssuedAt: t0}, true},
		{"client token issued after resume", authn.TokenRef{Issuer: "sts", JTI: "x", ClientID: "shopr", IssuedAt: t0.Add(time.Second)}, false},
		{"client token without iat (fail closed)", authn.TokenRef{Issuer: "sts", JTI: "x", ClientID: "shopr"}, true},
		{"other client", authn.TokenRef{Issuer: "sts", JTI: "x", ClientID: "acme", IssuedAt: t0.Add(-time.Minute)}, false},
		{"empty jti never matches", authn.TokenRef{Issuer: "sts"}, false},
	}
	for _, tc := range cases {
		if got := s.Revoked(tc.ref); got != tc.want {
			t.Errorf("%s: Revoked = %v, want %v", tc.name, got, tc.want)
		}
	}

	// A later suspension extends the cut-off; an older event does not shrink it.
	s.Apply(Event{Kind: KindClient, Issuer: "sts", Value: "shopr", NotBefore: t0.Add(time.Minute).Unix(), ExpiresAt: exp})
	s.Apply(Event{Kind: KindClient, Issuer: "sts", Value: "shopr", NotBefore: t0.Add(-time.Hour).Unix(), ExpiresAt: exp})
	if !s.Revoked(authn.TokenRef{Issuer: "sts", ClientID: "shopr", IssuedAt: t0.Add(30 * time.Second)}) {
		t.Error("cut-off not extended by the later suspension, or shrunk by the older one")
	}

	// Entries stop applying and are purged after they expire.
	now = t0.Add(6 * time.Minute)
	if s.Revoked(authn.TokenRef{Issuer: "sts", JTI: "j1"}) {
		t.Error("expired entry still applies")
	}
	s.Purge()
	if s.Len() != 0 {
		t.Errorf("Len after purge = %d", s.Len())
	}
}
