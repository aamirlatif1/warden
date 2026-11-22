package issuer_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/issuer"
)

func TestInspect(t *testing.T) {
	ctx := context.Background()
	m := newMinter(t, localSigner(t))
	tok, err := m.Mint(ctx, issuer.Grant{ClientID: "shopr", PartnerID: "shopr", Scopes: []string{"quotes:write"}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.Inspect(tok.Value)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientID != "shopr" || c.PartnerID != "shopr" || c.JTI != tok.JTI || !c.ExpiresAt.Equal(now.Add(5*time.Minute)) || !c.IssuedAt.Equal(now) {
		t.Fatalf("claims = %+v", c)
	}

	other := newMinter(t, localSigner(t))
	foreign, _ := other.Mint(ctx, issuer.Grant{ClientID: "shopr", PartnerID: "shopr"})
	parts := strings.Split(tok.Value, ".")
	bad := map[string]string{
		"signed by another key": foreign.Value,
		"tampered payload":      parts[0] + "." + strings.Split(foreign.Value, ".")[1] + "." + parts[2],
		"garbage":               "a.b.c",
		"empty":                 "",
		"oversized":             strings.Repeat("a", 10<<10),
	}
	for name, raw := range bad {
		if _, err := m.Inspect(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
