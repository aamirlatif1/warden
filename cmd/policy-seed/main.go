// Command policy-seed loads synthetic demo data into policy-api's database.
// It is idempotent: re-running resets the demo rows (claims back to open).
//
// Policy ownership is by Keycloak sub (a UUID Keycloak assigns), so the
// Makefile reads the seed users' IDs from Tofu outputs and passes them in.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/aamirlatif1/warden/internal/policy/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "policy-seed:", err)
		os.Exit(1)
	}
}

func run() error {
	annaSub := flag.String("anna-sub", "", "Keycloak sub of anna (required)")
	bobSub := flag.String("bob-sub", "", "Keycloak sub of bob (required)")
	benSub := flag.String("ben-sub", "", "Keycloak sub of underwriter ben (optional until LDAP federation)")
	dsn := flag.String("database-url", envOr("WARDEN_DATABASE_URL", "postgres://warden:warden@localhost:5434/warden?sslmode=disable"), "Postgres DSN")
	flag.Parse()

	for name, v := range map[string]string{"anna-sub": *annaSub, "bob-sub": *bobSub} {
		if !uuidRE.MatchString(v) {
			return fmt.Errorf("-%s must be a Keycloak user ID (UUID), got %q; run make infra first", name, v)
		}
	}
	if *benSub != "" && !uuidRE.MatchString(*benSub) {
		return errors.New("-ben-sub must be a UUID")
	}

	ctx := context.Background()
	st, err := pgstore.Open(*dsn)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	eur := func(euros int64) domain.Money { return domain.Money{AmountMinor: euros * 100, Currency: "EUR"} }
	policies := []domain.Policy{
		{ID: "pol_anna_travel", HolderSubject: *annaSub, Product: "travel", Status: "active", PayoutIBAN: "DE89370400440532013000"},
		{ID: "pol_bob_phone", HolderSubject: *bobSub, Product: "phone", Status: "active", PayoutIBAN: "GB82WEST12345698765432"},
	}
	claims := []domain.Claim{
		{ID: "clm_anna_small", PolicyID: "pol_anna_travel", Amount: eur(500), Status: domain.ClaimOpen},    // within limit
		{ID: "clm_anna_large", PolicyID: "pol_anna_travel", Amount: eur(15_000), Status: domain.ClaimOpen}, // > 10 000 €: introspection
		{ID: "clm_bob_huge", PolicyID: "pol_bob_phone", Amount: eur(25_000), Status: domain.ClaimOpen},     // over ben's limit
	}

	return st.InTx(ctx, func(ctx context.Context) error {
		for _, p := range policies {
			if err := st.UpsertPolicy(ctx, p); err != nil {
				return fmt.Errorf("policy %s: %w", p.ID, err)
			}
		}
		for _, c := range claims {
			if err := st.UpsertClaim(ctx, c); err != nil {
				return fmt.Errorf("claim %s: %w", c.ID, err)
			}
		}
		if *benSub != "" {
			if err := st.UpsertApprovalLimit(ctx, *benSub, eur(20_000).AmountMinor); err != nil {
				return fmt.Errorf("approval limit: %w", err)
			}
		}
		fmt.Printf("seeded %d policies, %d claims", len(policies), len(claims))
		if *benSub != "" {
			fmt.Print(", approval limit 20 000 EUR for ben")
		}
		fmt.Println()
		return nil
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
