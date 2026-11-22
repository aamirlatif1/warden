// Command sts-seed registers a partner in partner-sts's registry
// (idempotent). Its public JWK Set comes from a file, for example the one
// `partnercli keygen` writes.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aamirlatif1/warden/internal/sts/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

func main() {
	clientID := flag.String("client-id", "", "OAuth client_id (required)")
	partnerID := flag.String("partner-id", "", "tenant written into tokens as partner_id (required)")
	name := flag.String("name", "", "display name")
	scopes := flag.String("scopes", "quotes:read quotes:write", "allowed scopes, space-separated")
	jwksFile := flag.String("jwks", "", "path to the partner's public JWK Set (required)")
	status := flag.String("status", "active", "active | suspended")
	dsn := flag.String("database-url", envOr("WARDEN_DATABASE_URL", "postgres://warden:warden@localhost:5434/warden?sslmode=disable"), "Postgres DSN")
	flag.Parse()

	if err := run(*clientID, *partnerID, *name, *scopes, *jwksFile, *status, *dsn); err != nil {
		fmt.Fprintln(os.Stderr, "sts-seed:", err)
		os.Exit(1)
	}
}

func run(clientID, partnerID, name, scopes, jwksFile, status, dsn string) error {
	if clientID == "" || partnerID == "" || jwksFile == "" {
		return fmt.Errorf("-client-id, -partner-id and -jwks are required")
	}
	if status != string(domain.PartnerActive) && status != string(domain.PartnerSuspended) {
		return fmt.Errorf("-status must be active or suspended")
	}
	jwks, err := os.ReadFile(jwksFile)
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := pgstore.Open(dsn)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	if name == "" {
		name = clientID
	}
	p := domain.Partner{
		ClientID: clientID, PartnerID: partnerID, Name: name, Status: domain.PartnerStatus(status),
		AllowedScopes: strings.Fields(scopes), JWKS: jwks,
	}
	if err := st.UpsertPartner(ctx, p); err != nil {
		return err
	}
	fmt.Printf("registered partner %s (partner_id=%s, scopes=%q, status=%s)\n", clientID, partnerID, scopes, status)
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
