package authn

import (
	"context"
	"slices"
	"time"
)

// Principal is the caller after authentication, normalised across issuers.
// Fields that an issuer does not provide are left at their zero value.
type Principal struct {
	Subject   string    // sub
	Issuer    string    // iss, exactly as in the token
	ClientID  string    // azp (Keycloak) or client_id (partner-sts, Cognito)
	PartnerID string    // partner_id, the tenant
	Roles     []string  // Keycloak realm_access.roles, Cognito cognito:groups
	Scopes    []string  // scope, split on spaces
	ACR       string    // acr, e.g. "gold"; empty for client credentials
	AuthTime  time.Time // auth_time; zero when absent
	TokenID   string    // jti
	ExpiresAt time.Time // exp
}

// HasRole reports whether the principal holds role r.
func (p Principal) HasRole(r string) bool { return slices.Contains(p.Roles, r) }

// HasScope reports whether the token was granted scope s.
func (p Principal) HasScope(s string) bool { return slices.Contains(p.Scopes, s) }

type principalKey struct{}

// WithPrincipal returns a copy of ctx that carries p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the principal stored by WithPrincipal, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

type rawTokenKey struct{}

// WithRawToken stores the validated bearer token. The authn adapters call
// it after a successful Validate, because online introspection (RFC 7662)
// needs the token itself. Never log what RawTokenFrom returns.
func WithRawToken(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, rawTokenKey{}, raw)
}

// RawTokenFrom returns the token stored by WithRawToken.
func RawTokenFrom(ctx context.Context) (string, bool) {
	raw, ok := ctx.Value(rawTokenKey{}).(string)
	return raw, ok && raw != ""
}
