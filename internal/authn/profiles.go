package authn

import "github.com/go-jose/go-jose/v4"

// HAND-BUILD (S2). Signatures are the contract the tests use; the struct
// fields are a suggestion — change them freely, tests only call the
// constructors below.

// ProfileKind selects the claim mapping and audience rule.
type ProfileKind int

const (
	KindKeycloak   ProfileKind = iota + 1 // aud rule; roles from realm_access.roles; ClientID from azp
	KindPartnerSTS                        // aud rule; typ must be at+jwt; jti required; ClientID from client_id
	KindCognito                           // no aud: client_id allow-list + token_use=access; roles from cognito:groups
)

// IssuerProfile is everything policy-api trusts about one issuer. It is
// selected by an exact match of the token's iss against Issuer.
type IssuerProfile struct {
	Name      string                  // metric label: "keycloak", "partner-sts", "cognito"
	Kind      ProfileKind             //
	Issuer    string                  // exact iss value
	Alg       jose.SignatureAlgorithm // the one alg this issuer may use
	Audience  string                  // required aud entry (Keycloak, STS)
	ClientIDs []string                // allowed client_id (Cognito)
	Type      string                  // required typ header, "" = not checked
}

// KeycloakProfile trusts RS256 access tokens from a Keycloak realm whose
// aud contains audience.
func KeycloakProfile(issuer, audience string) IssuerProfile {
	panic("TODO(S2 hand-build): KeycloakProfile")
}

// PartnerSTSProfile trusts ES256 at+jwt access tokens from partner-sts
// whose aud contains audience.
func PartnerSTSProfile(issuer, audience string) IssuerProfile {
	panic("TODO(S2 hand-build): PartnerSTSProfile")
}

// CognitoProfile trusts RS256 Cognito access tokens (token_use=access)
// whose client_id is one of clientIDs. Cognito access tokens carry no aud.
func CognitoProfile(issuer string, clientIDs ...string) IssuerProfile {
	panic("TODO(S2 hand-build): CognitoProfile")
}
