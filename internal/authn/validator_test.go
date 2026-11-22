package authn_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/authn"
)

// TestValidateRejects is the "list every token that would wrongly pass"
// table. Each case has exactly one fault, so the expected reason is
// unambiguous regardless of check order.
func TestValidateRejects(t *testing.T) {
	ks := k(t)
	v := newTestValidator(t)

	attackerSrv, attackerHits := attackerJWKS(t)

	cases := []struct {
		name string
		tok  func(t *testing.T) string
		want authn.Reason
	}{
		// ---- malformed input ----
		{"empty string", func(t *testing.T) string { return "" }, authn.ReasonMalformed},
		{"two segments", func(t *testing.T) string { return "eyJhbGciOiJSUzI1NiJ9.e30" }, authn.ReasonMalformed},
		{"garbage base64", func(t *testing.T) string { return "!!!.@@@.###" }, authn.ReasonMalformed},
		{"JWE (five segments)", func(t *testing.T) string { return "a.b.c.d.e" }, authn.ReasonMalformed},
		{"header is not JSON", func(t *testing.T) string {
			return b64.EncodeToString([]byte("nope")) + "." + b64.EncodeToString([]byte("{}")) + ".c2ln"
		}, authn.ReasonMalformed},
		{"oversized token (32 KiB claim)", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "pad", strings.Repeat("a", 32<<10)))
		}, authn.ReasonMalformed},
		{"exp is not a number", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "exp", "tomorrow"))
		}, authn.ReasonMalformed},

		// ---- alg pinning (D1, D2) ----
		{"alg none", func(t *testing.T) string {
			return unsigned(t, map[string]any{"alg": "none", "typ": "JWT", "kid": kcKid}, kcClaims())
		}, authn.ReasonAlgNotAllowed},
		{"alg None (case variant)", func(t *testing.T) string {
			return unsigned(t, map[string]any{"alg": "None", "kid": kcKid}, kcClaims())
		}, authn.ReasonAlgNotAllowed},
		{"alg confusion: HS256 keyed with the RSA public key PEM", func(t *testing.T) string {
			return sign(t, spec{alg: jose.HS256, key: rsaPublicPEM(t, ks.kc), kid: kcKid, typ: "JWT"}, kcClaims())
		}, authn.ReasonAlgNotAllowed},
		{"HS512 on the STS issuer", func(t *testing.T) string {
			return sign(t, spec{alg: jose.HS512, key: make([]byte, 64), kid: stsKid, typ: "at+jwt"}, stsClaims())
		}, authn.ReasonAlgNotAllowed},
		{"ES256 on the Keycloak issuer", func(t *testing.T) string {
			return sign(t, spec{alg: jose.ES256, key: ks.attackEC, kid: kcKid, typ: "JWT"}, kcClaims())
		}, authn.ReasonAlgNotAllowed},
		{"RS256 on the STS issuer", func(t *testing.T) string {
			return sign(t, spec{alg: jose.RS256, key: ks.attacker, kid: stsKid, typ: "at+jwt"}, stsClaims())
		}, authn.ReasonAlgNotAllowed},
		{"PS256 on the Keycloak issuer", func(t *testing.T) string {
			return sign(t, spec{alg: jose.PS256, key: ks.kc, kid: kcKid, typ: "JWT"}, kcClaims())
		}, authn.ReasonAlgNotAllowed},

		// ---- issuer selection (D3) ----
		{"unknown iss", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "iss", "https://evil.example/realms/insurance"))
		}, authn.ReasonIssuerUnknown},
		{"iss with trailing slash", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "iss", kcIss+"/"))
		}, authn.ReasonIssuerUnknown},
		{"iss differs in case", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "iss", strings.ToUpper(kcIss)))
		}, authn.ReasonIssuerUnknown},
		{"iss missing", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "iss", nil))
		}, authn.ReasonIssuerUnknown},

		// ---- key lookup and signature ----
		{"unknown kid", func(t *testing.T) string {
			s := kcSpec(t)
			s.kid = "nope"
			return sign(t, s, kcClaims())
		}, authn.ReasonKidUnknown},
		{"no kid header", func(t *testing.T) string {
			s := kcSpec(t)
			s.kid = ""
			return sign(t, s, kcClaims())
		}, authn.ReasonKidUnknown},
		{"kid of another issuer's key (keys are scoped per issuer)", func(t *testing.T) string {
			return sign(t, spec{alg: jose.RS256, key: ks.cognito, kid: cognitoKid, typ: "JWT"}, kcClaims())
		}, authn.ReasonKidUnknown},
		{"jku header pointing at the attacker's JWKS", func(t *testing.T) string {
			s := spec{alg: jose.RS256, key: ks.attacker, kid: "attacker-1", typ: "JWT",
				headers: map[jose.HeaderKey]any{"jku": attackerSrv.URL}}
			return sign(t, s, kcClaims())
		}, authn.ReasonKidUnknown},
		{"right kid, signed with the attacker's key", func(t *testing.T) string {
			return sign(t, spec{alg: jose.RS256, key: ks.attacker, kid: kcKid, typ: "JWT"}, kcClaims())
		}, authn.ReasonSignatureInvalid},
		{"attacker key embedded as jwk header (CVE-2018-0114 style)", func(t *testing.T) string {
			return sign(t, spec{alg: jose.RS256, key: ks.attacker, kid: kcKid, typ: "JWT", embed: true}, kcClaims())
		}, authn.ReasonSignatureInvalid},
		{"payload tampered after signing", func(t *testing.T) string {
			tok := sign(t, kcSpec(t), kcClaims())
			return swapPayload(t, tok, with(kcClaims(), "sub", "user-bob"))
		}, authn.ReasonSignatureInvalid},
		{"signature stripped", func(t *testing.T) string {
			return stripSignature(t, sign(t, kcSpec(t), kcClaims()))
		}, authn.ReasonSignatureInvalid},

		// ---- time claims (D3), 30 s leeway ----
		{"expired 31 s ago", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "exp", unix(-31*time.Second)))
		}, authn.ReasonExpired},
		{"expired an hour ago", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "exp", unix(-time.Hour)))
		}, authn.ReasonExpired},
		{"exp missing", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "exp", nil))
		}, authn.ReasonClaimMissing},
		{"nbf 60 s in the future", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "nbf", unix(time.Minute)))
		}, authn.ReasonNotYetValid},
		{"iat 60 s in the future", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "iat", unix(time.Minute)))
		}, authn.ReasonIssuedInFuture},

		// ---- required claims ----
		{"sub missing", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "sub", nil))
		}, authn.ReasonClaimMissing},
		{"STS token without jti (revocation needs it)", func(t *testing.T) string {
			return sign(t, stsSpec(t), with(stsClaims(), "jti", nil))
		}, authn.ReasonClaimMissing},

		// ---- audience (D3) ----
		{"wrong aud", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "aud", "account"))
		}, authn.ReasonAudienceMismatch},
		{"aud missing", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "aud", nil))
		}, authn.ReasonAudienceMismatch},
		{"aud is a prefix-similar value", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "aud", []string{"policy-api-admin", "account"}))
		}, authn.ReasonAudienceMismatch},
		{"STS token for another resource server", func(t *testing.T) string {
			return sign(t, stsSpec(t), with(stsClaims(), "aud", "claims-api"))
		}, authn.ReasonAudienceMismatch},
		{"Cognito client_id not allowed", func(t *testing.T) string {
			return sign(t, cognitoSpec(t), with(cognitoClaims(), "client_id", "other-app"))
		}, authn.ReasonAudienceMismatch},
		{"Cognito ID token (token_use=id)", func(t *testing.T) string {
			return sign(t, cognitoSpec(t), with(cognitoClaims(), "token_use", "id"))
		}, authn.ReasonTokenUseInvalid},

		// ---- typ (RFC 9068) ----
		{"STS token with typ JWT", func(t *testing.T) string {
			s := stsSpec(t)
			s.typ = "JWT"
			return sign(t, s, stsClaims())
		}, authn.ReasonTypeInvalid},
		{"STS token without typ", func(t *testing.T) string {
			s := stsSpec(t)
			s.typ = ""
			return sign(t, s, stsClaims())
		}, authn.ReasonTypeInvalid},

		// ---- revocation (D13) ----
		{"revoked jti (Keycloak)", func(t *testing.T) string {
			return sign(t, kcSpec(t), with(kcClaims(), "jti", "revoked-jti"))
		}, authn.ReasonRevoked},
		{"revoked jti (STS)", func(t *testing.T) string {
			return sign(t, stsSpec(t), with(stsClaims(), "jti", "revoked-jti"))
		}, authn.ReasonRevoked},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tc.tok(t)
			p, err := v.Validate(context.Background(), tok)
			if err == nil {
				t.Fatalf("token accepted, principal %+v", p)
			}
			if got := authn.ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %q, want %q (err: %v)", got, tc.want, err)
			}
			if p.Subject != "" {
				t.Errorf("rejected token returned a non-empty principal: %+v", p)
			}
			if len(tok) > 20 && strings.Contains(err.Error(), tok[len(tok)-20:]) {
				t.Errorf("error message leaks the token: %v", err)
			}
		})
	}

	if n := attackerHits.Load(); n != 0 {
		t.Errorf("validator fetched the attacker's jku %d times, want 0", n)
	}
}

func TestValidateAccepts(t *testing.T) {
	v := newTestValidator(t)

	cases := []struct {
		name string
		tok  func(t *testing.T) string
		want authn.Principal
	}{
		{
			name: "Keycloak browser token",
			tok:  func(t *testing.T) string { return sign(t, kcSpec(t), kcClaims()) },
			want: authn.Principal{
				Subject: "user-anna", Issuer: kcIss, ClientID: "portal-bff", PartnerID: "nordbank",
				Roles:  []string{"policyholder", "default-roles-insurance"},
				Scopes: []string{"openid", "profile", "policies"},
				ACR:    "gold", AuthTime: now.Add(-60 * time.Second),
				TokenID: "kc-jti-1", ExpiresAt: now.Add(5 * time.Minute),
			},
		},
		{
			name: "Keycloak token with aud as a single string",
			tok:  func(t *testing.T) string { return sign(t, kcSpec(t), with(kcClaims(), "aud", audience)) },
			want: authn.Principal{Subject: "user-anna", Issuer: kcIss, TokenID: "kc-jti-1"},
		},
		{
			name: "Keycloak client-credentials token (no acr, auth_time, partner_id)",
			tok: func(t *testing.T) string {
				return sign(t, kcSpec(t), with(kcClaims(), "sub", "svc-warden-test", "azp", "warden-test",
					"acr", nil, "auth_time", nil, "partner_id", nil))
			},
			want: authn.Principal{Subject: "svc-warden-test", Issuer: kcIss, ClientID: "warden-test", TokenID: "kc-jti-1"},
		},
		{
			name: "expired 20 s ago, within leeway",
			tok:  func(t *testing.T) string { return sign(t, kcSpec(t), with(kcClaims(), "exp", unix(-20*time.Second))) },
			want: authn.Principal{Subject: "user-anna", Issuer: kcIss, TokenID: "kc-jti-1"},
		},
		{
			name: "nbf and iat 20 s in the future, within leeway",
			tok: func(t *testing.T) string {
				return sign(t, kcSpec(t), with(kcClaims(), "nbf", unix(20*time.Second), "iat", unix(20*time.Second)))
			},
			want: authn.Principal{Subject: "user-anna", Issuer: kcIss, TokenID: "kc-jti-1"},
		},
		{
			name: "partner-sts token",
			tok:  func(t *testing.T) string { return sign(t, stsSpec(t), stsClaims()) },
			want: authn.Principal{
				Subject: "shopr", Issuer: stsIss, ClientID: "shopr", PartnerID: "shopr",
				Scopes: []string{"quotes:write"}, TokenID: "sts-jti-1", ExpiresAt: now.Add(5 * time.Minute),
			},
		},
		{
			name: "partner-sts token with typ application/at+jwt (RFC 7515 §4.1.9)",
			tok: func(t *testing.T) string {
				s := stsSpec(t)
				s.typ = "application/at+jwt"
				return sign(t, s, stsClaims())
			},
			want: authn.Principal{Subject: "shopr", Issuer: stsIss, TokenID: "sts-jti-1"},
		},
		{
			name: "Cognito access token",
			tok:  func(t *testing.T) string { return sign(t, cognitoSpec(t), cognitoClaims()) },
			want: authn.Principal{
				Subject: "8f0c-cognito-user", Issuer: cognitoIss, ClientID: cognitoApp,
				Roles: []string{"underwriter"}, Scopes: []string{"warden/quotes.read"},
				AuthTime: now.Add(-5 * time.Second), TokenID: "cognito-jti-1", ExpiresAt: now.Add(5 * time.Minute),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := v.Validate(context.Background(), tc.tok(t))
			if err != nil {
				t.Fatalf("rejected: %v (reason %q)", err, authn.ReasonOf(err))
			}
			assertPrincipal(t, got, tc.want)
		})
	}
}

// assertPrincipal compares the fields set in want. Zero-valued fields in
// want are not checked, so short cases can focus on what they test.
func assertPrincipal(t *testing.T, got, want authn.Principal) {
	t.Helper()
	str := func(field, g, w string) {
		if w != "" && g != w {
			t.Errorf("%s = %q, want %q", field, g, w)
		}
	}
	str("Subject", got.Subject, want.Subject)
	str("Issuer", got.Issuer, want.Issuer)
	str("ClientID", got.ClientID, want.ClientID)
	str("PartnerID", got.PartnerID, want.PartnerID)
	str("ACR", got.ACR, want.ACR)
	str("TokenID", got.TokenID, want.TokenID)
	if want.Roles != nil && !slices.Equal(got.Roles, want.Roles) {
		t.Errorf("Roles = %v, want %v", got.Roles, want.Roles)
	}
	if want.Scopes != nil && !slices.Equal(got.Scopes, want.Scopes) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, want.Scopes)
	}
	if !want.AuthTime.IsZero() && !got.AuthTime.Equal(want.AuthTime) {
		t.Errorf("AuthTime = %v, want %v", got.AuthTime, want.AuthTime)
	}
	if !want.ExpiresAt.IsZero() && !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
}

// Claims a client credentials token does not have must come out empty, not
// carry over defaults (e.g. ACR "0", AuthTime = iat).
func TestValidateAbsentClaimsStayEmpty(t *testing.T) {
	v := newTestValidator(t)
	tok := sign(t, kcSpec(t), with(kcClaims(), "acr", nil, "auth_time", nil, "partner_id", nil, "realm_access", nil, "scope", nil))
	p, err := v.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if p.ACR != "" || !p.AuthTime.IsZero() || p.PartnerID != "" || len(p.Roles) != 0 || len(p.Scopes) != 0 {
		t.Errorf("absent claims leaked values: %+v", p)
	}
}

// The issuer label on the error feeds authn_validations_total{issuer}.
func TestRejectionCarriesIssuerLabel(t *testing.T) {
	v := newTestValidator(t)

	s := kcSpec(t)
	s.kid = "nope"
	_, err := v.Validate(context.Background(), sign(t, s, kcClaims()))
	var ae *authn.Error
	if !asAuthnError(err, &ae) || ae.Issuer != "keycloak" {
		t.Errorf("kid_unknown on a Keycloak token: Issuer = %q, want %q (err %v)", issuerOf(ae), "keycloak", err)
	}

	_, err = v.Validate(context.Background(), sign(t, kcSpec(t), with(kcClaims(), "iss", "https://evil.example")))
	if !asAuthnError(err, &ae) || ae.Issuer != "" {
		t.Errorf("iss_unknown must not name an issuer (unbounded label): Issuer = %q", issuerOf(ae))
	}
}

func asAuthnError(err error, target **authn.Error) bool {
	e, ok := err.(*authn.Error)
	if !ok {
		return false
	}
	*target = e
	return true
}

func issuerOf(e *authn.Error) string {
	if e == nil {
		return "<nil error>"
	}
	return e.Issuer
}

func TestValidatorIsSafeForConcurrentUse(t *testing.T) {
	v := newTestValidator(t)
	good := sign(t, kcSpec(t), kcClaims())
	bad := sign(t, kcSpec(t), with(kcClaims(), "aud", "x"))
	done := make(chan struct{})
	for i := range 16 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 50 {
				tok := good
				if i%2 == 0 {
					tok = bad
				}
				_, err := v.Validate(context.Background(), tok)
				if (err == nil) != (tok == good) {
					t.Errorf("unexpected result: %v", err)
					return
				}
			}
		}()
	}
	for range 16 {
		<-done
	}
}

func TestNewValidatorRefusesWeakConfig(t *testing.T) {
	ks := k(t)
	keysKC := newStaticKeys(pubJWK(ks.kc, kcKid, jose.RS256))
	kc := authn.KeycloakProfile(kcIss, audience)

	// These cases mutate the suggested IssuerProfile fields (Alg, Audience).
	// If you rename them, adjust here.
	algNone := kc
	algNone.Alg = "none"
	algHS := kc
	algHS.Alg = jose.HS256
	noAud := kc
	noAud.Audience = ""

	cases := []struct {
		name string
		cfg  authn.Config
	}{
		{"no issuers", authn.Config{}},
		{"duplicate iss", authn.Config{Issuers: []authn.Issuer{{Profile: kc, Keys: keysKC}, {Profile: kc, Keys: keysKC}}}},
		{"nil key source", authn.Config{Issuers: []authn.Issuer{{Profile: kc}}}},
		{"alg none", authn.Config{Issuers: []authn.Issuer{{Profile: algNone, Keys: keysKC}}}},
		{"symmetric alg", authn.Config{Issuers: []authn.Issuer{{Profile: algHS, Keys: keysKC}}}},
		{"no audience rule", authn.Config{Issuers: []authn.Issuer{{Profile: noAud, Keys: keysKC}}}},
		{"Cognito without client IDs", authn.Config{Issuers: []authn.Issuer{{Profile: authn.CognitoProfile(cognitoIss), Keys: keysKC}}}},
		{"empty issuer", authn.Config{Issuers: []authn.Issuer{{Profile: authn.KeycloakProfile("", audience), Keys: keysKC}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := authn.NewValidator(tc.cfg); err == nil {
				t.Fatal("NewValidator accepted a weak config")
			}
		})
	}
}

func TestProfilesPinAlgorithms(t *testing.T) {
	cases := []struct {
		p    authn.IssuerProfile
		alg  jose.SignatureAlgorithm
		name string
	}{
		{authn.KeycloakProfile(kcIss, audience), jose.RS256, "keycloak"},
		{authn.PartnerSTSProfile(stsIss, audience), jose.ES256, "partner-sts"},
		{authn.CognitoProfile(cognitoIss, cognitoApp), jose.RS256, "cognito"},
	}
	for _, tc := range cases {
		if tc.p.Alg != tc.alg {
			t.Errorf("%s: Alg = %q, want %q", tc.name, tc.p.Alg, tc.alg)
		}
		if tc.p.Name != tc.name {
			t.Errorf("%s: Name = %q, want %q (metric label)", tc.name, tc.p.Name, tc.name)
		}
	}
}

// attackerJWKS serves the attacker's public key and counts requests. The
// validator must never fetch it.
func attackerJWKS(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK(k(t).attacker, "attacker-1", jose.RS256)}}
	body, _ := json.Marshal(set)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}
