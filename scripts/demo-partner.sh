#!/usr/bin/env bash
# Partner M2M demo (REQUIREMENTS §8 step 5): Shopr authenticates with
# private_key_jwt, gets a KMS-signed at+jwt from partner-sts, creates a
# quote, and is refused for another tenant. Also shows D12 (assertion replay).
#
# Needs: make up, make kms-key, make sts-seed, make run-sts, make run-api.
# Revocation and rotation (the rest of FR-4's demo) arrive in S5.
set -euo pipefail

STS_URL=${STS_URL:-http://localhost:8083}
API_URL=${API_URL:-http://localhost:8081}
CLI=(go run ./cmd/partnercli)

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { echo "ok   $*"; }
fail() { echo "FAIL $*"; exit 1; }
b64d() { local s=${1//-/+}; s=${s//_//}; while (( ${#s} % 4 )); do s+='='; done; base64 -d <<<"$s" 2>/dev/null; }

say "1. partner-sts discovery and JWKS"
curl -sf "$STS_URL/.well-known/oauth-authorization-server" | jq '{issuer, token_endpoint, token_endpoint_auth_methods_supported}'
curl -sf "$STS_URL/jwks.json" | jq -c '.keys[] | {kid, kty, crv, alg, use}'

say "2. Shopr gets a token (private_key_jwt → KMS-signed ES256 at+jwt)"
token=$("${CLI[@]}" token -scope "quotes:write")
echo "header:  $(b64d "$(cut -d. -f1 <<<"$token")" | jq -c .)"
echo "payload: $(b64d "$(cut -d. -f2 <<<"$token")" | jq -c '{iss, sub, aud, client_id, partner_id, scope, exp}')"

say "3. D12: replay the same client assertion"
assertion=$("${CLI[@]}" assertion)
post_assertion() {
  curl -s -o /dev/null -w '%{http_code}' "$STS_URL/token" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=$assertion"
}
first=$(post_assertion); second=$(post_assertion)
[[ $first == 200 ]] && ok "first use: 200" || fail "first use: $first"
[[ $second == 400 ]] && ok "replay: 400 invalid_client" || fail "replay: $second, want 400"

say "4. Create a quote for Shopr's own tenant"
quote() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/v1/quotes" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "{\"partner_id\":\"$1\",\"product\":\"phone\",\"insured_value\":{\"amount_minor\":80000,\"currency\":\"EUR\"}}"
}
code=$(quote shopr); [[ $code == 201 ]] && ok "quote for shopr: 201" || fail "quote for shopr: $code"

say "5. D5: cross-tenant quote (partner_id=nordbank)"
code=$(quote nordbank); [[ $code == 403 ]] && ok "quote for nordbank: 403" || fail "quote for nordbank: $code, want 403"
