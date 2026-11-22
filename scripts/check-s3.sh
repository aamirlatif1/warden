#!/usr/bin/env bash
# S3 acceptance: drills D6 (BOLA) and D7 (step-up) by hand against a
# running policy-api, with a real Keycloak token for seed user anna.
# D5 (cross-tenant quote) needs a partner-sts token and is checked in S4.
#
# Needs: make up, make infra, make seed, make run-api.
# Env: TEST_CLIENT_SECRET (warden-test), ANNA_PASSWORD, KEYCLOAK_URL, API_URL.
set -euo pipefail

: "${TEST_CLIENT_SECRET:?}" "${ANNA_PASSWORD:?}" "${KEYCLOAK_URL:?}" "${API_URL:?}"

token=$(curl -sf -u "warden-test:${TEST_CLIENT_SECRET}" \
  -d grant_type=password -d username=anna --data-urlencode "password=${ANNA_PASSWORD}" -d scope=openid \
  "${KEYCLOAK_URL}/realms/insurance/protocol/openid-connect/token" | jq -r .access_token)
[[ -n "$token" && "$token" != null ]] || { echo "FAIL could not get a token for anna"; exit 1; }

hdrs=$(mktemp); trap 'rm -f "$hdrs"' EXIT
call() { # method path [body] -> prints status; headers in $hdrs
  local args=(-s -o /dev/null -D "$hdrs" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $token")
  [[ $# -ge 3 ]] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${API_URL}$2"
}
check() { # name got want
  if [[ "$2" == "$3" ]]; then echo "ok   $1 ($2)"; else echo "FAIL $1: got $2, want $3"; exit 1; fi
}

check "anna lists her policies"                 "$(call GET /v1/policies)" 200
check "anna reads her own policy"               "$(call GET /v1/policies/pol_anna_travel)" 200
check "D6 anna reads bob's policy"              "$(call GET /v1/policies/pol_bob_phone)" 403
check "D7 anna changes payout with acr=1"       "$(call PUT /v1/policies/pol_anna_travel/payout-account '{"iban":"DE89370400440532013000"}')" 401
www=$(grep -i '^www-authenticate:' "$hdrs" | tr -d '\r')
if [[ "$www" == *'error="insufficient_user_authentication"'* && "$www" == *'acr_values="gold"'* && "$www" == *'max_age=300'* ]]; then
  echo "ok   D7 RFC 9470 challenge: ${www#*: }"
else
  echo "FAIL D7 challenge header: ${www:-<missing>}"; exit 1
fi
check "D6 anna changes bob's payout (no MFA prompt)" "$(call PUT /v1/policies/pol_bob_phone/payout-account '{"iban":"DE89370400440532013000"}')" 403
check "anna approves a claim (not underwriter)" "$(call POST /v1/claims/clm_anna_small:approve)" 403
