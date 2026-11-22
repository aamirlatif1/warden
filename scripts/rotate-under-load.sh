#!/usr/bin/env bash
# Rotate partner-sts's signing key while a load loop keeps calling
# policy-api with fresh tokens. Pass condition: zero 401s, and tokens
# signed by both the old and the new kid were accepted.
#
# Run partner-sts with a short lead so this takes ~1 minute:
#   make run-sts STS_PUBLISH_LEAD=20s     (and make run-api)
set -euo pipefail

STS_URL=${STS_URL:-http://localhost:8083}
API_URL=${API_URL:-http://localhost:8081}
ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:9083}
CLI=bin/partnercli
go build -o "$CLI" ./cmd/partnercli

b64d() { local s=${1//-/+}; s=${s//_//}; while (( ${#s} % 4 )); do s+='='; done; base64 -d <<<"$s" 2>/dev/null; }
kid_of() { b64d "$(cut -d. -f1 <<<"$1")" | jq -r .kid; }

old_kid=$(curl -sf "$ADMIN_URL/admin/keys" | jq -r '.keys[] | select(.state=="current") | .kid')
echo "current kid: $old_kid"
echo "rotating..."
next=$(curl -sf -X POST "$ADMIN_URL/admin/rotate")
new_kid=$(jq -r .next.kid <<<"$next")
activates=$(jq -r .next.activates_at <<<"$next")
echo "next kid:    $new_kid (activates at $activates)"

total=0; unauthorized=0; other=0
old_ok=""; new_ok=""   # bash 3.2 (macOS): no associative arrays
token=""; minted=0
while :; do
  now=$(date +%s)
  if (( now - minted >= 2 )); then       # a fresh token every 2 s
    token=$("$CLI" token -scope quotes:write); minted=$now
  fi
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/v1/quotes" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' -d '{"partner_id":"shopr","product":"phone","insured_value":{"amount_minor":100,"currency":"EUR"}}')
  total=$((total + 1))
  case $code in
    201) k=$(kid_of "$token"); [[ $k == "$old_kid" ]] && old_ok=1; [[ $k == "$new_kid" ]] && new_ok=1 ;;
    401) unauthorized=$((unauthorized + 1)); echo "401 with kid $(kid_of "$token")" ;;
    *)   other=$((other + 1)) ;;
  esac
  state=$(curl -sf "$ADMIN_URL/admin/keys" | jq -r --arg k "$new_kid" '.keys[] | select(.kid==$k) | .state')
  if [[ $state == current && -n $new_ok ]]; then
    # keep going a few seconds after the switch
    (( ${end_at:-0} == 0 )) && end_at=$((now + 5))
    (( now >= end_at )) && break
  fi
  sleep 0.1
done

echo
echo "requests: $total, 401: $unauthorized, other non-201: $other"
echo "old kid accepted: ${old_ok:-no}, new kid accepted: ${new_ok:-no}"
[[ $unauthorized == 0 && -n $old_ok && -n $new_ok ]] \
  && echo "PASS: zero 401s across the rotation" || { echo "FAIL"; exit 1; }
