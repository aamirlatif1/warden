# Warden — Identity Layer

Warden is a **learning project**: a small identity layer for an
embedded-insurance integration platform that sells policies through partner
banks and e-commerce shops. I built it with Claude Code as a pair, to get
hands-on with the issuer side of identity: SSO, MFA, federation, and token
issuance, rotation and revocation. It is not a production IdP, and it is not
production IdP experience. [`docs/ai-log.md`](docs/ai-log.md) records what was
delegated to the AI and what I wrote and changed myself.

## Status

Work in progress. What runs today:

| Part | State |
| --- | --- |
| Local stack (Keycloak 26, Postgres, Redis, OpenLDAP, LocalStack KMS + Secrets Manager, Grafana LGTM) | Working |
| Keycloak realm `insurance` as code (OpenTofu + Terragrunt) | Working |
| `policy-api` (resource server, gRPC + REST) | In progress: API, Postgres store, seed data, authz wiring and the authn/authz test suites done; token validator, JWKS cache and `authz.Decide` being written by hand |
| `partner-sts` (custom token issuer for partners, KMS-signed) | In progress: token endpoint, discovery, JWKS, KMS and local signers, partner registry, replay store done; `private_key_jwt` verification being written by hand; rotation and revocation next |
| `bff` (policyholder portal, server-side sessions, step-up) | Planned |
| SAML federation, LDAP federation, MFA flows | Planned |
| Attack drills, threat model, ADRs | Planned |

The design, actors, trust boundaries and data flows are in
[`docs/design.md`](docs/design.md). The architecture decisions are indexed in
[`docs/adr/`](docs/adr/README.md).

## Prerequisites

- **Docker** with Compose v2. That's all: OpenTofu and Terragrunt run inside a
  container built from `deploy/tools/Dockerfile`, so you don't install them.
- `make`, `curl` and `jq` for the helper targets.
- **Go 1.27** for the services (`make test`, `make run-api`).
- About 4 GB of free memory for the stack.

## Quick start

```bash
make up      # start the stack and wait until every service is healthy
make infra   # build the Keycloak realm from code (terragrunt run --all apply)
make check-s1
```

`check-s1` confirms Keycloak serves the realm's discovery document and that a
second plan shows no changes, which proves the config is idempotent.

Then open the discovery document:

```bash
curl -s http://localhost:8080/realms/insurance/.well-known/openid-configuration | jq .issuer
# "http://localhost:8080/realms/insurance"
```

## Make targets

| Target | What it does |
| --- | --- |
| `make up` | Start the stack (`deploy/compose.yaml`) and wait for health checks |
| `make down` | Stop the stack and keep the data volumes |
| `make clean` | Stop the stack, delete its volumes, local Tofu state and the Terragrunt cache |
| `make tools` | Build the OpenTofu + Terragrunt image (`warden-tools:local`) |
| `make infra` | Apply all Keycloak config under `infra/live/local` |
| `make infra-plan` | Show the plan without applying it |
| `make infra-check` | Exit non-zero if the plan has any change (drift detection) |
| `make check-s1` | Discovery document served + no changes in the plan |
| `make test` | `go test -race ./...` |
| `make bench` | Token validation benchmarks (`internal/authn`, target < 50 µs/op warm) |
| `make proto-tools` / `make proto` | Install pinned buf + protoc plugins into `./bin`; lint and regenerate `gen/` |
| `make run-api` | Run `policy-api` on the host: gRPC `:9090`, REST `:8081` |
| `make test-db` | Integration tests against the compose Postgres (`warden_test`), Redis and LocalStack KMS |
| `make seed` | Demo policies and claims owned by the Keycloak users `anna` and `bob` (by their `sub`) |
| `make check-s3` | With anna's real token: own policy 200, bob's policy 403 (BOLA), payout change 401 with the RFC 9470 step-up challenge |
| `make kms-key` | Create the STS signing key (`ECC_NIST_P256`, alias `alias/warden-sts`) in LocalStack KMS; safe to re-run |
| `make sts-seed` | Create Shopr's key pair in `.local/` (gitignored) and register Shopr in partner-sts |
| `make run-sts` | Run `partner-sts` on `:8083` (`WARDEN_SIGNER=kms`, or `local` for a file key) |
| `make demo-partner` | Partner demo: token, assertion replay refused, quote created, cross-tenant quote 403 |
| `make check-s2` | Get a client-credentials token from Keycloak and check `policy-api` accepts it and rejects no / tampered / `alg=none` tokens |
| `make help` | List the targets |

To start over from nothing: `make clean && make up && make infra`.

## Services and ports

All credentials below are throwaway values for a laptop.

| Service | URL / port | Login |
| --- | --- | --- |
| Keycloak | <http://localhost:8080> (admin console at `/admin`), management on `:9000` | `admin` / `admin` |
| Postgres 17 | `localhost:5434` (inside the network: `postgres:5432`) | databases `keycloak` and `warden`; user = password = database name |
| Redis 7 | `localhost:6379` | none |
| OpenLDAP | `ldap://localhost:1389`, base `dc=warden,dc=local` | `cn=admin,dc=warden,dc=local` / `admin` |
| LocalStack (KMS, Secrets Manager) | <http://localhost:4566>, region `eu-central-1` | any credentials |
| Grafana (Tempo, Prometheus, Loki) | <http://localhost:3000> | anonymous access on; `admin` / `admin` also works |
| OTLP collector | `localhost:4317` (gRPC), `localhost:4318` (HTTP) | none |

Postgres is on host port 5434 because 5432 and 5433 are often taken on a dev
machine.

## What's in the Keycloak realm

`infra/modules/keycloak-realm` creates realm `insurance`:

- **Clients:** `portal-bff` and `claims-app` (confidential, authorization
  code + PKCE S256 only, exact redirect URIs, back-channel logout),
  `policy-api` (an audience only, with every flow off), and `warden-test` (a
  client-credentials client that exists only in `live/local`).
- **Client scope `policies`:** adds `aud=policy-api`, `partner_id` and
  `groups` to the access token.
- **Realm roles:** `policyholder`, `underwriter`, `partner-agent`.
- **Token and session lifetimes:** access token 5 min, SSO idle 30 min,
  SSO max 10 h. Refresh tokens are single-use, and reusing one ends the
  session.
- **Brute-force detection** (5 failures, 60 s wait increment) and a
  password policy (length 12, not the username, history 3).
- **User profile:** `partner_id` is declared and only admins can see or edit
  it, so a user can't change the claim that decides their tenant.
- **Seed users** (synthetic): `anna` and `bob`, both `policyholder`. Their
  passwords are in `infra/live/local/env.hcl`.

The LDAP directory (`deploy/ldap/seed.ldif`) holds the underwriter `ben`
(password `ben-dev-password`) in group `underwriters`. Keycloak doesn't
federate it yet.

## Try it: get a token

Read the test client's secret from Tofu state, then ask Keycloak for a token
with client credentials:

```bash
SECRET=$(docker run --rm --network warden_default \
  -v "$PWD":/work -v warden-plugin-cache:/plugin-cache \
  -w /work/infra/live/local/keycloak-realm warden-tools:local \
  terragrunt output -json client_secrets 2>/dev/null | jq -r '."warden-test"')

TOKEN=$(curl -s -u "warden-test:$SECRET" -d grant_type=client_credentials \
  http://localhost:8080/realms/insurance/protocol/openid-connect/token | jq -r .access_token)

# Decode the payload (no signature check, inspection only)
cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{iss, aud, azp, scope, exp}'
```

`aud` contains `policy-api` and `scope` contains `policies`.

## policy-api

The resource server. REST (Gin) and gRPC are two driving adapters over the
same use cases, and both authenticate with one shared token validator.

| RPC | REST |
| --- | --- |
| `CreateQuote` | `POST /v1/quotes` |
| `ListPolicies` | `GET /v1/policies` (only the caller's policies) |
| `GetPolicy` | `GET /v1/policies/{id}` |
| `UpdatePayoutAccount` | `PUT /v1/policies/{id}/payout-account` |
| `ApproveClaim` | `POST /v1/claims/{id}:approve` |

Token validation (`internal/authn`) makes no network call on the hot path.
It selects an **issuer profile** by exact `iss` match, and the profile pins
the algorithm (Keycloak RS256, partner-sts ES256), the audience rule and the
claim mapping. Keys come from a JWKS cache with a rate-limited, singleflight
refetch on an unknown `kid`. Every rejection carries a stable reason label
(`alg_not_allowed`, `kid_unknown`, `aud_mismatch`, ...).

Authorization (`internal/authz`) is a pure function,
`Decide(principal, action, resource, env)`, that returns allow, deny with a
reason, or step-up. Each use case loads the resource first, because
ownership and amount checks need it, then asks the engine and logs the
decision:

| RPC | Rule |
| --- | --- |
| `CreateQuote` | scope `quotes:write` and token `partner_id` = request `partner_id` |
| `ListPolicies` | role `policyholder`; only the caller's own policies |
| `GetPolicy` | owner, or role `underwriter` |
| `UpdatePayoutAccount` | owner, then `acr` ≥ 2 and `auth_time` ≤ 5 min, else 401 with an RFC 9470 challenge (`acr_values="gold", max_age=300`) |
| `ApproveClaim` | role `underwriter` and amount ≤ the underwriter's approval limit (Postgres); above 10 000 € the token is checked online first, failing closed until that check exists |

A non-owner gets 403 and is never sent to MFA. Data lives in Postgres
(`warden` database, GORM); `make seed` loads the demo rows.

## partner-sts

The token issuer for partner backends. A partner authenticates with
`private_key_jwt` (RFC 7523): it signs a short-lived JWT with its own
private key, and partner-sts checks it against the public key in the
partner registry. No shared secret exists anywhere.

- **Assertion rules:** ES256 only; `iss` = `sub` = `client_id`; `aud` is
  exactly the STS issuer identifier (`http://localhost:8083`), as the OAuth
  WG's rfc7523bis draft requires after the 2025 audience-injection finding.
  That is stricter than the original RFC 7523 "token endpoint URL", which
  partner-sts rejects. Lifetime at most 5 min. The `jti` is recorded in
  Redis with `SET NX` until the assertion expires, so a replay is refused
  (`invalid_client`), and only after every other check passed, so a forged
  assertion can't burn a real `jti`.
- **Tokens:** `at+jwt` (RFC 9068), ES256, 5 min, `aud=policy-api`, with
  `client_id`, `partner_id` and the requested scope narrowed to what the
  partner is allowed.
- **Signing:** the private key stays in KMS. partner-sts sends a SHA-256
  digest and gets back a DER-encoded ECDSA signature, which JWS can't use:
  it needs R and S as two fixed 32-byte values (RFC 7518 §3.4).
  `internal/kms/der.go` converts it, and a startup self-test signs and
  verifies a probe so a wrong format fails at boot, not on every request.
  The `kid` is the key's RFC 7638 thumbprint.
- **Endpoints:** `POST /token`, `GET /.well-known/oauth-authorization-server`
  (also at `openid-configuration`), `GET /jwks.json` (cacheable 5 min).

policy-api trusts it through a second issuer profile (ES256, `typ`
`at+jwt`, its own JWKS cache). Rotation, revocation and introspection come
next.

## Repository layout

```text
cmd/policy-api/       composition root
proto/                buf module (warden.policy.v1)
gen/                  generated Go code (committed; `make proto`)
internal/
  authn/              token validator, issuer profiles, reasons
    jwks/             JWKS cache (driven adapter)
    ginauth/          HTTP middleware (driving adapter)
    grpcauth/         gRPC interceptor (driving adapter)
  policy/
    domain/           entities and rules, pure Go
    app/              use cases and the store interfaces they need
    adapters/         grpcapi, httpapi (driving); pgstore, memstore (driven)
  authz/              authorization engine: Decide, reasons, step-up challenge
  issuer/             token minting (compact JWS) over a Signer
  kms/                KMS and local ES256 signers, DER → JOSE conversion
  sts/
    clientauth/       private_key_jwt assertion verification
    domain/, app/     partner, token use case
    adapters/         httpapi (driving); pgstore, redisreplay (driven)
cmd/policy-seed/      demo data loader
cmd/partner-sts/      partner token issuer (composition root)
cmd/sts-seed/         registers a partner
cmd/partnercli/       plays partner Shopr: keygen, assertions, tokens
scripts/              acceptance checks and demos
deploy/
  compose.yaml        local stack
  postgres/init.sql   creates the keycloak and warden databases
  ldap/seed.ldif      synthetic directory (underwriters)
  tools/Dockerfile    OpenTofu + Terragrunt image
infra/
  root.hcl            generates provider and backend config for every unit
  modules/            plain OpenTofu modules (keycloak-realm, ...)
  live/local/         env.hcl inputs + one Terragrunt unit per module
docs/
  design.md           actors, trust boundaries, data-flow diagram, flows
  adr/                architecture decision records
  ai-log.md           per-session log of AI-delegated work
Makefile
```

Tofu state lives in `infra/.state/`. It's gitignored because it holds client
secrets and seed passwords. A real deployment would use an encrypted remote
backend.

## Troubleshooting

- **`port is already allocated`:** another process uses one of the ports
  above. Stop it, or change the host side of the mapping in
  `deploy/compose.yaml`.
- **`make infra` can't reach Keycloak:** the tools container joins the
  `warden_default` network, so the stack must be up first (`make up`).
- **Keycloak config changed by hand in the admin console:** `make infra-check`
  exits non-zero, and `make infra` puts it back. Nothing is meant to be
  clicked in the admin UI.
