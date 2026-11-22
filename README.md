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
| `policy-api` (resource server, gRPC + REST) | Planned |
| `partner-sts` (custom token issuer for partners, KMS-signed) | Planned |
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

## Repository layout

```text
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
