# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

In progress (S0–S5 scaffolding done; hand-build bodies in `internal/authn`,
`internal/authn/jwks`, `ginauth`, `grpcauth`, `authz.Decide`,
`sts/clientauth` and `issuer/keyring` are the author's, still `TODO` stubs
until written). Client
assertions use `aud` = STS issuer identifier only (rfc7523bis), a deliberate
deviation from FR-4's "token endpoint URL". The source of truth is
`REQUIREMENTS.md` (FR-1…FR-7, drills, ADRs, Definition of Done) and
`SCHEDULE.md` (sessions S0–S9, hand-build vs delegate split, cut list). Both are
**local working notes, gitignored on purpose**. Never commit them, and never
copy personal content from them (names, external links, notes about people)
into tracked files. Technical content (requirements, drill lists, ADR titles)
is fine to carry over.

When a session starts with `S<n>` or `FR-<n>`, read that section of
SCHEDULE.md / REQUIREMENTS.md first, propose a plan, then code.

## What Warden is

A 14-hour **learning demonstrator** of an identity layer for an embedded-insurance
integration platform (partner banks and e-commerce shops). Framing matters: the
README and docs must present it as a learning project built with Claude Code,
never as production IdP experience. Don't write copy that overclaims.

Actors: policyholder (Keycloak browser SSO + MFA), bank customer (SAML brokered
via Keycloak realm `nordbank`), partner backend "Shopr" (`private_key_jwt` to
the custom STS), underwriter (LDAP federation → realm role).

## Tech stack and code structure

- **Go**, with **Gin** for all HTTP (BFF, partner-sts, policy-api REST) and
  **GORM** for Postgres. gRPC for policy-api.
- **Hexagonal architecture** (ports and adapters). Dependencies point inward:
  - `domain` — entities, value objects, domain errors. Pure Go: no Gin, GORM,
    gRPC, Redis or JWT library imports.
  - `app` — use cases / application services. Depends only on `domain` and on
    the interfaces it declares itself.
  - `adapters` — driving (Gin handlers, gRPC servers, interceptors/middleware)
    and driven (GORM repositories, Redis, KMS, JWKS fetchers, Keycloak client).
  - `cmd/<service>/main.go` is the composition root: build adapters, inject
    them into `app`, start servers. No business logic there.
- **Small, consumer-side interfaces.** Define an interface in the package that
  *uses* it, next to the code that calls it, with only the methods that caller
  needs (often one or two). Adapter packages export concrete structs and
  constructors, not interfaces. Don't create a shared "ports" package of large
  interfaces, and don't add an interface until there is a consumer for it.
  Accept interfaces, return structs.
- policy-api's REST and gRPC are two driving adapters over the same `app`
  services (Gin replaces grpc-gateway from REQUIREMENTS.md). **Authn** runs as
  Gin middleware and a gRPC interceptor sharing one validator. **Authz runs in
  the `app` layer**: each use case loads the resource, calls `authz.Decide()`
  (injected via `app.Deps.Decide`), logs the decision, and only then validates
  input and acts. Ownership and amount checks need the loaded resource, which
  middleware doesn't have. `app` may import `authn.Principal` and `authz`
  (both pure). Adapters map `*authz.DeniedError` → 403/`PermissionDenied` and
  `*authz.StepUpError` → 401 + RFC 9470 `WWW-Authenticate` (gRPC: trailer).
- ABAC attributes owned by the business (e.g. an underwriter's approval
  limit) live in policy-api's Postgres, keyed by `sub`, not in token claims.
- GORM models live in the driven adapter and are mapped to/from domain types;
  `gorm.Model` tags and `*gorm.DB` never leak into `domain` or `app`.
  Transactions are exposed to `app` through a small consumer-side interface,
  not by passing `*gorm.DB`.
- Gin `*gin.Context` stops at the handler: handlers translate request →
  app call → response and pass `c.Request.Context()` downward.

## Hand-build vs delegate (important)

This is a learning project: the author writes the security-critical code
themselves and must be able to explain every line of it.
For these, **do not write the implementation unless explicitly asked** — review,
critique, attack ("list every token that would wrongly pass"), or write tests instead:

- JWT validator (alg pinning, claim checks, issuer profiles) and JWKS cache
  (singleflight, rate-limited refetch, last-known-good)
- Authz `Decide()` incl. step-up result
- `private_key_jwt` assertion verification + `jti` replay check
- Key rotation state machine
- BFF callback (state/nonce/PKCE, session ID rotation), refresh-under-lock
- Back-channel `logout_token` validation
- Sliding-window rate limiter, log redaction
- THREAT-MODEL and ADRs

Fine to delegate: compose, Makefile, Dockerfiles, dev PKI, OpenTofu/Terragrunt
modules, proto/buf boilerplate, Gin routing and GORM repository plumbing, KMS adapter + DER→JOSE conversion
(explain it afterwards), OTel/Prometheus wiring, Grafana JSON, HTML templates,
drill harness plumbing, CI, load-test scripts. Include tests with delegated code.

After each session, `docs/ai-log.md` gets one line: what was delegated, what
Claude got wrong, what was changed.

## Commands

Targets (`make help` lists what exists; `drills`, `demo*` come later):

- `make up` — docker compose stack (`deploy/compose.yaml`): Keycloak 26 (Postgres-backed), Postgres, Redis, OpenLDAP, LocalStack (KMS + Secrets Manager), grafana/otel-lgtm
- `make infra` — `terragrunt run --all apply` over `infra/live/local`; a second run must show no changes
- `make test` — `go test -race ./...`
- `make drills` — attack drills against the live stack (`go test -tags=drills ./drills/...`)
- `make bench` — `internal/authn` benchmarks (target < 50 µs/op warm)
- `make demo`, `make demo-partner`
- CI also runs `golangci-lint`, `gosec`, `govulncheck`, `buf lint`, `buf breaking --against main`, `tofu fmt -check`, `tofu validate`

- `make test-db` — pgstore integration tests (Postgres `warden_test` database)
- `make seed` — demo policies/claims owned by the Keycloak seed users' `sub`
- `make kms-key`, `make sts-seed`, `make run-sts` — partner-sts setup (keys in gitignored `.local/`)
- `make rotate-under-load` — rotation drill (`make run-sts STS_PUBLISH_LEAD=20s`)

Single test: `go test -race -run TestName ./internal/authn/`.

## Architecture

Single Go module, three services plus Keycloak:

- **`cmd/policy-api`** (gRPC :9090, REST :8081 via Gin) — resource
  server. Every call: authn interceptor → use case → `authz.Decide()`. Accepts tokens from
  two issuers (Keycloak RS256 and partner-sts ES256), selected by exact `iss`
  match against **issuer profiles** (`internal/authn/profiles.go`), each pinning
  its alg, JWKS source, audience rule and claim mapping (a Cognito profile uses
  `client_id`+`token_use` instead of `aud`). Produces a normalised `Principal`.
  No network call on the hot path: JWKS is cached, revocation is a local
  in-memory denylist fed by Redis pub/sub (`warden.revocations`); online
  introspection only for high-risk actions (claims > 10 000 €).
  `authn.Denylist.Revoked(TokenRef{Issuer, JTI, ClientID, IssuedAt})` covers
  single tokens and client-level cut-offs (partner suspension); the authn
  adapters also store the raw token (`authn.WithRawToken`) for introspection.
- **`cmd/bff`** (:8082) — OIDC auth code + PKCE against Keycloak; tokens live
  server-side in Redis (AES-GCM), browser gets only `__Host-sid`. Handles
  refresh rotation, CSRF, step-up (on RFC 9470 `insufficient_user_authentication`
  from policy-api → re-auth with `acr_values=gold&max_age=300` → replay),
  RP-initiated and back-channel logout. Talks to policy-api over mTLS
  (`deploy/pki`). A second instance as `claims-app` proves SSO.
- **`cmd/partner-sts`** (:8083) — custom issuer for partners: `private_key_jwt`
  client auth, `/token`, `/jwks.json`, discovery, `/introspect` (RFC 7662),
  `/revoke` (RFC 7009), `/admin/rotate`, partner suspend. Signs via the
  `internal/kms` `Signer` interface (`WARDEN_SIGNER=kms|local`); KMS returns
  DER ECDSA signatures that must be converted to JOSE raw R||S. Rotation
  publishes the next key in JWKS for `publish_lead` (2× JWKS cache TTL) before
  signing with it (ADR-004).
- **Keycloak** is configured entirely as code in `infra/modules/*` (realm
  `insurance`, broker realm `nordbank`, LDAP federation, Cognito module
  validate-only), wired by Terragrunt `infra/live/{local,stage}` with
  `infra/root.hcl`. Nothing is clicked in the admin UI. Step-up uses Keycloak's
  Conditional Level of Authentication flow (`silver=1`, `gold=2`).

Planned packages under `internal/`: `authn`, `authz`, `issuer`, `kms`,
`session`, `revocation`, `ratelimit`, `telemetry`, `tlsutil`. Each follows the
domain / app / adapters split above where it has I/O (for example, `kms`'s
`Signer` is declared by `issuer`, the consumer, and the KMS and local-file
signers are adapters). `authz.Decide()` stays a pure domain function. Proto
lives in `proto/warden/policy/v1/` (buf module).

## Conventions that cut across the code

- Every authn rejection carries a **reason** label (`alg_not_allowed`,
  `kid_unknown`, …) used in `authn_validations_total{issuer,result,reason}` and
  asserted by drills. Keep reasons stable.
- **Never log tokens.** slog `ReplaceAttr` redacts `authorization`, `cookie`,
  `client_assertion`, `code`, `refresh_token`; drill D15 greps logs for `eyJ`.
- Every authz decision is logged with its reason.
- `docs/attack-drills.md` records **observed** results, not expected ones —
  including drills that failed first and how they were fixed.
- ADRs in `docs/adr/` must name the rejected option.
- Scope is controlled by the cut list in SCHEDULE.md; don't add FR-7 stretch
  work before the §9 Definition of Done is met.
