# AI log

One line per session: what was delegated to Claude Code, what it got wrong,
what I changed.

| Session | Delegated | Claude got wrong | I changed |
| --- | --- | --- | --- |
| S0 | `.gitignore`, first draft of `docs/design.md` (actor table, trust boundaries, DFD, flow list), ADR index | — | — |
| S1 | `deploy/compose.yaml` (Keycloak 26.4 on Postgres, Redis, OpenLDAP + seed, LocalStack 4.9, otel-lgtm), Dockerised tofu/terragrunt tools image, `infra/root.hcl`, `keycloak-realm` module, `live/local`, Makefile | Used `keycloak_openid_client_default_scopes` (deprecated in provider 5.11) — migrated to `keycloak_client_scope_assignments`; first compose run bound host port 5432, already taken locally | — |
