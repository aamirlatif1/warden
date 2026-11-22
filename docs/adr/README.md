# Architecture Decision Records

Each ADR is short and names the option it rejected. Bodies are written in S9;
this index fixes the titles.

| ADR | Decision | Rejected option |
| --- | --- | --- |
| 001 | BFF with server-side tokens for the browser | Tokens in the SPA (XSS exfiltration) |
| 002 | Custom STS for partners as a learning vehicle; Keycloak client credentials with `private_key_jwt` would be the production default | Treating a custom STS as required |
| 003 | Local JWT validation + pushed denylist; introspection only above a risk threshold | Introspect every call (latency, IdP coupling) |
| 004 | Signing-key rotation state machine with a publish lead time | Rotate and sign at once (breaks cached JWKS) |
| 005 | ES256 for STS tokens (Keycloak stays RS256) | RS256 everywhere (bigger tokens, slower KMS sign) |
| 006 | Keycloak configuration as OpenTofu + Terragrunt | Realm JSON import (drift, no plan/diff) |
| 007 | Redis pub/sub for revocation fan-out | Kafka/NATS (durable but overkill here) |
| 008 | Step-up via RFC 9470 challenge + Keycloak Level of Authentication | A separate "MFA app" |
