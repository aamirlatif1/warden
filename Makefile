SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE      := docker compose -f deploy/compose.yaml
TOOLS_IMAGE  := warden-tools:local
INFRA_ENV    ?= local
KEYCLOAK_URL := http://localhost:8080

# OpenTofu + Terragrunt run in a container on the compose network, so the
# host needs only Docker. Provider downloads are cached in a named volume.
TG_DOCKER = docker run --rm \
	--network warden_default \
	-v $(CURDIR):/work \
	-v warden-plugin-cache:/plugin-cache \
	-e KEYCLOAK_ADMIN_USER -e KEYCLOAK_ADMIN_PASSWORD
TG       := $(TG_DOCKER) -w /work/infra/live/$(INFRA_ENV) $(TOOLS_IMAGE) terragrunt
TG_REALM := $(TG_DOCKER) -w /work/infra/live/$(INFRA_ENV)/keycloak-realm $(TOOLS_IMAGE) terragrunt

# Go tooling for proto generation, pinned and installed into ./bin.
BIN                   := $(CURDIR)/bin
BUF_VERSION           := v1.75.0
PROTOC_GEN_GO_VERSION := v1.36.12
PROTOC_GEN_GRPC_VER   := v1.6.2
API_URL               := http://localhost:8081
DATABASE_URL          ?= postgres://warden:warden@localhost:5434/warden?sslmode=disable
TEST_DATABASE_URL     ?= postgres://warden:warden@localhost:5434/warden_test?sslmode=disable
# Synthetic dev password from infra/live/local/env.hcl.
ANNA_PASSWORD         ?= anna-dev-password
# Dev-only shared secret: policy-api's credentials at partner-sts /introspect.
STS_INTROSPECT_SECRET ?= dev-only-introspection-secret
# How long a new STS key is published before it signs (ADR-004). 10m by
# default; use e.g. STS_PUBLISH_LEAD=20s for the rotation demo.
STS_PUBLISH_LEAD      ?= 10m

.PHONY: help up down clean tools infra infra-plan infra-check check-s1 \
	proto-tools proto proto-lint test bench run-api check-s2 \
	test-db seed check-s3 kms-key partner-keys sts-seed run-sts demo-partner \
	rotate-under-load pki run-bff run-claims-app infra-cognito

help: ## List targets
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

up: ## Start the local stack and wait until every service is healthy
	$(COMPOSE) up -d --wait

down: ## Stop the stack (keeps data volumes)
	$(COMPOSE) down

clean: ## Stop the stack and delete its volumes and local Tofu state
	$(COMPOSE) down -v
	rm -rf infra/.state
	find infra -type d -name .terragrunt-cache -prune -exec rm -rf {} +

tools: ## Build the OpenTofu + Terragrunt tools image
	docker build -q -t $(TOOLS_IMAGE) deploy/tools >/dev/null

infra: tools ## Apply all Keycloak config (terragrunt run --all apply)
	$(TG) run --all --non-interactive apply

infra-plan: tools ## Plan all Keycloak config
	$(TG) run --all --non-interactive plan

infra-check: tools ## Fail if a plan shows any change (drift / non-idempotent config)
	$(TG) run --all --non-interactive plan -- -detailed-exitcode -lock=false

infra-cognito: tools ## Validate and test the Cognito module against a mocked AWS provider (never applied)
	docker run --rm -v $(CURDIR)/infra/modules/cognito-user-pool:/m -v warden-plugin-cache:/plugin-cache \
		-e TF_DATA_DIR=/tmp/tfdata -w /m $(TOOLS_IMAGE) \
		sh -c 'tofu init -backend=false -input=false -lockfile=readonly >/dev/null 2>&1 || tofu init -backend=false -input=false >/dev/null; tofu validate && tofu test; rm -f .terraform.lock.hcl'

check-s1: ## S1 acceptance: discovery document is served and a plan shows no changes
	@curl -sf $(KEYCLOAK_URL)/realms/insurance/.well-known/openid-configuration \
		| jq -e '.issuer == "$(KEYCLOAK_URL)/realms/insurance"' >/dev/null \
		&& echo "discovery OK"
	@$(MAKE) --no-print-directory infra-check >/dev/null && echo "plan: no changes"

proto-tools: ## Install buf, protoc-gen-go and protoc-gen-go-grpc into ./bin
	GOBIN=$(BIN) go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	GOBIN=$(BIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(BIN) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GRPC_VER)

proto: ## Lint the proto and regenerate gen/
	PATH=$(BIN):$$PATH $(BIN)/buf lint
	PATH=$(BIN):$$PATH $(BIN)/buf generate

proto-lint: ## buf lint only
	$(BIN)/buf lint

test: ## go test -race ./...
	go test -race ./...

bench: ## authn benchmarks (target < 50 us/op warm)
	go test -run '^$$' -bench . -benchmem ./internal/authn/

run-api: tools pki ## Run policy-api (gRPC :9090, REST :8081, mTLS REST :8444 for the BFF); reads its introspection secret from Tofu
	@WARDEN_KEYCLOAK_INTROSPECT_SECRET=$$($(TG_REALM) output -json client_secrets 2>/dev/null | jq -r '."policy-api" // empty') \
	WARDEN_STS_INTROSPECT_SECRET='$(STS_INTROSPECT_SECRET)' \
	go run ./cmd/policy-api

check-s2: tools ## S2 acceptance: a real Keycloak token is accepted by policy-api (needs make up, make infra, make run-api)
	@set -euo pipefail; \
	secret=$$($(TG_REALM) output -json client_secrets 2>/dev/null | jq -r '."warden-test"'); \
	token=$$(curl -sf -u "warden-test:$$secret" -d grant_type=client_credentials \
		$(KEYCLOAK_URL)/realms/insurance/protocol/openid-connect/token | jq -r .access_token); \
	code() { curl -s -o /dev/null -w '%{http_code}' "$$@"; }; \
	check() { if [ "$$2" = "$$3" ]; then echo "ok   $$1 ($$2)"; else echo "FAIL $$1: got $$2, want $$3"; exit 1; fi; }; \
	check "Keycloak token accepted"   "$$(code -H "Authorization: Bearer $$token" $(API_URL)/v1/policies)" 200; \
	check "no token rejected"         "$$(code $(API_URL)/v1/policies)" 401; \
	check "tampered token rejected"   "$$(code -H "Authorization: Bearer $${token%?????}AAAAA" $(API_URL)/v1/policies)" 401; \
	check "alg=none token rejected"   "$$(code -H "Authorization: Bearer $$(printf '{"alg":"none"}' | base64 | tr '+/' '-_' | tr -d '=').$$(cut -d. -f2 <<<"$$token")." $(API_URL)/v1/policies)" 401

test-db: ## Integration tests against compose Postgres, Redis and LocalStack KMS (needs make up)
	@$(COMPOSE) exec -T postgres psql -q -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'warden_test'" | grep -q 1 \
		|| $(COMPOSE) exec -T postgres psql -q -U postgres -c "CREATE DATABASE warden_test OWNER warden"
	WARDEN_TEST_DATABASE_URL='$(TEST_DATABASE_URL)' WARDEN_TEST_REDIS_ADDR=localhost:6379 \
	WARDEN_TEST_KMS_ENDPOINT=http://localhost:4566 \
		go test -race -count=1 ./internal/policy/adapters/pgstore/ ./internal/sts/adapters/... ./internal/kms/ ./internal/revocation/ \
		./internal/bff/adapters/redisstore/ ./internal/ratelimit/

seed: tools ## Load demo policies and claims, owned by the Keycloak seed users (needs make infra)
	@set -euo pipefail; \
	ids=$$($(TG_REALM) output -json user_ids 2>/dev/null); \
	WARDEN_DATABASE_URL='$(DATABASE_URL)' go run ./cmd/policy-seed \
		-anna-sub "$$(jq -r .anna <<<"$$ids")" -bob-sub "$$(jq -r .bob <<<"$$ids")"

check-s3: tools ## S3 acceptance: D6 (BOLA) and D7 (step-up challenge) with anna's real token (needs seed + run-api)
	@set -euo pipefail; \
	TEST_CLIENT_SECRET=$$($(TG_REALM) output -json client_secrets 2>/dev/null | jq -r '."warden-test"') \
	ANNA_PASSWORD='$(ANNA_PASSWORD)' KEYCLOAK_URL='$(KEYCLOAK_URL)' API_URL='$(API_URL)' \
	./scripts/check-s3.sh

KMS_ALIAS  := alias/warden-sts
AWSLOCAL    = $(COMPOSE) exec -T localstack awslocal --region eu-central-1

kms-key: ## Create the STS signing key (ECC_NIST_P256) in LocalStack KMS, if missing
	@if $(AWSLOCAL) kms describe-key --key-id $(KMS_ALIAS) >/dev/null 2>&1; then \
		echo "$(KMS_ALIAS) exists"; \
	else \
		id=$$($(AWSLOCAL) kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
			--description "warden partner-sts signing key" --query KeyMetadata.KeyId --output text) && \
		$(AWSLOCAL) kms create-alias --alias-name $(KMS_ALIAS) --target-key-id "$$id" && \
		echo "created $(KMS_ALIAS) -> $$id"; \
	fi

partner-keys: ## Create Shopr's private key and public JWKS in .local/ (kept if present)
	go run ./cmd/partnercli keygen -key .local/shopr.key.pem -jwks .local/shopr.jwks.json -kid shopr-1

sts-seed: partner-keys ## Register partner Shopr (client_id shopr, tenant shopr) in partner-sts
	WARDEN_DATABASE_URL='$(DATABASE_URL)' go run ./cmd/sts-seed -client-id shopr -partner-id shopr \
		-name Shopr -scopes "quotes:read quotes:write" -jwks .local/shopr.jwks.json

run-sts: ## Run partner-sts on :8083, admin on 127.0.0.1:9083 (WARDEN_SIGNER=kms|local, STS_PUBLISH_LEAD=10m)
	WARDEN_STS_PUBLISH_LEAD=$(STS_PUBLISH_LEAD) WARDEN_STS_INTROSPECT_SECRET='$(STS_INTROSPECT_SECRET)' \
	go run ./cmd/partner-sts

demo-partner: ## Partner demo: token, D12 replay, quote, D5 403, D13 revoke + suspend (needs run-sts + run-api)
	./scripts/demo-partner.sh

rotate-under-load: ## Rotate the STS key while a load loop runs; expects zero 401s (run-sts with STS_PUBLISH_LEAD=20s)
	./scripts/rotate-under-load.sh

pki: ## Create the dev mTLS PKI in deploy/pki (CA, policy-api server cert, BFF client cert); kept if present
	go run ./cmd/devpki -out deploy/pki

# bff_secret reads a browser client's secret from Tofu state.
bff_secret = $$($(TG_REALM) output -json client_secrets 2>/dev/null | jq -r '."$(1)" // empty')

run-bff: tools pki ## Run the portal BFF on :8082 (client portal-bff); needs Keycloak, Redis and run-api
	@WARDEN_BFF_CLIENT_SECRET=$(call bff_secret,portal-bff) \
	WARDEN_BFF_INSTANCE=portal WARDEN_BFF_TITLE="Policyholder portal" \
	WARDEN_BFF_ADDR=:8082 WARDEN_BFF_BASE_URL=http://localhost:8082 WARDEN_BFF_CLIENT_ID=portal-bff \
	go run ./cmd/bff

run-claims-app: tools pki ## Run the second BFF instance on :8084 (client claims-app) to show SSO
	@WARDEN_BFF_CLIENT_SECRET=$(call bff_secret,claims-app) \
	WARDEN_BFF_INSTANCE=claims WARDEN_BFF_TITLE="Claims app" \
	WARDEN_BFF_ADDR=:8084 WARDEN_BFF_BASE_URL=http://localhost:8084 WARDEN_BFF_CLIENT_ID=claims-app \
	go run ./cmd/bff
