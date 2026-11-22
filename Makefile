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

.PHONY: help up down clean tools infra infra-plan infra-check check-s1 \
	proto-tools proto proto-lint test bench run-api check-s2

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

run-api: ## Run policy-api on the host (gRPC :9090, REST :8081) against local Keycloak
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
