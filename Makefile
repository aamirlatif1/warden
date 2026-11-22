SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE      := docker compose -f deploy/compose.yaml
TOOLS_IMAGE  := warden-tools:local
INFRA_ENV    ?= local
KEYCLOAK_URL := http://localhost:8080

# OpenTofu + Terragrunt run in a container on the compose network, so the
# host needs only Docker. Provider downloads are cached in a named volume.
TG := docker run --rm \
	--network warden_default \
	-v $(CURDIR):/work \
	-v warden-plugin-cache:/plugin-cache \
	-w /work/infra/live/$(INFRA_ENV) \
	-e KEYCLOAK_ADMIN_USER -e KEYCLOAK_ADMIN_PASSWORD \
	$(TOOLS_IMAGE) terragrunt

.PHONY: help up down clean tools infra infra-plan infra-check check-s1

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
