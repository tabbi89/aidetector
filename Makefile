# AI-Detector — developer entrypoints.
#
# Quick start:  make start   (everything: stack + OAST + ZAP + Kali, migrated)
#               make stop    (stop it all, keep the database volume)
# Everything is thin wrappers around docker compose + alembic, so nothing here
# hides state you can't reproduce by hand.

COMPOSE ?= docker compose
# The web UI's host port (WEB_HOST_PORT in .env), for the ready banners.
WEB_HOST_PORT ?= $(or $(shell sed -n 's/^WEB_HOST_PORT=//p' .env 2>/dev/null),3000)

# Run one-off/exec commands non-interactively (-T) so they work in CI too.
DC_EXEC := $(COMPOSE) exec -T

.DEFAULT_GOAL := help
.PHONY: help env start stop up up-oob up-zap up-kali up-all up-aws migrate wait-db migration \
        down down-v fresh logs ps rebuild test lint

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# The api encrypts credentials and the worker decrypts them, so both must share
# one VAULT_KEY — generate it here rather than leave each process to invent its own.
env: ## Create .env (with a generated VAULT_KEY) from .env.example if it does not exist
	@if [ ! -f .env ]; then \
	  key=$$(openssl rand -base64 32 | tr '+/' '-_'); \
	  awk -v k="$$key" '/^VAULT_KEY=$$/ {print "VAULT_KEY=" k; next} {print}' .env.example > .env && \
	  echo "created .env with a generated VAULT_KEY — set any AI/OAST/ZAP keys you need"; \
	elif grep -q '^VAULT_KEY=$$' .env; then \
	  echo "warning: VAULT_KEY is empty in .env — the api and worker will each invent a key and scans cannot read their credentials"; \
	fi

up: env ## Start the full stack (build) and apply all schema migrations
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait-db
	@$(MAKE) --no-print-directory migrate
	@echo ""
	@echo "stack ready:  web http://localhost:$(WEB_HOST_PORT)   api http://localhost:8000   target :9000"

up-oob: env ## Start the stack + self-hosted interactsh (OAST) and migrate
	$(COMPOSE) --profile oob up -d --build
	@$(MAKE) --no-print-directory wait-db
	@$(MAKE) --no-print-directory migrate
	@echo "OOB enabled — set OAST_SERVER in .env to activate the oob_injection check"

up-zap: env ## Start the stack + OWASP ZAP daemon and migrate
	$(COMPOSE) --profile zap up -d --build
	@$(MAKE) --no-print-directory wait-db
	@$(MAKE) --no-print-directory migrate
	@echo "ZAP enabled — set ZAP_BASE_URL in .env and run scans with zap:true"

up-kali: env ## Start the stack + Kali adjunct service (nuclei/ffuf) and migrate
	$(COMPOSE) --profile kali up -d --build
	@$(MAKE) --no-print-directory wait-db
	@$(MAKE) --no-print-directory migrate
	@echo "Kali enabled — set KALI_BASE_URL in .env and run scans with kali:true"

# up-all also mounts the local AWS credential chain when there is one: running it
# after up-aws would otherwise recreate the worker without it, and monitoring
# collection fails with credential_unavailable.
AWS_CONFIG_DIR ?= $(HOME)/.aws
AWS_OVERLAY := $(if $(wildcard $(AWS_CONFIG_DIR)),-f docker-compose.yml -f docker-compose.aws.yml)

up-all: env ## Start the stack + interactsh + ZAP + Kali (+ ~/.aws if present) and migrate
	$(COMPOSE) $(AWS_OVERLAY) --profile oob --profile zap --profile kali up -d --build
	@$(MAKE) --no-print-directory wait-db
	@$(MAKE) --no-print-directory migrate

start: up-all ## Start everything (stack + interactsh + ZAP + Kali) and migrate
	@echo ""
	@echo "all services up:  web http://localhost:$(WEB_HOST_PORT)   api http://localhost:8000   target :9000"
	@echo "adjuncts: interactsh (oob), ZAP, Kali — stop everything with: make stop"

stop: down ## Stop everything started by make start (keep the database volume)

up-aws: env ## Start the stack with your local AWS profile mounted read-only into the worker
	$(COMPOSE) -f docker-compose.yml -f docker-compose.aws.yml up -d --build
	@$(MAKE) --no-print-directory wait-db
	@$(MAKE) --no-print-directory migrate
	@echo "AWS credential chain mounted — list log-group ARNs in MONITORING_AWS_LOG_GROUPS"

wait-db: ## Block until Postgres accepts connections
	@echo "waiting for postgres..."
	@until $(DC_EXEC) postgres pg_isready -U aidetector -q; do sleep 1; done
	@echo "postgres ready"

migrate: ## Apply all Alembic migrations (alembic upgrade head)
	$(DC_EXEC) api alembic upgrade head

migration: ## Autogenerate a revision:  make migration m="add widgets table"
	@test -n "$(m)" || { echo "usage: make migration m=\"message\""; exit 1; }
	$(DC_EXEC) api alembic revision --autogenerate -m "$(m)"

admin: ## Create the workspace admin (or reset their password):  make admin email=you@example.com name="You"
	@test -n "$(email)" || { echo "usage: make admin email=you@example.com [name=\"You\"]"; exit 1; }
	$(COMPOSE) exec api python -m app.manage create-admin --email "$(email)" --name "$(name)"

down: ## Stop the stack (keep the database volume)
	$(COMPOSE) --profile oob --profile zap --profile kali down

down-v: ## Stop the stack and DELETE the database volume
	$(COMPOSE) --profile oob --profile zap --profile kali down -v

fresh: down-v up ## Wipe the database, then start clean and re-migrate

logs: ## Follow logs for all services
	$(COMPOSE) logs -f

ps: ## Show service status
	$(COMPOSE) ps

rebuild: ## Rebuild images without starting
	$(COMPOSE) build

# Each gate ends with a line saying it passed, printed only when it did, so a
# run that was filtered or cut short still shows which gates passed (the
# feature-pipeline band in .claude/skills reads these lines).
check: lint test test-cli web test-web ## Every gate but the code review: lint, tests, CLI, web build, e2e, diff check
	git diff --check
	@echo "Diff check passed."
	@echo "All checks passed."

test: ## Run the API test suite inside the api container (parallel; one _test DB per worker)
	$(DC_EXEC) api pytest -n auto -q
	@echo "Tests passed."

lint: ## Run ruff + mypy inside the api container
	$(DC_EXEC) api ruff check .
	$(DC_EXEC) api mypy app
	@echo "Lint passed."

web: ## Lint, type-check and build the web app
	cd apps/web && npm run lint && npx tsc --noEmit && npm run build
	@echo "Web build passed."

# Separate process/service suite; TEST_DATABASE_URL and TEST_REDIS_URL are required.
test-integration: ## Run real-worker tests locally against explicit test services
	cd services/api && .venv/bin/python -m pytest integration_tests -q

test-web: ## Build the UI and run Chromium workflows with a mocked API
	cd apps/web && npm run test:e2e
	@echo "End-to-end tests passed."

test-coverage: ## Full DB-backed coverage report and floors (local venv)
	cd services/api && TEST_REQUIRE_DB=1 .venv/bin/python -m pytest -ra --cov=app --cov-report=term:skip-covered --cov-report=json --cov-report=xml --junitxml=test-report.xml
	cd services/api && .venv/bin/python -m scripts.check_coverage

test-contracts: ## Compare handwritten web types with the exported backend OpenAPI
	cd services/api && .venv/bin/python -m scripts.export_openapi ../../apps/web/contracts/openapi.json
	cd apps/web && npm run test:contracts

test-mutation: ## Report targeted policy mutations (no database or target needed)
	cd services/api && .venv/bin/mutmut run --max-children 2
	cd services/api && .venv/bin/mutmut results > mutation-results.txt
	cd services/api && .venv/bin/python -m scripts.mutation_report

.PHONY: check web test-integration test-web test-coverage test-contracts test-mutation

# --- aidetector CLI (Go) -----------------------------------------------------
# Go is not required on the host: every target runs in the official image.
GO_IMAGE ?= golang:1.23
CLI_OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
CLI_ARCH := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
# `aidetector version` prints this; a tag is nice, a bare commit is enough.
CLI_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO_RUN   := docker run --rm --user $$(id -u):$$(id -g) -e HOME=/tmp -e GOPATH=/tmp/go \
            -e GOCACHE=/tmp/gocache -v "$(CURDIR)/cli":/src -w /src

cli: ## Build cli/bin/aidetector for this machine
	@mkdir -p cli/bin
	$(GO_RUN) -e CGO_ENABLED=0 -e GOOS=$(CLI_OS) -e GOARCH=$(CLI_ARCH) $(GO_IMAGE) \
	    go build -trimpath -ldflags "-s -w -X aidetector/cli/internal/commands.Version=$(CLI_VERSION)" \
	    -o bin/aidetector ./cmd/aidetector
	@echo "built cli/bin/aidetector ($(CLI_OS)/$(CLI_ARCH))"

BINDIR ?= /usr/local/bin

install-cli: cli ## Build the CLI and install it as /usr/local/bin/aidetector (sudo only if needed; BINDIR=dir to change)
	@if [ -w "$(BINDIR)" ]; then \
	    install -m 0755 cli/bin/aidetector "$(BINDIR)/aidetector"; \
	else \
	    echo "$(BINDIR) is not writable; installing with sudo"; \
	    sudo install -m 0755 cli/bin/aidetector "$(BINDIR)/aidetector"; \
	fi
	@echo "installed $(BINDIR)/aidetector ($$("$(BINDIR)/aidetector" version 2>/dev/null || echo unknown version))"

cli-all: ## Cross-compile the CLI for macOS, Linux and Windows into cli/bin
	@mkdir -p cli/bin
	@for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do \
	    os=$${target%/*}; arch=$${target#*/}; ext=""; [ "$$os" = windows ] && ext=".exe"; \
	    echo "-> $$os/$$arch"; \
	    $(GO_RUN) -e CGO_ENABLED=0 -e GOOS=$$os -e GOARCH=$$arch $(GO_IMAGE) \
	        go build -trimpath -ldflags "-s -w -X aidetector/cli/internal/commands.Version=$(CLI_VERSION)" \
	            -o bin/aidetector-$$os-$$arch$$ext ./cmd/aidetector || exit 1; \
	done

test-cli: ## gofmt + vet + race-enabled tests for the CLI
	$(GO_RUN) $(GO_IMAGE) sh -c 'test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }; \
	    go vet ./... && go test -race -count=1 ./...'
	@echo "CLI tests passed."

runner-image: ## Build the runner image every `aidetector` CLI run uses (OAST + the confirm/testssl tools)
	docker build -f services/api/runner.Dockerfile \
	    --label org.opencontainers.image.revision=$(CLI_VERSION) \
	    -t aidetector-runner:latest services/api

kali-image: ## Build the Kali adjunct image `aidetector run --zap/--kali` starts as a sibling
	docker build -t aidetector-kali:latest services/kali

cli-contract: ## Refresh cli/testdata/openapi.json from the running api (then run test-cli)
	$(DC_EXEC) api python -m scripts.export_openapi /app/openapi.json
	cp services/api/openapi.json cli/testdata/openapi.json

.PHONY: cli install-cli cli-all test-cli cli-contract runner-image kali-image

# --- Production (aidetector.com) ----------------------------------------------
# One host over ssh; see deploy/compose.prod.yml. Secrets stay on the host in
# /etc/runpentests.env and are generated there on the first deploy.
DEPLOY_HOST ?= prod-runpentests
DEPLOY_DIR  ?= /opt/runpentests
PROD_DC     := sudo docker compose -f $(DEPLOY_DIR)/deploy/compose.prod.yml --env-file /etc/runpentests.env

deploy: ## Ship the committed tree to prod-runpentests and (re)start production (ALLOW_DIRTY=1 to ship uncommitted work)
	@DEPLOY_HOST=$(DEPLOY_HOST) DEPLOY_DIR=$(DEPLOY_DIR) scripts/deploy.sh

deploy-admin: ## Create or reset the production admin:  make deploy-admin email=you@example.com name="You"
	@test -n "$(email)" || { echo "usage: make deploy-admin email=you@example.com [name=\"You\"]"; exit 1; }
	ssh -t $(DEPLOY_HOST) '$(PROD_DC) exec api python -m app.manage create-admin --email "$(email)" --name "$(name)"'

deploy-ps: ## Show production service status
	ssh $(DEPLOY_HOST) '$(PROD_DC) ps'

deploy-logs: ## Follow production logs (s=api to pick one service)
	ssh -t $(DEPLOY_HOST) '$(PROD_DC) logs -f --tail 100 $(s)'

.PHONY: deploy deploy-admin deploy-ps deploy-logs
