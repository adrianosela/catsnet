SHELL := /bin/bash
PROGRAM_NAME := catsnet

# Helper function to check if CATSNET_TS_AUTHKEY is set
define check_ts_authkey
	@if [ -z "$$CATSNET_TS_AUTHKEY" ]; then \
		echo "ERROR: CATSNET_TS_AUTHKEY is not set. Please set it before running this command."; \
		exit 1; \
	fi
endef

.PHONY: help
help: ## Print this help menu
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: run
run: ## Run the catsnet service
	$(call check_ts_authkey)
	@go run . \
		-authkey=$$CATSNET_TS_AUTHKEY \
		-cert="./.sample_data/ca-cert.pem" \
		-key="./.sample_data/ca-key.pem"

.PHONY: build
build: ## Build binary for current OS/ARCH
	@go build -o $(PROGRAM_NAME) .

.PHONY: lint
lint: ## Lint code
	@golangci-lint run ./...
