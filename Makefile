.PHONY: all build run test clean fmt lint tidy deps coverage quality security lefthook-install lefthook-run help ko-local ko-build ko-run ko-apply

##@ Main Tasks

all: deps quality test security build ## Run all essential tasks (deps, quality, test, security, build)
	@echo "✅ All essential tasks completed successfully!"

##@ Build & Run

build: ## Build the gitguard binary
	go build -o gitguard ./cmd/gitguard

run: ## Run the application
	go run ./cmd/gitguard

##@ Testing

test: ## Run tests
	go test -v ./...

coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | grep total | awk '{print "Coverage: " $$3}'

##@ Dependencies & Quality

deps: ## Install dependencies
	go mod download
	go mod tidy
	go mod verify

quality: fmt tidy ## Run quality checks
	@echo "Running quality checks..."
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted correctly"; \
		gofmt -s -d .; \
		exit 1; \
	fi
	@echo "Quality checks passed"

fmt: ## Format code
	go fmt ./...

lint: ## Run linter (if available)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping..."; \
	fi

tidy: ## Tidy dependencies
	go mod tidy

##@ Security & Hooks

security: ## Run security checks
	@echo "Running security checks..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed, install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

lefthook-install: ## Install and configure lefthook
	@echo "Installing lefthook..."
	@if ! command -v lefthook >/dev/null 2>&1; then \
		echo "Installing lefthook..."; \
		go install github.com/evilmartians/lefthook@latest; \
	fi
	@lefthook install
	@echo "✅ Lefthook installed and configured"

lefthook-run: ## Run lefthook pre-commit hooks
	@if command -v lefthook >/dev/null 2>&1; then \
		lefthook run pre-commit; \
	else \
		echo "Lefthook not installed. Run 'make lefthook-install' first."; \
	fi

##@ Container & Ko

ko-local: ## Build container image locally with Ko
	@echo "Building container image locally..."
	@if ! command -v ko >/dev/null 2>&1; then \
		echo "Ko not installed. Install with: go install github.com/google/ko@latest"; \
		exit 1; \
	fi
	@export KO_DOCKER_REPO=ko.local && \
	export VERSION=$$(git describe --tags --always --dirty) && \
	export COMMIT=$$(git rev-parse HEAD) && \
	export DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) && \
	ko build --local ./cmd/gitguard

ko-build: ## Build and push container image with Ko (requires KO_DOCKER_REPO)
	@echo "Building and pushing container image..."
	@if ! command -v ko >/dev/null 2>&1; then \
		echo "Ko not installed. Install with: go install github.com/google/ko@latest"; \
		exit 1; \
	fi
	@if [ -z "$$KO_DOCKER_REPO" ]; then \
		echo "KO_DOCKER_REPO environment variable must be set"; \
		echo "Example: export KO_DOCKER_REPO=ghcr.io/omercnet/gitguard"; \
		exit 1; \
	fi
	@export VERSION=$$(git describe --tags --always --dirty) && \
	export COMMIT=$$(git rev-parse HEAD) && \
	export DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) && \
	ko build ./cmd/gitguard \
		--image-label org.opencontainers.image.title=GitGuard \
		--image-label org.opencontainers.image.description="A GitHub App for detecting secrets in commits using Gitleaks" \
		--image-label org.opencontainers.image.source=https://github.com/omercnet/gitguard \
		--image-label org.opencontainers.image.vendor=omercnet \
		--image-label org.opencontainers.image.licenses=MIT \
		--image-label org.opencontainers.image.version=$$VERSION \
		--image-label org.opencontainers.image.revision=$$COMMIT \
		--image-label org.opencontainers.image.created=$$DATE \
		--image-label org.opencontainers.image.url=https://github.com/omercnet/gitguard \
		--image-label org.opencontainers.image.documentation=https://github.com/omercnet/gitguard/blob/main/README.md \
		--tags $$VERSION,latest

ko-run: ## Run the container locally with Ko
	@echo "Running container locally..."
	@if ! command -v ko >/dev/null 2>&1; then \
		echo "Ko not installed. Install with: go install github.com/google/ko@latest"; \
		exit 1; \
	fi
	@export VERSION=$$(git describe --tags --always --dirty) && \
	export COMMIT=$$(git rev-parse HEAD) && \
	export DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) && \
	ko run ./cmd/gitguard

ko-apply: ## Apply Kubernetes manifests with Ko (requires manifests and KO_DOCKER_REPO)
	@echo "Applying Kubernetes manifests with Ko..."
	@if ! command -v ko >/dev/null 2>&1; then \
		echo "Ko not installed. Install with: go install github.com/google/ko@latest"; \
		exit 1; \
	fi
	@if [ -z "$$KO_DOCKER_REPO" ]; then \
		echo "KO_DOCKER_REPO environment variable must be set"; \
		exit 1; \
	fi
	@if [ ! -d "k8s" ] && [ ! -d "deploy" ] && [ ! -d "manifests" ]; then \
		echo "No Kubernetes manifests found in k8s/, deploy/, or manifests/ directories"; \
		exit 1; \
	fi
	@export VERSION=$$(git describe --tags --always --dirty) && \
	export COMMIT=$$(git rev-parse HEAD) && \
	export DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) && \
	for dir in k8s deploy manifests; do \
		if [ -d "$$dir" ]; then \
			echo "Applying manifests from $$dir/"; \
			ko apply -f $$dir/; \
			break; \
		fi; \
	done

##@ Utilities

clean: ## Clean build artifacts
	rm -f gitguard coverage.out

# Show help - automatically generated from target comments
help: ## Show this help
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)