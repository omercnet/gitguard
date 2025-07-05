.PHONY: all build run test clean fmt lint tidy deps coverage quality security lefthook-install lefthook-run help

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

##@ Utilities

clean: ## Clean build artifacts
	rm -f gitguard coverage.out

# Show help - automatically generated from target comments
help: ## Show this help
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)