.PHONY: build test clean deps lint fmt vet ko-build release-test ci help install-lefthook hooks

# Variables
BINARY_NAME=gitguard
LDFLAGS=-ldflags "-s -w"

# Default target
all: deps lint test build

# Build
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/gitguard

# Test
test:
	@echo "Running tests..."
	@go test -v -race ./...

# Lint
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run

# Format
fmt:
	go fmt ./...

# Vet
vet:
	go vet ./...

# Dependencies
deps:
	go mod download
	go mod tidy
	@echo "Checking lefthook installation..."
	@which lefthook >/dev/null 2>&1 || (echo "Installing lefthook..." && go install github.com/evilmartians/lefthook@latest)
	@lefthook install

# Build container with ko
ko-build:
	@which ko > /dev/null || go install github.com/google/ko@latest
	@export KO_DOCKER_REPO=gitguard-local && ko build --local ./cmd/gitguard

# Test release build locally
release-test:
	@which ko > /dev/null || go install github.com/google/ko@latest
	@export KO_DOCKER_REPO=gitguard-test && ko build --local ./cmd/gitguard

# Run all checks
ci: deps lint vet test build

# Clean
clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -rf dist/

# Run
run: build
	./$(BINARY_NAME)

# Check commit message format 
check-commit:
	@echo "🔍 Checking last commit message format..."
	@command -v npx >/dev/null 2>&1 || (echo "❌ npx not found. Install Node.js to use commitlint." && exit 1)
	@git log -1 --pretty=format:"%s" | npx commitlint || (echo "❌ Use: <type>[scope]: <description>" && exit 1)
	@echo "✅ Commit message follows conventional commit format!"

# Help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  deps         - Install dependencies"
	@echo "  ko-build     - Build container image with ko"
	@echo "  release-test - Test release build locally"
	@echo "  check-commit - Check last commit message format"
	@echo "  ci           - Run all checks"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Build and run"
	@echo "  help         - Show this help"

.PHONY: install-lefthook
install-lefthook:
	@echo "Installing lefthook..."
	@go install github.com/evilmartians/lefthook@latest
	@lefthook install

.PHONY: hooks
hooks:
	@echo "Setting up lefthook hooks..."
	@lefthook install 