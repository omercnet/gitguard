# GitGuard Makefile
# All development tasks use this Makefile for consistency

# Variables
BINARY_NAME=gitguard
LDFLAGS=-ldflags "-s -w"
COVERAGE_FILE=coverage.out
COVERAGE_THRESHOLD=60

# Main CI target (excludes linting - now handled by GitHub Action)
ci: deps quality test-coverage build
	@echo "✅ All CI checks passed!"

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	go mod download
	go mod tidy
	@echo "✅ Dependencies installed"

# Auto-fix all formatting issues
fix: fmt-go fmt-imports fmt-whitespace go-mod-tidy
	@echo "✅ All formatting issues fixed"

# Format Go code
fmt-go:
	@echo "🔧 Formatting Go code..."
	@gofmt -s -w .
	@echo "✅ Go code formatted"

# Import formatting
fmt-imports:
	@echo "📦 Formatting imports..."
	@which gci >/dev/null 2>&1 || (echo "Installing gci..." && go install github.com/daixiang0/gci@latest)
	@gci write .
	@echo "✅ Import formatting completed"

# Remove trailing whitespace
fmt-whitespace:
	@echo "🧹 Removing trailing whitespace..."
	@if command -v gsed >/dev/null 2>&1; then \
		find . -type f \( -name "*.go" -o -name "*.md" -o -name "*.yml" -o -name "*.yaml" \) -exec gsed -i 's/[[:space:]]*$$//' {} \; ; \
	elif sed --version 2>/dev/null | grep -q GNU; then \
		find . -type f \( -name "*.go" -o -name "*.md" -o -name "*.yml" -o -name "*.yaml" \) -exec sed -i 's/[[:space:]]*$$//' {} \; ; \
	else \
		find . -type f \( -name "*.go" -o -name "*.md" -o -name "*.yml" -o -name "*.yaml" \) -exec sed -i '' 's/[[:space:]]*$$//' {} \; ; \
	fi
	@echo "✅ Trailing whitespace removed"

# Tidy go modules
go-mod-tidy:
	@echo "📦 Tidying go modules..."
	@go mod tidy
	@echo "✅ Go modules tidied"

# Lint code
lint:
	@echo "🔍 Running linters..."
	@which golangci-lint >/dev/null 2>&1 || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run --config=.golangci.yml
	@echo "✅ Linting completed"

# Quality checks
quality: fmt-imports
	@echo "✨ Running quality checks..."
	@echo "Checking Go formatting..."
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "❌ Go code is not formatted correctly"; \
		gofmt -s -d .; \
		exit 1; \
	fi; \
	echo "✅ Go code is formatted correctly"
	@echo "Checking Go modules tidiness..."
	@go mod tidy; \
	if [ -n "$$(git status --porcelain go.mod go.sum 2>/dev/null || echo '')" ]; then \
		echo "❌ go.mod or go.sum is not tidy"; \
		git diff go.mod go.sum 2>/dev/null || echo "Cannot show diff in CI environment"; \
		exit 1; \
	fi; \
	echo "✅ go.mod and go.sum are tidy"
	@echo "Checking for trailing whitespace..."
	@if grep -r '[[:space:]]$$' --include="*.go" --include="*.md" --include="*.yml" --include="*.yaml" .; then \
		echo "❌ Files contain trailing whitespace"; \
		exit 1; \
	fi; \
	echo "✅ No trailing whitespace found"
	@echo "✅ Quality checks completed"

# Run tests
test:
	@echo "🧪 Running tests..."
	go test -v ./...
	@echo "✅ Tests completed"

# Run tests with coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	go test -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@echo "✅ Tests completed"

# Check test coverage
coverage: test-coverage
	@echo "📊 Checking test coverage..."
	@go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print "Coverage: " $$3}'
	@COVERAGE=$$(go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$COVERAGE" -lt $(COVERAGE_THRESHOLD) ]; then \
		echo "❌ Test coverage is too low: $$COVERAGE% (minimum $(COVERAGE_THRESHOLD)%)"; \
		exit 1; \
	fi; \
	echo "✅ Test coverage is acceptable: $$COVERAGE%"

# Build binary
build:
	@echo "🔨 Building binary..."
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/gitguard
	@echo "✅ Binary built successfully"

# Build container image with ko
ko-build:
	@echo "🐳 Building container image with ko..."
	@which ko >/dev/null 2>&1 || (echo "Installing ko..." && go install github.com/google/ko@latest)
	@ko build --local github.com/omercnet/gitguard/cmd/gitguard
	@echo "✅ Container image built successfully"

# Security scanning
security:
	@echo "🔒 Running security scans..."
	@echo "Running govulncheck..."
	@which govulncheck >/dev/null 2>&1 || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	@govulncheck ./...
	@echo "✅ Security scanning completed"

# Container security scan
container-security:
	@echo "🔒 Running container security scan..."
	@which trivy >/dev/null 2>&1 || (echo "Installing Trivy..." && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.0)
	@trivy image --severity CRITICAL,HIGH ko.local/github.com/omercnet/gitguard/cmd/gitguard:ci
	@echo "✅ Container security scan completed"

# Test release build locally
release-test:
	@echo "🧪 Testing release build..."
	@which ko >/dev/null 2>&1 || (echo "Installing ko..." && go install github.com/google/ko@latest)
	@export KO_DOCKER_REPO=gitguard-test && ko build --local github.com/omercnet/gitguard/cmd/gitguard
	@echo "✅ Release test completed"

# Install lefthook for pre-commit hooks
install-lefthook:
	@echo "🔧 Installing lefthook..."
	@which lefthook >/dev/null 2>&1 || (echo "Installing lefthook..." && curl -sfL https://raw.githubusercontent.com/evilmartians/lefthook/master/install.sh | sh -s -- -b /usr/local/bin)
	@lefthook install
	@echo "✅ Lefthook installed and configured"

# Run pre-commit hooks
pre-commit:
	@echo "🔍 Running pre-commit hooks..."
	@lefthook run pre-commit
	@echo "✅ Pre-commit hooks completed"

# Check commit message format 
check-commit:
	@echo "🔍 Checking last commit message format..."
	@command -v npx >/dev/null 2>&1 || (echo "❌ npx not found. Install Node.js to use commitlint." && exit 1)
	@command -v commitlint >/dev/null 2>&1 || (echo "Installing commitlint..." && npm install -g @commitlint/cli @commitlint/config-conventional)
	@git log -1 --pretty=format:"%s" | commitlint || (echo "❌ Use: <type>[scope]: <description>" && exit 1)
	@echo "✅ Commit message follows conventional commit format!"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(COVERAGE_FILE)
	rm -f coverage.html
	@echo "✅ Clean completed"

# Run the application
run: build
	@echo "🚀 Starting GitGuard..."
	./$(BINARY_NAME)

# Help
help:
	@echo "Available targets:"
	@echo "  ci                - Run CI checks (quality, tests, build)"
	@echo "  deps              - Install dependencies"
	@echo "  fix               - Auto-fix all formatting issues"
	@echo "  fmt-go            - Format Go code"
	@echo "  fmt-imports       - Format Go imports"
	@echo "  fmt-whitespace    - Remove trailing whitespace"
	@echo "  go-mod-tidy       - Tidy go modules"
	@echo "  lint              - Run linters"
	@echo "  quality           - Run quality checks"
	@echo "  test              - Run tests"
	@echo "  coverage          - Run tests with coverage check"
	@echo "  build             - Build binary"
	@echo "  ko-build          - Build container image with ko"
	@echo "  security          - Run security scans"
	@echo "  container-security - Scan container for vulnerabilities"
	@echo "  release-test      - Test release build"
	@echo "  install-lefthook  - Install pre-commit hooks"
	@echo "  pre-commit        - Run pre-commit hooks"
	@echo "  check-commit      - Check commit message format"
	@echo "  clean             - Clean build artifacts"
	@echo "  run               - Build and run"
	@echo "  help              - Show this help"

.PHONY: ci deps fix fmt-go fmt-imports fmt-whitespace go-mod-tidy lint quality test test-coverage coverage build ko-build security container-security release-test install-lefthook pre-commit check-commit clean run help 