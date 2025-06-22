# GitGuard 🛡️

A high-performance GitHub App that scans commits for secrets and sensitive information using the [Gitleaks](https://github.com/gitleaks/gitleaks) library. GitGuard automatically creates GitHub check runs to report security findings directly in your pull requests and commits.

## ✨ Features

- **🔍 Comprehensive Secret Detection**: Uses Gitleaks library with 100+ built-in rules for detecting API keys, tokens, passwords, and other sensitive data
- **⚡ High Performance**: In-memory scanning with no file I/O - processes only changed files in commits
- **🛡️ Privacy-First**: Never stores or logs actual secrets - only metadata for reporting
- **🔄 Real-Time Scanning**: Responds immediately to push events via GitHub webhooks
- **📊 GitHub Integration**: Creates detailed check runs with pass/fail status
- **🏗️ Scalable Architecture**: Stateless design that scales horizontally without databases
- **🐳 Cloud-Ready**: Optimized for free hosting services with minimal resource usage
- **🔐 Signed Images**: Container images signed with cosign for supply chain security
- **📋 SBOM Included**: Software Bill of Materials for transparency and vulnerability tracking

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or later
- GitHub App with webhook permissions
- Basic understanding of GitHub Apps and webhooks

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/omercnet/gitguard.git
   cd gitguard
   ```

2. **Quick setup** (recommended):
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

3. **Manual setup**:
   ```bash
   # Install dependencies
   go mod tidy
   
   # Build the application
   go build -o gitguard .
   
   # Copy configuration template
   cp config-example.yml config.yml
   ```

## ⚙️ Configuration

### GitHub App Setup

1. Create a new GitHub App in your organization/account settings
2. Configure the following permissions:
   - **Repository permissions**:
     - Checks: Read & Write
     - Contents: Read
     - Metadata: Read
     - Pull requests: Read

3. Subscribe to webhook events:
   - Push

4. Note your App ID and generate a private key

### Configuration File

Edit `config.yml` with your GitHub App credentials:

```yaml
github:
  webhook_secret: "your-webhook-secret"
  app_id: 123456
  private_key: |
    -----BEGIN PRIVATE KEY-----
    [Your GitHub App private key]
    -----END PRIVATE KEY-----

server:
  port: 8080
```

### Environment Variables

Alternatively, use environment variables:

```bash
export GITHUB_WEBHOOK_SECRET="your-webhook-secret"
export GITHUB_APP_ID="123456"
export GITHUB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."
export PORT="8080"
```

### .env File (Local Development)

For local development, you can use a `.env` file:

```bash
# Copy the example file
cp .env.example .env

# Edit .env with your values
```

Example `.env` file:
```env
# GitHub App Configuration
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
your_private_key_here
-----END RSA PRIVATE KEY-----

# Server Configuration
PORT=8080
```

**Note**: The `.env` file is automatically loaded if it exists. Environment variables take precedence over `.env` file values.

## 🚀 Running GitGuard

### Local Development

```bash
# Run directly
./gitguard

# Or with Go
go run .

# With race detection (development)
go run -race .
```

### Container Images

#### Using pre-built signed images (Recommended)

```bash
# Pull the latest signed container image
docker pull ghcr.io/omercnet/gitguard:latest

# Verify the signature (requires cosign)
cosign verify ghcr.io/omercnet/gitguard:latest \
  --certificate-identity-regexp https://github.com/omercnet/gitguard \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Run with environment variables
docker run -p 8080:8080 \
  -e GITHUB_WEBHOOK_SECRET="your-webhook-secret" \
  -e GITHUB_APP_ID="your-app-id" \
  -e GITHUB_PRIVATE_KEY="your-private-key" \
  gitguard

# Or use secret files (recommended for production)
docker run -p 8080:8080 \
  -e GITHUB_WEBHOOK_SECRET_FILE="/path/to/webhook-secret.txt" \
  -e GITHUB_APP_ID="your-app-id" \
  -e GITHUB_PRIVATE_KEY_FILE="/path/to/private-key.pem" \
  -v /path/to/webhook-secret.txt:/path/to/webhook-secret.txt:ro \
  -v /path/to/private-key.pem:/path/to/private-key.pem:ro \
  gitguard
```

#### Using Docker secrets (recommended for production)

```bash
# First, create the secrets:
echo -n "your-webhook-secret" | docker secret create github_webhook_secret -
echo -n "your-private-key-content" | docker secret create github_private_key -

# Then run the container with secrets mounted
# (Docker Swarm mode required for secrets)
docker service create \
  --name gitguard \
  --secret source=github_webhook_secret,target=webhook-secret.txt \
  --secret source=github_private_key,target=private-key.pem \
  -e GITHUB_WEBHOOK_SECRET_FILE="/run/secrets/webhook-secret.txt" \
  -e GITHUB_APP_ID="your-app-id" \
  -e GITHUB_PRIVATE_KEY_FILE="/run/secrets/private-key.pem" \
  -p 8080:8080 \
  gitguard

# For local testing without Swarm, you can still use file mounts as shown below:
# docker run -p 8080:8080 \
#   -e GITHUB_WEBHOOK_SECRET_FILE="/app/webhook-secret.txt" \
#   -e GITHUB_APP_ID="your-app-id" \
#   -e GITHUB_PRIVATE_KEY_FILE="/app/private-key.pem" \
#   -v $(pwd)/webhook-secret.txt:/app/webhook-secret.txt:ro \
#   -v $(pwd)/private-key.pem:/app/private-key.pem:ro \
#   gitguard
```

#### Local builds

```bash
# Build container image with ko
make ko-build

# Build binary locally
make build

# Run the application
make run
```

### Production Service

```bash
# Install as systemd service (Linux)
sudo ./install.sh --service

# Start the service
sudo systemctl start gitguard
sudo systemctl status gitguard
```

## 🔍 How It Works

1. **Webhook Reception**: GitGuard receives push event webhooks from GitHub
2. **Commit Analysis**: For each commit, it fetches only the changed files' diffs
3. **In-Memory Scanning**: Uses Gitleaks library to scan file contents directly in memory
4. **Result Processing**: Aggregates findings by rule type without exposing actual secrets
5. **GitHub Reporting**: Creates check runs with detailed security status
6. **Clean Exit**: No temporary files or persistent storage - completely stateless

### Performance Benefits

- **Memory Efficient**: Scans files in memory without writing to disk
- **Scalable**: No database dependencies - stateless architecture
- **Fast**: Only processes changed files, not entire repositories
- **Secure**: Never logs or stores actual secret values

## 📊 Check Run Examples

### ✅ Clean Commit
```
✅ No secrets or sensitive information detected in this commit.
```

### 🚨 Secrets Detected
```
🚨 3 secret(s) detected in this commit. Please review and remove sensitive information.

Types of secrets found:
- aws-access-token
- github-pat
- generic-api-key
```

## 🛠️ Development

### Building

```bash
make build      # Build binary
make test       # Run tests
make lint       # Run linter
make fmt        # Format code
make ko-build   # Build container image
make ci         # Run all checks
```

### Releasing

GitGuard uses [release-please](https://github.com/googleapis/release-please) for automated releases:

1. **Commit with conventional commits**: Use `feat:`, `fix:`, `docs:`, etc.
2. **Automatic PRs**: Release-please creates PRs with version bumps
3. **Merge to release**: Merging the PR triggers the release build
4. **Signed artifacts**: All binaries and container images are automatically signed

```bash
# Example conventional commits
git commit -m "feat: add new secret detection rule"
git commit -m "fix: improve error handling in webhook"
git commit -m "docs: update installation instructions"
```

### Testing

```bash
# Run all tests
go test -v ./...

# Test with coverage
go test -v -cover ./...

# Test secret detection
go test -v -run TestGitleaksLibraryIntegration
```

### Architecture

```
GitHub Push Event → GitGuard Webhook → Gitleaks Library → GitHub Check Run
                                    ↓
                              In-Memory Scanning
                              (No File I/O)
```

## 🚀 Deployment

GitGuard can be deployed in multiple ways:

### Option 1: Traditional Server/Container Deployment

Deploy GitGuard as a standalone server using Docker or Kubernetes:

```bash
# Build container image with ko
make ko-build

# Or use the provided Dockerfile
docker build -t gitguard .

# Run with environment variables
docker run -p 8080:8080 \
  -e GITHUB_WEBHOOK_SECRET="your-webhook-secret" \
  -e GITHUB_APP_ID="your-app-id" \
  -e GITHUB_PRIVATE_KEY="your-private-key" \
  gitguard
```

### Option 2: Cloud Run, Lambda, etc.

GitGuard can also be deployed to other serverless platforms. The application is designed to be stateless and can be adapted for AWS Lambda, Google Cloud Functions, etc.

## 📋 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_WEBHOOK_SECRET` | GitHub App webhook secret | ✅* |
| `GITHUB_WEBHOOK_SECRET_FILE` | Path to GitHub App webhook secret file | ✅* |
| `GITHUB_APP_ID` | GitHub App ID | ✅ |
| `GITHUB_PRIVATE_KEY` | GitHub App private key (PEM format) | ✅** |
| `GITHUB_PRIVATE_KEY_FILE` | Path to GitHub App private key file | ✅** |
| `PORT` | Server port (default: 8080) | ❌ |

*Either `GITHUB_WEBHOOK_SECRET` or `GITHUB_WEBHOOK_SECRET_FILE` is required. If both are set, `GITHUB_WEBHOOK_SECRET_FILE` takes precedence.
**Either `GITHUB_PRIVATE_KEY` or `GITHUB_PRIVATE_KEY_FILE` is required. If both are set, `GITHUB_PRIVATE_KEY_FILE` takes precedence.

## 🔧 Configuration Options

### Gitleaks Rules

GitGuard uses the default Gitleaks configuration with 100+ built-in rules. The detection includes:

- **Cloud Providers**: AWS, GCP, Azure access keys
- **Version Control**: GitHub, GitLab, Bitbucket tokens
- **Databases**: MongoDB, MySQL, PostgreSQL connection strings
- **Communication**: Slack, Discord, Mailgun tokens
- **Generic Patterns**: High-entropy strings, API key formats

### Resource Limits

- **File Size Limit**: 1000 changes per file (configurable)
- **Memory Usage**: ~10-50MB per scan operation
- **Timeout**: 30-second webhook timeout
- **Concurrency**: Handles multiple repositories simultaneously

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following conventional commits
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Conventional Commits

We use [conventional commits](https://www.conventionalcommits.org/) for automated releases:

- `feat: add new feature` - triggers minor version bump
- `fix: resolve bug` - triggers patch version bump  
- `docs: update readme` - documentation changes
- `chore: update dependencies` - maintenance tasks
- `perf: improve performance` - performance improvements
- `test: add missing tests` - test additions

### Commit Validation

Conventional commits are enforced both locally and in CI:

- **Commit Hooks**: Uses [lefthook](https://github.com/evilmartians/lefthook) for fast, reliable Git hooks. To set up:

```bash
make install-lefthook
# or manually:
go install github.com/evilmartians/lefthook@latest
lefthook install
```

- **Linting & Tests**: Run `make lint` and `make test` or use `lefthook run pre-commit` to check before committing.

### Development Guidelines

- Follow Go conventions and gofmt
- Add tests for new functionality
- Update documentation for new features
- Keep the stateless architecture
- Never log actual secret values
- Use conventional commit messages

## 📈 Monitoring

### Health Check

```bash
curl http://localhost:8080/health
# Returns: 200 OK
```

### Logs

GitGuard provides structured JSON logging:

```json
{
  "level": "info",
  "time": "2024-01-15T10:30:00Z",
  "message": "Commit scan completed",
  "commit_sha": "abc123...",
  "has_leaks": false,
  "files_scanned": 3,
  "total_findings": 0
}
```

## 🔒 Security

- **No Secret Storage**: Secrets are never stored or logged
- **Minimal Permissions**: Only requires read access to repository contents
- **Stateless Design**: No persistent data that could be compromised
- **Memory-Only Processing**: All scanning happens in memory

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Gitleaks](https://github.com/gitleaks/gitleaks) - The powerful secret detection engine
- [go-githubapp](https://github.com/palantir/go-githubapp) - GitHub App framework for Go
- [go-github](https://github.com/google/go-github) - GitHub API client for Go

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/omercnet/gitguard/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/omercnet/gitguard/discussions)
- 📖 **Documentation**: [Wiki](https://github.com/omercnet/gitguard/wiki)

---

**GitGuard** - Keeping your secrets safe, one commit at a time! 🛡️ 
