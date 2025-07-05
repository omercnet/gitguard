# GitGuard 🛡️

A GitHub App that scans commits for secrets using [Gitleaks](https://github.com/gitleaks/gitleaks).

## Features

- **Secret Detection**: 100+ built-in rules for API keys, tokens, passwords, and credentials
- **GitHub Integration**: Creates check runs on commits with pass/fail status
- **Privacy First**: Never logs or stores actual secrets, stateless operation
- **Zero Dependencies**: Single binary with environment variable configuration
- **Production Ready**: Structured logging, pre-commit hooks, security scanning

## Quick Start

1. **Environment Variables**:

   ```bash
   export GITHUB_WEBHOOK_SECRET="your-webhook-secret"
   export GITHUB_APP_ID="123456"
   export GITHUB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
   ...your private key...
   -----END PRIVATE KEY-----"
   ```

2. **Run**:

   ```bash
   make all    # Build and test
   ./gitguard  # Start server on port 8080
   ```

## GitHub App Setup

Create a GitHub App with minimal permissions:

- **Repository contents**: Read
- **Checks**: Write  
- **Metadata**: Read

Subscribe to **Push** events and set webhook URL to your deployment.

## Security & Privacy

- **No Secret Storage**: Secrets are never logged, stored, or transmitted
- **Minimal Permissions**: Only requires read access to changed files
- **Stateless Design**: No database or persistent storage required
- **In-Memory Processing**: Files scanned in memory, never written to disk
- **Standard Compliance**: Uses official Gitleaks detection rules

## Development

```bash
make all                    # Run all checks and build
make test                   # Run tests
make security              # Security scanning
make lefthook-install      # Install pre-commit hooks

# Development mode with debug logging
LOG_LEVEL=debug LOG_PRETTY=1 go run main.go
```

## Deployment

**Container**:

```bash
docker run -p 8080:8080 \
  -e GITHUB_WEBHOOK_SECRET=... \
  -e GITHUB_APP_ID=... \
  -e GITHUB_PRIVATE_KEY=... \
  ghcr.io/omercnet/gitguard:latest
```

**Environment Variables**:

- `GITHUB_WEBHOOK_SECRET` - GitHub webhook secret (required)
- `GITHUB_APP_ID` - GitHub App ID (required)  
- `GITHUB_PRIVATE_KEY` - GitHub App private key (required)
- `PORT` - Server port (default: 8080)
- `LOG_LEVEL` - Log level: trace, debug, info, warn, error (default: info)
- `LOG_PRETTY` - Pretty console output for development (optional)

## How It Works

1. Receives GitHub push webhook
2. Creates "in progress" check run
3. Fetches only changed files from the commit
4. Scans file contents with Gitleaks engine
5. Updates check run with results (pass/fail + summary)

## License

MIT License - see [LICENSE](LICENSE)

---
**GitGuard** - Simple secret scanning for GitHub! 🛡️
