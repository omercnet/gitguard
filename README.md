# GitGuard 🛡️

A high-performance GitHub App that scans commits for secrets and sensitive information using the [Gitleaks](https://github.com/gitleaks/gitleaks) library. GitGuard automatically creates GitHub check runs to report security findings directly in your pull requests and commits.

## ✨ Features
- **Comprehensive Secret Detection**: 100+ built-in rules for API keys, tokens, passwords, and more
- **High Performance**: In-memory scanning, only changed files, no file I/O
- **Privacy-First**: Never stores or logs actual secrets
- **Real-Time Scanning**: Responds instantly to push events
- **GitHub Integration**: Detailed check runs with pass/fail status
- **Stateless & Scalable**: No database, cloud-ready, minimal resources
- **Signed Images & SBOM**: Supply chain security and transparency

## 🚀 Quick Start
1. **Clone & Install**
   ```bash
   git clone https://github.com/omercnet/gitguard.git && cd gitguard
   make deps
   cp config-example.yml config.yml
   ```
2. **Configure**: Edit `config.yml` or set environment variables (see below).
3. **Run**:
   ```bash
   make build
   ./gitguard
   # or
   make run
   ```

## ⚙️ Configuration
- **GitHub App**: Create an app, set required permissions (Checks: RW, Contents: R, Metadata: R, PRs: R), subscribe to Push events, get App ID and private key.
- **Config file** (`config.yml`):
  ```yaml
github:
  webhook_secret: "your-webhook-secret"
  app_id: 123456
  private_key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
server:
  port: 8080
  ```
- **Environment variables** (alternative):
  ```bash
  export GITHUB_WEBHOOK_SECRET=...
  export GITHUB_APP_ID=...
  export GITHUB_PRIVATE_KEY=...
  export PORT=8080
  ```

## 🛠️ Development
- **All tasks use the Makefile**:
  - `make build` — Build binary
  - `make run` — Build and run
  - `make test` — Run tests
  - `make coverage` — Test with coverage check
  - `make lint` — Lint code
  - `make quality` — Format, import, tidy, whitespace checks
  - `make security` — Run govulncheck
  - `make ci` — Run all checks
  - `make check-commit` — Validate commit message
  - `make help` — List all commands

- **Conventional Commits**: Enforced via CI and `make check-commit`.
- **Pre-commit hooks**: `make install-lefthook` to set up [lefthook](https://github.com/evilmartians/lefthook).

## 🚀 Deployment
- **Build container image with GoReleaser (recommended)**:
  ```bash
  make goreleaser-build
  # or directly:
  goreleaser build --snapshot --clean
  ```
- **Run the container**:
  ```bash
  docker run -p 8080:8080 \
    -e GITHUB_WEBHOOK_SECRET=... \
    -e GITHUB_APP_ID=... \
    -e GITHUB_PRIVATE_KEY=... \
    ghcr.io/omercnet/gitguard:latest
  ```
- **Pre-built image**: `docker pull ghcr.io/omercnet/gitguard:latest`
- **Docker secrets**: Use `*_FILE` env vars and mount secrets as files.
- **Cloud/Serverless**: Stateless, can run on Cloud Run, Lambda, etc.

## 🔍 How It Works
1. Receives GitHub push event
2. Fetches changed files only
3. Scans in-memory with Gitleaks
4. Aggregates findings (never logs secrets)
5. Reports via GitHub check runs

## 🤝 Contributing
- Fork, branch, and PR (conventional commits required)
- Run `make ci` before pushing
- Add tests for new features
- Never log or store secrets

## 🔒 Security
- No secret storage or logging
- Minimal permissions
- Stateless, memory-only processing
- Signed images and SBOM

## 📄 License
MIT — see [LICENSE](LICENSE)

## 📞 Support
- [GitHub Issues](https://github.com/omercnet/gitguard/issues)
- [GitHub Discussions](https://github.com/omercnet/gitguard/discussions)
- [Wiki](https://github.com/omercnet/gitguard/wiki)

---
**GitGuard** — Keeping your secrets safe, one commit at a time! 🛡️
