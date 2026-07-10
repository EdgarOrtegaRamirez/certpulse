# AGENTS.md

## Project: CertPulse

### Overview
CertPulse is a Go CLI tool for TLS certificate monitoring. It connects to hosts over TLS, extracts certificate details, and reports on expiration status.

### Build & Test Commands
```bash
# Build
go build -o certpulse ./cmd/certpulse

# Run tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run tests verbose
go test ./... -v

# Vet
go vet ./...

# Format
gofmt -w .
```

### Architecture
- `cmd/certpulse/main.go` — CLI entry point using Cobra
- `internal/checker/` — TLS connection and certificate extraction logic
- `internal/report/` — Data structures (CertInfo, CheckResult, Summary) and exit code logic
- `internal/output/` — Output formatters (text, JSON, CSV)

### Key Patterns
- Concurrent host checking via goroutines with ordered results
- Standard library only for TLS (`crypto/tls`, `crypto/x509`)
- External dependency: `spf13/cobra` for CLI
- Tests use local TLS servers with self-signed certificates (no network needed)

### Conventions
- Commit messages follow conventional commits: `feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`, `ci:`, `security:`
- Go version: 1.25+
- Module path: `github.com/EdgarOrtegaRamirez/certpulse`
