# CertPulse

> TLS certificate monitoring CLI — check, track, and alert on certificate expiration from your terminal.

[![CI](https://github.com/EdgarOrtegaRamirez/certpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/EdgarOrtegaRamirez/certpulse/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/EdgarOrtegaRamirez/certpulse)](https://goreportcard.com/report/github.com/EdgarOrtegaRamirez/certpulse)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What It Does

CertPulse connects to one or more hosts over TLS and extracts certificate details — subject, issuer, SANs, validity dates, key algorithm, chain validation status — then reports which certificates are healthy, expiring soon, or already expired.

It's designed for **DevOps teams and CI pipelines** who need a fast, scriptable way to monitor certificate expiration without setting up a full monitoring stack.

## Quick Start

### Install

```bash
go install github.com/EdgarOrtegaRamirez/certpulse/cmd/certpulse@latest
```

Or build from source:

```bash
git clone https://github.com/EdgarOrtegaRamirez/certpulse.git
cd certpulse
go build -o certpulse ./cmd/certpulse
```

### Basic Usage

```bash
# Check a single domain
certpulse check example.com

# Check multiple domains
certpulse check example.com google.com github.com

# Use a custom port
certpulse check example.com:8443

# Read hosts from a file (one per line, # comments supported)
certpulse check --file hosts.txt

# Pipe hosts via stdin
echo "example.com" | certpulse check --stdin
```

### CI Integration

```bash
# Fail if any certificate expires within 60 days
certpulse check example.com --threshold 60 --format json

# Exit codes:
#   0 = all certificates OK
#   1 = one or more certificates expiring soon or expired
#   2 = connection error(s)
```

## Output Formats

### Text (default)

```
HOST            PORT  STATUS     DAYS LEFT  ISSUER                                  EXPIRES
----------------------------------------------------------------------------------------------------
google.com      443   ✓ ok       65         WR2                                     2026-09-14
github.com      443   ✓ ok       82         Sectigo Public Server Authentication  2026-09-30
expiring.com    443   ⚠ warning  15         DigiCert                                2026-07-25
broken.com      443   ✗ error    -          -                                       -
  └─ Error: dial tcp 127.0.0.1:1: connect: connection refused

Summary: 4 checked — 2 OK, 1 warning, 0 expired, 1 errors
⚠  1 certificate(s) need attention (threshold: 30 days)
```

### JSON

```bash
certpulse check example.com --format json
```

Returns a structured `CheckResult` with `checked_at`, `threshold`, `certificates[]`, and `summary` fields — ideal for programmatic consumption.

### CSV

```bash
certpulse check example.com --format csv > cert-report.csv
```

Outputs a header row followed by one row per certificate with all fields.

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | `443` | Default port to connect to |
| `--threshold` | `-t` | `30` | Days before expiry to trigger warning |
| `--format` | `-f` | `text` | Output format: `text`, `json`, `csv` |
| `--timeout` | | `10s` | Connection timeout per host |
| `--file` | `-F` | | Read hosts from a file (one per line) |
| `--stdin` | | `false` | Read hosts from stdin |
| `--insecure` | | `false` | Skip certificate chain validation |
| `--quiet` | `-q` | `false` | Only show warnings and errors |
| `--verbose` | `-v` | `false` | Show detailed certificate info (SANs, serial, key, chain) |
| `--version` | | | Print version and exit |

## Architecture

```
certpulse/
├── cmd/certpulse/          # CLI entry point (cobra)
├── internal/
│   ├── checker/            # TLS connection + certificate extraction
│   ├── report/             # Data structures + exit code logic
│   └── output/             # Text/JSON/CSV formatters
├── go.mod
└── .github/workflows/      # CI pipeline
```

### Key Design Decisions

- **Concurrent checking**: All hosts are checked in parallel using goroutines, with results collected in order.
- **Standard library TLS**: Uses Go's `crypto/tls` and `crypto/x509` — no external TLS dependencies.
- **CI-friendly exit codes**: Exit 0 (OK), 1 (warning/expired), 2 (error) — perfect for pipeline gates.
- **Multiple input sources**: CLI args, file, or stdin — flexible for scripts and automation.
- **IPv6 support**: Handles `[::1]:port` and bare IPv6 address syntax.

## Security

- Certificate chain validation is enabled by default (use `--insecure` to disable).
- Minimum TLS version is TLS 1.2.
- Error messages are truncated to avoid leaking sensitive connection details.
- File path input is validated against path traversal.
- No secrets or credentials are stored or transmitted.

See [SECURITY.md](SECURITY.md) for responsible disclosure details.

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run with race detection
go test -race ./...
```

Tests use local TLS servers with self-signed certificates — no external dependencies required.

## License

[MIT](LICENSE)
