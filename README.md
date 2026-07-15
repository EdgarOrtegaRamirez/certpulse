# CertPulse

> TLS certificate monitoring CLI — check, track, score, audit, and manage certificates from your terminal.

[![CI](https://github.com/EdgarOrtegaRamirez/certpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/EdgarOrtegaRamirez/certpulse/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/EdgarOrtegaRamirez/certpulse)](https://goreportcard.com/report/github.com/EdgarOrtegaRamirez/certpulse)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What It Does

CertPulse is a comprehensive TLS certificate toolkit. It connects to hosts over TLS to check certificate expiration, inspects certificate files, scores security posture, audits against best practices, generates certificates, compares chains, and converts formats — all from a single CLI.

It's designed for **DevOps teams, security engineers, and CI pipelines** who need a fast, scriptable way to work with TLS certificates.

## Subcommands

| Command | Description |
|---------|-------------|
| `check` | Check TLS certificates for one or more hosts |
| `inspect` | Decode and display certificate details from a PEM/DER file |
| `validate` | Validate certificate expiry, key strength, and chain |
| `generate` | Generate self-signed certificates or CSRs |
| `score` | Evaluate certificate security with a 0-100 score and grade |
| `compare` | Compare two certificates side-by-side with diff output |
| `audit` | Audit certificates against security best practices |
| `convert` | Convert certificates between PEM and DER formats |

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

### Check Remote Hosts

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

### Inspect a Certificate File

```bash
# Text output (default)
certpulse inspect cert.pem

# JSON output
certpulse inspect cert.pem --format json

# Show only specific fields
certpulse inspect cert.pem --fields subject,sans,dates,fingerprint
```

### Score a Certificate

```bash
# Security score with breakdown
certpulse score cert.pem

# JSON output for programmatic use
certpulse score cert.pem --format json
```

### Generate a Self-Signed Certificate

```bash
certpulse generate \
  --cn "myserver.example.com" \
  --sans "myserver.example.com,www.example.com" \
  --days 365 \
  --output-cert server.pem \
  --output-key server-key.pem \
  --org "My Organization"
```

### Compare Two Certificates

```bash
certpulse compare old.pem new.pem
certpulse compare old.pem new.pem --format json
```

### Audit Against Best Practices

```bash
certpulse audit cert.pem
certpulse audit cert.pem --format json
```

### Convert Formats

```bash
# PEM to DER
certpulse convert cert.pem cert.der

# DER to PEM (auto-inferred from extension)
certpulse convert cert.der cert.pem
```

### CI Integration

```bash
# Fail if any certificate expires within 60 days
certpulse check example.com --threshold 60 --format json

# Check a cert file's security score
score_output=$(certpulse score cert.pem --format json)

# Audit and fail on critical issues
certpulse audit cert.pem

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

## Command Reference

### check

Check TLS certificates for remote hosts.

```
Flags:
  -F, --file string     Read hosts from a file (one per line)
  -f, --format string   Output format: text, json, csv (default "text")
  -h, --help            help for check
      --insecure        Skip certificate chain validation
  -p, --port int        Default port to connect to (default 443)
  -q, --quiet           Only show warnings and errors
      --stdin           Read hosts from stdin
  -t, --threshold int   Days before expiry to warn (default 30)
      --timeout duration Connection timeout per host (default 10s)
  -v, --verbose         Show detailed certificate info
```

### inspect

Parse and display certificate file details.

```
Flags:
  -f, --format string   Output format: text, json, yaml (default "text")
  -h, --help            help for inspect
      --fields string   Show specific fields: subject,issuer,sans,dates,fingerprint,algorithms
```

### validate

Quick validation of certificate files.

```
Flags:
  -h, --help            help for validate
      --ca string       Path to CA bundle (optional)
```

### generate

Generate self-signed certificates or CSRs.

```
Flags:
  -h, --help              help for generate
      --days int          Validity period in days (default 365)
      --cn string         Common Name (default "localhost")
      --csr               Generate a CSR instead of self-signed cert
  -k, --output-key string Output key file (default "key.pem")
      --output-cert string Output certificate file (default "cert.pem")
      --org string        Organization (O)
      --sans string       SANs comma-separated (default "localhost,127.0.0.1")
      --key-size int      Key size in bits (default 2048)
```

### score

Security scoring with category breakdown.

```
Flags:
  -f, --format string   Output format: text, json, yaml (default "text")
  -h, --help            help for score
```

Scoring categories:
- **Key Strength** (25 pts): RSA ≥2048, EC ≥256
- **Signature Algorithm** (20 pts): SHA-256+, no MD5/SHA-1
- **Expiry Proximity** (20 pts): >365 days = full marks
- **SANs** (15 pts): Presence and count
- **Chain & CA** (20 pts): Issued vs self-signed vs root CA

### compare

Side-by-side certificate comparison.

```
Flags:
  -f, --format string   Output format: text, json, yaml (default "text")
  -h, --help            help for compare
```

### audit

Security best-practice audit.

```
Flags:
  -f, --format string   Output format: text, json, yaml (default "text")
  -h, --help            help for audit
```

Audit checks:
- **KEY-001**: Key size ≥ 2048 bits
- **SIG-001**: SHA-256+ signature algorithm
- **VAL-001**: Certificate not expired
- **SAN-001**: SANs present on leaf certs
- **CHAIN-001**: CA-issued vs self-signed
- **EXT-001**: Subject Key Identifier present

### convert

Format conversion between PEM and DER.

```
Flags:
  -h, --help                help for convert
      --input-format string  Input format (pem or der, auto-detect)
      --output-format string Output format (pem or der, inferred from path)
```

## Flags (Global)

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | `443` | Default port to connect to |
| `--threshold` | `-t` | `30` | Days before expiry to trigger warning |
| `--format` | `-f` | `text` | Output format: `text`, `json`, `csv`, `yaml` |
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
│   ├── output/             # Text/JSON/CSV formatters
│   ├── inspect/            # Certificate file parsing & display
│   ├── validate/           # Quick validation checks
│   ├── generate/           # Self-signed cert & CSR generation
│   ├── convert/            # PEM/DER format conversion
│   ├── score/              # Security scoring engine
│   ├── compare/            # Certificate diff engine
│   └── audit/              # Best-practice audit engine
├── go.mod
└── .github/workflows/      # CI pipeline
```

### Key Design Decisions

- **Concurrent checking**: All hosts are checked in parallel using goroutines, with results collected in order.
- **Standard library TLS**: Uses Go's `crypto/tls` and `crypto/x509` — no external TLS dependencies.
- **CI-friendly exit codes**: Exit 0 (OK), 1 (warning/expired), 2 (error) — perfect for pipeline gates.
- **Multiple input sources**: CLI args, file, or stdin — flexible for scripts and automation.
- **IPv6 support**: Handles `[::1]:port` and bare IPv6 address syntax.
- **Single binary**: All features in one statically-linked binary — no runtime dependencies.

## Security

- Certificate chain validation is enabled by default (use `--insecure` to disable).
- Minimum TLS version is TLS 1.2.
- Error messages are truncated to avoid leaking sensitive connection details.
- File path input is validated against path traversal.
- No secrets or credentials are stored or transmitted.
- Generated certificates use secure random key generation.

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
