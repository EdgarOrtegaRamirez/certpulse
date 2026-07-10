# Security Policy

## Supported Versions

Only the latest release is supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in CertPulse, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email the maintainer with a description of the vulnerability and steps to reproduce.
3. You will receive a response within 48 hours.

## Security Measures

CertPulse is designed with security in mind:

- **TLS 1.2 minimum**: All connections enforce TLS 1.2 or higher.
- **Chain validation**: Certificate chain validation is enabled by default. The `--insecure` flag exists for testing self-signed certificates but should not be used in production.
- **Path traversal protection**: File input via `--file` is validated against path traversal attacks.
- **Error sanitization**: Error messages are truncated to prevent information leakage.
- **No credential storage**: CertPulse does not store or transmit any secrets.
- **No network listeners**: CertPulse only makes outbound connections — it never opens ports.

## Scope

CertPulse makes outbound TLS connections to user-specified hosts. It does not:
- Store credentials or API keys
- Open network listeners
- Execute external commands
- Modify files on the system (except writing to stdout)
