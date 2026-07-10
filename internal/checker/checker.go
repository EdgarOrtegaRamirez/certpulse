// Package checker provides TLS certificate checking functionality.
package checker

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/report"
)

// Config holds the configuration for a certificate check.
type Config struct {
	// Timeout is the connection timeout per host.
	Timeout time.Duration
	// Threshold is the number of days before expiry to warn.
	Threshold int
	// SkipVerify disables certificate chain validation.
	SkipVerify bool
	// Port is the default port to connect to (overridden by host:port syntax).
	Port int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:    10 * time.Second,
		Threshold:  30,
		SkipVerify: false,
		Port:       443,
	}
}

// Checker performs TLS certificate checks against hosts.
type Checker struct {
	config Config
}

// New creates a new Checker with the given configuration.
func New(config Config) *Checker {
	return &Checker{config: config}
}

// CheckHost checks the TLS certificate for a single host.
// The host string can be in the form "hostname" or "hostname:port".
func (c *Checker) CheckHost(host string) report.CertInfo {
	return c.CheckHostAtTime(host, time.Now())
}

// CheckHostAtTime checks the TLS certificate for a single host,
// using the given reference time for expiry calculations.
func (c *Checker) CheckHostAtTime(host string, now time.Time) report.CertInfo {
	hostname, port := parseHost(host, c.config.Port)

	info := report.CertInfo{
		Host: hostname,
		Port: port,
	}

	addr := fmt.Sprintf("%s:%d", hostname, port)

	dialer := &net.Dialer{Timeout: c.config.Timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: c.config.SkipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		info.Status = report.StatusError
		info.Error = sanitizeErr(err)
		return info
	}
	defer func() {
		_ = conn.Close()
	}()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		info.Status = report.StatusError
		info.Error = "no certificates received from server"
		return info
	}

	leaf := certs[0]

	info.Subject = certSubjectCN(leaf)
	info.Issuer = certIssuerCN(leaf)
	info.SANs = leaf.DNSNames
	info.SerialNumber = leaf.SerialNumber.String()
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter
	info.KeyAlgorithm = keyAlgorithm(leaf)
	info.KeySize = keySize(leaf)
	info.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
	info.Version = leaf.Version + 1 // x509.Version is 0-indexed
	info.IsCA = leaf.IsCA
	info.ChainLength = len(certs)
	info.ChainValid = !c.config.SkipVerify && state.VerifiedChains != nil

	days := int(info.NotAfter.Sub(now).Hours() / 24)
	info.DaysUntilExpiry = days

	switch {
	case now.Before(info.NotBefore):
		info.Status = report.StatusNotYetValid
	case days < 0:
		info.Status = report.StatusExpired
	case days <= c.config.Threshold:
		info.Status = report.StatusWarning
	default:
		info.Status = report.StatusOK
	}

	return info
}

// CheckAll checks multiple hosts concurrently and returns a CheckResult.
func (c *Checker) CheckAll(hosts []string) report.CheckResult {
	return c.CheckAllAtTime(hosts, time.Now())
}

// CheckAllAtTime checks multiple hosts concurrently using the given reference time.
func (c *Checker) CheckAllAtTime(hosts []string, now time.Time) report.CheckResult {
	result := report.CheckResult{
		CheckedAt:    now,
		Threshold:    c.config.Threshold,
		Certificates: make([]report.CertInfo, len(hosts)),
	}

	type resultSlot struct {
		idx  int
		info report.CertInfo
	}

	ch := make(chan resultSlot, len(hosts))

	for i, host := range hosts {
		go func(idx int, h string) {
			ch <- resultSlot{idx: idx, info: c.CheckHostAtTime(h, now)}
		}(i, host)
	}

	for range hosts {
		slot := <-ch
		result.Certificates[slot.idx] = slot.info
	}

	result.Summary = computeSummary(result.Certificates)
	return result
}

func (c *Checker) computeSummary(certs []report.CertInfo) report.Summary {
	return computeSummary(certs)
}

func computeSummary(certs []report.CertInfo) report.Summary {
	s := report.Summary{Total: len(certs)}
	for _, ci := range certs {
		switch ci.Status {
		case report.StatusOK:
			s.OK++
		case report.StatusWarning:
			s.Warning++
		case report.StatusExpired:
			s.Expired++
		case report.StatusError, report.StatusNotYetValid:
			s.Errors++
		}
	}
	return s
}

// parseHost splits a host string into hostname and port.
// If no port is specified, the default port is used.
func parseHost(host string, defaultPort int) (string, int) {
	// Handle [IPv6]:port syntax
	if strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, "]"); idx >= 0 {
			hostname := host[1:idx]
			rest := host[idx+1:]
			if strings.HasPrefix(rest, ":") {
				port := defaultPort
				fmt.Sscanf(rest[1:], "%d", &port)
				return hostname, port
			}
			return hostname, defaultPort
		}
	}

	// Handle host:port syntax (but not for IPv6 without brackets)
	if strings.Count(host, ":") == 1 {
		parts := strings.SplitN(host, ":", 2)
		port := defaultPort
		fmt.Sscanf(parts[1], "%d", &port)
		return parts[0], port
	}

	return host, defaultPort
}

func certSubjectCN(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	// Fall back to the first SAN if CN is empty
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.String()
}

func certIssuerCN(cert *x509.Certificate) string {
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	return cert.Issuer.String()
}

func keyAlgorithm(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func keySize(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// sanitizeErr removes sensitive connection details from error messages.
func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Truncate very long error messages
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return msg
}
