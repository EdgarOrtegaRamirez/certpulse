// Package report defines the data structures for certificate check results.
package report

import (
	"time"
)

// Status represents the health status of a certificate check.
type Status string

const (
	// StatusOK indicates the certificate is valid and not near expiry.
	StatusOK Status = "ok"
	// StatusWarning indicates the certificate is expiring within the threshold.
	StatusWarning Status = "warning"
	// StatusExpired indicates the certificate has already expired.
	StatusExpired Status = "expired"
	// StatusError indicates a connection or validation error occurred.
	StatusError Status = "error"
	// StatusNotYetValid indicates the certificate is not yet valid.
	StatusNotYetValid Status = "not_yet_valid"
)

// CertInfo holds the extracted information from a TLS certificate.
type CertInfo struct {
	// Host is the hostname that was checked.
	Host string `json:"host"`
	// Port is the port that was checked.
	Port int `json:"port"`
	// Subject is the certificate subject Common Name.
	Subject string `json:"subject"`
	// Issuer is the certificate issuer Common Name.
	Issuer string `json:"issuer"`
	// SANs are the Subject Alternative Names (DNS names).
	SANs []string `json:"sans"`
	// SerialNumber is the certificate serial number in hex.
	SerialNumber string `json:"serial_number"`
	// NotBefore is the certificate validity start time.
	NotBefore time.Time `json:"not_before"`
	// NotAfter is the certificate validity end time.
	NotAfter time.Time `json:"not_after"`
	// DaysUntilExpiry is the number of days until the certificate expires.
	// Can be negative if already expired.
	DaysUntilExpiry int `json:"days_until_expiry"`
	// KeyAlgorithm is the public key algorithm (RSA, ECDSA, Ed25519).
	KeyAlgorithm string `json:"key_algorithm"`
	// KeySize is the key size in bits (0 for Ed25519).
	KeySize int `json:"key_size"`
	// SignatureAlgorithm is the signature algorithm name.
	SignatureAlgorithm string `json:"signature_algorithm"`
	// Version is the X.509 version (1, 2, or 3).
	Version int `json:"version"`
	// IsCA indicates whether the certificate is a Certificate Authority.
	IsCA bool `json:"is_ca"`
	// ChainLength is the number of certificates in the chain.
	ChainLength int `json:"chain_length"`
	// ChainValid indicates whether the certificate chain validated successfully.
	ChainValid bool `json:"chain_valid"`
	// Status is the overall check status.
	Status Status `json:"status"`
	// Error is the error message if status is error.
	Error string `json:"error,omitempty"`
}

// CheckResult holds the result of checking one or more hosts.
type CheckResult struct {
	// CheckedAt is when the check was performed.
	CheckedAt time.Time `json:"checked_at"`
	// Threshold is the warning threshold in days.
	Threshold int `json:"threshold"`
	// Certificates is the list of certificate check results.
	Certificates []CertInfo `json:"certificates"`
	// Summary holds aggregate counts.
	Summary Summary `json:"summary"`
}

// Summary holds aggregate counts for a check result.
type Summary struct {
	// Total is the total number of hosts checked.
	Total int `json:"total"`
	// OK is the number of hosts with valid certificates.
	OK int `json:"ok"`
	// Warning is the number of hosts with certificates expiring soon.
	Warning int `json:"warning"`
	// Expired is the number of hosts with expired certificates.
	Expired int `json:"expired"`
	// Errors is the number of hosts with connection errors.
	Errors int `json:"errors"`
}

// ExitCode returns the appropriate exit code based on the check results.
// 0 = all OK, 1 = warnings/expired, 2 = errors.
func (r *CheckResult) ExitCode() int {
	if r.Summary.Errors > 0 {
		return 2
	}
	if r.Summary.Warning > 0 || r.Summary.Expired > 0 {
		return 1
	}
	return 0
}
