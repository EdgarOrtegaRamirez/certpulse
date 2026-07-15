// Package inspect provides certificate file inspection functionality.
package inspect

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Info holds extracted certificate information for display.
type Info struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serial_number"`
	Version            int      `json:"version"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysRemaining      int64    `json:"days_remaining"`
	Expired            bool     `json:"expired"`
	SANs               []string `json:"sans"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	KeySize            int      `json:"key_size"`
	IsCA               bool     `json:"is_ca"`
	SubjectKeyID       string   `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string   `json:"authority_key_id,omitempty"`
	SHA256Fingerprint  string   `json:"sha256_fingerprint"`
	SHA1Fingerprint    string   `json:"sha1_fingerprint"`
}

// LoadCertificate loads a certificate from a file, supporting PEM and DER formats.
func LoadCertificate(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	// Try PEM first
	var certs []*x509.Certificate
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certs, fmt.Errorf("parsing PEM certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		remaining = rest
	}

	if len(certs) > 0 {
		return certs, nil
	}

	// Try DER
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate from %s (not valid PEM or DER)", path)
	}
	return []*x509.Certificate{cert}, nil
}

// ExtractInfo extracts certificate information from a parsed X509 certificate.
func ExtractInfo(cert *x509.Certificate) Info {
	now := time.Now()
	daysRemaining := int64(cert.NotAfter.Sub(now).Hours() / 24)
	expired := now.After(cert.NotAfter)

	info := Info{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())),
		Version:            cert.Version + 1,
		NotBefore:          cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
		NotAfter:           cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
		DaysRemaining:      daysRemaining,
		Expired:            expired,
		SANs:               cert.DNSNames,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
	}

	// Public key info
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyAlgorithm = "RSA"
		info.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyAlgorithm = "ECDSA"
		info.KeySize = pub.Params().BitSize
	case ed25519.PublicKey:
		info.PublicKeyAlgorithm = "Ed25519"
		info.KeySize = 256
	default:
		info.PublicKeyAlgorithm = "Unknown"
		info.KeySize = 0
	}

	// Fingerprints
	info.SHA256Fingerprint = sha256Fingerprint(cert.Raw)
	info.SHA1Fingerprint = sha1Fingerprint(cert.Raw)

	// Extensions
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) { // Basic Constraints OID
			// Parse basic constraints to get CA flag
			// We already have IsCA from cert.IsCA
			_ = ext
		}
	}

	info.SubjectKeyID = extractExtensionHex(cert, []int{2, 5, 29, 14})
	info.AuthorityKeyID = extractExtensionHex(cert, []int{2, 5, 29, 35})

	return info
}

func sha256Fingerprint(data []byte) string {
	hash := sha256.Sum256(data)
	hexStr := hex.EncodeToString(hash[:])
	return formatFingerprint(hexStr)
}

func sha1Fingerprint(data []byte) string {
	hash := sha1.Sum(data)
	hexStr := hex.EncodeToString(hash[:])
	return formatFingerprint(hexStr)
}

func formatFingerprint(hexStr string) string {
	runes := []rune(hexStr)
	var parts []string
	for i := 0; i < len(runes); i += 2 {
		parts = append(parts, string(runes[i:i+2]))
	}
	return strings.ToUpper(strings.Join(parts, ":"))
}

func extractExtensionHex(cert *x509.Certificate, oid []int) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return hex.EncodeToString(ext.Value)
		}
	}
	return ""
}

// PrintInfo prints certificate info in the specified format.
func PrintInfo(w io.Writer, info Info, format string, fields []string) error {
	switch format {
	case "json":
		return printJSON(w, info, fields)
	case "yaml":
		return printYAML(w, info, fields)
	default:
		return printText(w, info, fields)
	}
}

func printText(w io.Writer, info Info, fields []string) error {
	show := func(field string) bool {
		if len(fields) == 0 {
			return true
		}
		for _, f := range fields {
			if f == field {
				return true
			}
		}
		return false
	}

	if show("subject") {
		fmt.Fprintf(w, "Subject: %s\n", info.Subject)
	}
	if show("issuer") {
		fmt.Fprintf(w, "Issuer: %s\n", info.Issuer)
	}
	if show("serial") {
		fmt.Fprintf(w, "Serial Number: %s\n", info.SerialNumber)
	}
	if show("version") {
		fmt.Fprintf(w, "Version: v%d\n", info.Version)
	}
	if show("dates") {
		expiredStr := ""
		if info.Expired {
			expiredStr = " [EXPIRED]"
		}
		fmt.Fprintf(w, "Not Before: %s  (%d days remaining)%s\n", info.NotBefore, info.DaysRemaining, expiredStr)
		fmt.Fprintf(w, "Not After:  %s\n", info.NotAfter)
	}
	if show("sans") && len(info.SANs) > 0 {
		fmt.Fprintf(w, "Subject Alternative Names:\n")
		for _, san := range info.SANs {
			fmt.Fprintf(w, "  - %s\n", san)
		}
	}
	if show("algorithms") {
		fmt.Fprintf(w, "Signature Algorithm: %s\n", info.SignatureAlgorithm)
		fmt.Fprintf(w, "Public Key: %s (%d bits)\n", info.PublicKeyAlgorithm, info.KeySize)
	}
	if show("fingerprint") {
		fmt.Fprintf(w, "Fingerprints:\n")
		fmt.Fprintf(w, "  SHA-256: %s\n", info.SHA256Fingerprint)
		fmt.Fprintf(w, "  SHA-1:   %s\n", info.SHA1Fingerprint)
	}
	if show("ca") {
		fmt.Fprintf(w, "CA Certificate: %s\n", yesNo(info.IsCA))
		if info.SubjectKeyID != "" {
			fmt.Fprintf(w, "  Subject Key Identifier: %s\n", info.SubjectKeyID)
		}
		if info.AuthorityKeyID != "" {
			fmt.Fprintf(w, "  Authority Key Identifier: %s\n", info.AuthorityKeyID)
		}
	}

	return nil
}

func printJSON(w io.Writer, info Info, _ []string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

func printYAML(w io.Writer, info Info, _ []string) error {
	// Simple YAML-like output
	fmt.Fprintf(w, "subject: %s\n", info.Subject)
	fmt.Fprintf(w, "issuer: %s\n", info.Issuer)
	fmt.Fprintf(w, "serial_number: %s\n", info.SerialNumber)
	fmt.Fprintf(w, "version: %d\n", info.Version)
	fmt.Fprintf(w, "not_before: %s\n", info.NotBefore)
	fmt.Fprintf(w, "not_after: %s\n", info.NotAfter)
	fmt.Fprintf(w, "days_remaining: %d\n", info.DaysRemaining)
	fmt.Fprintf(w, "expired: %t\n", info.Expired)
	fmt.Fprintf(w, "sans:\n")
	for _, san := range info.SANs {
		fmt.Fprintf(w, "  - %s\n", san)
	}
	fmt.Fprintf(w, "signature_algorithm: %s\n", info.SignatureAlgorithm)
	fmt.Fprintf(w, "public_key_algorithm: %s\n", info.PublicKeyAlgorithm)
	fmt.Fprintf(w, "key_size: %d\n", info.KeySize)
	fmt.Fprintf(w, "is_ca: %t\n", info.IsCA)
	fmt.Fprintf(w, "sha256_fingerprint: %s\n", info.SHA256Fingerprint)
	fmt.Fprintf(w, "sha1_fingerprint: %s\n", info.SHA1Fingerprint)
	if info.SubjectKeyID != "" {
		fmt.Fprintf(w, "subject_key_id: %s\n", info.SubjectKeyID)
	}
	if info.AuthorityKeyID != "" {
		fmt.Fprintf(w, "authority_key_id: %s\n", info.AuthorityKeyID)
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
