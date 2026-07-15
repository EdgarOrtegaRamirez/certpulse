// Package audit provides certificate audit functionality.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/inspect"
)

// Result holds the audit results.
type Result struct {
	Passed      uint32  `json:"passed"`
	Warnings    uint32  `json:"warnings"`
	Failures    uint32  `json:"failures"`
	Checks      []Check `json:"checks"`
	OverallPass bool    `json:"overall_pass"`
}

// Check is a single audit check.
type Check struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation,omitempty"`
}

// RunAudit runs best-practice audit checks against a certificate.
func RunAudit(info inspect.Info) Result {
	var checks []Check
	var passed, warnings, failures uint32

	// KEY-001: Key size
	if isEC(info.PublicKeyAlgorithm) && info.KeySize >= 256 {
		checks = append(checks, Check{ID: "KEY-001", Name: "Key Size ≥ 2048 bits / EC ≥ 256 bits", Severity: "pass", Message: fmt.Sprintf("EC %d bits (strong)", info.KeySize)})
		passed++
	} else if info.KeySize >= 4096 {
		checks = append(checks, Check{ID: "KEY-001", Name: "Key Size ≥ 2048 bits", Severity: "pass", Message: fmt.Sprintf("Key size is %d bits (very strong)", info.KeySize)})
		passed++
	} else if info.KeySize >= 2048 {
		checks = append(checks, Check{ID: "KEY-001", Name: "Key Size ≥ 2048 bits", Severity: "pass", Message: fmt.Sprintf("Key size is %d bits (adequate)", info.KeySize)})
		passed++
	} else {
		checks = append(checks, Check{ID: "KEY-001", Name: "Key Size ≥ 2048 bits", Severity: "fail", Message: fmt.Sprintf("Key size is %d bits (below minimum 2048)", info.KeySize), Recommendation: "Regenerate with at least 2048-bit RSA or 256-bit ECC key."})
		failures++
	}

	// SIG-001: Signature algorithm
	sigFriendly := friendlySigAlgo(info.SignatureAlgorithm)
	sigUpper := strings.ToUpper(sigFriendly)
	if strings.Contains(sigUpper, "SHA256") || strings.Contains(sigUpper, "SHA384") || strings.Contains(sigUpper, "SHA512") {
		checks = append(checks, Check{ID: "SIG-001", Name: "Signature Algorithm (SHA-256+)", Severity: "pass", Message: fmt.Sprintf("Using %s", sigFriendly)})
		passed++
	} else if strings.Contains(sigUpper, "SHA1") {
		checks = append(checks, Check{ID: "SIG-001", Name: "Signature Algorithm (SHA-256+)", Severity: "fail", Message: fmt.Sprintf("Using deprecated %s", sigFriendly), Recommendation: "SHA-1 is deprecated and considered weak. Regenerate with SHA-256."})
		failures++
	} else {
		checks = append(checks, Check{ID: "SIG-001", Name: "Signature Algorithm (SHA-256+)", Severity: "fail", Message: fmt.Sprintf("Using weak/broken %s", sigFriendly), Recommendation: "Regenerate with SHA-256 or stronger."})
		failures++
	}

	// VAL-001: Validity / Not expired
	if info.DaysRemaining > 398 {
		checks = append(checks, Check{ID: "VAL-001", Name: "Validity Period ≤ 398 days", Severity: "warning", Message: fmt.Sprintf("Certificate has %d days remaining.", info.DaysRemaining), Recommendation: "CA/Browser Forum limits certificate validity to 398 days."})
		warnings++
	} else if info.Expired {
		checks = append(checks, Check{ID: "VAL-001", Name: "Not Expired", Severity: "fail", Message: "Certificate has expired.", Recommendation: "Renew the certificate immediately."})
		failures++
	} else {
		checks = append(checks, Check{ID: "VAL-001", Name: "Not Expired", Severity: "pass", Message: fmt.Sprintf("%d days remaining", info.DaysRemaining)})
		passed++
	}

	// SAN-001: SANs present
	if !info.IsCA {
		if len(info.SANs) == 0 {
			checks = append(checks, Check{ID: "SAN-001", Name: "Subject Alternative Names Present", Severity: "fail", Message: "No SANs found on leaf certificate.", Recommendation: "Modern browsers require SANs. Regenerate with --sans flag."})
			failures++
		} else {
			wildcardCount := 0
			for _, san := range info.SANs {
				if strings.Contains(san, "*") {
					wildcardCount++
				}
			}
			if wildcardCount == 0 {
				checks = append(checks, Check{ID: "SAN-001", Name: "Subject Alternative Names Present", Severity: "pass", Message: fmt.Sprintf("%d SANs present (no wildcards)", len(info.SANs))})
				passed++
			} else {
				checks = append(checks, Check{ID: "SAN-001", Name: "Subject Alternative Names Present", Severity: "warning", Message: fmt.Sprintf("%d SANs present, %d wildcard(s)", len(info.SANs), wildcardCount), Recommendation: "Wildcard certificates should be used sparingly in production."})
				warnings++
			}
		}
	} else {
		checks = append(checks, Check{ID: "SAN-001", Name: "Subject Alternative Names Present", Severity: "pass", Message: "CA certificate (SANs not required)."})
		passed++
	}

	// CHAIN-001: CA-Issued detection
	if info.Subject == info.Issuer {
		if info.IsCA {
			checks = append(checks, Check{ID: "CHAIN-001", Name: "CA-Issued Certificate", Severity: "pass", Message: "Root CA certificate (self-signed is expected for root CAs)."})
			passed++
		} else {
			checks = append(checks, Check{ID: "CHAIN-001", Name: "CA-Issued Certificate", Severity: "warning", Message: "Self-signed leaf certificate (not trusted by browsers).", Recommendation: "Use a CA-signed certificate for production."})
			warnings++
		}
	} else {
		checks = append(checks, Check{ID: "CHAIN-001", Name: "CA-Issued Certificate", Severity: "pass", Message: fmt.Sprintf("Issued by: %s", info.Issuer)})
		passed++
	}

	// EXT-001: Subject Key Identifier
	if info.SubjectKeyID != "" {
		checks = append(checks, Check{ID: "EXT-001", Name: "Subject Key Identifier Present", Severity: "pass", Message: "SKI extension present."})
		passed++
	} else {
		checks = append(checks, Check{ID: "EXT-001", Name: "Subject Key Identifier Present", Severity: "warning", Message: "SKI extension missing.", Recommendation: "Consider adding Subject Key Identifier extension."})
		warnings++
	}

	return Result{
		Passed:      passed,
		Warnings:    warnings,
		Failures:    failures,
		Checks:      checks,
		OverallPass: failures == 0,
	}
}

func friendlySigAlgo(oid string) string {
	switch oid {
	case "1.2.840.10045.4.3.2":
		return "ECDSA-SHA256"
	case "1.2.840.10045.4.3.3":
		return "ECDSA-SHA384"
	case "1.2.840.10045.4.3.4":
		return "ECDSA-SHA512"
	case "1.2.840.113549.1.1.11":
		return "RSA-SHA256"
	case "1.2.840.113549.1.1.12":
		return "RSA-SHA384"
	case "1.2.840.113549.1.1.13":
		return "RSA-SHA512"
	case "1.2.840.113549.1.1.5":
		return "RSA-SHA1"
	case "1.2.840.113549.1.1.4":
		return "RSA-MD5"
	default:
		return oid
	}
}

func isEC(algo string) bool {
	s := strings.ToUpper(algo)
	return strings.Contains(s, "EC") || strings.Contains(s, "id-ecPublicKey") || algo == "1.2.840.10045.2.1"
}

// PrintResult prints the audit result.
func PrintResult(result Result, format string, w io.Writer) error {
	switch format {
	case "json":
		return printJSON(result, w)
	case "yaml":
		return printYAML(result, w)
	default:
		return printText(result, w)
	}
}

func printJSON(result Result, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func printYAML(result Result, w io.Writer) error {
	fmt.Fprintf(w, "passed: %d\n", result.Passed)
	fmt.Fprintf(w, "warnings: %d\n", result.Warnings)
	fmt.Fprintf(w, "failures: %d\n", result.Failures)
	fmt.Fprintf(w, "overall_pass: %t\n", result.OverallPass)
	fmt.Fprintf(w, "checks:\n")
	for _, c := range result.Checks {
		fmt.Fprintf(w, "  - id: %s\n", c.ID)
		fmt.Fprintf(w, "    name: %s\n", c.Name)
		fmt.Fprintf(w, "    severity: %s\n", c.Severity)
		fmt.Fprintf(w, "    message: %s\n", c.Message)
		if c.Recommendation != "" {
			fmt.Fprintf(w, "    recommendation: %s\n", c.Recommendation)
		}
	}
	return nil
}

func printText(result Result, w io.Writer) error {
	statusLine := ""
	if result.OverallPass {
		statusLine = fmt.Sprintf("✓ PASSED (%d passed, %d warnings)", result.Passed, result.Warnings)
	} else {
		statusLine = fmt.Sprintf("✗ FAILED (%d passed, %d warnings, %d failed)", result.Passed, result.Warnings, result.Failures)
	}

	fmt.Fprintf(w, "\nCertificate Security Audit\n")
	fmt.Fprintf(w, "═══════════════════════════════════════\n")
	fmt.Fprintf(w, "  %s\n\n", statusLine)
	fmt.Fprintf(w, "Check Results:\n")

	for _, c := range result.Checks {
		icon := "✓"
		switch c.Severity {
		case "warning":
			icon = "⚠"
		case "fail":
			icon = "✗"
		}
		fmt.Fprintf(w, "  %s %s: %s\n", icon, c.Name, c.Message)
		if c.Recommendation != "" {
			fmt.Fprintf(w, "    → %s\n", c.Recommendation)
		}
	}

	total := result.Passed + result.Warnings + result.Failures
	fmt.Fprintf(w, "\nSummary: %d/%d passed, %d/%d warnings, %d/%d failures\n",
		result.Passed, total, result.Warnings, total, result.Failures, total)
	fmt.Fprintf(w, "\n")
	return nil
}
