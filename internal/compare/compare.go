// Package compare provides certificate comparison functionality.
package compare

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/inspect"
)

// Result holds the comparison output.
type Result struct {
	Cert1       CertSummary `json:"cert1"`
	Cert2       CertSummary `json:"cert2"`
	Differences []DiffEntry   `json:"differences"`
}

// CertSummary holds a summary of one certificate.
type CertSummary struct {
	Source      string   `json:"source"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	Serial      string   `json:"serial_number"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DaysRemain  int64    `json:"days_remaining"`
	Expired     bool     `json:"expired"`
	SANs        []string `json:"sans"`
	SigAlg      string   `json:"signature_algorithm"`
	KeyAlgo     string   `json:"public_key_algorithm"`
	KeySize     int      `json:"key_size"`
	IsCA        bool     `json:"is_ca"`
	SHA256FP    string   `json:"sha256_fingerprint"`
}

// DiffEntry describes a single field difference.
type DiffEntry struct {
	Field       string `json:"field"`
	Cert1Value  string `json:"cert1_value"`
	Cert2Value  string `json:"cert2_value"`
	Changed     bool   `json:"changed"`
	Severity    string `json:"severity"`
}

// Compare compares two certificates.
func Compare(info1, info2 inspect.Info, src1, src2 string) Result {
	var diffs []DiffEntry

	diffs = append(diffs, diffField("Subject", info1.Subject, info2.Subject, "info"))
	diffs = append(diffs, diffField("Issuer", info1.Issuer, info2.Issuer, "info"))
	diffs = append(diffs, diffField("Serial Number", info1.SerialNumber, info2.SerialNumber, "info"))
	diffs = append(diffs, diffField("Not Before", info1.NotBefore, info2.NotBefore, "info"))
	diffs = append(diffs, diffField("Not After", info1.NotAfter, info2.NotAfter, "info"))
	diffs = append(diffs, diffField("Days Remaining", fmt.Sprintf("%d", info1.DaysRemaining), fmt.Sprintf("%d", info2.DaysRemaining), criticalOrInfo(info1.Expired || info2.Expired)))
	diffs = append(diffs, diffField("Expired", fmt.Sprintf("%t", info1.Expired), fmt.Sprintf("%t", info2.Expired), criticalOrInfo(info1.Expired || info2.Expired)))
	diffs = append(diffs, diffField("Signature Algorithm", info1.SignatureAlgorithm, info2.SignatureAlgorithm, "info"))
	diffs = append(diffs, diffField("Key Algorithm", info1.PublicKeyAlgorithm, info2.PublicKeyAlgorithm, "info"))
	diffs = append(diffs, diffField("Key Size", fmt.Sprintf("%d bits", info1.KeySize), fmt.Sprintf("%d bits", info2.KeySize), warningOrInfo(info1.KeySize < 2048 || info2.KeySize < 2048)))
	diffs = append(diffs, diffField("SANs", joinSANs(info1.SANs), joinSANs(info2.SANs), warningIfEmpty(info1.SANs, info2.SANs)))
	diffs = append(diffs, diffField("CA Certificate", fmt.Sprintf("%t", info1.IsCA), fmt.Sprintf("%t", info2.IsCA), "info"))
	diffs = append(diffs, diffField("SHA-256 Fingerprint", info1.SHA256Fingerprint, info2.SHA256Fingerprint, "info"))

	return Result{
		Cert1:       CertSummary{Source: src1, Subject: info1.Subject, Issuer: info1.Issuer, Serial: info1.SerialNumber, NotBefore: info1.NotBefore, NotAfter: info1.NotAfter, DaysRemain: info1.DaysRemaining, Expired: info1.Expired, SANs: info1.SANs, SigAlg: info1.SignatureAlgorithm, KeyAlgo: info1.PublicKeyAlgorithm, KeySize: info1.KeySize, IsCA: info1.IsCA, SHA256FP: info1.SHA256Fingerprint},
		Cert2:       CertSummary{Source: src2, Subject: info2.Subject, Issuer: info2.Issuer, Serial: info2.SerialNumber, NotBefore: info2.NotBefore, NotAfter: info2.NotAfter, DaysRemain: info2.DaysRemaining, Expired: info2.Expired, SANs: info2.SANs, SigAlg: info2.SignatureAlgorithm, KeyAlgo: info2.PublicKeyAlgorithm, KeySize: info2.KeySize, IsCA: info2.IsCA, SHA256FP: info2.SHA256Fingerprint},
		Differences: diffs,
	}
}

func diffField(field, v1, v2, severity string) DiffEntry {
	return DiffEntry{Field: field, Cert1Value: v1, Cert2Value: v2, Changed: v1 != v2, Severity: severity}
}

func criticalOrInfo(critical bool) string {
	if critical {
		return "critical"
	}
	return "info"
}

func warningOrInfo(warning bool) string {
	if warning {
		return "warning"
	}
	return "info"
}

func warningIfEmpty(s1, s2 []string) string {
	if len(s1) == 0 || len(s2) == 0 {
		return "warning"
	}
	return "info"
}

func joinSANs(sans []string) string {
	if len(sans) == 0 {
		return "(none)"
	}
	return strings.Join(sans, ", ")
}

// PrintResult prints the comparison in the given format.
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
	fmt.Fprintf(w, "cert1:\n")
	fmt.Fprintf(w, "  source: %s\n", result.Cert1.Source)
	fmt.Fprintf(w, "  subject: %s\n", result.Cert1.Subject)
	fmt.Fprintf(w, "  issuer: %s\n", result.Cert1.Issuer)
	fmt.Fprintf(w, "  sha256_fingerprint: %s\n", result.Cert1.SHA256FP)
	fmt.Fprintf(w, "cert2:\n")
	fmt.Fprintf(w, "  source: %s\n", result.Cert2.Source)
	fmt.Fprintf(w, "  subject: %s\n", result.Cert2.Subject)
	fmt.Fprintf(w, "  issuer: %s\n", result.Cert2.Issuer)
	fmt.Fprintf(w, "  sha256_fingerprint: %s\n", result.Cert2.SHA256FP)
	fmt.Fprintf(w, "differences:\n")
	for _, d := range result.Differences {
		fmt.Fprintf(w, "  - field: %s\n", d.Field)
		fmt.Fprintf(w, "    cert1_value: %s\n", d.Cert1Value)
		fmt.Fprintf(w, "    cert2_value: %s\n", d.Cert2Value)
		fmt.Fprintf(w, "    changed: %t\n", d.Changed)
		fmt.Fprintf(w, "    severity: %s\n", d.Severity)
	}
	return nil
}

func printText(result Result, w io.Writer) error {
	sameFP := result.Cert1.SHA256FP == result.Cert2.SHA256FP
	fmt.Fprintf(w, "\n%s  ←→  %s\n", result.Cert1.Source, result.Cert2.Source)
	fmt.Fprintf(w, "═══════════════════════════════════════\n")

	if sameFP {
		fmt.Fprintf(w, "  ✓ Same certificate (identical fingerprints)\n")
	} else {
		fmt.Fprintf(w, "  ✗ Different certificates\n")
	}

	fmt.Fprintf(w, "\nField Differences:\n")
	for _, d := range result.Differences {
		icon := "✓"
		if d.Changed {
			switch d.Severity {
			case "critical":
				icon = "✗"
			case "warning":
				icon = "⚠"
			default:
				icon = "→"
			}
		}
		fmt.Fprintf(w, "  %s %s: ", icon, d.Field)
		if d.Changed {
			fmt.Fprintf(w, "\n")
			fmt.Fprintf(w, "    [1] %s\n", d.Cert1Value)
			fmt.Fprintf(w, "    [2] %s\n", d.Cert2Value)
		} else {
			fmt.Fprintf(w, "%s\n", d.Cert1Value)
		}
	}

	fmt.Fprintf(w, "\nCertificate Summaries:\n")
	fmt.Fprintf(w, "  [1] Subject: %s\n", result.Cert1.Subject)
	fmt.Fprintf(w, "       Issuer: %s\n", result.Cert1.Issuer)
	fmt.Fprintf(w, "       Key: %d bits\n", result.Cert1.KeySize)
	if result.Cert1.Expired {
		fmt.Fprintf(w, "       Expires: %s (EXPIRED)\n", result.Cert1.NotAfter)
	} else {
		fmt.Fprintf(w, "       Expires: %s (%d days)\n", result.Cert1.NotAfter, result.Cert1.DaysRemain)
	}
	fmt.Fprintf(w, "  [2] Subject: %s\n", result.Cert2.Subject)
	fmt.Fprintf(w, "       Issuer: %s\n", result.Cert2.Issuer)
	fmt.Fprintf(w, "       Key: %d bits\n", result.Cert2.KeySize)
	if result.Cert2.Expired {
		fmt.Fprintf(w, "       Expires: %s (EXPIRED)\n", result.Cert2.NotAfter)
	} else {
		fmt.Fprintf(w, "       Expires: %s (%d days)\n", result.Cert2.NotAfter, result.Cert2.DaysRemain)
	}
	fmt.Fprintf(w, "\n")
	return nil
}
