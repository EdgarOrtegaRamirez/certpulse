// Package output provides formatting for certificate check results.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/report"
)

// Format represents the output format for check results.
type Format string

const (
	// FormatText produces a human-readable table.
	FormatText Format = "text"
	// FormatJSON produces machine-readable JSON.
	FormatJSON Format = "json"
	// FormatCSV produces CSV output.
	FormatCSV Format = "csv"
)

// ParseFormat converts a string to a Format. Returns an error for unknown formats.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "text", "table", "t":
		return FormatText, nil
	case "json", "j":
		return FormatJSON, nil
	case "csv", "c":
		return FormatCSV, nil
	default:
		return "", fmt.Errorf("unknown format: %s (use text, json, or csv)", s)
	}
}

// Write writes the check result in the specified format to the writer.
func Write(w io.Writer, result *report.CheckResult, format Format) error {
	switch format {
	case FormatText:
		return writeText(w, result)
	case FormatJSON:
		return writeJSON(w, result)
	case FormatCSV:
		return writeCSV(w, result)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func writeText(w io.Writer, result *report.CheckResult) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintln(tw, "HOST\tPORT\tSTATUS\tDAYS LEFT\tISSUER\tEXPIRES")
	fmt.Fprintln(tw, strings.Repeat("-", 100))

	for _, ci := range result.Certificates {
		expires := ci.NotAfter.Format("2006-01-02")
		if ci.Status == report.StatusError {
			fmt.Fprintf(tw, "%s	%d	%s	-	-	-\n", ci.Host, ci.Port, statusIcon(ci.Status))
			fmt.Fprintf(tw, "  └─ Error: %s\n", truncateErr(ci.Error))
			continue
		}

		daysStr := fmt.Sprintf("%d", ci.DaysUntilExpiry)
		if ci.DaysUntilExpiry < 0 {
			daysStr = fmt.Sprintf("%d (expired)", ci.DaysUntilExpiry)
		}

		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n",
			ci.Host, ci.Port, statusIcon(ci.Status), daysStr, truncateIssuer(ci.Issuer), expires)
	}

	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Summary: %d checked — %d OK, %d warning, %d expired, %d errors\n",
		result.Summary.Total, result.Summary.OK, result.Summary.Warning,
		result.Summary.Expired, result.Summary.Errors)

	if result.Summary.Warning > 0 || result.Summary.Expired > 0 {
		fmt.Fprintf(w, "⚠  %d certificate(s) need attention (threshold: %d days)\n",
			result.Summary.Warning+result.Summary.Expired, result.Threshold)
	}

	return nil
}

func writeJSON(w io.Writer, result *report.CheckResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func writeCSV(w io.Writer, result *report.CheckResult) error {
	cw := csv.NewWriter(w)

	header := []string{"host", "port", "status", "subject", "issuer", "sans",
		"serial_number", "not_before", "not_after", "days_until_expiry",
		"key_algorithm", "key_size", "signature_algorithm", "version",
		"is_ca", "chain_length", "chain_valid", "error"}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, ci := range result.Certificates {
		row := []string{
			ci.Host,
			fmt.Sprintf("%d", ci.Port),
			string(ci.Status),
			ci.Subject,
			ci.Issuer,
			strings.Join(ci.SANs, ";"),
			ci.SerialNumber,
			ci.NotBefore.Format(time.RFC3339),
			ci.NotAfter.Format(time.RFC3339),
			fmt.Sprintf("%d", ci.DaysUntilExpiry),
			ci.KeyAlgorithm,
			fmt.Sprintf("%d", ci.KeySize),
			ci.SignatureAlgorithm,
			fmt.Sprintf("%d", ci.Version),
			fmt.Sprintf("%t", ci.IsCA),
			fmt.Sprintf("%d", ci.ChainLength),
			fmt.Sprintf("%t", ci.ChainValid),
			ci.Error,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	cw.Flush()
	return cw.Error()
}

// statusIcon returns a colored status indicator for text output.
func statusIcon(s report.Status) string {
	switch s {
	case report.StatusOK:
		return "✓ ok"
	case report.StatusWarning:
		return "⚠ warning"
	case report.StatusExpired:
		return "✗ expired"
	case report.StatusNotYetValid:
		return "✗ not-yet-valid"
	case report.StatusError:
		return "✗ error"
	default:
		return string(s)
	}
}

func truncateIssuer(issuer string) string {
	if len(issuer) > 40 {
		return issuer[:37] + "..."
	}
	return issuer
}

func truncateErr(err string) string {
	if len(err) > 80 {
		return err[:77] + "..."
	}
	return err
}
