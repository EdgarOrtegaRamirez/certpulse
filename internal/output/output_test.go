package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/report"
)

func sampleResult() report.CheckResult {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	return report.CheckResult{
		CheckedAt: now,
		Threshold: 30,
		Certificates: []report.CertInfo{
			{
				Host:               "example.com",
				Port:               443,
				Subject:            "example.com",
				Issuer:             "Let's Encrypt R3",
				SANs:               []string{"example.com", "www.example.com"},
				SerialNumber:       "1234567890",
				NotBefore:          now.Add(-180 * 24 * time.Hour),
				NotAfter:           now.Add(60 * 24 * time.Hour),
				DaysUntilExpiry:    60,
				KeyAlgorithm:       "RSA",
				KeySize:            2048,
				SignatureAlgorithm: "SHA256-RSA",
				Version:            3,
				IsCA:               false,
				ChainLength:        2,
				ChainValid:         true,
				Status:             report.StatusOK,
			},
			{
				Host:               "expiring.com",
				Port:               443,
				Subject:            "expiring.com",
				Issuer:             "DigiCert",
				SANs:               []string{"expiring.com"},
				SerialNumber:       "9876543210",
				NotBefore:          now.Add(-350 * 24 * time.Hour),
				NotAfter:           now.Add(15 * 24 * time.Hour),
				DaysUntilExpiry:    15,
				KeyAlgorithm:       "ECDSA",
				KeySize:            256,
				SignatureAlgorithm: "ECDSA-SHA256",
				Version:            3,
				IsCA:               false,
				ChainLength:        2,
				ChainValid:         true,
				Status:             report.StatusWarning,
			},
			{
				Host:   "broken.com",
				Port:   443,
				Status: report.StatusError,
				Error:  "connection refused",
			},
		},
		Summary: report.Summary{
			Total:   3,
			OK:      1,
			Warning: 1,
			Expired: 0,
			Errors:  1,
		},
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
		wantErr  bool
	}{
		{"text", FormatText, false},
		{"table", FormatText, false},
		{"t", FormatText, false},
		{"json", FormatJSON, false},
		{"j", FormatJSON, false},
		{"csv", FormatCSV, false},
		{"c", FormatCSV, false},
		{"TEXT", FormatText, false},
		{"JSON", FormatJSON, false},
		{"xml", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFormat(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got %s", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
				return
			}
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestWriteText(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer
	if err := Write(&buf, &result, FormatText); err != nil {
		t.Fatalf("Write text: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain 'example.com'")
	}
	if !strings.Contains(output, "expiring.com") {
		t.Error("expected output to contain 'expiring.com'")
	}
	if !strings.Contains(output, "broken.com") {
		t.Error("expected output to contain 'broken.com'")
	}
	if !strings.Contains(output, "Summary") {
		t.Error("expected output to contain 'Summary'")
	}
	if !strings.Contains(output, "connection refused") {
		t.Error("expected output to contain error message")
	}
}

func TestWriteJSON(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer
	if err := Write(&buf, &result, FormatJSON); err != nil {
		t.Fatalf("Write JSON: %v", err)
	}

	var decoded report.CheckResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if decoded.Summary.Total != 3 {
		t.Errorf("expected total 3, got %d", decoded.Summary.Total)
	}
	if len(decoded.Certificates) != 3 {
		t.Errorf("expected 3 certificates, got %d", len(decoded.Certificates))
	}
	if decoded.Certificates[0].Host != "example.com" {
		t.Errorf("expected first cert host 'example.com', got %q", decoded.Certificates[0].Host)
	}
	if decoded.Certificates[0].KeyAlgorithm != "RSA" {
		t.Errorf("expected RSA, got %s", decoded.Certificates[0].KeyAlgorithm)
	}
}

func TestWriteCSV(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer
	if err := Write(&buf, &result, FormatCSV); err != nil {
		t.Fatalf("Write CSV: %v", err)
	}

	reader := csv.NewReader(&buf)
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV output: %v", err)
	}

	// Header + 3 data rows
	if len(rows) != 4 {
		t.Fatalf("expected 4 rows (header + 3 data), got %d", len(rows))
	}

	// Check header
	if rows[0][0] != "host" {
		t.Errorf("expected first header column 'host', got %q", rows[0][0])
	}

	// Check first data row
	if rows[1][0] != "example.com" {
		t.Errorf("expected first row host 'example.com', got %q", rows[1][0])
	}
	if rows[1][10] != "RSA" {
		t.Errorf("expected key algorithm 'RSA', got %q", rows[1][10])
	}
}

func TestWrite_UnsupportedFormat(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer
	err := Write(&buf, &result, Format("xml"))
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestStatusIcon(t *testing.T) {
	tests := []struct {
		status   report.Status
		contains string
	}{
		{report.StatusOK, "ok"},
		{report.StatusWarning, "warning"},
		{report.StatusExpired, "expired"},
		{report.StatusError, "error"},
		{report.StatusNotYetValid, "not-yet-valid"},
	}
	for _, tt := range tests {
		got := statusIcon(tt.status)
		if !strings.Contains(got, tt.contains) {
			t.Errorf("statusIcon(%s): expected to contain %q, got %q", tt.status, tt.contains, got)
		}
	}
}

func TestTruncateIssuer(t *testing.T) {
	short := "Let's Encrypt R3"
	if got := truncateIssuer(short); got != short {
		t.Errorf("expected %q, got %q", short, got)
	}

	long := strings.Repeat("A", 50)
	got := truncateIssuer(long)
	if len(got) != 40 {
		t.Errorf("expected length 40, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("expected to end with ...")
	}
}

func TestTruncateErr(t *testing.T) {
	short := "connection refused"
	if got := truncateErr(short); got != short {
		t.Errorf("expected %q, got %q", short, got)
	}

	long := strings.Repeat("E", 100)
	got := truncateErr(long)
	if len(got) != 80 {
		t.Errorf("expected length 80, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("expected to end with ...")
	}
}

func TestWriteText_EmptyResult(t *testing.T) {
	result := report.CheckResult{
		CheckedAt:    time.Now(),
		Threshold:    30,
		Certificates: []report.CertInfo{},
		Summary:      report.Summary{},
	}
	var buf bytes.Buffer
	if err := Write(&buf, &result, FormatText); err != nil {
		t.Fatalf("Write text: %v", err)
	}
	if !strings.Contains(buf.String(), "Summary") {
		t.Error("expected output to contain Summary")
	}
}

func TestWriteJSON_EmptyResult(t *testing.T) {
	result := report.CheckResult{
		CheckedAt:    time.Now(),
		Threshold:    30,
		Certificates: []report.CertInfo{},
		Summary:      report.Summary{},
	}
	var buf bytes.Buffer
	if err := Write(&buf, &result, FormatJSON); err != nil {
		t.Fatalf("Write JSON: %v", err)
	}

	var decoded report.CheckResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.Summary.Total != 0 {
		t.Errorf("expected total 0, got %d", decoded.Summary.Total)
	}
}

func TestWriteText_ExpiredCert(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	result := report.CheckResult{
		CheckedAt: now,
		Threshold: 30,
		Certificates: []report.CertInfo{
			{
				Host:            "expired.com",
				Port:            443,
				NotAfter:        now.Add(-10 * 24 * time.Hour),
				DaysUntilExpiry: -10,
				Status:          report.StatusExpired,
			},
		},
		Summary: report.Summary{
			Total:   1,
			Expired: 1,
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, &result, FormatText); err != nil {
		t.Fatalf("Write text: %v", err)
	}
	if !strings.Contains(buf.String(), "expired") {
		t.Error("expected output to contain 'expired'")
	}
	if !strings.Contains(buf.String(), "need attention") {
		t.Error("expected attention warning")
	}
}
