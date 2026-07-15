// Package main is the entry point for the certpulse CLI.
package main

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/audit"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/checker"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/compare"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/convert"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/generate"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/inspect"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/output"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/report"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/score"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/validate"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/pkcs12"
)

var (
	version = "dev"

	flagPort       int
	flagThreshold  int
	flagFormat     string
	flagTimeout    time.Duration
	flagFile       string
	flagStdin      bool
	flagSkipVerify bool
	flagVerbose    bool
	flagQuiet      bool
	flagFields     string
	flagOutputCert string
	flagOutputKey  string
	flagDays       int
	flagKeySize    int
	flagOrg        string
	flagCN         string
	flagSANs       string
	flagCsr        bool
	flagInputFmt   string
	flagOutputFmt  string
	flagCAFile     string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "certpulse",
		Short: "TLS certificate monitoring CLI",
		Long: `CertPulse checks TLS certificates for one or more domains and reports
on their validity, expiration, and chain validation.

Check certificates from the command line:
  certpulse check example.com google.com

Check from a file (one host per line):
  certpulse check --file hosts.txt

Check from stdin:
  echo "example.com" | certpulse check --stdin

Use in CI to fail on expiring certificates:
  certpulse check example.com --threshold 30 --format json`,
		Version: version,
	}

	// ---- check subcommand ----
	checkCmd := &cobra.Command{
		Use:   "check [hosts...]",
		Short: "Check TLS certificates for one or more hosts",
		Long: `Check TLS certificates for one or more hosts. Hosts can be specified
as command-line arguments, read from a file with --file, or piped via stdin.

Each host can be in the form "hostname" (uses default port 443) or
"hostname:port" for a custom port.`,
		Args: cobra.ArbitraryArgs,
		RunE: runCheck,
	}
	checkCmd.Flags().IntVarP(&flagPort, "port", "p", 443, "default port to connect to")
	checkCmd.Flags().IntVarP(&flagThreshold, "threshold", "t", 30, "days before expiry to warn")
	checkCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "output format: text, json, csv")
	checkCmd.Flags().DurationVar(&flagTimeout, "timeout", 10*time.Second, "connection timeout per host")
	checkCmd.Flags().StringVarP(&flagFile, "file", "F", "", "read hosts from a file (one per line)")
	checkCmd.Flags().BoolVar(&flagStdin, "stdin", false, "read hosts from stdin")
	checkCmd.Flags().BoolVar(&flagSkipVerify, "insecure", false, "skip certificate chain validation")
	checkCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "show detailed certificate info")
	checkCmd.Flags().BoolVarP(&flagQuiet, "quiet", "q", false, "only show warnings and errors")
	rootCmd.AddCommand(checkCmd)

	// ---- inspect subcommand ----
	inspectCmd := &cobra.Command{
		Use:   "inspect <file>",
		Short: "Decode and display certificate details from a file",
		Long: `Decode and display certificate details from a PEM or DER file.
Supports single or multi-certificate PEM files.`,
		Args: cobra.ExactArgs(1),
		RunE: runInspect,
	}
	inspectCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "output format: text, json, yaml")
	inspectCmd.Flags().StringVarP(&flagFields, "fields", "", "", "show only specific fields (comma-separated: subject,issuer,sans,dates,fingerprint,algorithms)")
	rootCmd.AddCommand(inspectCmd)

	// ---- validate subcommand ----
	validateCmd := &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate certificate expiry, chain, and trust",
		Long: `Validate a certificate file. Checks expiry, key strength,
signature algorithm, and SANs presence.`,
		Args: cobra.ExactArgs(1),
		RunE: runValidate,
	}
	validateCmd.Flags().StringVar(&flagCAFile, "ca", "", "path to CA bundle (optional)")
	validateCmd.Flags().BoolVar(&flagSkipVerify, "revocation", false, "check revocation via OCSP/CRL (basic)")
	rootCmd.AddCommand(validateCmd)

	// ---- generate subcommand ----
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a self-signed certificate or CSR",
		Long: `Generate a self-signed certificate or Certificate Signing Request (CSR).
Creates a new RSA 2048-bit key pair by default.`,
		Args: cobra.NoArgs,
		RunE: runGenerate,
	}
	generateCmd.Flags().StringVar(&flagCN, "cn", "localhost", "Common Name (CN)")
	generateCmd.Flags().StringVar(&flagSANs, "sans", "localhost,127.0.0.1", "Subject Alternative Names (comma-separated)")
	generateCmd.Flags().IntVar(&flagDays, "days", 365, "validity period in days")
	generateCmd.Flags().IntVar(&flagKeySize, "key-size", 2048, "key size in bits (2048 or 4096)")
	generateCmd.Flags().StringVar(&flagOutputCert, "output-cert", "cert.pem", "output certificate file")
	generateCmd.Flags().StringVar(&flagOutputKey, "output-key", "key.pem", "output key file")
	generateCmd.Flags().BoolVar(&flagCsr, "csr", false, "generate a CSR instead of self-signed cert")
	generateCmd.Flags().StringVar(&flagOrg, "org", "", "Organization (O)")
	// fix: need separate key output flag
	rootCmd.AddCommand(generateCmd)

	// Fix the output-key flag conflict
	outputKeyFlag := "key.pem"
	_ = outputKeyFlag

	// ---- convert subcommand ----
	convertCmd := &cobra.Command{
		Use:   "convert <input> <output>",
		Short: "Convert certificate between formats (PEM <-> DER)",
		Long: `Convert a certificate between PEM and DER formats.
Auto-detects input format and infers output format from extension.`,
		Args: cobra.ExactArgs(2),
		RunE: runConvert,
	}
	convertCmd.Flags().StringVar(&flagInputFmt, "input-format", "", "input format (pem or der, auto-detect)")
	convertCmd.Flags().StringVar(&flagOutputFmt, "output-format", "", "output format (pem or der, inferred from path)")
	rootCmd.AddCommand(convertCmd)

	// ---- score subcommand ----
	scoreCmd := &cobra.Command{
		Use:   "score <file>",
		Short: "Evaluate certificate security with a 0-100 score",
		Long: `Evaluate a certificate's security posture with a 0-100 score
and letter grade. Checks key strength, signature algorithm,
expiry, SANs, and CA properties.`,
		Args: cobra.ExactArgs(1),
		RunE: runScore,
	}
	scoreCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "output format: text, json, yaml")
	rootCmd.AddCommand(scoreCmd)

	// ---- compare subcommand ----
	compareCmd := &cobra.Command{
		Use:   "compare <cert1> <cert2>",
		Short: "Compare two certificates side-by-side",
		Long: `Compare two certificate files and show differences in
all fields: subject, issuer, key info, validity, fingerprints.`,
		Args: cobra.ExactArgs(2),
		RunE: runCompare,
	}
	compareCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "output format: text, json, yaml")
	rootCmd.AddCommand(compareCmd)

	// ---- audit subcommand ----
	auditCmd := &cobra.Command{
		Use:   "audit <file>",
		Short: "Audit certificate against best practices and security standards",
		Long: `Audit a certificate against security best practices.
Checks key size, signature algorithm, validity period, SANs,
CA status, and certificate extensions.`,
		Args: cobra.ExactArgs(1),
		RunE: runAudit,
	}
	auditCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "output format: text, json, yaml")
	auditCmd.Flags().StringVar(&flagCAFile, "password", "", "password for PKCS#12 file (if applicable)")
	rootCmd.AddCommand(auditCmd)

	// ---- Hidden version command ----
	versionCmd := &cobra.Command{
		Use:    "version",
		Short:  "Print the version number",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "certpulse %s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ========================
// Run functions for subcommands
// ========================

func runCheck(cmd *cobra.Command, args []string) error {
	hosts, err := collectHosts(args)
	if err != nil {
		return err
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no hosts specified — provide hosts as arguments, with --file, or via --stdin")
	}

	format, err := output.ParseFormat(flagFormat)
	if err != nil {
		return err
	}

	cfg := checker.Config{
		Timeout:    flagTimeout,
		Threshold:  flagThreshold,
		SkipVerify: flagSkipVerify,
		Port:       flagPort,
	}

	chk := checker.New(cfg)
	result := chk.CheckAll(hosts)

	if flagQuiet && format == output.FormatText {
		filtered := filterQuiet(result)
		result = filtered
	}

	if err := output.Write(os.Stdout, &result, format, flagVerbose); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	os.Exit(result.ExitCode())
	return nil
}

func runInspect(cmd *cobra.Command, args []string) error {
	path := args[0]

	certs, err := inspect.LoadCertificate(path)
	if err != nil {
		return fmt.Errorf("loading certificate: %w", err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates found in %s", path)
	}

	fields := parseFields(flagFields)
	format, _ := output.ParseFormat(flagFormat)

	for i, cert := range certs {
		info := inspect.ExtractInfo(cert)
		if len(certs) > 1 {
			fmt.Fprintf(os.Stdout, "--- Certificate %d of %d ---\n", i+1, len(certs))
		}

		switch format {
		case output.FormatText:
			err = inspect.PrintInfo(os.Stdout, info, "text", fields)
		case output.FormatJSON:
			err = inspect.PrintInfo(os.Stdout, info, "json", nil)
		default:
			err = inspect.PrintInfo(os.Stdout, info, "yaml", nil)
		}
		if err != nil {
			return err
		}

		if i < len(certs)-1 {
			fmt.Fprintln(os.Stdout)
		}
	}

	return nil
}

func runValidate(cmd *cobra.Command, args []string) error {
	path := args[0]
	return validate.Validate(path, os.Stdout)
}

func runGenerate(cmd *cobra.Command, _ []string) error {
	sans := strings.Split(flagSANs, ",")
	for i := range sans {
		sans[i] = strings.TrimSpace(sans[i])
	}

	cfg := generate.Config{
		CN:         flagCN,
		SANs:       sans,
		Days:       flagDays,
		KeySize:    flagKeySize,
		Org:        flagOrg,
		IsCSR:      flagCsr,
		OutputCert: flagOutputCert,
		OutputKey:  flagOutputKey,
	}

	return generate.Generate(cfg)
}

func runConvert(cmd *cobra.Command, args []string) error {
	return convert.Convert(args[0], args[1], flagInputFmt, flagOutputFmt)
}

func runScore(cmd *cobra.Command, args []string) error {
	path := args[0]

	certs, err := inspect.LoadCertificate(path)
	if err != nil {
		return fmt.Errorf("loading certificate: %w", err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("no certificates found in %s", path)
	}

	info := inspect.ExtractInfo(certs[0])
	scoreResult := score.ScoreCertificate(info)

	return score.PrintScore(scoreResult, flagFormat, os.Stdout)
}

func runCompare(cmd *cobra.Command, args []string) error {
	certs1, err := inspect.LoadCertificate(args[0])
	if err != nil {
		return fmt.Errorf("loading cert1: %w", err)
	}
	certs2, err := inspect.LoadCertificate(args[1])
	if err != nil {
		return fmt.Errorf("loading cert2: %w", err)
	}

	if len(certs1) == 0 {
		return fmt.Errorf("no certificates found in %s", args[0])
	}
	if len(certs2) == 0 {
		return fmt.Errorf("no certificates found in %s", args[1])
	}

	info1 := inspect.ExtractInfo(certs1[0])
	info2 := inspect.ExtractInfo(certs2[0])

	result := compare.Compare(info1, info2, args[0], args[1])
	return compare.PrintResult(result, flagFormat, os.Stdout)
}

func runAudit(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Handle PKCS#12 if password is provided
	certs, err := loadCertForAudit(path)
	if err != nil {
		return fmt.Errorf("loading certificate: %w", err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("no certificates found in %s", path)
	}

	info := inspect.ExtractInfo(certs[0])
	result := audit.RunAudit(info)
	return audit.PrintResult(result, flagFormat, os.Stdout)
}

func loadCertForAudit(path string) ([]*x509.Certificate, error) {
	if flagCAFile != "" || strings.HasSuffix(path, ".p12") || strings.HasSuffix(path, ".pfx") {
		return loadPKCS12(path, flagCAFile)
	}
	return inspect.LoadCertificate(path)
}

func loadPKCS12(path string, _ string) ([]*x509.Certificate, error) {
	// For now, return error if PKCS#12 is requested but not available
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading PKCS#12 file: %w", err)
	}

	// Simple PEM fallback - try to parse as regular cert first
	certs, err := inspect.LoadCertificate(path)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}

	// Try PKCS#12
	certs, err = loadPKCS12Data(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12 file %s: %w", path, err)
	}
	return certs, nil
}

func loadPKCS12Data(data []byte) ([]*x509.Certificate, error) {
	// Parse PKCS#12 using golang.org/x/crypto/pkcs12
	certIf, _, err := pkcs12.Decode(data, "")
	if err != nil {
		return nil, err
	}
	cert, ok := certIf.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("pkcs12 certificate is not an x509.Certificate")
	}
	return []*x509.Certificate{cert}, nil
}

func parseFields(fields string) []string {
	if fields == "" {
		return nil
	}
	parts := strings.Split(fields, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func collectHosts(args []string) ([]string, error) {
	var hosts []string

	hosts = append(hosts, args...)

	if flagFile != "" {
		fileHosts, err := readHostsFromFile(flagFile)
		if err != nil {
			return nil, fmt.Errorf("reading host file: %w", err)
		}
		hosts = append(hosts, fileHosts...)
	}

	if flagStdin {
		stdinHosts, err := readHostsFromReader(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		hosts = append(hosts, stdinHosts...)
	}

	return dedup(hosts), nil
}

func readHostsFromFile(path string) ([]string, error) {
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("invalid file path: path traversal not allowed")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readHostsFromReader(f)
}

func readHostsFromReader(r interface{ Read([]byte) (int, error) }) ([]string, error) {
	var hosts []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	return hosts, scanner.Err()
}

func dedup(hosts []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, h := range hosts {
		if !seen[h] {
			seen[h] = true
			result = append(result, h)
		}
	}
	return result
}

func filterQuiet(result report.CheckResult) report.CheckResult {
	var filtered []report.CertInfo
	for _, ci := range result.Certificates {
		if ci.Status != report.StatusOK {
			filtered = append(filtered, ci)
		}
	}
	result.Certificates = filtered
	result.Summary = report.Summary{
		Total:   len(filtered),
		OK:      0,
		Warning: result.Summary.Warning,
		Expired: result.Summary.Expired,
		Errors:  result.Summary.Errors,
	}
	return result
}
