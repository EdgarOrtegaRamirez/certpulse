// Package main is the entry point for the certpulse CLI.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/checker"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/output"
	"github.com/EdgarOrtegaRamirez/certpulse/internal/report"
	"github.com/spf13/cobra"
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

	// Hidden version command
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
		// Filter to only show warnings, expired, and errors
		filtered := filterQuiet(result)
		result = filtered
	}

	if err := output.Write(os.Stdout, &result, format); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	os.Exit(result.ExitCode())
	return nil
}

func collectHosts(args []string) ([]string, error) {
	var hosts []string

	// From command-line arguments
	hosts = append(hosts, args...)

	// From file
	if flagFile != "" {
		fileHosts, err := readHostsFromFile(flagFile)
		if err != nil {
			return nil, fmt.Errorf("reading host file: %w", err)
		}
		hosts = append(hosts, fileHosts...)
	}

	// From stdin
	if flagStdin {
		stdinHosts, err := readHostsFromReader(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		hosts = append(hosts, stdinHosts...)
	}

	// Deduplicate while preserving order
	hosts = dedup(hosts)

	return hosts, nil
}

func readHostsFromFile(path string) ([]string, error) {
	// Validate path to prevent directory traversal in certain contexts
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("invalid file path: path traversal not allowed")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return readHostsFromReader(f)
}

func readHostsFromReader(r interface{ Read([]byte) (int, error) }) ([]string, error) {
	var hosts []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
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
