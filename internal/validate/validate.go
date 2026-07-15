// Package validate provides certificate validation functionality.
package validate

import (
	"fmt"
	"io"
	"os"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/inspect"
)

// Validate checks a certificate file and prints validation results.
func Validate(path string, w io.Writer) error {
	certs, err := inspect.LoadCertificate(path)
	if err != nil {
		return fmt.Errorf("loading certificate: %w", err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates found in %s", path)
	}

	for i, cert := range certs {
		info := inspect.ExtractInfo(cert)

		if len(certs) > 1 {
			fmt.Fprintf(w, "--- Certificate %d of %d ---\n", i+1, len(certs))
		}

		// Check expiry
		if info.Expired {
			fmt.Fprintf(w, "  ✗ EXPIRED (since %s)\n", info.NotAfter)
		} else {
			fmt.Fprintf(w, "  ✓ Valid for %d more days\n", info.DaysRemaining)
		}

		// Check self-signed vs CA-issued
		if info.Subject == info.Issuer {
			fmt.Fprintf(w, "  ℹ Self-signed certificate\n")
		} else {
			fmt.Fprintf(w, "  ℹ Issued by: %s\n", info.Issuer)
		}

		// Key size check
		if info.KeySize < 2048 {
			fmt.Fprintf(w, "  ⚠ Weak key size: %d bits (minimum 2048)\n", info.KeySize)
		} else if info.KeySize >= 4096 {
			fmt.Fprintf(w, "  ✓ Key size: %d bits (strong)\n", info.KeySize)
		} else {
			fmt.Fprintf(w, "  ✓ Key size: %d bits\n", info.KeySize)
		}

		// Signature algorithm
		if containsWeakSig(info.SignatureAlgorithm) {
			fmt.Fprintf(w, "  ⚠ Weak signature algorithm: %s\n", info.SignatureAlgorithm)
		} else {
			fmt.Fprintf(w, "  ✓ Signature: %s\n", info.SignatureAlgorithm)
		}

		// SANs check for leaf certs
		if !info.IsCA && len(info.SANs) == 0 {
			fmt.Fprintf(w, "  ⚠ No Subject Alternative Names (SANs)\n")
		}

		fmt.Fprintf(w, "\n")
	}

	// Exit 1 if single cert is expired
	if len(certs) == 1 {
		info := inspect.ExtractInfo(certs[0])
		if info.Expired {
			os.Exit(1)
		}
	}

	return nil
}

func containsWeakSig(algo string) bool {
	s := algo
	return contains(s, "SHA1") || contains(s, "MD5")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
