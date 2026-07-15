// Package convert provides certificate format conversion.
package convert

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Convert converts a certificate between PEM and DER formats.
func Convert(inputPath, outputPath string, inputFormat, outputFormat string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	isPEMInput := inputFormat == "pem" || (inputFormat == "" && detectPEM(data))
	isDERInput := inputFormat == "der" || (inputFormat == "" && !detectPEM(data))

	outFormat := outputFormat
	if outFormat == "" {
		lower := strings.ToLower(outputPath)
		if strings.HasSuffix(lower, ".der") || strings.HasSuffix(lower, ".cer") {
			outFormat = "der"
		} else {
			outFormat = "pem"
		}
	}

	if isPEMInput && outFormat == "der" {
		// PEM -> DER
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("input is not a valid PEM certificate")
		}
		if err := os.WriteFile(outputPath, block.Bytes, 0644); err != nil {
			return fmt.Errorf("writing DER output: %w", err)
		}
		fmt.Fprintf(os.Stdout, "✓ Converted PEM -> DER: %s\n", outputPath)
	} else if isDERInput && outFormat == "pem" {
		// DER -> PEM
		pemOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
		if err := os.WriteFile(outputPath, pemOut, 0644); err != nil {
			return fmt.Errorf("writing PEM output: %w", err)
		}
		fmt.Fprintf(os.Stdout, "✓ Converted DER -> PEM: %s\n", outputPath)
	} else {
		// Same format, copy
		if err := copyFile(inputPath, outputPath); err != nil {
			return fmt.Errorf("copying file: %w", err)
		}
		fmt.Fprintf(os.Stdout, "✓ Copied (same format): %s\n", outputPath)
	}

	return nil
}

func detectPEM(data []byte) bool {
	text := string(data)
	return strings.Contains(text, "-----BEGIN")
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
