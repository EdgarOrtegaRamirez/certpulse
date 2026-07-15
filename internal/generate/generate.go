// Package generate provides certificate and CSR generation.
package generate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Config holds generation parameters.
type Config struct {
	CN         string
	SANs       []string
	Days       int
	KeySize    int
	Org        string
	IsCSR      bool
	OutputCert string
	OutputKey  string
}

// Generate creates a self-signed certificate or CSR.
func Generate(cfg Config) error {
	var key interface{}
	var err error

	switch cfg.KeySize {
	case 4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case 2048, 0:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		key, err = rsa.GenerateKey(rand.Reader, cfg.KeySize)
	}
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cfg.CN,
			Organization: []string{cfg.Org},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(cfg.Days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Set SANs
	for _, san := range cfg.SANs {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	if cfg.IsCSR {
		// Generate CSR
		csrReq := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   cfg.CN,
				Organization: []string{cfg.Org},
			},
			DNSNames:    template.DNSNames,
			IPAddresses: template.IPAddresses,
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrReq, key)
		if err != nil {
			return fmt.Errorf("creating CSR: %w", err)
		}
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("marshaling private key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

		if err := os.WriteFile(cfg.OutputCert, csrPEM, 0644); err != nil {
			return fmt.Errorf("writing CSR: %w", err)
		}
		if err := os.WriteFile(cfg.OutputKey, keyPEM, 0600); err != nil {
			return fmt.Errorf("writing key: %w", err)
		}
		fmt.Fprintf(os.Stdout, "✓ CSR written to: %s\n", cfg.OutputCert)
		fmt.Fprintf(os.Stdout, "✓ Private key written to: %s\n", cfg.OutputKey)
	} else {
		// Generate self-signed certificate
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(key), key)
		if err != nil {
			return fmt.Errorf("creating certificate: %w", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("marshaling private key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

		if err := os.WriteFile(cfg.OutputCert, certPEM, 0644); err != nil {
			return fmt.Errorf("writing certificate: %w", err)
		}
		if err := os.WriteFile(cfg.OutputKey, keyPEM, 0600); err != nil {
			return fmt.Errorf("writing key: %w", err)
		}
		fmt.Fprintf(os.Stdout, "✓ Self-signed certificate written to: %s\n", cfg.OutputCert)
		fmt.Fprintf(os.Stdout, "✓ Private key written to: %s\n", cfg.OutputKey)
		fmt.Fprintf(os.Stdout, "  Subject: CN=%s\n", cfg.CN)
		fmt.Fprintf(os.Stdout, "  SANs: %s\n", strings.Join(cfg.SANs, ", "))
		fmt.Fprintf(os.Stdout, "  Valid for: %d days\n", cfg.Days)
	}

	return nil
}

func getPublicKey(key interface{}) interface{} {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}
