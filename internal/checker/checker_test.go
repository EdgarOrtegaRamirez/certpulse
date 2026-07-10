package checker

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/report"
)

// testTLSServer starts a local TLS server with a self-signed certificate.
// Returns the server address and a cleanup function.
func testTLSServer(t *testing.T, certTemplate *x509.Certificate, key any) (string, func()) {
	t.Helper()

	// Set the public key on the template so x509.CreateCertificate can use it
	certTemplate.PublicKey = getPublicKey(key)

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, certTemplate.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loading key pair: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	server := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()

	cleanup := func() {
		_ = server.Close()
	}

	return ln.Addr().String(), cleanup
}

func makeCertTemplate(host string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:              []string{host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
}

// getPublicKey extracts the public key from a private key.
func getPublicKey(key any) any {
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

func TestCheckHost_ValidCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	now := time.Now()
	tmpl := makeCertTemplate("127.0.0.1", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	addr, cleanup := testTLSServer(t, tmpl, key)
	defer cleanup()

	cfg := Config{
		Timeout:    5 * time.Second,
		Threshold:  30,
		SkipVerify: true, // Self-signed cert
		Port:       443,
	}
	chk := New(cfg)
	info := chk.CheckHostAtTime(addr, now)

	if info.Status != report.StatusOK {
		t.Errorf("expected status OK, got %s (error: %s)", info.Status, info.Error)
	}
	if info.Subject != "127.0.0.1" {
		t.Errorf("expected subject '127.0.0.1', got %q", info.Subject)
	}
	if info.KeyAlgorithm != "ECDSA" {
		t.Errorf("expected key algorithm ECDSA, got %s", info.KeyAlgorithm)
	}
	if info.KeySize != 256 {
		t.Errorf("expected key size 256, got %d", info.KeySize)
	}
	if info.ChainLength != 1 {
		t.Errorf("expected chain length 1, got %d", info.ChainLength)
	}
	if info.DaysUntilExpiry <= 0 {
		t.Errorf("expected positive days until expiry, got %d", info.DaysUntilExpiry)
	}
}

func TestCheckHost_ExpiringSoon(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	now := time.Now()
	tmpl := makeCertTemplate("127.0.0.1", now.Add(-time.Hour), now.Add(15*24*time.Hour))
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	addr, cleanup := testTLSServer(t, tmpl, key)
	defer cleanup()

	cfg := Config{
		Timeout:    5 * time.Second,
		Threshold:  30,
		SkipVerify: true,
		Port:       443,
	}
	chk := New(cfg)
	info := chk.CheckHostAtTime(addr, now)

	if info.Status != report.StatusWarning {
		t.Errorf("expected status Warning (15 days < 30 threshold), got %s", info.Status)
	}
	if info.DaysUntilExpiry < 14 || info.DaysUntilExpiry > 16 {
		t.Errorf("expected ~15 days until expiry, got %d", info.DaysUntilExpiry)
	}
}

func TestCheckHost_Expired(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	now := time.Now()
	tmpl := makeCertTemplate("127.0.0.1", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	addr, cleanup := testTLSServer(t, tmpl, key)
	defer cleanup()

	cfg := Config{
		Timeout:    5 * time.Second,
		Threshold:  30,
		SkipVerify: true,
		Port:       443,
	}
	chk := New(cfg)
	info := chk.CheckHostAtTime(addr, now)

	if info.Status != report.StatusExpired {
		t.Errorf("expected status Expired, got %s", info.Status)
	}
	if info.DaysUntilExpiry >= 0 {
		t.Errorf("expected negative days until expiry, got %d", info.DaysUntilExpiry)
	}
}

func TestCheckHost_NotYetValid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	now := time.Now()
	tmpl := makeCertTemplate("127.0.0.1", now.Add(24*time.Hour), now.Add(365*24*time.Hour))
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	addr, cleanup := testTLSServer(t, tmpl, key)
	defer cleanup()

	cfg := Config{
		Timeout:    5 * time.Second,
		Threshold:  30,
		SkipVerify: true,
		Port:       443,
	}
	chk := New(cfg)
	info := chk.CheckHostAtTime(addr, now)

	if info.Status != report.StatusNotYetValid {
		t.Errorf("expected status NotYetValid, got %s", info.Status)
	}
}

func TestCheckHost_ConnectionError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 1 * time.Second
	chk := New(cfg)
	info := chk.CheckHost("127.0.0.1:1") // Port 1 should fail

	if info.Status != report.StatusError {
		t.Errorf("expected status Error, got %s", info.Status)
	}
	if info.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestCheckAll_MultipleHosts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	now := time.Now()
	tmpl := makeCertTemplate("127.0.0.1", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	addr, cleanup := testTLSServer(t, tmpl, key)
	defer cleanup()

	cfg := Config{
		Timeout:    5 * time.Second,
		Threshold:  30,
		SkipVerify: true,
		Port:       443,
	}
	chk := New(cfg)

	hosts := []string{addr, "127.0.0.1:1"} // One valid, one error
	result := chk.CheckAllAtTime(hosts, now)

	if result.Summary.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Summary.Total)
	}
	if result.Summary.OK != 1 {
		t.Errorf("expected OK 1, got %d", result.Summary.OK)
	}
	if result.Summary.Errors != 1 {
		t.Errorf("expected errors 1, got %d", result.Summary.Errors)
	}
}

func TestParseHost_DefaultPort(t *testing.T) {
	host, port := parseHost("example.com", 443)
	if host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", host)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestParseHost_CustomPort(t *testing.T) {
	host, port := parseHost("example.com:8443", 443)
	if host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", host)
	}
	if port != 8443 {
		t.Errorf("expected port 8443, got %d", port)
	}
}

func TestParseHost_IPv6(t *testing.T) {
	host, port := parseHost("[::1]:8443", 443)
	if host != "::1" {
		t.Errorf("expected host '::1', got %q", host)
	}
	if port != 8443 {
		t.Errorf("expected port 8443, got %d", port)
	}
}

func TestParseHost_IPv6NoPort(t *testing.T) {
	host, port := parseHost("[::1]", 443)
	if host != "::1" {
		t.Errorf("expected host '::1', got %q", host)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestParseHost_IPv6NoBrackets(t *testing.T) {
	// IPv6 without brackets should use default port (multiple colons)
	host, port := parseHost("::1", 443)
	if host != "::1" {
		t.Errorf("expected host '::1', got %q", host)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestKeyAlgorithm_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := makeCertTemplate("test", time.Now(), time.Now().Add(time.Hour))
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	if alg := keyAlgorithm(cert); alg != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", alg)
	}
	if size := keySize(cert); size != 256 {
		t.Errorf("expected 256, got %d", size)
	}
}

func TestKeyAlgorithm_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := makeCertTemplate("test", time.Now(), time.Now().Add(time.Hour))
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	if alg := keyAlgorithm(cert); alg != "RSA" {
		t.Errorf("expected RSA, got %s", alg)
	}
	if size := keySize(cert); size != 2048 {
		t.Errorf("expected 2048, got %d", size)
	}
}

func TestKeyAlgorithm_Ed25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := makeCertTemplate("test", time.Now(), time.Now().Add(time.Hour))
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	cert, _ := x509.ParseCertificate(der)
	if alg := keyAlgorithm(cert); alg != "Ed25519" {
		t.Errorf("expected Ed25519, got %s", alg)
	}
	if size := keySize(cert); size != 256 {
		t.Errorf("expected 256, got %d", size)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", cfg.Timeout)
	}
	if cfg.Threshold != 30 {
		t.Errorf("expected threshold 30, got %d", cfg.Threshold)
	}
	if cfg.Port != 443 {
		t.Errorf("expected port 443, got %d", cfg.Port)
	}
	if cfg.SkipVerify != false {
		t.Error("expected SkipVerify false")
	}
}

func TestSanitizeErr(t *testing.T) {
	// Test nil error
	if got := sanitizeErr(nil); got != "" {
		t.Errorf("expected empty string for nil error, got %q", got)
	}

	// Test short error
	if got := sanitizeErr(fmt.Errorf("connection refused")); got != "connection refused" {
		t.Errorf("expected 'connection refused', got %q", got)
	}

	// Test long error truncation
	long := strings.Repeat("x", 300)
	result := sanitizeErr(fmt.Errorf("%s", long))
	if len(result) > 203 {
		t.Errorf("expected truncated error, got length %d", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("expected error to end with ...")
	}
}

func TestCheckHost_PreservesHostOrder(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 1 * time.Second
	chk := New(cfg)

	hosts := []string{"127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"}
	result := chk.CheckAllAtTime(hosts, time.Now())

	for i := range hosts {
		if result.Certificates[i].Host != "127.0.0.1" {
			t.Errorf("host %d: expected 127.0.0.1, got %s", i, result.Certificates[i].Host)
		}
	}
}
