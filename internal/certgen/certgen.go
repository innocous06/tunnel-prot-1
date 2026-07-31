// Package certgen provides certificate generation functions for the tunnel project.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateAll generates a private CA, server certificate, and client certificates
// for laptop and phone in outDir.
func GenerateAll(domainOrIP, outDir string) error {
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return fmt.Errorf("create output dir %s: %w", outDir, err)
	}

	fmt.Printf("==> Generating certificates in '%s/' for: %s\n", outDir, domainOrIP)

	// 1. Private CA
	caKey, caCert, err := GenerateCA()
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	if err := WriteCert(outDir, "ca-cert.pem", caCert); err != nil { return err }
	if err := WriteKey(outDir, "ca-key.pem", caKey); err != nil { return err }

	// 2. Server cert
	srvKey, srvCert, err := GenerateServerCert(domainOrIP, caKey, caCert)
	if err != nil {
		return fmt.Errorf("generate server cert: %w", err)
	}
	if err := WriteCert(outDir, "server-cert.pem", srvCert); err != nil { return err }
	if err := WriteKey(outDir, "server-key.pem", srvKey); err != nil { return err }

	// 3. Device: laptop
	laptopKey, laptopCert, err := GenerateClientCert("device-laptop", caKey, caCert)
	if err != nil {
		return fmt.Errorf("generate laptop cert: %w", err)
	}
	if err := WriteCert(outDir, "device-laptop-cert.pem", laptopCert); err != nil { return err }
	if err := WriteKey(outDir, "device-laptop-key.pem", laptopKey); err != nil { return err }

	// 4. Device: phone
	phoneKey, phoneCert, err := GenerateClientCert("device-phone", caKey, caCert)
	if err != nil {
		return fmt.Errorf("generate phone cert: %w", err)
	}
	if err := WriteCert(outDir, "device-phone-cert.pem", phoneCert); err != nil { return err }
	if err := WriteKey(outDir, "device-phone-key.pem", phoneKey); err != nil { return err }

	fmt.Println("✓ All certificates successfully generated!")
	return nil
}

// GenerateCA creates a new ECDSA P-256 root certificate authority.
func GenerateCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "TunnelCA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	return key, cert, err
}

// GenerateServerCert creates a server certificate signed by the given CA.
func GenerateServerCert(domainOrIP string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: domainOrIP},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(domainOrIP); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domainOrIP}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	return key, cert, err
}

// GenerateClientCert creates a client certificate for device authentication.
func GenerateClientCert(name string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	return key, cert, err
}

// WriteCert writes an X.509 certificate to a PEM file.
func WriteCert(dir, name string, cert *x509.Certificate) error {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("write cert %s: %w", name, err)
	}
	return nil
}

// WriteKey writes an EC private key to a PEM file.
func WriteKey(dir, name string, key *ecdsa.PrivateKey) error {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key %s: %w", name, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		return fmt.Errorf("write key %s: %w", name, err)
	}
	return nil
}

func newSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}
