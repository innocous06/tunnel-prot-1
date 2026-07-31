// cmd/gencerts/main.go — Generates the private CA, server cert, and device client certs.
// Run this once on your local machine. All private keys stay here.
//
// Usage:
//   go run ./cmd/gencerts/ -domain in.yourdomain.com -out certs/
//   go run ./cmd/gencerts/ -domain se.yourdomain.com -out certs/se/  (separate dir per VPS)
//
// Generated files:
//   <out>/ca-cert.pem          — CA certificate (upload to every VPS + embed in client)
//   <out>/ca-key.pem           — CA private key  (NEVER upload anywhere)
//   <out>/server-cert.pem      — Server cert     (upload to VPS only)
//   <out>/server-key.pem       — Server key      (upload to VPS only)
//   <out>/device-laptop-cert.pem
//   <out>/device-laptop-key.pem
//   <out>/device-phone-cert.pem
//   <out>/device-phone-key.pem
//
// The CA cert is shared — one CA authenticates all your devices to all your VPS servers.
// Adding a new VPS only requires uploading ca-cert.pem + a new server cert to that VPS.
// Adding a new device only requires generating a new client cert signed by this CA.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	domain  := flag.String("domain", "", "Server domain name, e.g. in.yourdomain.com (required)")
	outDir  := flag.String("out", "certs", "Output directory for generated files")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Usage: gencerts -domain <your-vps-domain> [-out <output-dir>]")
	}

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	fmt.Printf("Generating certificates in %s/ for domain: %s\n\n", *outDir, *domain)

	// --- 1. Private CA ---
	fmt.Println("  [1/4] Generating private CA...")
	caKey, caCert, err := generateCA()
	if err != nil { log.Fatalf("generate CA: %v", err) }
	writeCert(*outDir, "ca-cert.pem", caCert)
	writeKey(*outDir,  "ca-key.pem",  caKey)

	// --- 2. Server cert ---
	fmt.Printf("  [2/4] Generating server cert for %s...\n", *domain)
	srvKey, srvCert, err := generateServerCert(*domain, caKey, caCert)
	if err != nil { log.Fatalf("generate server cert: %v", err) }
	writeCert(*outDir, "server-cert.pem", srvCert)
	writeKey(*outDir,  "server-key.pem",  srvKey)

	// --- 3. Device: laptop ---
	fmt.Println("  [3/4] Generating client cert for device: laptop...")
	laptopKey, laptopCert, err := generateClientCert("device-laptop", caKey, caCert)
	if err != nil { log.Fatalf("generate laptop cert: %v", err) }
	writeCert(*outDir, "device-laptop-cert.pem", laptopCert)
	writeKey(*outDir,  "device-laptop-key.pem",  laptopKey)

	// --- 4. Device: phone (Android) ---
	fmt.Println("  [4/4] Generating client cert for device: phone (Android)...")
	phoneKey, phoneCert, err := generateClientCert("device-phone", caKey, caCert)
	if err != nil { log.Fatalf("generate phone cert: %v", err) }
	writeCert(*outDir, "device-phone-cert.pem", phoneCert)
	writeKey(*outDir,  "device-phone-key.pem",  phoneKey)

	fmt.Printf("\nDone! Files written to %s/\n", *outDir)
	fmt.Println()
	fmt.Println("Upload to each Oracle VPS:")
	fmt.Println("  ca-cert.pem  server-cert.pem  server-key.pem")
	fmt.Println()
	fmt.Println("Keep on this machine only:")
	fmt.Println("  ca-key.pem")
	fmt.Println()
	fmt.Println("Bundle with Windows client (in same dir as .exe or in certs/):")
	fmt.Println("  ca-cert.pem  device-laptop-cert.pem  device-laptop-key.pem")
	fmt.Println()
	fmt.Println("Bundle with Android app (import via app UI):")
	fmt.Println("  ca-cert.pem  device-phone-cert.pem  device-phone-key.pem")
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { return nil, nil, err }

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
	if err != nil { return nil, nil, err }
	cert, err := x509.ParseCertificate(certDER)
	return key, cert, err
}

func generateServerCert(domain string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { return nil, nil, err }

	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Auto-detect: if it's a raw IP address, use IPAddresses SAN.
	// Otherwise use DNSNames SAN (for domain names).
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domain}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil { return nil, nil, err }
	cert, err := x509.ParseCertificate(certDER)
	return key, cert, err
}

func generateClientCert(name string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { return nil, nil, err }

	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil { return nil, nil, err }
	cert, err := x509.ParseCertificate(certDER)
	return key, cert, err
}

func writeCert(dir, name string, cert *x509.Certificate) {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil { log.Fatalf("open %s: %v", path, err) }
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		log.Fatalf("write cert %s: %v", name, err)
	}
	fmt.Printf("      wrote %s\n", path)
}

func writeKey(dir, name string, key *ecdsa.PrivateKey) {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil { log.Fatalf("open %s: %v", path, err) }
	defer f.Close()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil { log.Fatalf("marshal key %s: %v", name, err) }
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		log.Fatalf("write key %s: %v", name, err)
	}
	fmt.Printf("      wrote %s\n", path)
}

func newSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil { log.Fatalf("serial: %v", err) }
	return n
}
