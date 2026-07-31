// cmd/gencerts/main.go — Generates the private CA, server cert, and device client certs.
// Run this once on your local machine. All private keys stay here.
//
// Usage:
//   go run ./cmd/gencerts/ -domain 1.2.3.4 -out certs/
//   go run ./cmd/gencerts/   (interactive prompt if flags omitted)

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"tunnel/internal/certgen"
)

func main() {
	domain := flag.String("domain", "", "Server IP address or domain name (e.g. 1.2.3.4 or vpn.example.com)")
	outDir := flag.String("out", "certs", "Output directory for generated files")
	flag.Parse()

	targetDomain := strings.TrimSpace(*domain)
	if targetDomain == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("==================================================")
		fmt.Println(" Personal Tunnel Certificate Generator")
		fmt.Println("==================================================")
		for targetDomain == "" {
			fmt.Print("Enter your VPS IP address or domain name: ")
			line, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalf("failed to read input: %v", err)
			}
			targetDomain = strings.TrimSpace(line)
		}
	}

	if err := certgen.GenerateAll(targetDomain, *outDir); err != nil {
		log.Fatalf("Certificate generation failed: %v", err)
	}

	fmt.Printf("\nDone! Certificate files created in '%s/':\n", *outDir)
	fmt.Println()
	fmt.Println("Upload to your VPS:")
	fmt.Println("  ca-cert.pem  server-cert.pem  server-key.pem")
	fmt.Println()
	fmt.Println("Keep on client device:")
	fmt.Println("  ca-cert.pem  device-laptop-cert.pem  device-laptop-key.pem")
}
