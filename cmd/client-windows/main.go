package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tunnel/internal/certgen"
	"tunnel/internal/config"
	"tunnel/internal/engine"
	"tunnel/internal/tunif"
)

const (
	tunName   = "PersonalTunnel"
	tunMTU    = 1350
	dnsServer = "1.1.1.1"
)

func main() {
	cfgPath := flag.String("config", "client_config.json", "Path to client config JSON file")
	setupFlag := flag.Bool("setup", false, "Force interactive setup wizard")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil || *setupFlag || len(cfg.Profiles) == 0 {
		cfg = runInteractiveSetup(*cfgPath, cfg)
	}

	for {
		// --- Probe all servers for latency ---
		type probeResult struct {
			profile config.ServerProfile
			rtt     time.Duration
			err     error
		}
		results := make([]probeResult, len(cfg.Profiles))
		var wg sync.WaitGroup
		for i, p := range cfg.Profiles {
			wg.Add(1)
			go func(i int, p config.ServerProfile) {
				defer wg.Done()
				tlsCfg, err := engine.NewClientTLSConfig(cfg.ClientCert, cfg.ClientKey, cfg.CACert, p.Hostname)
				if err != nil {
					results[i] = probeResult{profile: p, err: err}
					return
				}
				addr := fmt.Sprintf("%s:%d", p.Hostname, p.Port)
				rtt, err := engine.ProbeRTT(context.Background(), addr, tlsCfg)
				results[i] = probeResult{profile: p, rtt: rtt, err: err}
			}(i, p)
		}
		wg.Wait()

		// --- Display server list for manual selection ---
		fmt.Println("\n==================================================")
		fmt.Println(" Personal Network Tunnel — Server Selection")
		fmt.Println("==================================================")
		sort.Slice(results, func(i, j int) bool {
			if results[i].err != nil {
				return false
			}
			if results[j].err != nil {
				return true
			}
			return results[i].rtt < results[j].rtt
		})
		for i, r := range results {
			if r.err != nil {
				fmt.Printf("  [%d] %-20s %-10s  UNREACHABLE (%v)\n", i+1, r.profile.Name, r.profile.RegionLabel, r.err)
			} else {
				fmt.Printf("  [%d] %-20s %-10s  %dms\n", i+1, r.profile.Name, r.profile.RegionLabel, r.rtt.Milliseconds())
			}
		}
		fmt.Println("  [A] Add a new VPS server profile")
		fmt.Println("  [G] Re-generate certificates")
		fmt.Println("  [Q] Quit")
		fmt.Printf("\nSelect option [1-%d, A, G, Q]: ", len(results))

		reader := bufio.NewReader(os.Stdin)
		inputStr, _ := reader.ReadString('\n')
		inputStr = strings.TrimSpace(inputStr)

		if strings.EqualFold(inputStr, "q") {
			fmt.Println("Exiting.")
			os.Exit(0)
		}

		if strings.EqualFold(inputStr, "a") {
			addNewProfile(*cfgPath, cfg, reader)
			continue
		}

		if strings.EqualFold(inputStr, "g") {
			runCertWizard(reader)
			continue
		}

		choice, err := strconv.Atoi(inputStr)
		if err != nil || choice < 1 || choice > len(results) {
			choice = 1
		}
		selected := results[choice-1].profile
		if results[choice-1].err != nil {
			fmt.Printf("\nWARN: Server %s appears unreachable (%v). Try anyway? (y/N): ", selected.Name, results[choice-1].err)
			confirm, _ := reader.ReadString('\n')
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(confirm)), "y") {
				continue
			}
		}

		connectAndRun(cfg, selected)
		break
	}
}

func connectAndRun(cfg *config.ClientConfig, selected config.ServerProfile) {
	fmt.Printf("\nConnecting to %s (%s)...\n", selected.Name, selected.RegionLabel)

	// --- Build TLS config for selected server ---
	tlsCfg, err := engine.NewClientTLSConfig(cfg.ClientCert, cfg.ClientKey, cfg.CACert, selected.Hostname)
	if err != nil {
		log.Fatalf("[client] TLS config error: %v\nMake sure certificates exist in 'certs/'.", err)
	}

	serverAddr := fmt.Sprintf("%s:%d", selected.Hostname, selected.Port)

	// --- Dial: try QUIC first, fall back to TCP ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var transport io.ReadWriteCloser
	var serverPublicIP string

	log.Println("[client] trying QUIC (UDP/443)...")
	quicClient := &engine.QUICClient{ServerAddr: serverAddr, TLSConfig: tlsCfg}
	stream, conn, quicErr := quicClient.Dial(ctx)
	if quicErr == nil {
		transport = stream
		serverPublicIP = engine.QUICRemoteAddr(conn)
		log.Printf("[client] ✓ QUIC connected to %s (%s)", serverAddr, serverPublicIP)
	} else {
		log.Printf("[client] QUIC failed: %v", quicErr)
		log.Println("[client] trying TCP fallback (TCP/443)...")
		fb, err := engine.DialTCPFallback(ctx, serverAddr, tlsCfg)
		if err != nil {
			log.Fatalf("[client] TCP fallback also failed: %v\nCheck that ports 443/UDP and 443/TCP are open on the VPS.", err)
		}
		transport = fb
		addrs, _ := net.LookupHost(selected.Hostname)
		if len(addrs) > 0 {
			serverPublicIP = addrs[0]
		}
		log.Printf("[client] ✓ TCP fallback connected to %s (%s)", serverAddr, serverPublicIP)
	}

	// --- Read default gateway BEFORE setting up TUN ---
	gw, err := tunif.DefaultGateway()
	if err != nil {
		log.Fatalf("[client] could not determine default gateway: %v\nCannot continue — routing loop risk.", err)
	}
	log.Printf("[client] physical default gateway: %s", gw)

	// --- Setup TUN adapter ---
	dev, err := tunif.CreateTUN(tunName, selected.TunClientAddr, tunMTU)
	if err != nil {
		log.Fatalf("[client] create TUN: %v\nMake sure wintun.dll is in the same directory as this .exe and you are running as Administrator.", err)
	}
	luid, err := tunif.LUIDFromTUN(dev)
	if err != nil {
		dev.Close()
		log.Fatalf("[client] get LUID: %v", err)
	}
	tunRW := tunif.WrapTUN(dev)

	// Cleanup runs in reverse-creation order on any exit path.
	defer func() {
		log.Println("[client] cleaning up routes...")
		tunif.RemoveDefaultRoute(luid)
		if serverPublicIP != "" {
			tunif.RemoveHostRoute(serverPublicIP)
		}
		tunRW.Close()
		log.Println("[client] routes restored, TUN removed.")
	}()

	// --- Setup routing (ORDER IS CRITICAL) ---
	if serverPublicIP != "" {
		if err := tunif.AddHostRoute(serverPublicIP, gw); err != nil {
			log.Fatalf("[client] add host route: %v", err)
		}
		log.Printf("[client] host route: %s via %s (physical)", serverPublicIP, gw)
	}

	if err := tunif.AddDefaultRoute(tunName, luid); err != nil {
		log.Fatalf("[client] add default route: %v", err)
	}
	log.Printf("[client] default route: 0.0.0.0/0 via TUN %s", tunName)

	if err := tunif.SetDNS(luid, dnsServer); err != nil {
		log.Printf("[client] WARN: set DNS: %v (continuing, DNS may leak)", err)
	} else {
		log.Printf("[client] DNS: %s via TUN", dnsServer)
	}

	log.Printf("\n[client] ✓ Tunnel is UP — all traffic routing through %s (%s)\n", selected.Name, selected.RegionLabel)
	log.Println("[client] Press Ctrl+C to disconnect.")

	// --- Start packet relay ---
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- engine.RelayLoop(tunRW, transport)
	}()

	// --- Wait for disconnect or Ctrl+C ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-relayDone:
		log.Printf("[client] relay ended: %v", err)
	case s := <-sig:
		log.Printf("[client] received %s, disconnecting...", s)
		cancel()
	}
}

func runInteractiveSetup(cfgPath string, existing *config.ClientConfig) *config.ClientConfig {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\n==================================================")
	fmt.Println(" Personal Network Tunnel — Setup Wizard")
	fmt.Println("==================================================")
	fmt.Println("No active server configuration found.")
	fmt.Println("Let's configure your VPS server connection.\n")

	fmt.Print("1. Enter VPS IP Address or Hostname: ")
	hostname, _ := reader.ReadString('\n')
	hostname = strings.TrimSpace(hostname)
	for hostname == "" {
		fmt.Print("   IP Address or Hostname cannot be empty. Try again: ")
		hostname, _ = reader.ReadString('\n')
		hostname = strings.TrimSpace(hostname)
	}

	fmt.Print("2. Enter Server Port [default 443]: ")
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	port := 443
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	fmt.Print("3. Enter Server Name/Label [default Oracle-VPS]: ")
	label, _ := reader.ReadString('\n')
	label = strings.TrimSpace(label)
	if label == "" {
		label = "Oracle-VPS"
	}

	fmt.Print("4. Enter Client TUN Address [default 10.66.0.2/24]: ")
	tunAddr, _ := reader.ReadString('\n')
	tunAddr = strings.TrimSpace(tunAddr)
	if tunAddr == "" {
		tunAddr = "10.66.0.2/24"
	}

	// Check certificates
	caPath := filepath.Join("certs", "ca-cert.pem")
	certPath := filepath.Join("certs", "device-laptop-cert.pem")
	keyPath := filepath.Join("certs", "device-laptop-key.pem")

	if !fileExists(caPath) || !fileExists(certPath) || !fileExists(keyPath) {
		fmt.Println("\n[!] Certificates missing in 'certs/'.")
		fmt.Printf("    Generate mTLS certificates for '%s' now? (Y/n): ", hostname)
		ans, _ := reader.ReadString('\n')
		ans = strings.TrimSpace(ans)
		if ans == "" || strings.HasPrefix(strings.ToLower(ans), "y") {
			if err := certgen.GenerateAll(hostname, "certs"); err != nil {
				log.Printf("WARN: cert generation failed: %v", err)
			}
		}
	}

	cfg := &config.ClientConfig{
		ClientCert: filepath.ToSlash(certPath),
		ClientKey:  filepath.ToSlash(keyPath),
		CACert:     filepath.ToSlash(caPath),
		Profiles: []config.ServerProfile{
			{
				Name:          label,
				Hostname:      hostname,
				Port:          port,
				RegionLabel:   label,
				TunClientAddr: tunAddr,
			},
		},
	}

	if err := config.SaveClientConfig(cfgPath, cfg); err != nil {
		log.Printf("WARN: failed to save config to %s: %v", cfgPath, err)
	} else {
		fmt.Printf("\n✓ Saved configuration to '%s'\n", cfgPath)
	}

	return cfg
}

func addNewProfile(cfgPath string, cfg *config.ClientConfig, reader *bufio.Reader) {
	fmt.Println("\n--- Add New VPS Server Profile ---")
	fmt.Print("1. Enter VPS IP Address or Hostname: ")
	hostname, _ := reader.ReadString('\n')
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		fmt.Println("Cancelled.")
		return
	}

	fmt.Print("2. Enter Server Port [default 443]: ")
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	port := 443
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			port = p
		}
	}

	fmt.Print("3. Enter Server Name/Label: ")
	label, _ := reader.ReadString('\n')
	label = strings.TrimSpace(label)
	if label == "" {
		label = hostname
	}

	fmt.Print("4. Enter Client TUN Address [default 10.66.0.2/24]: ")
	tunAddr, _ := reader.ReadString('\n')
	tunAddr = strings.TrimSpace(tunAddr)
	if tunAddr == "" {
		tunAddr = "10.66.0.2/24"
	}

	cfg.Profiles = append(cfg.Profiles, config.ServerProfile{
		Name:          label,
		Hostname:      hostname,
		Port:          port,
		RegionLabel:   label,
		TunClientAddr: tunAddr,
	})

	if err := config.SaveClientConfig(cfgPath, cfg); err != nil {
		fmt.Printf("WARN: failed to save profile: %v\n", err)
	} else {
		fmt.Printf("✓ Added '%s' to %s\n", label, cfgPath)
	}
}

func runCertWizard(reader *bufio.Reader) {
	fmt.Println("\n--- Certificate Generator Wizard ---")
	fmt.Print("Enter VPS IP Address or Hostname for certificate: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)
	if domain == "" {
		fmt.Println("Cancelled.")
		return
	}

	if err := certgen.GenerateAll(domain, "certs"); err != nil {
		fmt.Printf("Error generating certs: %v\n", err)
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
