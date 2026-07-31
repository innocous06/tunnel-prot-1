package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

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
	flag.Parse()

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		log.Fatalf("[client] failed to load config: %v", err)
	}
	if len(cfg.Profiles) == 0 {
		log.Fatal("[client] no server profiles configured")
	}

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
	fmt.Println("\n=== Personal Network Tunnel ===")
	fmt.Println("Available servers (sorted by latency):")
	fmt.Println()
	sort.Slice(results, func(i, j int) bool {
		if results[i].err != nil { return false }
		if results[j].err != nil { return true }
		return results[i].rtt < results[j].rtt
	})
	for i, r := range results {
		if r.err != nil {
			fmt.Printf("  [%d] %-20s %-10s  UNREACHABLE (%v)\n", i+1, r.profile.Name, r.profile.RegionLabel, r.err)
		} else {
			fmt.Printf("  [%d] %-20s %-10s  %dms\n", i+1, r.profile.Name, r.profile.RegionLabel, r.rtt.Milliseconds())
		}
	}
	fmt.Printf("\nSelect server [1-%d]: ", len(results))
	var choice int
	if _, err := fmt.Scanf("%d", &choice); err != nil || choice < 1 || choice > len(results) {
		choice = 1
	}
	selected := results[choice-1].profile
	if results[choice-1].err != nil {
		log.Fatalf("[client] selected server is unreachable: %v", results[choice-1].err)
	}
	fmt.Printf("\nConnecting to %s (%s)...\n", selected.Name, selected.RegionLabel)

	// --- Build TLS config for selected server ---
	tlsCfg, err := engine.NewClientTLSConfig(cfg.ClientCert, cfg.ClientKey, cfg.CACert, selected.Hostname)
	if err != nil {
		log.Fatalf("[client] TLS config: %v", err)
	}

	serverAddr := fmt.Sprintf("%s:%d", selected.Hostname, selected.Port)

	// --- Dial: try QUIC first, fall back to TCP ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var transport io.ReadWriteCloser
	var serverPublicIP string

	log.Println("[client] trying QUIC (UDP/443)...")
	quicClient := &engine.QUICClient{ServerAddr: serverAddr, TLSConfig: tlsCfg}
	// Use the main ctx — quic-go ties the connection lifetime to the dial context.
	// Cancelling it (even from a short-lived timeout ctx) closes the connection immediately.
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
	// Step 1: punch a hole for the server's real IP through the physical gateway.
	if serverPublicIP != "" {
		if err := tunif.AddHostRoute(serverPublicIP, gw); err != nil {
			log.Fatalf("[client] add host route: %v", err)
		}
		log.Printf("[client] host route: %s via %s (physical)", serverPublicIP, gw)
	}

	// Step 2: now it's safe to redirect all other traffic through the TUN.
	if err := tunif.AddDefaultRoute(tunName, luid); err != nil {
		log.Fatalf("[client] add default route: %v", err)
	}
	log.Printf("[client] default route: 0.0.0.0/0 via TUN %s", tunName)

	// Step 3: set DNS on the TUN interface.
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
