package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"tunnel/internal/config"
	"tunnel/internal/engine"
	"tunnel/internal/tunif"
)

func main() {
	cfgPath := flag.String("config", "server_config.json", "Path to server config JSON file")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		log.Printf("[server] config '%s' not found or invalid: %v", *cfgPath, err)
		log.Printf("[server] creating default server config at '%s'...", *cfgPath)
		cfg = &config.ServerConfig{
			ListenUDP:      ":443",
			ListenTCP:      ":443",
			TunAddress:     "10.66.0.1/24",
			TunSubnet:      "10.66.0.0/24",
			ServerCertFile: "certs/server-cert.pem",
			ServerKeyFile:  "certs/server-key.pem",
			CACert:         "certs/ca-cert.pem",
		}
		if saveErr := config.SaveServerConfig(*cfgPath, cfg); saveErr != nil {
			log.Fatalf("[server] failed to save default config: %v", saveErr)
		}
	}

	// --- TLS config (mTLS: server cert + require client cert from our CA) ---
	tlsCfg, err := engine.NewServerTLSConfig(cfg.ServerCertFile, cfg.ServerKeyFile, cfg.CACert)
	if err != nil {
		log.Fatalf("[server] TLS config error: %v\nMake sure server certificates exist at '%s', '%s', '%s'",
			err, cfg.ServerCertFile, cfg.ServerKeyFile, cfg.CACert)
	}

	// --- Create TUN interface ---
	// On Linux, CreateTUN opens /dev/net/tun with IFF_NO_PI and returns a
	// plain io.ReadWriteCloser — raw IP packets, no offset headers.
	tunRW, err := tunif.CreateTUN("tun0", cfg.TunAddress, 1350)
	if err != nil {
		log.Fatalf("[server] create TUN: %v", err)
	}
	defer tunRW.Close()
	log.Printf("[server] TUN tun0 up at %s (MTU 1350)", cfg.TunAddress)

	// --- Setup NAT ---
	physIface, err := tunif.DefaultPhysicalInterface()
	if err != nil {
		log.Fatalf("[server] detect physical interface: %v", err)
	}
	// Derive /24 subnet from TUN address for NAT rule
	if err := tunif.SetupNAT("tun0", physIface, cfg.TunSubnet); err != nil {
		log.Fatalf("[server] NAT setup: %v", err)
	}
	log.Printf("[server] NAT enabled on %s -> %s", "tun0", physIface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// --- QUIC listener (primary) ---
	quicSrv := &engine.QUICServer{
		Addr:      cfg.ListenUDP,
		TLSConfig: tlsCfg,
		TUN:       tunRW,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := quicSrv.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[server] QUIC error: %v", err)
		}
	}()

	// --- TCP fallback listener (for UDP-blocked networks) ---
	tcpSrv := &engine.TCPFallbackServer{
		Addr:      cfg.ListenTCP,
		TLSConfig: tlsCfg,
		TUN:       tunRW,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := tcpSrv.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[server] TCP fallback error: %v", err)
		}
	}()

	log.Printf("[server] ready — QUIC %s | TCP fallback %s", cfg.ListenUDP, cfg.ListenTCP)

	// --- Graceful shutdown on SIGINT/SIGTERM ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("[server] shutting down...")
	cancel()
	wg.Wait()
	log.Println("[server] stopped.")
}
