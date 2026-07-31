// Package gomobile exposes the tunnel engine to Android via gomobile bind.
// Only types with simple fields (string, int, bool, []byte) can cross the JNI boundary.
// This package is the bridge between the Kotlin VpnService and the Go engine.
package gomobile

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	"tunnel/internal/engine"
)

// TunnelEngine is the main object that Kotlin holds a reference to.
// Create one per VpnService lifecycle.
type TunnelEngine struct {
	mu        sync.Mutex
	cancelFn  context.CancelFunc
	relayDone chan error
}

// ProbeResult holds the latency result for a single server.
type ProbeResult struct {
	Name        string
	RegionLabel string
	RTTMs       int64  // round-trip time in milliseconds; -1 means unreachable
	Error       string // empty on success
}

// ProbeServer probes a single server's latency.
// Called from Kotlin to populate the server selection UI.
//   - certPem, keyPem, caPem: PEM content (not file paths) of the device cert, key, CA cert.
//   - hostname, port: server coordinates.
func ProbeServer(certPem, keyPem, caPem, hostname string, port int) *ProbeResult {
	tlsCfg, err := engine.NewClientTLSConfigFromPEM([]byte(certPem), []byte(keyPem), []byte(caPem), hostname)
	if err != nil {
		return &ProbeResult{RTTMs: -1, Error: err.Error()}
	}
	addr := fmt.Sprintf("%s:%d", hostname, port)
	rtt, err := engine.ProbeRTT(context.Background(), addr, tlsCfg)
	if err != nil {
		return &ProbeResult{RTTMs: -1, Error: err.Error()}
	}
	return &ProbeResult{RTTMs: rtt.Milliseconds()}
}

// Connect starts the tunnel.
//   - tunFd: the file descriptor returned by VpnService.Builder.establish() — Android provides this directly.
//   - certPem, keyPem, caPem: PEM content (not paths) of device cert, key, and CA cert.
//   - hostname: selected server hostname.
//   - port: server port (443).
//
// Returns nil on success or an error string.
func (t *TunnelEngine) Connect(tunFd int, certPem, keyPem, caPem, hostname string, port int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cancelFn != nil {
		return fmt.Errorf("tunnel already running — call Disconnect first")
	}

	tlsCfg, err := engine.NewClientTLSConfigFromPEM([]byte(certPem), []byte(keyPem), []byte(caPem), hostname)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	serverAddr := fmt.Sprintf("%s:%d", hostname, port)

	// Dial QUIC first, fall back to TCP.
	ctx, cancel := context.WithCancel(context.Background())
	var transport io.ReadWriteCloser

	quicClient := &engine.QUICClient{ServerAddr: serverAddr, TLSConfig: tlsCfg}
	stream, _, quicErr := quicClient.Dial(ctx)
	if quicErr == nil {
		transport = stream
		log.Printf("[android] connected via QUIC to %s", serverAddr)
	} else {
		log.Printf("[android] QUIC failed (%v), trying TCP fallback...", quicErr)
		fb, err := engine.DialTCPFallback(ctx, serverAddr, tlsCfg)
		if err != nil {
			cancel()
			return fmt.Errorf("both QUIC and TCP fallback failed: QUIC: %v | TCP: %v", quicErr, err)
		}
		transport = fb
		log.Printf("[android] connected via TCP fallback to %s", serverAddr)
	}

	// Wrap the Android-provided TUN fd as an io.ReadWriteCloser.
	tunRW := engine.WrapAndroidTUN(tunFd)

	t.cancelFn = cancel
	t.relayDone = make(chan error, 1)

	go func() {
		t.relayDone <- engine.RelayLoop(tunRW, transport)
		t.mu.Lock()
		t.cancelFn = nil
		t.mu.Unlock()
	}()

	return nil
}

// Disconnect tears down the tunnel cleanly.
func (t *TunnelEngine) Disconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cancelFn != nil {
		t.cancelFn()
		t.cancelFn = nil
	}
}

// IsConnected returns true if the relay is currently running.
func (t *TunnelEngine) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cancelFn != nil
}
