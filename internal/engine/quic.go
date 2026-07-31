package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICServer listens for incoming QUIC connections from tunnel clients.
// Only one relay is active at a time — this is a personal tunnel, not a shared VPN.
// A second connection attempt kicks the first connection off.
type QUICServer struct {
	Addr      string
	TLSConfig *tls.Config
	TUN       io.ReadWriteCloser

	mu           sync.Mutex
	activeCancel context.CancelFunc
	activeGen    uint64 // incremented on each new relay; used to detect stale relays
}

// ListenAndServe starts the QUIC listener. Blocks until ctx is cancelled.
func (s *QUICServer) ListenAndServe(ctx context.Context) error {
	ln, err := quic.ListenAddr(s.Addr, s.TLSConfig, &quic.Config{
		Allow0RTT:       true,
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("QUIC listen %s: %w", s.Addr, err)
	}
	defer ln.Close()
	log.Printf("[quic-server] listening on %s", s.Addr)

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		log.Printf("[quic-server] new connection from %s", conn.RemoteAddr())
		go s.handleConn(conn)
	}
}

func (s *QUICServer) handleConn(conn *quic.Conn) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("[quic-server] accept stream: %v", err)
		conn.CloseWithError(1, "stream error")
		return
	}

	// Cancel any existing relay before starting a new one.
	s.mu.Lock()
	if s.activeCancel != nil {
		log.Printf("[quic-server] kicking previous client to accept new connection")
		s.activeCancel()
	}
	relayCtx, relayCancel := context.WithCancel(context.Background())
	s.activeCancel = relayCancel
	s.activeGen++
	myGen := s.activeGen
	s.mu.Unlock()

	log.Printf("[quic-server] relay started for %s", conn.RemoteAddr())
	done := make(chan error, 1)
	go func() { done <- RelayLoop(s.TUN, stream) }()

	select {
	case err := <-done:
		log.Printf("[quic-server] relay ended: %v", err)
	case <-relayCtx.Done():
		log.Printf("[quic-server] relay cancelled (new client connected)")
		conn.CloseWithError(0, "replaced by new connection")
	}

	s.mu.Lock()
	if s.activeGen == myGen {
		s.activeCancel = nil
	}
	s.mu.Unlock()
	relayCancel()
}

// TCPFallbackServer listens on a TCP address for WebSocket-upgraded tunnel connections.
// Only one relay is active at a time.
type TCPFallbackServer struct {
	Addr      string
	TLSConfig *tls.Config
	TUN       io.ReadWriteCloser

	mu           sync.Mutex
	activeCancel context.CancelFunc
	activeGen    uint64
}

// QUICClient dials a QUIC connection to a tunnel server.
type QUICClient struct {
	ServerAddr string
	TLSConfig  *tls.Config
}

// Dial opens a QUIC connection and returns the first bidirectional stream, ready for relay.
func (c *QUICClient) Dial(ctx context.Context) (*quic.Stream, *quic.Conn, error) {
	conn, err := quic.DialAddr(ctx, c.ServerAddr, c.TLSConfig, &quic.Config{
		Allow0RTT:       true,
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("QUIC dial %s: %w", c.ServerAddr, err)
	}

	stream, err := conn.OpenStream()
	if err != nil {
		conn.CloseWithError(1, "stream open failed")
		return nil, nil, fmt.Errorf("open stream: %w", err)
	}

	return stream, conn, nil
}

// ProbeRTT does a cheap QUIC handshake-only probe and returns round-trip time.
func ProbeRTT(ctx context.Context, addr string, tlsCfg *tls.Config) (time.Duration, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := quic.DialAddr(probeCtx, addr, tlsCfg, nil)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	conn.CloseWithError(0, "probe done")
	return rtt, nil
}

// QUICRemoteAddr extracts the server's public IP from an established QUIC connection.
func QUICRemoteAddr(conn *quic.Conn) string {
	addr := conn.RemoteAddr()
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	host, _, _ := net.SplitHostPort(addr.String())
	return host
}
