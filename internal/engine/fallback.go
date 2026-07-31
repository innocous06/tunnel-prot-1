package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// wsFrameConn wraps a net.Conn with simple binary packet framing:
// [2-byte big-endian length][payload]. Used over the TCP fallback path.
type wsFrameConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func (w *wsFrameConn) Read(p []byte) (int, error) {
	var length uint16
	if err := binary.Read(w.r, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	if int(length) > len(p) {
		return 0, fmt.Errorf("recv buf too small: need %d have %d", length, len(p))
	}
	return io.ReadFull(w.r, p[:length])
}

func (w *wsFrameConn) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, fmt.Errorf("packet too large: %d bytes", len(p))
	}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(p)))
	if _, err := w.conn.Write(header); err != nil {
		return 0, err
	}
	return w.conn.Write(p)
}

func (w *wsFrameConn) Close() error { return w.conn.Close() }

// ListenAndServe starts the TCP fallback listener. Blocks until ctx is cancelled.
// Only one relay is active at a time — a new connection kicks the previous one.
func (s *TCPFallbackServer) ListenAndServe(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.Addr, s.TLSConfig)
	if err != nil {
		return fmt.Errorf("TCP fallback listen %s: %w", s.Addr, err)
	}
	defer ln.Close()
	log.Printf("[tcp-fallback] listening on %s", s.Addr)

	// Shut the listener when ctx is cancelled.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Upgrade") != "websocket" {
				// Anyone without a valid client cert never reaches here (mTLS rejects at handshake).
				// A prober with a cert but no upgrade header gets a plain 404 — looks like a normal site.
				http.NotFound(w, r)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack not supported", 500)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				log.Printf("[tcp-fallback] hijack: %v", err)
				return
			}
			_, _ = fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

			// Kick previous relay if any.
			s.mu.Lock()
			if s.activeCancel != nil {
				log.Printf("[tcp-fallback] kicking previous client for new connection")
				s.activeCancel()
			}
			relayCtx, relayCancel := context.WithCancel(ctx)
			s.activeCancel = relayCancel
			s.activeGen++
			myGen := s.activeGen
			s.mu.Unlock()

			log.Printf("[tcp-fallback] relay started for %s", conn.RemoteAddr())
			fc := &wsFrameConn{conn: conn, r: bufio.NewReader(conn)}

			done := make(chan error, 1)
			go func() { done <- RelayLoop(s.TUN, fc) }()

			select {
			case err := <-done:
				log.Printf("[tcp-fallback] relay ended: %v", err)
			case <-relayCtx.Done():
				log.Printf("[tcp-fallback] relay cancelled")
				conn.Close()
			}

			s.mu.Lock()
			if s.activeGen == myGen {
				s.activeCancel = nil
			}
			s.mu.Unlock()
			relayCancel()
		}),
	}
	return srv.Serve(ln)
}

// DialTCPFallback connects to the server's TCP fallback endpoint and returns
// a framed connection ready for RelayLoop.
func DialTCPFallback(ctx context.Context, addr string, tlsCfg *tls.Config) (io.ReadWriteCloser, error) {
	d := &tls.Dialer{Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP fallback dial %s: %w", addr, err)
	}

	// Send HTTP upgrade request.
	host, _, _ := net.SplitHostPort(addr)
	req := fmt.Sprintf("GET /tunnel HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", host)
	if _, err := fmt.Fprint(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send upgrade request: %w", err)
	}

	// Read 101 response (consume headers).
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read upgrade response: %w", err)
		}
		if line == "\r\n" {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})

	return &wsFrameConn{conn: conn, r: br}, nil
}
