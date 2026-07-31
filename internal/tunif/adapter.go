//go:build windows

package tunif

import (
	"io"

	"golang.zx2c4.com/wireguard/tun"
)

const maxPacketSize = 4096

// tunAdapter wraps tun.Device's batched Read/Write API into a simple
// per-packet io.ReadWriteCloser for use with RelayLoop.
//
// Platform offset notes:
//   - Linux (tunOffset=4): wireguard's NativeTun prepends a 4-byte TUN frame
//     header. Read() requires the buffer to have at least 4 bytes of headroom
//     before the packet data, and Write() needs the same layout.
//   - Windows (tunOffset=0): wintun has no frame header; offset is zero.
type tunAdapter struct {
	dev     tun.Device
	readBuf []byte // pre-allocated: [tunOffset bytes headroom | maxPacketSize bytes data]
}

// WrapTUN wraps a tun.Device as an io.ReadWriteCloser for RelayLoop.
func WrapTUN(dev tun.Device) io.ReadWriteCloser {
	return &tunAdapter{
		dev:     dev,
		readBuf: make([]byte, tunOffset+maxPacketSize),
	}
}

// Read reads one IP packet from the TUN device into p.
// Retries on empty reads (which can occur during device initialisation).
func (t *tunAdapter) Read(p []byte) (int, error) {
	for {
		bufs := [][]byte{t.readBuf}
		sizes := []int{0}
		n, err := t.dev.Read(bufs, sizes, tunOffset)
		if err != nil {
			return 0, err
		}
		if n == 0 || sizes[0] == 0 {
			// Transient empty read — the device is up but no packet arrived yet.
			// Retry instead of returning an error that would tear down the relay.
			continue
		}
		pktLen := sizes[0]
		if pktLen > len(p) {
			pktLen = len(p)
		}
		// Packet data lives at readBuf[tunOffset : tunOffset+pktLen].
		// Copy it to the start of p so the relay sees a plain IP packet.
		return copy(p, t.readBuf[tunOffset:tunOffset+pktLen]), nil
	}
}

// Write writes one IP packet p to the TUN device.
func (t *tunAdapter) Write(p []byte) (int, error) {
	// Allocate a buffer with tunOffset bytes of headroom before the packet.
	// This is required on Linux; on Windows the headroom is zero.
	buf := make([]byte, tunOffset+len(p))
	copy(buf[tunOffset:], p)
	if _, err := t.dev.Write([][]byte{buf}, tunOffset); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying TUN device.
func (t *tunAdapter) Close() error {
	return t.dev.Close()
}
