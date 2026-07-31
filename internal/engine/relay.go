package engine

import (
	"io"
	"log"
)

const packetBufSize = 4096 // large enough for any MTU 1350 packet plus overhead

// RelayLoop is the core bidirectional relay.
// It copies packets between the TUN device and the remote transport (QUIC stream or TCP fallback)
// in both directions until an error occurs or one side closes.
// Both closer are called on return regardless of which side triggered the exit.
func RelayLoop(tun io.ReadWriteCloser, remote io.ReadWriteCloser) error {
	defer func() {
		tun.Close()
		remote.Close()
	}()

	errc := make(chan error, 2)

	// TUN → Remote (outbound: client sends packets into the tunnel)
	go func() {
		buf := make([]byte, packetBufSize)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if n == 0 {
				continue
			}
			if _, err := remote.Write(buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()

	// Remote → TUN (inbound: server sends packets back to client)
	go func() {
		buf := make([]byte, packetBufSize)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if n == 0 {
				continue
			}
			if _, err := tun.Write(buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()

	// Block until either direction fails (connection drop, interface down, etc.)
	err := <-errc
	log.Printf("[relay] stopped: %v", err)
	return err
}
