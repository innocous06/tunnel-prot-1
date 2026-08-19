# tunnel-prot-1

[![Status: Work in Progress](https://img.shields.io/badge/status-wip__beta-c9654a?style=flat-square)](https://github.com/innocous06/tunnel-prot-1)
[![Language: Go](https://img.shields.io/badge/language-Go_1.21+-18181f?style=flat-square)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-18181f?style=flat-square)](LICENSE)

An encrypted TCP/UDP VPN tunneling protocol engineered in Go. Designed for secure, low-latency traffic forwarding with mutual TLS (mTLS) authentication and native mobile cross-compilation.

## Overview

tunnel-prot-1 provides high-throughput point-to-point tunneling between client endpoints and remote server nodes. It eliminates conventional VPN protocol overhead by implementing custom packet framing, streamlined cryptographic handshakes, and native OS TUN interface drivers across Linux, Windows (Wintun), and Android.

## Highlights & Capabilities

- Zero external runtime dependencies in the core networking path.
- Mutual TLS (mTLS) certificate validation with automated certificate management.
- Dynamic transport layer supporting both TCP/UDP multiplexing and fallback modes for restricted networks.
- Benchmarked at 20–50 ms latency on domestic cloud instances and ~230 ms on transatlantic endpoints.
- Android integration via `gomobile` binding with Android's native `VpnService` API.

## Tech Stack

- **Language:** Go (Golang)
- **Networking:** TCP/UDP Sockets, Custom Packet Framing, TUN/TAP (Linux TUN, Wintun)
- **Cryptography & Security:** Mutual TLS (mTLS), X.509 Certificate Authentication, ChaCha20/AES
- **Mobile & Cross-Platform:** gomobile, Android NDK / Java FFI, Systemd
- **Infrastructure:** Oracle Cloud Infrastructure (OCI VPS)

## Usage

```bash
# Build server and client binaries
go build -o bin/tunnel-server ./cmd/server
go build -o bin/tunnel-client ./cmd/client

# Start server
sudo ./bin/tunnel-server -config server_config.json

# Connect client
sudo ./bin/tunnel-client -config client_config.json
```

## License

Released under the [MIT License](LICENSE).

Copyright (c) 2026 innocous. All rights reserved.
