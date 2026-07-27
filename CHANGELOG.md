# TUNNEL-PROT-1 Technical Architecture & Changelog

- [2026-06-27 16:34] feat: implement SOCKS5 RFC 1928 authentication and negotiation state machine
- [2026-07-02 16:48] feat: add bidirectional TCP proxy stream handler with io.CopyBuffer
- [2026-07-07 11:05] feat: implement UDP associate packet relaying with NAT address mapping
- [2026-07-12 13:59] refactor: worker goroutine pool with bounded concurrency channels
- [2026-07-17 16:38] perf: recycle 32KB copy buffers using sync.Pool to minimize GC load
- [2026-07-22 17:12] fix: graceful server shutdown on context cancellation and OS signals
- [2026-07-27 18:25] test: add race condition unit tests with Go race detector
