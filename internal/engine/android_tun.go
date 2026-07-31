package engine

import (
	"io"
	"os"
)

// WrapAndroidTUN wraps the raw file descriptor provided by Android's
// VpnService.Builder.establish() into an io.ReadWriteCloser for RelayLoop.
// Android hands us a tun fd directly — no separate driver needed.
func WrapAndroidTUN(fd int) io.ReadWriteCloser {
	return os.NewFile(uintptr(fd), "android-tun")
}
