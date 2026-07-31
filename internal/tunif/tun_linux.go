//go:build linux

package tunif

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tunOffset is used only by the Windows adapter path (adapter.go references it
// via build tags). On Linux we bypass the wireguard batch API entirely, so
// tunOffset is 0 here but effectively unused for the server TUN path.
const tunOffset = 0

// rawTUN is a thin wrapper around an *os.File for a Linux TUN device opened
// with IFF_TUN|IFF_NO_PI. With IFF_NO_PI the kernel gives raw IP packets on
// every Read/Write — no frame header, no offset gymnastics.
type rawTUN struct{ f *os.File }

func (r *rawTUN) Read(p []byte) (int, error)  { return r.f.Read(p) }
func (r *rawTUN) Write(p []byte) (int, error) { return r.f.Write(p) }
func (r *rawTUN) Close() error                { return r.f.Close() }

// ifreqFlags is the subset of struct ifreq we need for TUNSETIFF:
//
//	char  ifr_name[16]   — interface name (null-terminated)
//	short ifr_flags      — IFF_TUN | IFF_NO_PI
//	[22 bytes padding to match kernel struct size]
type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

// CreateTUN opens /dev/net/tun with IFF_TUN|IFF_NO_PI, assigns addr (CIDR)
// and sets mtu. Returns a plain io.ReadWriteCloser — raw IP packets, no offset.
func CreateTUN(name, addr string, mtu int) (io.ReadWriteCloser, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	req := ifreqFlags{Flags: unix.IFF_TUN | unix.IFF_NO_PI}
	copy(req.Name[:], name)

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		unix.TUNSETIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	f := os.NewFile(uintptr(fd), name)

	// Assign IP, set MTU, bring up — order matters.
	cmds := [][]string{
		{"ip", "link", "set", name, "mtu", fmt.Sprint(mtu)},
		{"ip", "addr", "add", addr, "dev", name},
		{"ip", "link", "set", name, "up"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w\n%s", c, err, out)
		}
	}

	return &rawTUN{f}, nil
}

// SetupNAT configures iptables rules on the server to NAT traffic from the TUN
// interface out through the given physical interface (e.g. "eth0").
func SetupNAT(tunName, physIface, tunSubnet string) error {
	cmds := [][]string{
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", tunSubnet, "-o", physIface, "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-i", tunName, "-o", physIface, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-i", physIface, "-o", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("command %v: %w\noutput: %s", args, err, out)
		}
	}
	return nil
}

// DefaultPhysicalInterface returns the name of the default outbound interface.
func DefaultPhysicalInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			return iface.Name, nil
		}
	}
	return "", fmt.Errorf("no suitable physical interface found")
}

// WrapTUN on Linux is a no-op — CreateTUN already returns a plain
// io.ReadWriteCloser, so no wrapping is needed.
func WrapTUN(dev io.ReadWriteCloser) io.ReadWriteCloser { return dev }
