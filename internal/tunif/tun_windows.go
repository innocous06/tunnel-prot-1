//go:build windows

package tunif

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// tunOffset is 0 on Windows — wintun does not prepend any frame header,
// so the packet data starts at the beginning of the buffer.
const tunOffset = 0


// CreateTUN creates a Wintun TUN adapter on Windows with the given name and MTU.
// addr should be in CIDR notation, e.g. "10.66.0.2/24".
// Requires admin/elevated privileges. wintun.dll must be in the same directory as the .exe.
func CreateTUN(name, addr string, mtu int) (tun.Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create wintun %s: %w", name, err)
	}

	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		dev.Close()
		return nil, fmt.Errorf("unexpected TUN device type")
	}
	luid := winipcfg.LUID(nt.LUID())

	prefix, err := netip.ParsePrefix(addr)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("parse addr %s: %w", addr, err)
	}
	// Assign IP address to the TUN interface.
	if err := luid.SetIPAddresses([]netip.Prefix{prefix}); err != nil {
		dev.Close()
		return nil, fmt.Errorf("set IP address: %w", err)
	}

	return dev, nil
}

// AddHostRoute adds a host-specific /32 route for the VPN server's public IP
// via the physical default gateway. MUST be called BEFORE AddDefaultRoute to
// prevent a routing loop (server traffic must not go back through the tunnel).
func AddHostRoute(serverIP, gatewayIP string) error {
	out, err := exec.Command(
		"route", "ADD", serverIP, "MASK", "255.255.255.255", gatewayIP, "METRIC", "5",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("add host route for %s via %s: %w\n%s", serverIP, gatewayIP, err, out)
	}
	return nil
}

// RemoveHostRoute deletes the /32 host route for the VPN server IP.
func RemoveHostRoute(serverIP string) {
	exec.Command("route", "DELETE", serverIP, "MASK", "255.255.255.255").Run()
}

// AddDefaultRoute routes all traffic (0.0.0.0/0) through the TUN adapter.
// Uses the winipcfg API (more reliable than `route ADD` for TUN interfaces).
// Call AFTER AddHostRoute.
func AddDefaultRoute(name string, luid winipcfg.LUID) error {
	// Add 0.0.0.0/0 with next-hop 0.0.0.0 (on-link) through the TUN interface.
	// Metric 1 makes it preferred over the physical default route.
	dest := netip.MustParsePrefix("0.0.0.0/0")
	nextHop := netip.IPv4Unspecified()
	if err := luid.AddRoute(dest, nextHop, 1); err != nil {
		return fmt.Errorf("add default route via TUN: %w", err)
	}
	return nil
}

// RemoveDefaultRoute deletes the 0.0.0.0/0 route through the TUN adapter.
func RemoveDefaultRoute(luid winipcfg.LUID) {
	dest := netip.MustParsePrefix("0.0.0.0/0")
	nextHop := netip.IPv4Unspecified()
	luid.DeleteRoute(dest, nextHop) //nolint
}

// SetDNS sets the DNS server on the TUN interface via the winipcfg API.
// Windows does not infer DNS from the interface config automatically.
func SetDNS(luid winipcfg.LUID, dnsServer string) error {
	addr, err := netip.ParseAddr(dnsServer)
	if err != nil {
		return fmt.Errorf("parse DNS addr %s: %w", dnsServer, err)
	}
	return luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{addr}, nil)
}

// DefaultGateway reads the current default gateway from the Windows routing table.
// Uses `route print 0.0.0.0` and parses the output.
func DefaultGateway() (string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route print: %w", err)
	}
	// Parse output lines like:
	//   0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := fields[2]
			if gw != "On-link" && gw != "" {
				return gw, nil
			}
		}
	}
	return "", fmt.Errorf("default gateway not found in route table")
}

// LUIDFromTUN extracts the winipcfg.LUID from a tun.Device for use with
// AddDefaultRoute, RemoveDefaultRoute, and SetDNS.
func LUIDFromTUN(dev tun.Device) (winipcfg.LUID, error) {
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		return 0, fmt.Errorf("not a NativeTun device")
	}
	return winipcfg.LUID(nt.LUID()), nil
}
