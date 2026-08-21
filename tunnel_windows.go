//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/windtf/wireproxy"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// startTunnel parses a WireGuard .conf and brings up a kernel-level tunnel
// for it, backed by a Wintun adapter — the same primitive wireguard-windows
// itself uses, minus the system-wide default route and DNS changes it also
// makes. Must run elevated: creating a Wintun adapter requires
// Administrator rights, the same way raising a utun(4) device requires
// root on macOS (see tunnel_darwin.go).
func startTunnel(confPath string) (*tunnel, error) {
	conf, err := wireproxy.ParseConfig(confPath)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", confPath, err)
	}
	setting, err := wireproxy.CreateIPCRequest(conf.Device)
	if err != nil {
		return nil, fmt.Errorf("building wireguard config: %w", err)
	}

	tunDev, err := tun.CreateTUN("vpnproxy", setting.MTU)
	if err != nil {
		return nil, fmt.Errorf("creating wintun adapter: %w", err)
	}
	nativeTun, ok := tunDev.(*tun.NativeTun)
	if !ok {
		tunDev.Close()
		return nil, fmt.Errorf("unexpected tun.Device implementation %T", tunDev)
	}
	luid := winipcfg.LUID(nativeTun.LUID())

	if err := configureInterface(luid, setting.MTU, setting.DeviceAddr); err != nil {
		tunDev.Close()
		return nil, err
	}

	ifrow, err := luid.Interface()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("looking up wintun adapter: %w", err)
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	if err := dev.IpcSet(setting.IpcRequest); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configuring wireguard device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bringing wireguard device up: %w", err)
	}

	// dev.Up() returns as soon as the device is ready to send, not once a
	// peer has actually answered — see tunnel_darwin.go's startTunnel for
	// why this matters.
	if err := waitForHandshake(dev, 15*time.Second); err != nil {
		dev.Close()
		return nil, err
	}

	logPeerStatus(dev, setting.DNS)

	return &tunnel{dev: dev, ifIndex: int(ifrow.InterfaceIndex), dnsServers: setting.DNS}, nil
}

// configureInterface assigns addrs (point-to-point: /32 for IPv4, /128 for
// IPv6, matching how every WireGuard client config hands them out) and mtu
// to the Wintun adapter identified by luid, and gives it an
// interface-scoped default route — the Windows analogue of
// tunnel_darwin.go's ifconfig/route-based configureInterface, done here via
// the IP Helper API (through winipcfg, the same helper wireguard-windows
// itself uses) since Windows has no ifconfig/route CLI contract to script.
//
// The scoped route is the one place this touches routing at all: without
// it, the adapter has only its own point-to-point addresses, so a socket
// pinned to it with IP_UNICAST_IF (see boundControl) can reach nothing.
// winipcfg's AddRoute (CreateIpForwardEntry2) adds the route directly
// against this interface's LUID — it never becomes the system's actual
// default route (lowest-metric route wins there), and any socket not
// forced onto this interface never consults it, including a
// concurrently-connected VPN's.
func configureInterface(luid winipcfg.LUID, mtu int, addrs []netip.Addr) error {
	var prefixes []netip.Prefix
	var hasV4, hasV6 bool
	for _, a := range addrs {
		bits := 32
		if a.Is6() {
			bits = 128
			hasV6 = true
		} else {
			hasV4 = true
		}
		prefixes = append(prefixes, netip.PrefixFrom(a, bits))
	}
	if err := luid.SetIPAddresses(prefixes); err != nil {
		return fmt.Errorf("setting wintun adapter addresses: %w", err)
	}

	if hasV4 {
		if err := setInterfaceMTU(luid, windows.AF_INET, mtu); err != nil {
			return err
		}
		if err := luid.AddRoute(netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.IPv4Unspecified(), 0); err != nil {
			return fmt.Errorf("adding scoped default route: %w", err)
		}
	}
	if hasV6 {
		if err := setInterfaceMTU(luid, windows.AF_INET6, mtu); err != nil {
			return err
		}
		if err := luid.AddRoute(netip.PrefixFrom(netip.IPv6Unspecified(), 0), netip.IPv6Unspecified(), 0); err != nil {
			return fmt.Errorf("adding scoped default route: %w", err)
		}
	}
	return nil
}

func setInterfaceMTU(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	iface, err := luid.IPInterface(family)
	if err != nil {
		return fmt.Errorf("looking up wintun adapter interface: %w", err)
	}
	iface.NLMTU = uint32(mtu)
	if err := iface.Set(); err != nil {
		return fmt.Errorf("setting wintun adapter mtu: %w", err)
	}
	return nil
}

// ipUnicastIF and ipv6UnicastIF are IP_UNICAST_IF/IPV6_UNICAST_IF — not
// exposed by golang.org/x/sys/windows, but stable WinSock constants (see
// MSDN's ws2ipdef.h); copied from wireguard-go's own Windows UDP transport
// binding (conn/bind_windows.go), which pins its socket to an interface the
// same way.
const (
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// boundControl is a net.Dialer.Control function that pins every socket it
// opens to ifIndex via IP_UNICAST_IF/IPV6_UNICAST_IF, instead of letting the
// kernel's normal routing table pick an interface — the Windows analogue of
// tunnel_darwin.go's IP_BOUND_IF/IPV6_BOUND_IF. This is what scopes
// vpnproxy's relayed connections (and its tunnel-DNS lookups, see
// resolver.go) to the tunnel without adding any system-wide route.
func boundControl(ifIndex int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			handle := windows.Handle(fd)
			if isIPv6Network(network) {
				sockErr = windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, ipv6UnicastIF, ifIndex)
				return
			}
			// IP_UNICAST_IF wants the index in network byte order, as if it
			// were an IP address with leading zeros — unlike
			// IPV6_UNICAST_IF, which takes a plain host-order index. Per
			// MSDN; also see wireguard-go's own bindSocketToInterface4.
			var be [4]byte
			binary.BigEndian.PutUint32(be[:], uint32(ifIndex))
			sockErr = windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIF, int(*(*uint32)(unsafe.Pointer(&be[0]))))
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

func isIPv6Network(network string) bool {
	return len(network) > 0 && network[len(network)-1] == '6'
}

// dialerBoundTo returns a net.Dialer whose sockets are pinned to ifIndex,
// per boundControl.
func dialerBoundTo(ifIndex int) *net.Dialer {
	return &net.Dialer{Control: boundControl(ifIndex)}
}
