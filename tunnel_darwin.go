//go:build darwin

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/windtf/wireproxy"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// startTunnel parses a WireGuard .conf and brings up a kernel-level tunnel
// for it. Must run as root: creating and configuring a utun(4) device
// requires it. Unlike tvview (which runs unprivileged and offloads exactly
// this to a separate helper process via SCM_RIGHTS), vpnproxy's whole
// process is expected to run under sudo, so there is no privilege boundary
// to cross in-process, and no fd handoff is needed — tun.CreateTUN already
// hands back a ready-to-use tun.Device directly.
func startTunnel(confPath string) (*tunnel, error) {
	conf, err := wireproxy.ParseConfig(confPath)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", confPath, err)
	}
	setting, err := wireproxy.CreateIPCRequest(conf.Device)
	if err != nil {
		return nil, fmt.Errorf("building wireguard config: %w", err)
	}

	tunDev, err := tun.CreateTUN("utun", 0) // MTU is set explicitly below, alongside the addresses.
	if err != nil {
		return nil, fmt.Errorf("creating utun device: %w", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("naming utun device: %w", err)
	}

	if err := configureInterface(name, setting.MTU, setting.DeviceAddr); err != nil {
		tunDev.Close()
		return nil, err
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("looking up %s: %w", name, err)
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
	// peer has actually answered — the first packet written into it (e.g.
	// resolveTarget's DNS query, right after startTunnel returns) just
	// queues while a handshake happens in the background. Waiting for that
	// handshake here turns "wrong endpoint / blocked UDP egress / bad keys"
	// into a clear error now, instead of a generic timeout later on
	// whatever traffic happened to be sent first.
	if err := waitForHandshake(dev, 15*time.Second); err != nil {
		dev.Close()
		return nil, err
	}

	logPeerStatus(dev, setting.DNS)

	return &tunnel{dev: dev, ifIndex: iface.Index, dnsServers: setting.DNS}, nil
}

// configureInterface assigns addrs (point-to-point: /32 for IPv4, /128 for
// IPv6, matching how every WireGuard client config hands them out) and mtu
// to name, brings it up, and gives it an interface-scoped default route —
// copied from tvview's cmd/vpnhelper, which runs this same logic from a
// separate privileged helper; here the whole process is already root, so
// it just runs directly.
//
// The scoped route is the one place this touches routing at all: without
// it, the interface has only its own /32 (or /128) route to itself, so a
// socket bound to it with IP_BOUND_IF can reach nothing — IP_BOUND_IF
// restricts which interface's routes a socket may use, it doesn't invent
// one. `-ifscope` keeps this from becoming a normal system-wide default
// route: it's consulted only for sockets explicitly bound to this
// interface, invisible to `route get default` and to every other process
// on the machine, including a concurrently-connected VPN.
func configureInterface(name string, mtu int, addrs []netip.Addr) error {
	var hasV4, hasV6 bool
	for _, a := range addrs {
		var args []string
		if a.Is4() {
			args = []string{name, "inet", a.String(), a.String(), "mtu", fmt.Sprint(mtu), "up"}
			hasV4 = true
		} else {
			args = []string{name, "inet6", a.String(), "prefixlen", "128", "mtu", fmt.Sprint(mtu), "up"}
			hasV6 = true
		}

		out, err := exec.Command("/sbin/ifconfig", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ifconfig %s: %w: %s", a, err, out)
		}
	}

	if hasV4 {
		if err := addScopedDefaultRoute(name, "-inet"); err != nil {
			return err
		}
	}
	if hasV6 {
		if err := addScopedDefaultRoute(name, "-inet6"); err != nil {
			return err
		}
	}
	return nil
}

func addScopedDefaultRoute(name, family string) error {
	out, err := exec.Command("/sbin/route", "-q", "-n", "add", family,
		"-ifscope", name, "default", "-interface", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scoped route for %s: %w: %s", name, err, out)
	}
	return nil
}

// boundControl is a net.Dialer.Control function that pins every socket it
// opens to ifIndex via IP_BOUND_IF/IPV6_BOUND_IF, instead of letting the
// kernel's normal routing table pick an interface — copied from tvview's
// bindToInterface. This is what scopes vpnproxy's relayed connections (and
// its tunnel-DNS lookups, see resolver.go) to the tunnel without adding any
// system-wide route.
func boundControl(ifIndex int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			switch {
			case strings.Contains(network, "6"):
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifIndex)
			default:
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifIndex)
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

// dialerBoundTo returns a net.Dialer whose sockets are pinned to ifIndex,
// per boundControl.
func dialerBoundTo(ifIndex int) *net.Dialer {
	return &net.Dialer{Control: boundControl(ifIndex)}
}
