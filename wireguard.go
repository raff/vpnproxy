package main

import (
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// tunnel is a WireGuard connection raised on a real kernel-level virtual
// network interface — utun(4) on macOS (tunnel_darwin.go), a Wintun adapter
// on Windows (tunnel_windows.go) — the same primitive wg-quick/
// wireguard-windows use, minus the system-wide default route and DNS
// changes those also make. Traffic only reaches it through sockets
// explicitly bound to ifIndex (see dialerBoundTo), via an interface-scoped
// route, so nothing outside this process's own relayed connections ever
// uses it.
type tunnel struct {
	dev        *device.Device
	ifIndex    int
	dnsServers []netip.Addr
}

// Close tears down the tunnel; the virtual interface disappears the moment
// its underlying handle closes, so no manual address/route cleanup is
// needed on either platform.
func (t *tunnel) Close() {
	t.dev.Close()
}

// peerStatus summarizes one WireGuard peer's live state, parsed from the
// device's own UAPI "get" output (device.IpcGet) — the only way to learn
// whether a handshake has actually happened, or what AllowedIPs ended up
// configured, from outside the device itself.
type peerStatus struct {
	endpoint      string
	allowedIPs    []netip.Prefix
	lastHandshake time.Time
}

func peerStatuses(dev *device.Device) ([]peerStatus, error) {
	raw, err := dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parsePeerStatuses(raw), nil
}

// parsePeerStatuses is peerStatuses' actual parsing logic, split out so it
// can be unit-tested against a crafted UAPI string without a live
// *device.Device.
func parsePeerStatuses(raw string) []peerStatus {
	var peers []peerStatus
	var cur *peerStatus
	for _, line := range strings.Split(raw, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			peers = append(peers, peerStatus{})
			cur = &peers[len(peers)-1]
		case "endpoint":
			if cur != nil {
				cur.endpoint = val
			}
		case "allowed_ip":
			if cur != nil {
				if p, err := netip.ParsePrefix(val); err == nil {
					cur.allowedIPs = append(cur.allowedIPs, p)
				}
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if secs, err := strconv.ParseInt(val, 10, 64); err == nil && secs > 0 {
					cur.lastHandshake = time.Unix(secs, 0)
				}
			}
		}
	}
	return peers
}

// waitForHandshake polls the device's UAPI status until some peer reports
// a completed handshake, or timeout elapses.
func waitForHandshake(dev *device.Device, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		peers, err := peerStatuses(dev)
		if err != nil {
			return fmt.Errorf("querying wireguard device status: %w", err)
		}
		for _, p := range peers {
			if !p.lastHandshake.IsZero() {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no wireguard handshake completed within %s — check that the peer's Endpoint in the .conf is reachable and that outbound UDP to it isn't blocked (e.g. by comparing against `wg-quick up` on the same .conf)", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// logPeerStatus reports each peer's endpoint and AllowedIPs once the
// handshake is confirmed, and flags — as a warning, not a hard failure,
// since the check itself could have false negatives — any DNS server from
// the .conf that doesn't fall within any peer's AllowedIPs: WireGuard
// silently drops outbound packets that don't match an AllowedIPs entry for
// some peer, which looks identical to a timeout at the DNS-query layer but
// means something completely different (a routing/config mismatch, not a
// slow or unreachable server).
func logPeerStatus(dev *device.Device, dnsServers []netip.Addr) {
	peers, err := peerStatuses(dev)
	if err != nil {
		log.Printf("wireguard: could not query device status: %v", err)
		return
	}
	for _, p := range peers {
		log.Printf("wireguard: handshake completed with %s (allowed ips: %v)", p.endpoint, p.allowedIPs)
		for _, dns := range dnsServers {
			if !anyPrefixContains(p.allowedIPs, dns) {
				log.Printf("wireguard: warning: DNS server %s is not covered by this peer's AllowedIPs — queries to it will likely be dropped silently", dns)
			}
		}
	}
}

func anyPrefixContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
