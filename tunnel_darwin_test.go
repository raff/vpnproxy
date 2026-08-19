//go:build darwin

package main

import (
	"net/netip"
	"testing"
	"time"
)

// uapiSample is a representative device.IpcGet() response for one peer
// with a completed handshake, in the real key=value/newline-separated
// format wireguard-go emits (see uapi.go's IpcGetOperation).
const uapiSample = `private_key=0000000000000000000000000000000000000000000000000000000000000000
listen_port=51820
public_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
preshared_key=0000000000000000000000000000000000000000000000000000000000000000
protocol_version=1
endpoint=203.0.113.1:51820
last_handshake_time_sec=1700000000
last_handshake_time_nsec=0
tx_bytes=100
rx_bytes=200
persistent_keepalive_interval=25
allowed_ip=0.0.0.0/0
allowed_ip=::/0
`

func TestParsePeerStatuses(t *testing.T) {
	peers := parsePeerStatuses(uapiSample)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	p := peers[0]
	if p.endpoint != "203.0.113.1:51820" {
		t.Errorf("endpoint = %q, want 203.0.113.1:51820", p.endpoint)
	}
	if p.lastHandshake.IsZero() {
		t.Errorf("lastHandshake is zero, want the parsed time")
	}
	if !p.lastHandshake.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("lastHandshake = %v, want %v", p.lastHandshake, time.Unix(1700000000, 0))
	}
	if len(p.allowedIPs) != 2 {
		t.Fatalf("got %d allowed IPs, want 2", len(p.allowedIPs))
	}
}

// TestParsePeerStatusesNoHandshakeYet is what a freshly-brought-up device
// reports before any handshake completes: last_handshake_time_sec=0. This
// is exactly the state waitForHandshake must keep polling past, not
// mistake for "done".
func TestParsePeerStatusesNoHandshakeYet(t *testing.T) {
	raw := `public_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
last_handshake_time_sec=0
last_handshake_time_nsec=0
allowed_ip=0.0.0.0/0
`
	peers := parsePeerStatuses(raw)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	if !peers[0].lastHandshake.IsZero() {
		t.Errorf("lastHandshake = %v, want zero", peers[0].lastHandshake)
	}
}

func TestAnyPrefixContains(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")}
	in := netip.MustParseAddr("10.2.0.1")
	out := netip.MustParseAddr("8.8.8.8")

	if !anyPrefixContains(prefixes, in) {
		t.Errorf("10.2.0.1 should be covered by 10.2.0.0/24")
	}
	if anyPrefixContains(prefixes, out) {
		t.Errorf("8.8.8.8 should not be covered by 10.2.0.0/24")
	}
}
