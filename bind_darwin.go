//go:build darwin

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// ifaceBind is a minimal IPv4-only conn.Bind whose UDP socket is pinned to
// ifIndex (IP_BOUND_IF, via boundControl), so WireGuard's own packets leave
// through that physical interface instead of whatever the default route
// says — e.g. a full-tunnel corporate VPN like GlobalProtect that would
// otherwise carry (and may mangle) them. wireguard-go's StdNetBind can't
// do this: its socket options aren't injectable.
// ponytail: IPv4 endpoints only, one datagram per syscall; add a v6 socket/batching if needed.
type ifaceBind struct {
	ifIndex int

	mu   sync.Mutex
	conn *net.UDPConn
}

func (b *ifaceBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	lc := net.ListenConfig{Control: boundControl(b.ifIndex)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, 0, err
	}
	c := pc.(*net.UDPConn)
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)

	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, ap, err := c.ReadFromUDPAddrPort(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, actual, nil
}

func (b *ifaceBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

func (b *ifaceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	e, ok := ep.(*conn.StdNetEndpoint)
	if !ok || !e.Addr().Is4() {
		return errors.New("-bind-iface supports IPv4 WireGuard endpoints only")
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, e.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (b *ifaceBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

func (b *ifaceBind) SetMark(uint32) error { return nil }
func (b *ifaceBind) BatchSize() int       { return 1 }
