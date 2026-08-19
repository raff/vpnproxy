//go:build darwin

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// resolver turns a hostname (sniffed per-connection from SNI/Host, or the
// static fallback target) into a bare IP to dial, resolving through the
// WireGuard tunnel's own DNS server rather than net.Resolver/net.LookupIP:
// Go's resolver checks /etc/hosts before ever calling a custom Dial, hosts
// file hit or not, so it would just return 127.0.0.1 again — the very
// entry this proxy exists to work around — without a single packet going
// through the tunnel. Hand-rolling the query (via
// golang.org/x/net/dns/dnsmessage, see queryDNS) is what actually
// guarantees this goes over the wire to the tunnel's DNS server instead of
// being short-circuited locally.
//
// Answers are cached for their DNS TTL: with the hostname now sniffed off
// of every single connection instead of resolved once at startup, an
// uncached lookup would mean a DNS round trip through the tunnel per
// connection.
type resolver struct {
	ifIndex    int
	dnsServers []netip.Addr

	// port is the DNS server port, always "53" outside of tests: real
	// WireGuard DNS= servers are always plain port 53, but a test's fake
	// server needs an arbitrary, unprivileged one.
	port string

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ip     string
	expiry time.Time
}

func newResolver(ifIndex int, dnsServers []netip.Addr) *resolver {
	return &resolver{ifIndex: ifIndex, dnsServers: dnsServers, port: "53", cache: map[string]cacheEntry{}}
}

// Resolve returns the bare IP to dial for host, which may already be one.
func (r *resolver) Resolve(ctx context.Context, host string) (string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsLoopback() {
			return "", fmt.Errorf("target %q is a loopback address — did you mean the real hostname or its actual IP, not the one /etc/hosts now points at this proxy?", host)
		}
		return host, nil
	}

	key := strings.ToLower(host)
	r.mu.Lock()
	entry, cached := r.cache[key]
	r.mu.Unlock()
	if cached && time.Now().Before(entry.expiry) {
		return entry.ip, nil
	}

	resolved, ttl, err := r.lookup(ctx, host)
	if err != nil {
		if cached {
			// A cached-but-expired answer is still a better bet than
			// failing the connection outright over one bad DNS round trip
			// (e.g. a single dropped/retried-out packet) for a name that
			// resolved fine moments ago.
			return entry.ip, nil
		}
		return "", err
	}

	r.mu.Lock()
	r.cache[key] = cacheEntry{ip: resolved, expiry: time.Now().Add(ttl)}
	r.mu.Unlock()
	return resolved, nil
}

// lookup does the actual tunnel-DNS round trip for host: A first, then
// AAAA if there's no A record. Checked here, against whatever this
// actually resolved to — not with the system resolver up front, which
// would be the very /etc/hosts entry this proxy exists to work around:
// sniffing the same masqueraded hostname straight off the connection, to
// be resolved through the tunnel's own DNS instead of the poisoned system
// one, is the expected way this tool is used, not a mistake.
func (r *resolver) lookup(ctx context.Context, host string) (ip string, ttl time.Duration, err error) {
	if len(r.dnsServers) == 0 {
		return "", 0, fmt.Errorf("%q is not an IP address, and the wireguard config has no DNS server to resolve it through", host)
	}

	server := net.JoinHostPort(r.dnsServers[0].String(), r.port)
	dialer := dialerBoundTo(r.ifIndex)

	answers, err := queryDNSRetry(ctx, dialer, server, host, dnsmessage.TypeA)
	if err == nil && len(answers) == 0 {
		answers, err = queryDNSRetry(ctx, dialer, server, host, dnsmessage.TypeAAAA)
	}
	if err != nil {
		return "", 0, fmt.Errorf("resolving %s through the tunnel's DNS (%s): %w", host, r.dnsServers[0], err)
	}
	if len(answers) == 0 {
		return "", 0, fmt.Errorf("%s has no A or AAAA record via the tunnel's DNS (%s)", host, r.dnsServers[0])
	}

	a := answers[0]
	if a.ip.IsLoopback() {
		return "", 0, fmt.Errorf("%s resolved to %s through the tunnel's own DNS — that can't be relayed (it would just point back at this proxy)", host, a.ip)
	}

	// Clamped so a very long TTL doesn't pin a stale answer indefinitely,
	// and a 0 or near-0 one (some servers use this to mean "don't cache")
	// doesn't turn into a tight per-connection DNS-query loop.
	switch {
	case a.ttl < 5*time.Second:
		ttl = 5 * time.Second
	case a.ttl > 5*time.Minute:
		ttl = 5 * time.Minute
	default:
		ttl = a.ttl
	}
	return a.ip.String(), ttl, nil
}

// dnsAnswer is one address record from a DNS response, with its TTL.
type dnsAnswer struct {
	ip  net.IP
	ttl time.Duration
}

// queryDNSRetry calls queryDNS up to 3 times: UDP is lossy, and a single
// dropped packet (query or response) shouldn't be reported as "no such
// record" or, worse, misread as a tunnel/handshake problem — startTunnel
// already confirms the handshake itself before any lookup runs, so a
// timeout here specifically means the query or its response, not the
// tunnel, went missing.
func queryDNSRetry(ctx context.Context, dialer *net.Dialer, server, name string, qtype dnsmessage.Type) ([]dnsAnswer, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var answers []dnsAnswer
		answers, err = queryDNS(ctx, dialer, server, name, qtype)
		if err == nil {
			return answers, nil
		}
	}
	return nil, err
}

// queryDNS sends a single raw A/AAAA query for name to server (through
// dialer, so it goes over the tunnel) and returns whatever address records
// come back, with no /etc/hosts or system-resolver involvement at any
// point — see resolver's doc comment for why that matters here. UDP only,
// with a generous read buffer: fine for the handful of address records a
// query like this gets back, so there's no need for the usual
// truncated-response-retry-over-TCP dance a general-purpose resolver would
// do.
func queryDNS(ctx context.Context, dialer *net.Dialer, server, name string, qtype dnsmessage.Type) ([]dnsAnswer, error) {
	qname, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid hostname %q: %w", name, err)
	}

	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, err
	}

	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(idBuf[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{
			{Name: qname, Type: qtype, Class: dnsmessage.ClassINET},
		},
	}
	packed, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("building dns query: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, fmt.Errorf("dialing dns server %s through tunnel: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("sending dns query to %s: %w", server, err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading dns response from %s: %w", server, err)
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("parsing dns response from %s: %w", server, err)
	}
	if resp.Header.ID != query.Header.ID {
		return nil, fmt.Errorf("dns response from %s had a mismatched query id", server)
	}
	if resp.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns query to %s for %s: %s", server, name, resp.Header.RCode)
	}

	var answers []dnsAnswer
	for _, ans := range resp.Answers {
		ttl := time.Duration(ans.Header.TTL) * time.Second
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			answers = append(answers, dnsAnswer{ip: net.IP(body.A[:]), ttl: ttl})
		case *dnsmessage.AAAAResource:
			answers = append(answers, dnsAnswer{ip: net.IP(body.AAAA[:]), ttl: ttl})
		}
	}
	return answers, nil
}
