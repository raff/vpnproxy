package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
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

	// timeout is the wait for the first attempt's response; later
	// attempts wait 2x and 3x as long (see queryDNSRetry), so a slow
	// first handshake over a congested path still gets a chance to
	// complete. The whole lookup (A and AAAA together) is bounded by
	// budget().
	timeout time.Duration

	// Cached answers live for their DNS TTL, clamped to [minTTL, maxTTL].
	// The target of this proxy is a handful of hostnames whose addresses
	// rarely change, so the floor is deliberately generous: every
	// uncached lookup is a round trip through the tunnel.
	minTTL, maxTTL time.Duration

	// diag, if set, describes the tunnel's state (handshake age, byte
	// counters); logged when a lookup fails, to tell "the tunnel is
	// dead" apart from "the DNS server is slow".
	diag func() string

	mu       sync.Mutex
	cache    map[string]cacheEntry
	inflight map[string]*lookupCall
}

type cacheEntry struct {
	ip     string
	expiry time.Time
}

// lookupCall is one in-progress lookup that concurrent Resolve calls for
// the same name wait on instead of each sending their own queries.
type lookupCall struct {
	done chan struct{}
	ip   string
	err  error
}

const (
	defaultDNSTimeout = 2 * time.Second
	defaultMinTTL     = 5 * time.Minute
	defaultMaxTTL     = time.Hour
	dnsAttempts       = 3
)

func newResolver(ifIndex int, dnsServers []netip.Addr) *resolver {
	return &resolver{
		ifIndex:    ifIndex,
		dnsServers: dnsServers,
		port:       "53",
		timeout:    defaultDNSTimeout,
		minTTL:     defaultMinTTL,
		maxTTL:     defaultMaxTTL,
		cache:      map[string]cacheEntry{},
		inflight:   map[string]*lookupCall{},
	}
}

// budget is the most time one Resolve can spend on the network: all
// attempts (timeout, 2x, 3x) of the A query and, if needed, the AAAA one
// share it.
func (r *resolver) budget() time.Duration {
	return r.timeout * dnsAttempts * (dnsAttempts + 1) / 2
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

	resolved, err := r.lookupShared(ctx, key, host)
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
	return resolved, nil
}

// lookupShared runs lookup for host, making concurrent callers for the
// same name (a browser opening a handful of connections at once) share a
// single set of queries. The lookup runs detached from any one caller's
// ctx, bounded by budget(), so one caller giving up doesn't fail the
// others, and still fills the cache for whoever comes next.
func (r *resolver) lookupShared(ctx context.Context, key, host string) (string, error) {
	r.mu.Lock()
	call, running := r.inflight[key]
	if !running {
		call = &lookupCall{done: make(chan struct{})}
		r.inflight[key] = call
	}
	r.mu.Unlock()

	if !running {
		go func() {
			lctx, cancel := context.WithTimeout(context.Background(), r.budget())
			defer cancel()
			ip, ttl, err := r.lookup(lctx, host)
			if err != nil && r.diag != nil {
				log.Printf("dns: lookup of %s failed (%v); tunnel state: %s", host, err, r.diag())
			}

			r.mu.Lock()
			if err == nil {
				r.cache[key] = cacheEntry{ip: ip, expiry: time.Now().Add(ttl)}
			}
			delete(r.inflight, key)
			r.mu.Unlock()

			call.ip, call.err = ip, err
			close(call.done)
		}()
	}

	select {
	case <-call.done:
		return call.ip, call.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
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

	var servers []string
	for _, a := range r.dnsServers {
		servers = append(servers, net.JoinHostPort(a.String(), r.port))
	}
	dialer := dialerBoundTo(r.ifIndex)

	answers, err := queryDNSRetry(ctx, dialer, servers, host, dnsmessage.TypeA, r.timeout)
	if err == nil && len(answers) == 0 {
		answers, err = queryDNSRetry(ctx, dialer, servers, host, dnsmessage.TypeAAAA, r.timeout)
	}
	if err != nil {
		return "", 0, fmt.Errorf("resolving %s through the tunnel's DNS (%v): %w", host, r.dnsServers, err)
	}
	if len(answers) == 0 {
		return "", 0, fmt.Errorf("%s has no A or AAAA record via the tunnel's DNS (%v)", host, r.dnsServers)
	}

	a := answers[0]
	if a.ip.IsLoopback() {
		return "", 0, fmt.Errorf("%s resolved to %s through the tunnel's own DNS — that can't be relayed (it would just point back at this proxy)", host, a.ip)
	}

	// Clamped so a very long TTL doesn't pin a stale answer indefinitely,
	// and a short or zero one (some servers use this to mean "don't
	// cache") doesn't turn into a per-connection DNS-query loop.
	ttl = min(max(a.ttl, r.minTTL), r.maxTTL)
	return a.ip.String(), ttl, nil
}

// dnsAnswer is one address record from a DNS response, with its TTL.
type dnsAnswer struct {
	ip  net.IP
	ttl time.Duration
}

// queryDNSRetry calls queryDNS up to dnsAttempts times: UDP is lossy, and
// a single dropped packet (query or response) shouldn't be reported as "no
// such record" or, worse, misread as a tunnel/handshake problem —
// startTunnel already confirms the handshake itself before any lookup
// runs, so a timeout here specifically means the query or its response,
// not the tunnel, went missing (or the tunnel is re-handshaking, which
// WireGuard retries every 5s: hence the growing per-attempt timeout).
// Attempts rotate through servers, so one dead DNS server doesn't sink
// the lookup.
func queryDNSRetry(ctx context.Context, dialer *net.Dialer, servers []string, name string, qtype dnsmessage.Type, timeout time.Duration) ([]dnsAnswer, error) {
	var errs []string
	var last error
	for attempt := 0; attempt < dnsAttempts && ctx.Err() == nil; attempt++ {
		server := servers[attempt%len(servers)]
		answers, err := queryDNS(ctx, dialer, server, name, qtype, timeout*time.Duration(attempt+1))
		if err == nil {
			return answers, nil
		}
		last = err
		errs = append(errs, fmt.Sprintf("attempt %d: %v", attempt+1, err))
	}
	if last == nil {
		return nil, ctx.Err()
	}
	// Every attempt's error, not just the last: with several servers they
	// often differ (e.g. one fails to send at once, another times out).
	return nil, fmt.Errorf("%s: %w", strings.Join(errs, "; "), last)
}

// queryDNS sends a single raw A/AAAA query for name to server (through
// dialer, so it goes over the tunnel) and returns whatever address records
// come back, with no /etc/hosts or system-resolver involvement at any
// point — see resolver's doc comment for why that matters here. UDP only,
// with a generous read buffer: fine for the handful of address records a
// query like this gets back, so there's no need for the usual
// truncated-response-retry-over-TCP dance a general-purpose resolver would
// do.
func queryDNS(ctx context.Context, dialer *net.Dialer, server, name string, qtype dnsmessage.Type, timeout time.Duration) ([]dnsAnswer, error) {
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

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
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
