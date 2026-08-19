//go:build darwin

package main

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNSServer answers every A query for name with ip and ttl, on a
// loopback UDP socket, so queryDNS/resolver can be tested end to end
// without a real WireGuard tunnel. Each query received increments count,
// if non-nil, so callers can assert on how many round trips actually
// happened (e.g. to prove caching works).
func fakeDNSServer(t *testing.T, name string, ip net.IP, ttl uint32, count *int32) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // conn closed by t.Cleanup
			}
			if count != nil {
				atomic.AddInt32(count, 1)
			}

			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			qname, _ := dnsmessage.NewName(name + ".")
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: req.Header.ID, Response: true, RCode: dnsmessage.RCodeSuccess},
				Questions: req.Questions,
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
					Body:   &dnsmessage.AResource{A: [4]byte(ip.To4())},
				}},
			}
			packed, err := resp.Pack()
			if err != nil {
				continue
			}
			conn.WriteToUDP(packed, addr)
		}
	}()

	return conn.LocalAddr().String()
}

func TestQueryDNS(t *testing.T) {
	want := net.IPv4(203, 0, 113, 42)
	server := fakeDNSServer(t, "example.internal", want, 300, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	answers, err := queryDNS(ctx, &net.Dialer{}, server, "example.internal", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("queryDNS: %v", err)
	}
	if len(answers) != 1 || !answers[0].ip.Equal(want) {
		t.Fatalf("got %v, want [%v]", answers, want)
	}
	if answers[0].ttl != 300*time.Second {
		t.Fatalf("got ttl %v, want 300s", answers[0].ttl)
	}
}

// TestQueryDNSIgnoresHostsFile is the regression test for the actual bug
// reported: the resolution path resolver uses must never consult
// /etc/hosts. "localhost" is guaranteed to be in every machine's hosts
// file, resolving to 127.0.0.1 there; a fake DNS server answering with a
// different, obviously non-loopback address for the same name proves
// queryDNS went over the wire to it rather than being short-circuited
// locally the way net.Resolver.LookupIP would be (see the earlier
// experiment in the PR description: net.Resolver with PreferGo and a
// custom Dial still answers "localhost" from /etc/hosts without ever
// calling Dial).
func TestQueryDNSIgnoresHostsFile(t *testing.T) {
	want := net.IPv4(203, 0, 113, 42)
	server := fakeDNSServer(t, "localhost", want, 300, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	answers, err := queryDNS(ctx, &net.Dialer{}, server, "localhost", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("queryDNS: %v", err)
	}
	if len(answers) != 1 || !answers[0].ip.Equal(want) {
		t.Fatalf("got %v, want [%v] (i.e. queryDNS used /etc/hosts instead of the fake DNS server)", answers, want)
	}
}

// testResolver builds a resolver pointed at a fake DNS server's actual
// (unprivileged, random) port, bypassing the hardcoded port 53 that real
// WireGuard DNS servers always use — see resolver.port's doc comment.
func testResolver(t *testing.T, serverAddr string) *resolver {
	t.Helper()
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatalf("splitting %s: %v", serverAddr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("parsing %s: %v", host, err)
	}
	r := newResolver(0, []netip.Addr{ip})
	r.port = port
	return r
}

func TestResolverCachesAnswer(t *testing.T) {
	var queries int32
	server := fakeDNSServer(t, "example.internal", net.IPv4(203, 0, 113, 42), 300, &queries)
	r := testResolver(t, server)

	for i := 0; i < 3; i++ {
		got, err := r.Resolve(context.Background(), "example.internal")
		if err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
		if got != "203.0.113.42" {
			t.Fatalf("Resolve #%d: got %s, want 203.0.113.42", i, got)
		}
	}

	if n := atomic.LoadInt32(&queries); n != 1 {
		t.Fatalf("server saw %d queries, want 1 (later Resolve calls should have hit the cache)", n)
	}
}

func TestResolverRefetchesAfterTTLExpiry(t *testing.T) {
	var queries int32
	server := fakeDNSServer(t, "example.internal", net.IPv4(203, 0, 113, 42), 0, &queries) // TTL 0, clamped to 5s minimum by resolver.lookup
	r := testResolver(t, server)

	if _, err := r.Resolve(context.Background(), "example.internal"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Force the cached entry to look expired without waiting out the
	// clamped 5s minimum TTL.
	r.mu.Lock()
	r.cache["example.internal"] = cacheEntry{ip: "203.0.113.42", expiry: time.Now().Add(-time.Second)}
	r.mu.Unlock()

	if _, err := r.Resolve(context.Background(), "example.internal"); err != nil {
		t.Fatalf("Resolve after expiry: %v", err)
	}

	if n := atomic.LoadInt32(&queries); n != 2 {
		t.Fatalf("server saw %d queries, want 2 (expiry should have forced a refetch)", n)
	}
}

func TestResolverRejectsLoopbackAnswer(t *testing.T) {
	server := fakeDNSServer(t, "example.internal", net.IPv4(127, 0, 0, 1), 300, nil)
	r := testResolver(t, server)

	if _, err := r.Resolve(context.Background(), "example.internal"); err == nil {
		t.Fatal("Resolve should have rejected a loopback answer")
	}
}

func TestResolverPassesThroughLiteralIP(t *testing.T) {
	r := newResolver(0, nil)
	got, err := r.Resolve(context.Background(), "203.0.113.42")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "203.0.113.42" {
		t.Fatalf("got %s, want 203.0.113.42", got)
	}
}

func TestResolverRejectsLiteralLoopbackTarget(t *testing.T) {
	r := newResolver(0, nil)
	if _, err := r.Resolve(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("Resolve should have rejected a literal loopback target")
	}
}
