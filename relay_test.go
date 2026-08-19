package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestParseSNIRealClientHello drives an actual crypto/tls handshake over a
// net.Pipe and captures the real bytes a Go TLS client sends, so parseSNI is
// exercised against a real ClientHello rather than a hand-built one.
func TestParseSNIRealClientHello(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		tls.Client(client, &tls.Config{ServerName: "example.internal", InsecureSkipVerify: true}).Handshake()
	}()

	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("reading ClientHello: %v", err)
	}

	name, ok := parseSNI(buf[:n])
	if !ok {
		t.Fatalf("parseSNI failed to parse a real ClientHello")
	}
	if name != "example.internal" {
		t.Fatalf("got SNI %q, want %q", name, "example.internal")
	}
}

func TestParseSNINonTLS(t *testing.T) {
	if _, ok := parseSNI([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Fatal("parseSNI should not find an SNI in a plain HTTP request")
	}
}

func TestParseSNITruncated(t *testing.T) {
	for n := 0; n < 6; n++ {
		if _, ok := parseSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}[:n]); ok {
			t.Fatalf("parseSNI should not succeed on %d truncated bytes", n)
		}
	}
}

func TestParseHTTPHost(t *testing.T) {
	cases := []struct {
		name    string
		request string
		want    string
		wantOK  bool
	}{
		{"plain host", "GET / HTTP/1.1\r\nHost: example.internal\r\nUser-Agent: curl\r\n\r\n", "example.internal", true},
		{"host with port", "GET / HTTP/1.1\r\nHost: example.internal:8080\r\n\r\n", "example.internal", true},
		{"lowercase header name", "GET / HTTP/1.1\r\nhost: example.internal\r\n\r\n", "example.internal", true},
		{"no host header", "GET / HTTP/1.1\r\nUser-Agent: curl\r\n\r\n", "", false},
		{"not http at all", "\x16\x03\x01\x00\x01\x01", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseHTTPHost([]byte(c.request))
			if ok != c.wantOK || got != c.want {
				t.Fatalf("parseHTTPHost(%q) = (%q, %v), want (%q, %v)", c.request, got, ok, c.want, c.wantOK)
			}
		})
	}
}
