package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// serveRelay listens on listenAddr:port and, for every accepted
// connection, sniffs the intended hostname off the connection itself
// (SNI for TLS, the Host header for plain HTTP — see peekHostname),
// falling back to fallbackTarget when sniffing finds nothing, resolves it
// through resolver, and dials that through dialer.
//
// This is a dumb TCP relay, not an HTTP or TLS proxy: once the hostname is
// known, there is nothing left to inspect or rewrite for either protocol —
// the client already sent the real hostname on the wire (that's what it
// typed into a URL bar, unaffected by the /etc/hosts override that only
// changed where the TCP SYN lands), so relaying the raw bytes as-is is
// sufficient for both.
func serveRelay(listenAddr string, port int, dialer *net.Dialer, res *resolver, fallbackTarget string) error {
	addr := net.JoinHostPort(listenAddr, fmt.Sprint(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	log.Printf("relaying %s -> <sniffed SNI/Host, or %q if none> (via tunnel)", addr, fallbackTarget)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accepting on %s: %w", addr, err)
		}
		go relayConn(conn, dialer, res, fallbackTarget, port)
	}
}

// relayConn figures out which hostname client is actually after, resolves
// it through res, dials it through dialer, and splices client's traffic to
// it — logging enough at each stage (sniffed hostname, tunnel dial, close
// with byte counts) to tell whether a given connection actually made it
// through the tunnel, and to what.
func relayConn(client net.Conn, dialer *net.Dialer, res *resolver, fallbackTarget string, port int) {
	defer client.Close()

	clientReader, sniffed := peekHostname(client)
	host := sniffed
	source := "sniffed"
	if host == "" {
		host = fallbackTarget
		source = "fallback"
	}
	label := client.RemoteAddr().String()
	if host != "" {
		label = fmt.Sprintf("%s (%s=%s)", label, source, host)
	}
	if host == "" {
		log.Printf("%s: no SNI/Host found and no fallback target configured, dropping connection", label)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	target, err := res.Resolve(ctx, host)
	cancel()
	if err != nil {
		log.Printf("%s: resolving: %v", label, err)
		return
	}

	dst := net.JoinHostPort(target, fmt.Sprint(port))
	log.Printf("%s -> %s: dialing through tunnel", label, dst)
	start := time.Now()

	upstream, err := dialer.Dial("tcp", dst)
	if err != nil {
		log.Printf("%s -> %s: dial through tunnel failed: %v", label, dst, err)
		return
	}
	defer upstream.Close()

	log.Printf("%s -> %s: connected through tunnel", label, dst)

	var sent, recv int64
	done := make(chan struct{}, 2)
	go func() {
		sent, _ = io.Copy(upstream, clientReader)
		if c, ok := upstream.(*net.TCPConn); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		recv, _ = io.Copy(client, upstream)
		if c, ok := client.(*net.TCPConn); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done

	log.Printf("%s -> %s: closed after %s (sent %d bytes, received %d bytes)",
		label, dst, time.Since(start).Round(time.Millisecond), sent, recv)
}

// peekHostname best-effort-reads the start of client's first bytes to
// extract the hostname it's actually after — the SNI from a TLS
// ClientHello, or the Host header from a plaintext HTTP request — without
// losing any bytes: whatever it reads is replayed first by the returned
// reader, which relayConn uses in place of client. A connection that is
// neither (or sends nothing within the deadline) just yields "": relayConn
// falls back to the static target argument, if any, in that case.
func peekHostname(client net.Conn) (io.Reader, string) {
	buf := make([]byte, 4096)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	if n <= 0 {
		return client, ""
	}
	data := buf[:n]
	reader := io.MultiReader(bytes.NewReader(data), client)

	if name, ok := parseSNI(data); ok {
		return reader, name
	}
	if name, ok := parseHTTPHost(data); ok {
		return reader, name
	}
	return reader, ""
}

// parseSNI extracts the server_name extension from a (possibly truncated)
// TLS ClientHello record. It never panics on malformed or truncated input
// — any out-of-range slice just means "couldn't parse", reported as
// ok=false — since this is best-effort and must never affect the relay it
// sits in front of.
func parseSNI(data []byte) (name string, ok bool) {
	defer func() {
		if recover() != nil {
			name, ok = "", false
		}
	}()

	if len(data) < 5 || data[0] != 0x16 { // TLS handshake record
		return "", false
	}
	recLen := int(data[3])<<8 | int(data[4])
	rec := data[5:]
	if len(rec) > recLen {
		rec = rec[:recLen]
	}

	if len(rec) < 4 || rec[0] != 0x01 { // ClientHello
		return "", false
	}
	body := rec[4:]

	p := 2 + 32 // client_version + random
	p += 1 + int(body[p])
	p += 2 + (int(body[p])<<8 | int(body[p+1]))
	p += 1 + int(body[p])
	if p+2 > len(body) {
		return "", false
	}
	extLen := int(body[p])<<8 | int(body[p+1])
	p += 2
	exts := body[p : p+extLen]

	for len(exts) >= 4 {
		extType := int(exts[0])<<8 | int(exts[1])
		extDataLen := int(exts[2])<<8 | int(exts[3])
		extData := exts[4 : 4+extDataLen]
		if extType == 0x0000 { // server_name
			if len(extData) < 2 {
				return "", false
			}
			listLen := int(extData[0])<<8 | int(extData[1])
			list := extData[2 : 2+listLen]
			if len(list) >= 3 && list[0] == 0x00 {
				nameLen := int(list[1])<<8 | int(list[2])
				return string(list[3 : 3+nameLen]), true
			}
			return "", false
		}
		exts = exts[4+extDataLen:]
	}
	return "", false
}

// parseHTTPHost extracts the Host header from the start of a plaintext
// HTTP request — the same signal parseSNI reads out of a TLS ClientHello,
// for connections that skip TLS entirely (plain HTTP on port 80). Any
// "host:port" value has its port stripped, since the port to dial is
// already fixed by which listener accepted this connection.
func parseHTTPHost(data []byte) (string, bool) {
	for _, line := range strings.Split(string(data), "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "host") {
			continue
		}
		host := strings.TrimSpace(value)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		return host, host != ""
	}
	return "", false
}
