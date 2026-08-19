// Command vpnproxy relays local TCP connections to a service reachable
// through a WireGuard tunnel, so that a single hostname can be made to look
// like it's being accessed from wherever the tunnel's exit is — without
// routing anything else on the machine through it.
//
// Typical use: point /etc/hosts for the real service's hostname at
// 127.0.0.1, then run:
//
//	sudo vpnproxy FR
//
// which raises a WireGuard tunnel from FR.conf and relays 127.0.0.1:80 and
// 127.0.0.1:443 through it. Per connection, the destination hostname is
// sniffed straight off the connection itself — the SNI from a TLS
// ClientHello, or the Host header from a plaintext HTTP request — and
// resolved through the tunnel's own DNS server, not the system resolver
// (whose /etc/hosts entry for that name now points right back at this
// proxy; see target_darwin.go). A target argument is only needed as a
// fallback, for connections sniffing finds nothing on:
//
//	sudo vpnproxy FR 203.0.113.10
//
// vpnproxy must run as root: raising a real kernel WireGuard interface
// requires it (see tunnel_darwin.go). Unlike a full `wg-quick up`, it never
// touches the system routing table or DNS config — only sockets this
// process itself opens ever use the tunnel.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vpnproxy:", err)
		os.Exit(1)
	}
}

func run() error {
	portsFlag := flag.String("ports", "80,443", "comma-separated list of ports to relay 1:1, local to target")
	configDir := flag.String("config-dir", "", "directory containing <region>.conf (default: ./ then ~/.config/vpnproxy/wireguard/)")
	listenAddr := flag.String("listen", "127.0.0.1", "local address to listen on")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <region> [target]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "region names a <region>.conf WireGuard config. Per connection, the\n")
		fmt.Fprintf(os.Stderr, "destination hostname is sniffed from SNI (TLS) or the Host header\n")
		fmt.Fprintf(os.Stderr, "(plain HTTP) and resolved through the tunnel's own DNS. target is only\n")
		fmt.Fprintf(os.Stderr, "used as a fallback, for connections that yield neither — it may be an\n")
		fmt.Fprintf(os.Stderr, "IP or a hostname, and is safe to reuse the hostname /etc/hosts points\n")
		fmt.Fprintf(os.Stderr, "at this proxy.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 && flag.NArg() != 2 {
		flag.Usage()
		return fmt.Errorf("expected 1 or 2 arguments, got %d", flag.NArg())
	}
	region := flag.Arg(0)
	var fallbackTarget string
	if flag.NArg() == 2 {
		fallbackTarget = flag.Arg(1)
	}

	ports, err := parsePorts(*portsFlag)
	if err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (raising a kernel WireGuard interface requires it); try sudo")
	}

	confPath, err := findConfig(region, *configDir)
	if err != nil {
		return err
	}

	log.Printf("raising wireguard tunnel for %s from %s", region, confPath)
	t, err := startTunnel(confPath)
	if err != nil {
		return fmt.Errorf("starting tunnel: %w", err)
	}
	defer t.Close()

	dialer := dialerBoundTo(t.ifIndex)
	res := newResolver(t.ifIndex, t.dnsServers)

	errc := make(chan error, len(ports))
	for _, port := range ports {
		port := port
		go func() {
			errc <- serveRelay(*listenAddr, port, dialer, res, fallbackTarget)
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errc:
		return err
	case s := <-sig:
		log.Printf("received %s, shutting down", s)
		return nil
	}
}

func parsePorts(s string) ([]int, error) {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q in -ports", p)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("-ports must list at least one port")
	}
	return ports, nil
}
