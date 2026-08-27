//go:build darwin

package main

import (
	"fmt"
	"os"
)

// requireElevated returns an error if vpnproxy isn't running with the
// privileges needed to raise a kernel-level WireGuard interface — root on
// macOS (see tunnel_darwin.go), Administrator on Windows
// (tunnel_windows.go).
func requireElevated() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (raising a kernel WireGuard interface requires it); try sudo")
	}
	return nil
}
