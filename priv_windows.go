//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// requireElevated returns an error if vpnproxy isn't running with the
// privileges needed to raise a kernel-level WireGuard interface — see
// tunnel_darwin.go's requireElevated for the macOS equivalent.
func requireElevated() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("must run elevated (creating a wintun adapter requires it); try running from an Administrator command prompt")
	}
	return nil
}
