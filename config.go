package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// findConfig locates region's WireGuard .conf file.
//
// If configDir is set, only "<configDir>/<region>.conf" is considered.
// Otherwise the search order is "./<region>.conf" (matching how the .conf
// is downloaded and used with wg-quick) then
// "~/.config/vpnproxy/wireguard/<region>.conf".
func findConfig(region, configDir string) (string, error) {
	name := region + ".conf"

	if configDir != "" {
		p := filepath.Join(configDir, name)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("no %s in %s: %w", name, configDir, err)
		}
		return p, nil
	}

	candidates := []string{filepath.Join(".", name)}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "vpnproxy", "wireguard", name))
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no %s found (looked in: %v)", name, candidates)
}
