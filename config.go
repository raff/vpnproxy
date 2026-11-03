package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func configDirs(configDir string) []string {
	if configDir != "" {
		return []string{configDir}
	}
	dirs := []string{"."}
	if dir, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(dir, "vpnproxy", "wireguard"))
	}
	return dirs
}

func configDirUsage() string {
	paths := "./<region>.conf"
	for _, dir := range configDirs("")[1:] {
		paths += " then " + filepath.Join(dir, "<region>.conf")
	}
	return fmt.Sprintf("directory containing <region>.conf (default: %s)", paths)
}

func runList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	configDir := fs.String("config-dir", "", configDirUsage())
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s list [flags]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Lists available region names, one per line, without the .conf extension.")
		fmt.Fprintln(fs.Output())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("list: expected no arguments, got %d", fs.NArg())
	}

	regions := make(map[string]bool)
	for _, dir := range configDirs(*configDir) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if *configDir == "" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("list: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				region := strings.TrimSuffix(entry.Name(), ".conf")
				if region != "" {
					regions[region] = true
				}
			}
		}
	}
	names := make([]string, 0, len(regions))
	for region := range regions {
		names = append(names, region)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := fmt.Fprintln(out, name); err != nil {
			return err
		}
	}
	return nil
}

// findConfig locates region's WireGuard .conf file.
//
// If configDir is set, only "<configDir>/<region>.conf" is considered.
// Otherwise the search order is "./<region>.conf" (matching how the .conf
// is downloaded and used with wg-quick) then
// os.UserConfigDir()/vpnproxy/wireguard/<region>.conf.
func findConfig(region, configDir string) (string, error) {
	name := region + ".conf"

	if configDir != "" {
		p := filepath.Join(configDir, name)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("no %s in %s: %w", name, configDir, err)
		}
		return p, nil
	}

	var candidates []string
	for _, dir := range configDirs("") {
		candidates = append(candidates, filepath.Join(dir, name))
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no %s found (looked in: %v)", name, candidates)
}
