package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFetchAndFindConfig(t *testing.T) {
	home := t.TempDir()
	base := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("VAULT_TOKEN", "good")
	t.Chdir(t.TempDir())

	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "vpnproxy", "wireguard")
	srv := fakeVault(t)
	if err := runFetch([]string{"-addr", srv.URL, "kv/vpnproxy"}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "FR.conf"))
	if err != nil || string(content) != "[Interface]\nPrivateKey = x\n" {
		t.Fatalf("fetched FR.conf = %q, %v", content, err)
	}
	if got, err := findConfig("FR", ""); err != nil || got != filepath.Join(dir, "FR.conf") {
		t.Fatalf("findConfig = %q, %v; want user config directory", got, err)
	}

	if err := os.WriteFile("FR.conf", []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := findConfig("FR", ""); err != nil || got != "FR.conf" {
		t.Fatalf("findConfig = %q, %v; want current directory", got, err)
	}
	if got, err := findConfig("FR", dir); err != nil || got != filepath.Join(dir, "FR.conf") {
		t.Fatalf("findConfig = %q, %v; want explicit directory", got, err)
	}
	if _, err := findConfig("FR", t.TempDir()); err == nil {
		t.Fatal("findConfig fell back outside the explicit directory")
	}

	override := t.TempDir()
	if err := runFetch([]string{"-addr", srv.URL, "-dir", override, "kv/vpnproxy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(override, "FR.conf")); err != nil {
		t.Fatalf("fetch ignored -dir: %v", err)
	}
}
