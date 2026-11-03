package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestListConfigs(t *testing.T) {
	home := t.TempDir()
	base := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Chdir(t.TempDir())

	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "vpnproxy", "wireguard")
	check := func(args []string, want string) {
		t.Helper()
		var out bytes.Buffer
		if err := runList(args, &out); err != nil {
			t.Fatal(err)
		}
		if got := out.String(); got != want {
			t.Fatalf("list %v = %q; want %q", args, got, want)
		}
	}
	check(nil, "")
	for _, path := range []string{"FR.conf", "BR.conf", "notes.txt", ".conf"} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir("directory.conf", 0o700); err != nil {
		t.Fatal(err)
	}
	check(nil, "BR\nFR\n")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"FR.conf", "US.conf"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	check(nil, "BR\nFR\nUS\n")
	check([]string{"-config-dir", dir}, "FR\nUS\n")
	check([]string{"-config-dir", t.TempDir()}, "")

	for _, args := range [][]string{
		{"-config-dir", filepath.Join(dir, "missing")},
		{"-config-dir", "FR.conf"},
		{"unexpected"},
		{"-unknown"},
	} {
		if err := runList(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("list %v succeeded; want error", args)
		}
	}
	check([]string{"-h"}, "")
}

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
