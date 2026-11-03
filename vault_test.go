package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// fakeVault serves the OIDC login endpoints and a KV v2 secret at
// kv/vpnproxy, readable only with the token issued by the OIDC callback.
func fakeVault(t *testing.T) *httptest.Server {
	t.Helper()
	var redirectURI, nonce string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/oidc/oidc/auth_url", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		redirectURI, nonce = req["redirect_uri"], req["client_nonce"]
		u := redirectURI + "?state=st&code=cd"
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"auth_url": u}})
	})
	mux.HandleFunc("/v1/auth/oidc/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != "st" || q.Get("code") != "cd" || q.Get("client_nonce") != nonce {
			http.Error(w, `{"errors":["bad callback"]}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"auth": map[string]string{"client_token": "good"}})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "good" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"data":{}}`))
	})
	mux.HandleFunc("/v1/sys/internal/ui/mounts/kv/vpnproxy", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"path": "kv/", "options": map[string]string{"version": "2"},
		}})
	})
	mux.HandleFunc("/v1/kv/data/vpnproxy", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "good" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{
			"FR": "[Interface]\nPrivateKey = x\n",
			"BR": "[Interface]\nPrivateKey = y",
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestVaultOIDCLoginAndFetch(t *testing.T) {
	srv := fakeVault(t)
	ctx := context.Background()
	c := &vaultClient{addr: srv.URL, token: "stale", http: srv.Client()}

	if c.tokenValid(ctx) {
		t.Fatal("stale token reported valid")
	}

	// Stand in for the browser: follow the auth URL, which redirects to the
	// local callback listener.
	browser := func(u string) error {
		go func() {
			resp, err := http.Get(u)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	tok, err := oidcLogin(ctx, c, "oidc", "", 0, browser)
	if err != nil {
		t.Fatalf("oidcLogin: %v", err)
	}
	if tok != "good" {
		t.Fatalf("token = %q, want %q", tok, "good")
	}
	c.token = tok
	if !c.tokenValid(ctx) {
		t.Fatal("OIDC token reported invalid")
	}

	data, err := c.kvRead(ctx, "kv/vpnproxy")
	if err != nil {
		t.Fatalf("kvRead: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "wg")
	names, err := writeConfigs(dir, data)
	if err != nil {
		t.Fatalf("writeConfigs: %v", err)
	}
	if len(names) != 2 || names[0] != "BR" || names[1] != "FR" {
		t.Fatalf("names = %v", names)
	}
	b, err := os.ReadFile(filepath.Join(dir, "BR.conf"))
	if err != nil || string(b) != "[Interface]\nPrivateKey = y\n" {
		t.Fatalf("BR.conf = %q, %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "FR.conf")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("FR.conf mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestWriteConfigsRejectsBadNames(t *testing.T) {
	for _, name := range []string{"../evil", "a/b", ".hidden", ""} {
		if _, err := writeConfigs(t.TempDir(), map[string]any{name: "x"}); err == nil {
			t.Errorf("writeConfigs accepted field %q", name)
		}
	}
	if _, err := writeConfigs(t.TempDir(), map[string]any{"FR": 1}); err == nil {
		t.Error("writeConfigs accepted non-string value")
	}
}
