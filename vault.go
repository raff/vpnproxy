package main

// "vpnproxy fetch": download every <region>.conf from a single HashiCorp
// Vault KV secret whose fields are region names and whose values are the
// WireGuard config text, e.g.
//
//	vault kv put secret/vpnproxy FR=@FR.conf BR=@BR.conf
//	vpnproxy fetch secret/vpnproxy
//
// Talks to Vault's HTTP API directly (no hashicorp/vault/api dependency),
// reusing VAULT_TOKEN or ~/.vault-token when valid and otherwise logging in
// with the same browser-based OIDC flow as `vault login -method=oidc`.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

func runFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	addr := fs.String("addr", os.Getenv("VAULT_ADDR"), "Vault address ($VAULT_ADDR)")
	namespace := fs.String("namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace ($VAULT_NAMESPACE)")
	dir := fs.String("dir", "", "directory to write <region>.conf files to (default: OS user config directory + vpnproxy/wireguard/)")
	oidcMount := fs.String("oidc-mount", "oidc", "mount path of the OIDC auth method")
	oidcRole := fs.String("oidc-role", "", "OIDC role (default: the auth method's default role)")
	oidcPort := fs.Int("oidc-port", 8250, "local port for the OIDC callback; http://localhost:<port>/oidc/callback must be an allowed redirect URI of the role")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s fetch [flags] <kv-path>\n\n", os.Args[0])
		fmt.Fprintf(fs.Output(), "Reads the Vault KV secret at kv-path (e.g. secret/vpnproxy) and writes\n")
		fmt.Fprintf(fs.Output(), "each of its fields to <field>.conf. Uses $VAULT_TOKEN or ~/.vault-token\n")
		fmt.Fprintf(fs.Output(), "if valid, otherwise logs in via OIDC in the browser.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("fetch: expected 1 argument (kv path), got %d", fs.NArg())
	}
	if *addr == "" {
		return errors.New("fetch: no Vault address; set VAULT_ADDR or pass -addr")
	}
	outDir := *dir
	if outDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		outDir = filepath.Join(base, "vpnproxy", "wireguard")
	}

	c := &vaultClient{
		addr:      strings.TrimRight(*addr, "/"),
		namespace: *namespace,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
	c.token = existingVaultToken()

	ctx := context.Background()
	login := func() error {
		log.Printf("logging in to %s via OIDC", c.addr)
		tok, err := oidcLogin(ctx, c, *oidcMount, *oidcRole, *oidcPort, openBrowser)
		if err != nil {
			return err
		}
		c.token = tok
		saveVaultToken(tok)
		return nil
	}

	// Only log in when there's no usable token: a 403 on the secret itself
	// with a valid token means missing access, which a new login won't fix.
	if c.token == "" || !c.tokenValid(ctx) {
		if err := login(); err != nil {
			return err
		}
	}
	data, err := c.kvRead(ctx, fs.Arg(0))
	if err != nil {
		return err
	}

	names, err := writeConfigs(outDir, data)
	if err != nil {
		return err
	}
	log.Printf("wrote %d config(s) to %s: %s", len(names), outDir, strings.Join(names, ", "))
	return nil
}

type vaultClient struct {
	addr      string
	namespace string
	token     string
	http      *http.Client
}

type vaultError struct {
	status int
	path   string
	errors []string
}

func (e *vaultError) Error() string {
	msg := strings.Join(e.errors, "; ")
	if msg == "" {
		msg = http.StatusText(e.status)
	}
	return fmt.Sprintf("vault %s: %d %s", e.path, e.status, msg)
}

// vaultResponse covers the fields of Vault's response envelope used here.
type vaultResponse struct {
	Data json.RawMessage `json:"data"`
	Auth *struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

func (c *vaultClient) do(ctx context.Context, method, path string, query url.Values, body any) (*vaultResponse, error) {
	u := c.addr + "/v1/" + strings.TrimLeft(path, "/")
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(b, &e)
		return nil, &vaultError{status: resp.StatusCode, path: path, errors: e.Errors}
	}
	var vr vaultResponse
	if len(b) > 0 {
		if err := json.Unmarshal(b, &vr); err != nil {
			return nil, fmt.Errorf("vault %s: decoding response: %w", path, err)
		}
	}
	return &vr, nil
}

// tokenValid reports whether c.token is accepted by Vault.
func (c *vaultClient) tokenValid(ctx context.Context) bool {
	_, err := c.do(ctx, http.MethodGet, "auth/token/lookup-self", nil, nil)
	return err == nil
}

// kvRead reads the secret at path (as given to `vault kv get`), handling
// both KV v1 and v2 mounts.
func (c *vaultClient) kvRead(ctx context.Context, path string) (map[string]any, error) {
	path = strings.Trim(path, "/")
	mount, version := c.kvMount(ctx, path)

	apiPath := path
	if version == "2" {
		apiPath = mount + "data/" + strings.TrimPrefix(path, mount)
	}
	resp, err := c.do(ctx, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if version == "2" {
		var v2 struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(resp.Data, &v2); err != nil {
			return nil, fmt.Errorf("vault %s: decoding data: %w", apiPath, err)
		}
		data = v2.Data
	} else if err := json.Unmarshal(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("vault %s: decoding data: %w", apiPath, err)
	}
	if data == nil {
		return nil, fmt.Errorf("vault %s: secret not found or deleted", path)
	}
	return data, nil
}

// kvMount returns path's mount (with trailing slash) and KV version, the
// same way `vault kv` discovers them. If the lookup isn't permitted, it
// assumes the first path segment is a KV v2 mount.
func (c *vaultClient) kvMount(ctx context.Context, path string) (mount, version string) {
	mount, _, _ = strings.Cut(path, "/")
	mount, version = mount+"/", "2"

	resp, err := c.do(ctx, http.MethodGet, "sys/internal/ui/mounts/"+path, nil, nil)
	if err != nil {
		return mount, version
	}
	var m struct {
		Path    string `json:"path"`
		Options struct {
			Version string `json:"version"`
		} `json:"options"`
	}
	if json.Unmarshal(resp.Data, &m) != nil || m.Path == "" {
		return mount, version
	}
	if m.Options.Version == "2" {
		return m.Path, "2"
	}
	return m.Path, "1"
}

// oidcLogin performs Vault's browser-based OIDC login (the flow behind
// `vault login -method=oidc`) and returns the resulting client token.
func oidcLogin(ctx context.Context, c *vaultClient, mount, role string, port int, open func(string) error) (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", fmt.Errorf("oidc: listening for callback: %w", err)
	}
	defer ln.Close()
	redirectURI := fmt.Sprintf("http://localhost:%d/oidc/callback", ln.Addr().(*net.TCPAddr).Port)

	nonceBytes := make([]byte, 20)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(nonceBytes)

	mount = strings.Trim(mount, "/")
	resp, err := c.do(ctx, http.MethodPost, "auth/"+mount+"/oidc/auth_url", nil, map[string]string{
		"role":         role,
		"redirect_uri": redirectURI,
		"client_nonce": nonce,
	})
	if err != nil {
		return "", fmt.Errorf("oidc: %w", err)
	}
	var au struct {
		AuthURL string `json:"auth_url"`
	}
	if err := json.Unmarshal(resp.Data, &au); err != nil || au.AuthURL == "" {
		return "", fmt.Errorf("oidc: Vault returned no auth_url; check that %s is an allowed redirect URI for the role", redirectURI)
	}

	type result struct {
		token string
		err   error
	}
	done := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm() // query string, or body for form_post response mode
		q := url.Values{}
		for _, k := range []string{"state", "code", "id_token"} {
			q.Set(k, r.Form.Get(k))
		}
		q.Set("client_nonce", nonce)

		var res result
		cb, err := c.do(r.Context(), http.MethodGet, "auth/"+mount+"/oidc/callback", q, nil)
		switch {
		case err != nil:
			res.err = fmt.Errorf("oidc: %w", err)
		case cb.Auth == nil || cb.Auth.ClientToken == "":
			res.err = errors.New("oidc: callback returned no client token")
		default:
			res.token = cb.Auth.ClientToken
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "<html><body><h2>Vault login failed</h2><p>%s</p></body></html>", htmlEscape(res.err.Error()))
		} else {
			fmt.Fprint(w, "<html><body><h2>Vault login succeeded</h2><p>You can close this window and return to vpnproxy.</p></body></html>")
		}
		select {
		case done <- res:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	fmt.Fprintf(os.Stderr, "Complete the login in your browser. If it doesn't open, visit:\n\n    %s\n\n", au.AuthURL)
	if err := open(au.AuthURL); err != nil {
		log.Printf("could not open browser: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	select {
	case res := <-done:
		return res.token, res.err
	case <-ctx.Done():
		return "", errors.New("oidc: timed out waiting for browser login")
	}
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

func vaultTokenFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vault-token")
}

// existingVaultToken returns $VAULT_TOKEN or the token the vault CLI saved
// in ~/.vault-token, if any.
func existingVaultToken() string {
	if t := os.Getenv("VAULT_TOKEN"); t != "" {
		return t
	}
	if f := vaultTokenFile(); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// saveVaultToken stores tok in ~/.vault-token, like `vault login`, so later
// runs (and the vault CLI) can reuse it without another browser login.
func saveVaultToken(tok string) {
	f := vaultTokenFile()
	if f == "" {
		return
	}
	if err := os.WriteFile(f, []byte(tok), 0o600); err != nil {
		log.Printf("could not save token to %s: %v", f, err)
	}
}

var regionNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// writeConfigs writes each field of data to dir/<field>.conf (mode 0600)
// and returns the region names written, sorted.
func writeConfigs(dir string, data map[string]any) ([]string, error) {
	if len(data) == 0 {
		return nil, errors.New("secret has no fields")
	}
	names := make([]string, 0, len(data))
	for name, v := range data {
		if !regionNameRE.MatchString(name) {
			return nil, fmt.Errorf("field %q is not a valid region name", name)
		}
		if _, ok := v.(string); !ok {
			return nil, fmt.Errorf("field %q is not a string", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for _, name := range names {
		content := data[name].(string)
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := writeFileAtomic(filepath.Join(dir, name+".conf"), []byte(content)); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vpnproxy-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
