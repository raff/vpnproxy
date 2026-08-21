# vpnproxy (macOS)

Relays one hostname's traffic through a WireGuard tunnel, without routing
anything else on the machine through it — so a single region-gated or
"internal users only" service can be reached as if from wherever the
tunnel's exit is.

## Quickstart

1. Get a WireGuard config for the region you want (see below), and name it
   after that region, e.g. `FR.conf`. Put it in this same folder, next to
   `vpnproxy` (or in `~/.config/vpnproxy/wireguard/`).

2. Run, as root — raising a real WireGuard interface requires it:

   ```
   sudo ./run-with-hosts.sh FR
   ```

   This adds the masqueraded hostname to `/etc/hosts`, runs `vpnproxy`, and
   removes the entry again on exit (normal exit, an error, or Ctrl+C). The
   hostname is hardcoded in `run-with-hosts.sh` — open it in a text editor
   and edit the `HOSTS_ENTRY_HOST`/`HOSTS_ENTRY_IP` constants near the top
   if you're pointing at a different service.

3. Leave it running, and use the masqueraded hostname as normal (browser,
   `curl`, etc.) — `vpnproxy` figures out which real hostname each
   connection is actually for and relays it through the tunnel.

Any extra arguments are forwarded to `vpnproxy` as-is — a fallback target,
a different port list:

```
sudo ./run-with-hosts.sh FR 203.0.113.10
sudo ./run-with-hosts.sh FR -ports 80,443,8443
```

Run `./vpnproxy -h` for the full flag list, or run it directly (without
the `/etc/hosts` wrapper) if you'd rather manage that yourself.

## Getting a WireGuard config

### Proton VPN

1. Sign in at account.protonvpn.com.
2. Downloads → WireGuard configuration.
3. Name it something you'll recognize later — the name is only a label.
4. Platform doesn't matter here — every choice emits the same
   `[Interface]`/`[Peer]` file.
5. Server: pick a specific country server yourself. Don't take
   "Recommended" — that's chosen by load and proximity to you, not the
   country you actually want.
6. Create, wait a few seconds, Download.

Country selection needs a paid Proton plan; Free gives you a handful of
countries.

### NordVPN

1. Sign in at my.nordaccount.com and open the NordVPN service.
2. Find the manual/advanced setup area — NordVPN calls it something like
   "Set up NordVPN manually", separate from the main app download. It's
   there specifically for third-party clients.
3. Pick WireGuard and a specific server (by country or hostname, not
   "auto" or "recommended" — same reasoning as Proton above).
4. Generate and download the `.conf`.

Any paid NordVPN plan can do this; there's no free tier to worry about.
