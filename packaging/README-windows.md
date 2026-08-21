# vpnproxy (Windows)

Relays one hostname's traffic through a WireGuard tunnel, without routing
anything else on the machine through it — so a single region-gated or
"internal users only" service can be reached as if from wherever the
tunnel's exit is.

## Quickstart

1. Get a WireGuard config for the region you want (see below), and name it
   after that region, e.g. `FR.conf`. Put it in this same folder, next to
   `vpnproxy.exe` (or in `%USERPROFILE%\.config\vpnproxy\wireguard\`).

2. From an **elevated** PowerShell prompt (right-click PowerShell → "Run as
   Administrator" — raising a real WireGuard interface requires it), run:

   ```
   .\run-with-hosts.ps1 FR
   ```

   This adds the masqueraded hostname to the Windows hosts file, runs
   `vpnproxy.exe`, and removes the entry again on exit (normal exit, an
   error, or Ctrl+C). The hostname is hardcoded in `run-with-hosts.ps1` —
   open it in a text editor and edit the `$HostsEntryHost`/`$HostsEntryIP`
   values near the top if you're pointing at a different service.

3. Leave it running, and use the masqueraded hostname as normal (browser,
   `curl`, etc.) — `vpnproxy.exe` figures out which real hostname each
   connection is actually for and relays it through the tunnel.

Any extra arguments are forwarded to `vpnproxy.exe` as-is — a fallback
target, a different port list:

```
.\run-with-hosts.ps1 FR 203.0.113.10
.\run-with-hosts.ps1 FR -ports 80,443,8443
```

Run `.\vpnproxy.exe -h` for the full flag list, or run it directly
(without the hosts-file wrapper) if you'd rather manage that yourself.

`wintun.dll` in this folder is required — it's how `vpnproxy.exe` raises
the WireGuard network adapter. Keep it next to `vpnproxy.exe`; Windows
won't find it anywhere else (not even on `PATH`).

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
