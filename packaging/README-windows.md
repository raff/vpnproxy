# vpnproxy (Windows)

Relays one hostname's traffic through a WireGuard tunnel, without routing
anything else on the machine through it — so a single region-gated or
"internal users only" service can be reached as if from wherever the
tunnel's exit is.

## Quickstart

1. Get a WireGuard config for the region you want (see below), and name it
   after that region, e.g. `FR.conf`. Put it in this same folder, next to
   `vpnproxy.exe` (or in `%USERPROFILE%\.config\vpnproxy\wireguard\`).

2. Run it — raising a real WireGuard interface requires Administrator, so
   pick whichever of these fits how you're working:

   - **From a plain (non-elevated) `cmd` or PowerShell window** in this
     folder — double-clicking `run-with-hosts.bat` in Explorer works too,
     but it can't take a region argument that way, so you'd have to edit
     the region into the file first:

     ```
     run-with-hosts.bat FR
     ```

     It pops a UAC prompt, then opens a new elevated PowerShell window that
     runs the script there. This also sidesteps Windows' default execution
     policy, which otherwise blocks unsigned `.ps1` scripts from running at
     all (double-clicking `run-with-hosts.ps1` directly just opens it in a
     text editor instead of running it).

   - **Or, from an already-elevated PowerShell prompt** (right-click
     PowerShell → "Run as Administrator"):

     ```
     .\run-with-hosts.ps1 FR
     ```

   Either way, this adds the masqueraded hostname to the Windows hosts
   file, runs `vpnproxy.exe`, and removes the entry again on exit (normal
   exit, an error, or Ctrl+C). The hostname is hardcoded in
   `run-with-hosts.ps1` — open it in a text editor and edit the
   `$HostsEntryHost`/`$HostsEntryIP` values near the top if you're pointing
   at a different service.

3. Leave it running, and use the masqueraded hostname as normal (browser,
   `curl`, etc.) — `vpnproxy.exe` figures out which real hostname each
   connection is actually for and relays it through the tunnel.

Any extra arguments are forwarded to `vpnproxy.exe` as-is — a fallback
target, a different port list:

```
run-with-hosts.bat FR 203.0.113.10
run-with-hosts.bat FR -ports 80,443,8443
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

Unlike Proton, NordVPN doesn't officially hand you a downloadable
WireGuard `.conf`. They rebranded WireGuard as "NordLynx" internally, but
the only config export their manual-setup page (my.nordaccount.com →
NordVPN service → "Set up NordVPN manually") gives you is OpenVPN. There's
no first-party button that produces a `[Interface]`/`[Peer]` file — you
have to extract your own private key and assemble one. This is an
unofficial workaround (not documented behavior), and NordVPN can rotate
your key and break it without notice.

**Access-token method (works on any platform, no app required):**

1. From the manual-setup page above, generate an access token (email
   verification, then "Generate new token").
2. Fetch your NordLynx private key with it (from PowerShell, or any shell
   with `curl`):
   ```
   curl -s -u token:<ACCESS_TOKEN> \
     https://api.nordvpn.com/v1/users/services/credentials | jq -r .nordlynx_private_key
   ```
3. Pick a WireGuard-capable server and its public key/hostname from
   NordVPN's recommendations API (community scripts like
   [dvcrn/generate-nordvpn-wgconf](https://github.com/dvcrn/generate-nordvpn-wgconf)
   or [Ernestas-t/NordVPN-Wireguard-Generator](https://github.com/Ernestas-t/NordVPN-Wireguard-Generator)
   automate this step).
4. Assemble a normal `.conf`:
   ```
   [Interface]
   PrivateKey = <nordlynx_private_key>
   Address = 10.5.0.2/32

   [Peer]
   PublicKey = <server public key>
   AllowedIPs = 0.0.0.0/0, ::/0
   Endpoint = <server hostname>:51820
   ```

There's no more official documentation than this to point to; see
https://lazyadmin.nl/home-network/nordvpn-wireguard-as-unifi-vpn-client/
(targets Windows/PowerShell + a UniFi router specifically) and
https://gist.github.com/bluewalk/7b3db071c488c82c604baf76a42eaad3 for
worked examples. Any paid plan can do this — there's no free tier to worry
about. Treat the private key like a password: it's a permanent credential
tied to your account, not a per-session secret.
