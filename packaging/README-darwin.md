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
2. Fetch your NordLynx private key with it:
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

**macOS-specific alternative:** if you'd rather use the private key NordVPN
already generated for your Mac, install the NordVPN app, set the protocol
to NordLynx, connect, then run `sudo wg show nordlynx private-key` to read
it straight off the live interface — pair it with the endpoint/public key
from the app's connection info or the API above. If you installed via the
Mac App Store, NordVPN also stores that same key in the macOS keychain,
which [dvcrn/generate-nordvpn-wgconf](https://github.com/dvcrn/generate-nordvpn-wgconf)
can pull out directly (`npx generate-nordvpn-wgconf --nordvpn-accountid <id> --outdir .`).

There's no more official documentation than this to point to; see
https://lazyadmin.nl/home-network/nordvpn-wireguard-as-unifi-vpn-client/
and https://gist.github.com/bluewalk/7b3db071c488c82c604baf76a42eaad3 for
worked examples (the former targets Windows/PowerShell + a UniFi router,
not macOS, but the API calls are the same). Any paid plan can do this —
there's no free tier to worry about. Treat the private key like a
password: it's a permanent credential tied to your account, not a
per-session secret.
