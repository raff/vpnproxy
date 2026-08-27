# vpnproxy

`vpnproxy` relays local TCP connections to a service reachable through a
WireGuard tunnel, so that a single hostname can be made to look like it's
being accessed from wherever the tunnel's exit is — without routing
anything else on the machine through it.

It exists for testing region-gated or "internal users only" services: a
full system VPN would make *all* your traffic look external, including
requests to internal tools that need to see you as an internal user.
`vpnproxy` scopes the tunnel to exactly one hostname's traffic instead.

macOS and Windows. Single static binary, no separate helper process (on
Windows, `wintun.dll` — see the Building section — is the one extra file
needed alongside it).

## Usage

1. Get a WireGuard config file from your VPN provider — the same
   `[Interface]`/`[Peer]` `.conf` you'd hand to `wg-quick`, unmodified — and
   name it after the region it connects to, e.g. `FR.conf`.
2. Point the service's hostname at this proxy in `/etc/hosts`:

   ```
   127.0.0.1 adobeid-na1-stg1.services.adobe.com
   ```

3. Run vpnproxy as root (raising a real WireGuard interface requires it):

   ```
   sudo vpnproxy FR
   ```

That's it — `vpnproxy` raises the tunnel from `FR.conf`, listens on
`127.0.0.1:80` and `127.0.0.1:443`, and for every connection your browser
or `curl` makes to the masqueraded hostname, figures out which real
hostname it's for and relays the connection to it through the tunnel.

### Getting a WireGuard config

##### Proton VPN

1. Sign in at account.protonvpn.com.
2. Downloads → WireGuard configuration.
3. Name it something you'll recognise later — the name is only a label.
4. Platform doesn't matter here — every choice emits the same
   `[Interface]`/`[Peer]` file.
5. Server: pick a specific country server yourself. Don't take
   "Recommended" — that's chosen by load and proximity to you, which from
   the US is never going to be Italy or the UK.
6. Create, wait a few seconds, Download.

Country selection needs a paid Proton plan; Free gives you a handful of
countries.

##### NordVPN

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

### `run-with-hosts.sh`

`run-with-hosts.sh` wraps step 2 above so you don't have to touch
`/etc/hosts` by hand: it has the hostname hardcoded (edit the
`HOSTS_ENTRY_HOST`/`HOSTS_ENTRY_IP` constants at the top for your own),
adds it before running `vpnproxy`, and removes it again on exit — normal
exit, an error, or Ctrl+C.

```
sudo ./run-with-hosts.sh FR
```

Any extra arguments are forwarded to `vpnproxy` as-is (a fallback target,
`-ports`, etc.):

```
sudo ./run-with-hosts.sh FR 203.0.113.10
```

It only ever removes the exact line it added (tagged with a marker
comment), so a pre-existing, unrelated `/etc/hosts` entry for the same
host is left alone (with a warning, since whichever entry comes first in
the file wins).

### How the destination is determined

You don't pass the target hostname on the command line. Per connection,
`vpnproxy` sniffs it straight off the connection itself:

- **TLS (port 443):** the SNI from the ClientHello.
- **Plain HTTP (port 80):** the `Host:` header.

Either way, that's exactly the hostname the client put on the wire — the
`/etc/hosts` override only changed where the TCP `SYN` lands, not what the
client actually sent — so it's also exactly the hostname you want to
resolve and connect to. It's resolved through the WireGuard config's own
DNS server, reached through the tunnel, not your machine's regular
resolver (see [Why not the system resolver](#why-not-the-system-resolver)
below).

If a connection doesn't yield an SNI or a `Host` header, there's an
optional second argument as a fallback:

```
sudo vpnproxy FR 203.0.113.10
```

`target` can be a literal IP or a hostname (resolved the same way, through
the tunnel's DNS) — including the same masqueraded hostname `/etc/hosts`
points at this proxy.

### Flags

```
usage: vpnproxy [flags] <region> [target]

  -config-dir string
        directory containing <region>.conf (default: ./ then ~/.config/vpnproxy/wireguard/)
  -listen string
        local address to listen on (default "127.0.0.1")
  -ports string
        comma-separated list of ports to relay 1:1, local to target (default "80,443")
```

`<region>.conf` is looked up in the current directory first, then
`~/.config/vpnproxy/wireguard/`, unless `-config-dir` is set.

### Reading the logs

Every connection logs its lifecycle, so you can tell whether traffic is
actually flowing through the tunnel:

```
2026/08/18 16:53:22 raising wireguard tunnel for FR from FR.conf
2026/08/18 16:53:23 wireguard: handshake completed with 198.51.100.7:51820 (allowed ips: [0.0.0.0/0 ::/0])
2026/08/18 16:53:23 relaying 127.0.0.1:443 -> <sniffed SNI/Host, or "" if none> (via tunnel)
2026/08/18 16:53:30 127.0.0.1:54321 (sniffed=adobeid-na1-stg1.services.adobe.com) -> 10.2.0.5:443: dialing through tunnel
2026/08/18 16:53:30 127.0.0.1:54321 (sniffed=adobeid-na1-stg1.services.adobe.com) -> 10.2.0.5:443: connected through tunnel
2026/08/18 16:53:31 127.0.0.1:54321 (sniffed=adobeid-na1-stg1.services.adobe.com) -> 10.2.0.5:443: closed after 823ms (sent 612 bytes, received 4108 bytes)
```

If the tunnel comes up but a specific server never answers, the
"AllowedIPs" line above is the first thing worth checking — WireGuard
silently drops packets to destinations a peer's `AllowedIPs` doesn't
cover, which looks identical to a network timeout further down but is
actually a config mismatch.

## Implementation

### Raising the tunnel

`vpnproxy` brings up WireGuard on a real kernel-level virtual network
interface — `utun(4)` on macOS (the same primitive `wg-quick` uses there;
there's no in-kernel WireGuard on Darwin, so `wg-quick` is also just a
`utun` device plus a userspace `wireguard-go` process), or a Wintun adapter
on Windows (the same primitive `wireguard-windows` itself uses). What it
deliberately *doesn't* do is what `wg-quick`/`wireguard-windows` do on top
of that: install a system-wide default route or change DNS configuration.
Instead:

- The interface gets its WireGuard address(es)/MTU — via `ifconfig` on
  macOS, or the IP Helper API (through `winipcfg`) on Windows — plus an
  **interface-scoped** default route (`route -ifscope` on macOS,
  `CreateIpForwardEntry2` against the interface's LUID on Windows).
  Invisible to `route get default`/`route print` and to every other
  process, including a concurrently-connected VPN.
- Every socket `vpnproxy` opens for relayed traffic and tunnel DNS lookups
  is explicitly pinned to that interface — `IP_BOUND_IF`/`IPV6_BOUND_IF` on
  macOS, `IP_UNICAST_IF`/`IPV6_UNICAST_IF` on Windows. Combined with the
  scoped route, this is what actually routes traffic through the tunnel —
  nothing else on the machine ever does.
- After the device comes up, `vpnproxy` polls its UAPI status
  (`last_handshake_time_sec`) until a peer handshake actually completes (or
  times out with a clear error) before relaying or resolving anything —
  `dev.Up()` alone only means the device is ready to *try* sending, not
  that a peer has answered.

Since the whole process runs elevated anyway (`sudo` on macOS,
Administrator on Windows), there's no need to split privileges between a
long-running unprivileged process and a separate helper that raises the
interface: the interface is created and configured directly, in-process.

### The relay itself

Once the tunnel and a target hostname are known, relaying is a dumb TCP
byte copy — not an HTTP or TLS proxy. There's nothing to rewrite: the
client already sent the real hostname on the wire (SNI or `Host:`), so the
origin sees exactly what it would without `/etc/hosts` in the picture.
This also means TLS is never terminated or decrypted — it passes through
end to end between the client and the real origin.

### Why not the system resolver

The obvious way to resolve a hostname through the tunnel would be
`net.Resolver` with `PreferGo: true` and a custom `Dial` pointed at the
tunnel. That doesn't work here: Go's resolver checks `/etc/hosts` *before*
ever calling `Dial`, hosts-file hit or not. Since the whole point of this
tool is that `/etc/hosts` already points the target hostname at
`127.0.0.1`, that lookup would just return `127.0.0.1` again, silently,
without a single packet going through the tunnel.

Instead, DNS queries are hand-rolled (`golang.org/x/net/dns/dnsmessage`)
and sent directly over a UDP socket bound to the tunnel interface — no
`/etc/hosts`, no system resolver, at any point. Answers are cached by
their DNS TTL (clamped to 5s–5min) so that sniffing the hostname off of
every connection doesn't mean a DNS round trip through the tunnel per
connection.

### Files

| File | Contents |
| --- | --- |
| `main.go` | CLI parsing, orchestration, shutdown |
| `config.go` | Locates `<region>.conf` |
| `wireguard.go` | Cross-platform: the `tunnel` type, UAPI peer-status parsing, and handshake waiting |
| `tunnel_darwin.go` | Raises and configures the `utun` interface, exposes an interface-bound dialer |
| `tunnel_windows.go` | Raises and configures the Wintun adapter, exposes an interface-bound dialer |
| `priv_darwin.go` / `priv_windows.go` | Checks for root/Administrator before raising the interface |
| `resolver.go` | Resolves hostnames through the tunnel's own DNS server, with caching |
| `relay.go` | The TCP listener/relay loop, plus SNI and HTTP `Host:` sniffing |
| `run-with-hosts.sh` | Optional wrapper: manages the `/etc/hosts` entry around a `vpnproxy` run |

## Building

```
go build .
```

On Windows, the Wintun adapter is loaded from `wintun.dll` at runtime (via
`golang.zx2c4.com/wireguard/tun`) — it isn't linked into the binary, and
Windows only looks for it next to the .exe or in `System32`
(`LOAD_LIBRARY_SEARCH_APPLICATION_DIR`), not on `PATH` or anywhere else. A
copy of the official build (from [wintun.net](https://www.wintun.net/),
version 0.14.1) for each architecture is vendored in this repo under
`wintun/bin/<arch>/wintun.dll`; after `go build`, copy the one matching
your target next to `vpnproxy.exe`:

```
GOOS=windows GOARCH=amd64 go build -o vpnproxy.exe .
cp wintun/bin/amd64/wintun.dll .
```

`vpnproxy` also needs to run from an elevated (Administrator) prompt — see
`priv_windows.go`.

Wintun's prebuilt-binary license (`wintun/LICENSE.txt`) is not open source;
it permits redistributing `wintun.dll` unmodified alongside software that
only calls it through the documented API in `wintun.h` (which is exactly
what `golang.zx2c4.com/wintun` does), but not standalone redistribution or
reverse engineering.

Produces a single static `vpnproxy` binary. No separate helper process or
install step — just run it with `sudo`.
