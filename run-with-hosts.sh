#!/usr/bin/env bash
# Wraps vpnproxy so the caller doesn't have to manage /etc/hosts by hand:
# adds the masqueraded hostname below, runs vpnproxy, and always removes
# the entry again on exit (normal exit, error, or Ctrl+C).
#
#   sudo ./run-with-hosts.sh <region> [vpnproxy args...]
#
# e.g.:
#   sudo ./run-with-hosts.sh FR
#   sudo ./run-with-hosts.sh FR 203.0.113.10
set -euo pipefail

# Hardcoded on purpose: edit this to point at whatever service you're
# masquerading, so the caller never has to touch /etc/hosts themselves.
readonly HOSTS_ENTRY_HOST="adobeid-na1-stg1.services.adobe.com"
readonly HOSTS_ENTRY_IP="127.0.0.1"

# Marks lines this script added, so cleanup only ever removes exactly
# those — never a pre-existing entry a human put there some other way.
readonly HOSTS_MARKER="# vpnproxy-managed-entry"

script_name="$(basename "$0")"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

vpnproxy_bin="$script_dir/vpnproxy"
if [[ ! -x "$vpnproxy_bin" ]]; then
	vpnproxy_bin="$(command -v vpnproxy || true)"
fi
if [[ -z "$vpnproxy_bin" ]]; then
	echo "$script_name: vpnproxy binary not found next to this script or on PATH (build it with 'go build .' first)" >&2
	exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "$script_name: must run as root (vpnproxy needs it too); try sudo" >&2
	exit 1
fi

if [[ $# -lt 1 ]]; then
	echo "usage: sudo $script_name <region> [vpnproxy args...]" >&2
	exit 1
fi

add_hosts_entry() {
	if grep -qF "$HOSTS_MARKER" /etc/hosts; then
		echo "$script_name: a stale entry from a previous run is still in /etc/hosts, removing it first" >&2
		remove_hosts_entry
	fi
	if grep -qE "[[:space:]]${HOSTS_ENTRY_HOST}([[:space:]]|\$)" /etc/hosts; then
		echo "$script_name: warning: /etc/hosts already has an unrelated entry for $HOSTS_ENTRY_HOST — the one this script adds may not take effect if it resolves first" >&2
	fi

	# Guards against appending onto the same line as the file's last
	# entry if it happens to be missing a trailing newline — but only
	# when that's actually true, so this never leaves behind a blank
	# line of its own (which remove_hosts_entry, below, has no way to
	# know is ours to clean up).
	if [[ -s /etc/hosts ]] && [[ "$(tail -c1 /etc/hosts | wc -l)" -eq 0 ]]; then
		printf '\n' >>/etc/hosts
	fi
	printf '%s\t%s\t%s\n' "$HOSTS_ENTRY_IP" "$HOSTS_ENTRY_HOST" "$HOSTS_MARKER" >>/etc/hosts
	echo "$script_name: added $HOSTS_ENTRY_HOST -> $HOSTS_ENTRY_IP to /etc/hosts"
}

remove_hosts_entry() {
	if ! grep -qF "$HOSTS_MARKER" /etc/hosts; then
		return
	fi
	# In place, not a mv-based swap: keeps /etc/hosts's original
	# permissions/ownership instead of replacing it with a new inode.
	sed -i '' "/${HOSTS_MARKER}/d" /etc/hosts
	echo "$script_name: removed $HOSTS_ENTRY_HOST from /etc/hosts"
}

trap remove_hosts_entry EXIT INT TERM

add_hosts_entry

set +e
"$vpnproxy_bin" "$@"
rc=$?
set -e

exit "$rc"
