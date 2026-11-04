#!/bin/bash
# DarkWatch WireGuard kill switch.
#
# Mounted into tunnel1/tunnel2 at /custom-cont-init.d/, which the
# linuxserver/wireguard image runs as root at container start, before the
# tunnel comes up. It makes sure nothing in this network namespace (the WG
# container itself and the tor / tg-socks sidecars that share it) can reach
# the internet except through the WireGuard interface.
#
# Without it, wg-quick leaves the Docker bridge's default route in the main
# routing table: if wg0 never comes up or is torn down, Tor and Telegram
# traffic silently exits through eth0 -> Docker NAT -> the HOST's real IP.
#
# Allowed out:
#   - loopback
#   - the WireGuard interface (wg*)
#   - WireGuard's own encrypted packets to the VPN endpoint, which wg-quick
#     marks with fwmark 51820 (0xca6c) for full-tunnel configs
#   - the container's own Docker subnet(s) on eth0, so darkwatch on the
#     darknet bridge can reach the SOCKS ports and replies get back to it
# Everything else is rejected. The Setup UI only accepts full-tunnel configs
# (AllowedIPs 0.0.0.0/0, no Table/FwMark overrides), which this relies on.
#
# Inbound, nothing may open a connection to this netns through the tunnel
# (Tor's SocksPort / ControlPort listen on all interfaces): new connections
# arriving on wg* are dropped, replies to our own connections are not.
#
# Hostname Endpoints are resolved and pinned in /etc/hosts first, while
# egress is still open: afterwards DNS can't leave this netns (Docker's
# embedded DNS forwards from inside it), so wg-quick could never resolve them.
set -euo pipefail

CHAIN=DW_KILLSWITCH
IN_CHAIN=DW_KS_IN
WG_MARK=0xca6c
# Overridable for tests only.
WG_CONFS="${DW_KS_WG_CONFS:-/config/wg_confs}"
HOSTS_FILE="${DW_KS_HOSTS_FILE:-/etc/hosts}"
HOSTS_TAG="# dw-killswitch endpoint"

# Subnets of every non-WireGuard interface (normally just eth0 on darknet).
mapfile -t SUBNETS < <(ip -4 -o addr show | awk '$2 != "lo" && $2 !~ /^wg/ {print $4}')
mapfile -t SUBNETS6 < <(ip -6 -o addr show scope global 2>/dev/null | awk '$2 !~ /^wg/ {print $4}')

first_ipv4() { awk '{for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {print $i; exit}}'; }

# First IPv4 address for a name. Empty when unresolved.
#   1. getent ahostsv4: glibc (getaddrinfo, like wg itself).
#   2. nslookup -type=a: Alpine/musl, whose getent has no ahostsv4 and whose
#      `getent hosts` returns only the IPv6 addresses of a dual-stack name.
#      Only the answer section (after Name:) counts; the server's own
#      `Address: 127.0.0.11:53` line comes before it.
#   3. getent hosts: names only /etc/hosts knows (extra_hosts).
resolve4() {
    local ip
    ip="$(getent ahostsv4 "$1" 2>/dev/null | first_ipv4)" || true
    [[ -n "$ip" ]] || ip="$(nslookup -type=a "$1" 2>/dev/null \
        | awk '/^Name:/ {n = 1} n && /^Address/' | first_ipv4)" || true
    [[ -n "$ip" ]] || ip="$(getent hosts "$1" 2>/dev/null | first_ipv4)" || true
    printf '%s' "$ip"
}

# Pin each hostname Endpoint to its current IPv4 address in /etc/hosts (musl
# reads it before DNS). Best effort: logs and carries on, never aborts.
pin_endpoints() {
    local conf line host ip base rc=0
    local -a hosts=() pins=()
    for conf in "$WG_CONFS"/*.conf; do
        [[ -r "$conf" ]] || continue
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            if [[ "$line" =~ ^[[:space:]]*[Ee][Nn][Dd][Pp][Oo][Ii][Nn][Tt][[:space:]]*=[[:space:]]*([^[:space:]]+):[0-9]+[[:space:]]*$ ]]; then
                host="${BASH_REMATCH[1]}"
                # IP literals need no lookup ([v6] or dotted quad).
                if [[ "$host" != \[* && ! "$host" =~ ^[0-9.]+$ ]]; then
                    hosts+=("$host")
                fi
            fi
        done < "$conf"
    done
    [[ -w "$HOSTS_FILE" ]] || {
        (( ${#hosts[@]} == 0 )) || echo "[killswitch] could not pin endpoint(s) ${hosts[*]}: $HOSTS_FILE is not writable"
        return 0
    }
    # Drop earlier pins before resolving, so a stale one can't answer.
    # /etc/hosts is a bind mount: rewrite it in place, never rename over it.
    base="$(grep -vF -- "$HOSTS_TAG" "$HOSTS_FILE")" || rc=$?
    (( rc <= 1 )) || { echo "[killswitch] could not read $HOSTS_FILE; endpoints not pinned"; return 0; }
    if grep -qF -- "$HOSTS_TAG" "$HOSTS_FILE"; then
        printf '%s\n' "$base" > "$HOSTS_FILE" || return 0
    fi
    for host in "${hosts[@]}"; do
        if [[ ! "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
            echo "[killswitch] could not resolve endpoint $host (not a hostname)"
            continue
        fi
        ip="$(resolve4 "$host")"
        if [[ -n "$ip" ]]; then
            pins+=("$ip $host $HOSTS_TAG")
            echo "[killswitch] pinned endpoint $host -> $ip in $HOSTS_FILE"
        else
            echo "[killswitch] could not resolve endpoint $host: no handshake until it does (recreate the tunnel once DNS works, or use an IP Endpoint)"
        fi
    done
    (( ${#pins[@]} == 0 )) && return 0
    # Start on a new line even if the file doesn't end in one.
    [[ -z "$(tail -c1 "$HOSTS_FILE")" ]] || echo >> "$HOSTS_FILE" || true
    printf '%s\n' "${pins[@]}" >> "$HOSTS_FILE" || true
}

apply() {
    local ipt="$1"; shift
    "$ipt" -N "$CHAIN" 2>/dev/null || "$ipt" -F "$CHAIN"
    "$ipt" -A "$CHAIN" -o lo -j RETURN
    "$ipt" -A "$CHAIN" -o wg+ -j RETURN
    "$ipt" -A "$CHAIN" -m mark --mark "$WG_MARK" -j RETURN
    local net
    for net in "$@"; do
        "$ipt" -A "$CHAIN" -d "$net" -j RETURN
    done
    "$ipt" -A "$CHAIN" -j REJECT
    "$ipt" -C OUTPUT -j "$CHAIN" 2>/dev/null || "$ipt" -I OUTPUT 1 -j "$CHAIN"
    # Inbound: from the VPN side, only replies to our own connections.
    "$ipt" -N "$IN_CHAIN" 2>/dev/null || "$ipt" -F "$IN_CHAIN"
    "$ipt" -A "$IN_CHAIN" -i wg+ -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    "$ipt" -A "$IN_CHAIN" -i wg+ -j DROP
    "$ipt" -C INPUT -j "$IN_CHAIN" 2>/dev/null || "$ipt" -I INPUT 1 -j "$IN_CHAIN"
}

pin_endpoints || echo "[killswitch] endpoint pinning failed; applying the kill switch anyway"
apply iptables "${SUBNETS[@]}"
echo "[killswitch] IPv4: only wg*, lo, fwmark ${WG_MARK} and ${SUBNETS[*]:-no local subnets} may egress; nothing may connect in via wg*"
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L OUTPUT -n >/dev/null 2>&1; then
    apply ip6tables "${SUBNETS6[@]}"
    echo "[killswitch] IPv6: same policy applied"
fi
