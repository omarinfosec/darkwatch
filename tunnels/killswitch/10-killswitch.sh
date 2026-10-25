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
set -euo pipefail

CHAIN=DW_KILLSWITCH
WG_MARK=0xca6c

# Subnets of every non-WireGuard interface (normally just eth0 on darknet).
mapfile -t SUBNETS < <(ip -4 -o addr show | awk '$2 != "lo" && $2 !~ /^wg/ {print $4}')
mapfile -t SUBNETS6 < <(ip -6 -o addr show scope global 2>/dev/null | awk '$2 !~ /^wg/ {print $4}')

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
}

apply iptables "${SUBNETS[@]}"
echo "[killswitch] IPv4: only wg*, lo, fwmark ${WG_MARK} and ${SUBNETS[*]:-no local subnets} may egress"
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L OUTPUT -n >/dev/null 2>&1; then
    apply ip6tables "${SUBNETS6[@]}"
    echo "[killswitch] IPv6: same policy applied"
fi
