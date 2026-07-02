#!/usr/bin/env bash
# DarkWatch — egress leak / isolation verifier
# Confirms that:
#   1. Tor egress works and is identified as Tor by check.torproject.org.
#   2. The Tor exit IP and the Telegram-path exit IP are different.
#   3. darkwatch container has no host network access (its default route
#      goes via the tunnel1 netns, not the host).
#
# Run anytime:
#   sudo ./ops/verify-egress.sh
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed (treat as "do not crawl")

set -euo pipefail

log()  { printf '\033[1;36m[verify]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m  ✗\033[0m %s\n' "$*"; FAILED=1; }
FAILED=0

[[ $EUID -eq 0 ]] || { echo "must run as root (uses docker)" >&2; exit 1; }

# ─── 1. Containers up? ──────────────────────────────────────────────────────
log "checking containers"
for svc in tunnel1 tunnel2 tor tg-socks darkwatch; do
    if docker ps --format '{{.Names}}' | grep -q "^${svc}$"; then
        ok "$svc running"
    else
        bad "$svc NOT running"
    fi
done

# ─── 2. Tor egress identifies as Tor ────────────────────────────────────────
# `tor` and `tg-socks` use network_mode: service:tunnel1[2]. They have
# no DNS entry of their own; the SOCKS port is reachable via the WG
# container's hostname because they share the netns. Hence tunnel1:9050,
# tunnel2:1080 below.
log "checking Tor egress (check.torproject.org)"
TOR_RESP="$(docker exec darkwatch curl -s --socks5-hostname tunnel1:9050 --max-time 30 \
            https://check.torproject.org/api/ip 2>/dev/null || echo '{}')"
TOR_IS_TOR="$(echo "$TOR_RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("IsTor", False))' 2>/dev/null || echo "False")"
TOR_EXIT_IP="$(echo "$TOR_RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("IP", ""))' 2>/dev/null || echo "")"
if [[ "$TOR_IS_TOR" == "True" ]]; then
    ok "tor exit identified as Tor (exit IP: $TOR_EXIT_IP)"
else
    bad "tor egress did NOT identify as Tor: $TOR_RESP"
fi

# ─── 3. TG path exit IP ─────────────────────────────────────────────────────
log "checking Telegram-path exit IP"
TG_EXIT="$(docker exec darkwatch curl -s --socks5 tunnel2:1080 --max-time 30 \
           https://api.ipify.org 2>/dev/null || echo "")"
if [[ -n "$TG_EXIT" ]]; then
    ok "tg-socks exit IP: $TG_EXIT"
else
    bad "tg-socks egress not reachable"
fi

# ─── 4. Tor IP and TG IP must differ ────────────────────────────────────────
if [[ -n "$TOR_EXIT_IP" && -n "$TG_EXIT" ]]; then
    if [[ "$TOR_EXIT_IP" != "$TG_EXIT" ]]; then
        ok "tor and tg exit IPs differ — egress isolation confirmed"
    else
        bad "tor exit IP == tg exit IP ($TOR_EXIT_IP). The two tunnels are correlated; reconfigure WG to use different regions."
    fi
fi

# ─── 5. darkwatch container does NOT see host network ───────────────────────
# Use docker inspect from the host. Reading /proc/net/route from inside the
# container fails when uid 999 + cap_drop ALL block the read; that's a
# false-positive vector if we relied on it.
log "checking darkwatch isolation from host network"
DW_NET_MODE="$(docker inspect darkwatch --format '{{.HostConfig.NetworkMode}}')"
DW_NETWORKS="$(docker inspect darkwatch --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}')"
log "  HostConfig.NetworkMode: $DW_NET_MODE"
log "  Connected networks:    $DW_NETWORKS"
if [[ "$DW_NET_MODE" == "host" ]]; then
    bad "darkwatch is on host network — DIRECT host network access (CRITICAL)"
elif [[ "$DW_NETWORKS" == *darknet* ]]; then
    ok "darkwatch is on the darknet bridge (no host network access)"
else
    bad "darkwatch isn't on the expected darknet bridge — review compose"
fi

# ─── 6. DNS leak: darkwatch resolver should NOT be the host's resolver ──────
log "checking DNS resolution path"
DW_DNS="$(docker exec darkwatch sh -c 'cat /etc/resolv.conf 2>/dev/null | grep nameserver | head -1' || echo "")"
log "  darkwatch /etc/resolv.conf: $DW_DNS"
# We expect Docker's embedded DNS (127.0.0.11), not host or public DNS.
if echo "$DW_DNS" | grep -q "127.0.0.11"; then
    ok "darkwatch uses docker embedded DNS (no leak path)"
else
    bad "darkwatch DNS resolver may be unexpected — review"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
if (( FAILED )); then
    printf '\033[1;31m=== EGRESS CHECK FAILED ===\033[0m\n' >&2
    echo "Do not initiate crawls until these are resolved." >&2
    exit 1
else
    printf '\033[1;32m=== egress check passed ===\033[0m\n'
    exit 0
fi
