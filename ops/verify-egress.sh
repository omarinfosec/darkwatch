#!/usr/bin/env bash
# DarkWatch — egress leak / isolation verifier
# Confirms that:
#   1. Tor egress works and is identified as Tor by check.torproject.org.
#   2. The Tor exit IP and the Telegram-path exit IP differ, and the
#      Telegram-path exit IP is not the host's own IP.
#   3. darkwatch has no direct internet access: it is on the darknet bridge,
#      the egress-lockdown rule covers its actual address, and it can't reach
#      an IP literal that the host can.
#   4. darkwatch can't resolve clearnet names (its DNS never goes through the
#      host's resolver) but still resolves the tunnel service names.
#
# Run anytime:
#   sudo ./ops/verify-egress.sh            # auto-detect configured tunnels
#   sudo ./ops/verify-egress.sh --tor      # only check the Tor path
#   sudo ./ops/verify-egress.sh --tor --tg # check both explicitly
#
# Paths whose tunnel isn't configured are skipped, not failed — deploy.sh
# only enables the compose profiles whose WG config exists.
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed (treat as "do not crawl")

set -euo pipefail

log()  { printf '\033[1;36m[verify]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m  ✗\033[0m %s\n' "$*"; FAILED=1; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*"; }
FAILED=0

[[ $EUID -eq 0 ]] || { echo "must run as root (uses docker)" >&2; exit 1; }

DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# Same lookup as egress-lockdown.sh and deploy.sh (env file, else environment).
LOCKDOWN="$(env_val DARKWATCH_EGRESS_LOCKDOWN 1)"

CHECK_TOR=0
CHECK_TG=0
for arg in "$@"; do
    case "$arg" in
        --tor) CHECK_TOR=1 ;;
        --tg)  CHECK_TG=1 ;;
        -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done
if (( ! CHECK_TOR && ! CHECK_TG )); then
    [[ -f "$DATA_ROOT/secrets/tunnel1/wg_confs/wg0.conf" ]] && CHECK_TOR=1
    [[ -f "$DATA_ROOT/secrets/tunnel2/wg_confs/wg0.conf" ]] && CHECK_TG=1
fi
if (( ! CHECK_TOR && ! CHECK_TG )); then
    echo "no tunnels configured — nothing to verify" >&2
    exit 1
fi

# JSON parsing runs inside the darkwatch image so the host needs no python3.
json_field() {
    docker exec -i darkwatch python -c \
        'import sys,json; d=json.load(sys.stdin); print(d.get(sys.argv[1], ""))' "$1" 2>/dev/null || true
}

# ─── 1. Containers up? ──────────────────────────────────────────────────────
log "checking containers"
SERVICES=(darkwatch)
(( CHECK_TOR )) && SERVICES+=(tunnel1 tor)
(( CHECK_TG ))  && SERVICES+=(tunnel2 tg-socks)
for svc in "${SERVICES[@]}"; do
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
TOR_EXIT_IP=""
if (( CHECK_TOR )); then
    log "checking Tor egress (check.torproject.org)"
    TOR_RESP="$(docker exec darkwatch curl -s --socks5-hostname tunnel1:9050 --max-time 30 \
                https://check.torproject.org/api/ip 2>/dev/null || echo '{}')"
    TOR_IS_TOR="$(printf '%s' "$TOR_RESP" | json_field IsTor)"
    TOR_EXIT_IP="$(printf '%s' "$TOR_RESP" | json_field IP)"
    if [[ "$TOR_IS_TOR" == "True" ]]; then
        ok "tor exit identified as Tor (exit IP: $TOR_EXIT_IP)"
    else
        bad "tor egress did NOT identify as Tor: $TOR_RESP"
    fi
else
    log "skipping Tor egress check (tunnel1 not configured)"
fi

# ─── 3. TG path exit IP ─────────────────────────────────────────────────────
TG_EXIT=""
if (( CHECK_TG )); then
    log "checking Telegram-path exit IP"
    # tg-socks requires a login (TG_SOCKS_PASSWORD, same value darkwatch uses).
    TG_PASS="$(env_val TG_SOCKS_PASSWORD "")"
    TG_EXIT="$(docker exec darkwatch curl -s --socks5-hostname tunnel2:1080 \
               --proxy-user "darkwatch:${TG_PASS}" --max-time 30 \
               https://api.ipify.org 2>/dev/null || echo "")"
    if [[ -n "$TG_EXIT" ]]; then
        ok "tg-socks exit IP: $TG_EXIT"
        # The host's own IP, fetched from the host. Best effort: a host that
        # can't reach the echo service only skips this comparison.
        # Both sides must be bare IPv4 addresses: an error or proxy page would
        # otherwise "differ" without anything being compared.
        HOST_IP="$(curl -fsS --max-time 15 https://api.ipify.org 2>/dev/null || true)"
        ipv4='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
        if [[ ! "$HOST_IP" =~ $ipv4 ]]; then
            warn "could not fetch the host's own IP; tg-socks exit not compared with it"
        elif [[ ! "$TG_EXIT" =~ $ipv4 ]]; then
            warn "could not fetch tg-socks' exit IP as an address (got: ${TG_EXIT:0:80}); not compared with the host's IP"
        elif [[ "$TG_EXIT" == "$HOST_IP" ]]; then
            bad "tg-socks exit IP == the host's IP ($HOST_IP): Telegram traffic is NOT leaving through tunnel2"
        else
            ok "tg-socks exit IP differs from the host's IP"
        fi
    else
        bad "tg-socks egress not reachable"
    fi
else
    log "skipping Telegram-path check (tunnel2 not configured)"
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

# ─── 5b. darkwatch can't reach the internet except via the tunnels ──────────
# The probe is an IP literal: darkwatch can't resolve clearnet names (check 6),
# so a hostname would "fail" even with no lockdown at all.
log "checking darkwatch has no direct internet route (egress lockdown)"
if [[ "$LOCKDOWN" == "0" ]]; then
    warn "skipped: egress lockdown disabled by DARKWATCH_EGRESS_LOCKDOWN=0 (darkwatch can reach the internet directly)"
else
    # The rule must match the address darkwatch actually runs on, not just
    # DARKWATCH_IP in the env file.
    DW_IP="$(docker inspect darkwatch -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true)"
    LOCKDOWN_RULES="$(iptables -S DOCKER-USER 2>/dev/null | grep -F -- "--comment darkwatch-egress-lockdown" || true)"
    if [[ -z "$DW_IP" ]]; then
        bad "could not read darkwatch's IP address from docker inspect"
    elif [[ "$LOCKDOWN_RULES" == *"-s $DW_IP/32 "* ]]; then
        ok "DOCKER-USER has the egress-lockdown rule for darkwatch ($DW_IP)"
    else
        bad "no egress-lockdown rule in DOCKER-USER for darkwatch's address $DW_IP — run: sudo ./ops/egress-lockdown.sh (and check DARKWATCH_IP in the env file)"
    fi
    if docker exec darkwatch curl -s --max-time 5 -o /dev/null http://1.1.1.1 2>/dev/null; then
        bad "darkwatch reached http://1.1.1.1 DIRECTLY — run: sudo ./ops/egress-lockdown.sh; check: sudo iptables -S FORWARD | grep DOCKER-USER"
    elif curl -s --max-time 5 -o /dev/null http://1.1.1.1 2>/dev/null; then
        ok "darkwatch has no direct internet route (the host does)"
    else
        warn "direct-egress probe inconclusive: the host can't reach http://1.1.1.1 either"
    fi
fi

# ─── 5c. tunnel kill switches in place ──────────────────────────────────────
for t in $( (( CHECK_TOR )) && echo tunnel1; (( CHECK_TG )) && echo tunnel2 ); do
    if docker exec "$t" iptables -C OUTPUT -j DW_KILLSWITCH 2>/dev/null; then
        ok "$t kill switch active (no egress except WireGuard)"
    else
        bad "$t kill switch MISSING — traffic could leave via the host if the tunnel drops"
    fi
    if docker exec "$t" iptables -C INPUT -j DW_KS_IN 2>/dev/null; then
        ok "$t inbound drop active (nothing connects in through the tunnel)"
    else
        bad "$t inbound drop MISSING — the VPN side could reach the Tor / SOCKS ports; recreate $t"
    fi
done

# ─── 6. DNS: darkwatch's lookups must never be resolved by the host ─────────
# docker-compose.yml gives darkwatch `dns: 127.0.0.1`, so Docker's embedded
# DNS (127.0.0.11) forwards non-service names to 127.0.0.1 inside darkwatch's
# own namespace, where nothing answers. Without it, Docker forwards to the
# host's resolvers, and a loopback one (dnsmasq, unbound, bind) is queried
# from the HOST namespace, past the lockdown: resolv.conf then shows
# "ExtServers: [host(...)]". Docker 24/25 write no ExtServers footer; there
# only the lookup test below applies.
log "checking DNS resolution path"
if [[ "$LOCKDOWN" == "0" ]]; then
    warn "skipped clearnet DNS checks: DARKWATCH_EGRESS_LOCKDOWN=0 (a real DARKWATCH_DNS resolver is allowed)"
    [[ "$(env_val DARKWATCH_DNS 127.0.0.1)" != 127.0.0.1 ]] \
        || warn "DARKWATCH_EGRESS_LOCKDOWN=0 but DARKWATCH_DNS is unset: darkwatch can't resolve clearnet names, so the in-app IP-leak check fails and direct alerts don't send; set DARKWATCH_DNS to a resolver in the env file"
else
    [[ "$(env_val DARKWATCH_DNS 127.0.0.1)" == 127.0.0.1 ]] \
        || bad "DARKWATCH_DNS is set while the egress lockdown is on: leave it unset (darkwatch's lookups would stall on a dropped resolver)"
    DW_RESOLV="$(docker exec darkwatch cat /etc/resolv.conf 2>/dev/null || true)"
    DW_EXT="$(printf '%s\n' "$DW_RESOLV" | sed -n 's/^# ExtServers: *//p' | head -1)"
    log "  darkwatch resolv.conf ExtServers: ${DW_EXT:-(no footer)}"
    if [[ -z "$DW_RESOLV" ]]; then
        bad "could not read darkwatch's /etc/resolv.conf"
    elif [[ "$DW_RESOLV" == *"host("* ]]; then
        bad "darkwatch's DNS is resolved from the HOST namespace ($DW_EXT): lookups bypass the lockdown. Leave DARKWATCH_DNS unset and recreate darkwatch: sudo ./ops/deploy.sh"
    elif [[ -n "$DW_EXT" && "$DW_EXT" != "[127.0.0.1]" ]]; then
        bad "darkwatch's DNS upstream is $DW_EXT, expected [127.0.0.1]: leave DARKWATCH_DNS unset and recreate darkwatch"
    elif [[ -n "$DW_EXT" ]]; then
        ok "darkwatch's DNS upstream is 127.0.0.1 in its own namespace"
    fi
    # getent exits 2 for "not found"; anything else but a success means the
    # test itself didn't run.
    t0="$(date +%s%N)"
    rc=0; docker exec darkwatch timeout 10 getent hosts example.com >/dev/null 2>&1 || rc=$?
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    case "$rc" in
        0)   bad "darkwatch resolved example.com: clearnet lookups get answered (DNS leak)" ;;
        2)   ok "darkwatch can't resolve clearnet names (example.com failed in ${ms} ms)"
             # 127.0.0.1 is refused at once; a slow failure means lookups wait
             # on an unreachable resolver, which stalls the workers.
             (( ms < 3000 )) || warn "the failed lookup took ${ms} ms: check DARKWATCH_DNS is unset" ;;
        124) warn "the example.com lookup in darkwatch timed out after 10 s (no leak, but lookups stall the workers): check DARKWATCH_DNS is unset" ;;
        *)   bad "could not run the DNS lookup test in darkwatch (exit $rc)" ;;
    esac
fi
# Service names come from Docker's embedded DNS and must keep working.
for t in $( (( CHECK_TOR )) && echo tunnel1; (( CHECK_TG )) && echo tunnel2 ); do
    if docker exec darkwatch timeout 10 getent hosts "$t" >/dev/null 2>&1; then
        ok "darkwatch resolves $t"
    else
        bad "darkwatch can't resolve $t: the proxies are unreachable by name"
    fi
done
# tg-socks resolves Telegram's names in tunnel2's namespace. wg-quick points
# resolv.conf at the VPN's resolver only when wg0.conf has a DNS line; with
# Docker's embedded DNS left in place, a loopback resolver on the host can
# answer those lookups from the host.
if (( CHECK_TG )); then
    T2_RESOLV="$(docker exec tunnel2 cat /etc/resolv.conf 2>/dev/null || true)"
    if [[ -z "$T2_RESOLV" ]]; then
        warn "could not read tunnel2's /etc/resolv.conf"
    elif grep -q '^nameserver 127\.0\.0\.11' <<<"$T2_RESOLV"; then
        warn "tunnel2 resolves names through Docker's embedded DNS (127.0.0.11): add the VPN provider's DNS = line to tunnel2's wg0.conf, then recreate tunnel2 and tg-socks"
    else
        ok "tunnel2 resolves names through the VPN's resolver"
    fi
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
