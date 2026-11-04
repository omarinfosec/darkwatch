#!/usr/bin/env bash
# DarkWatch — block the darkwatch container's direct internet access.
#
# darkwatch must only reach the internet through the tunnels' SOCKS proxies
# (tunnel1:9050 Tor, tunnel2:1080 Telegram), which live on the darknet
# bridge. Docker gives every bridge container a NAT default route, so any
# code path that forgot the proxy would leave from the HOST's real IP. This
# installs a rule in Docker's DOCKER-USER chain (evaluated before Docker's
# own forwarding rules) that drops darkwatch traffic to anything outside the
# darknet subnet, except replies on connections opened TO it (the published
# dashboard port).
#
#   sudo ./ops/egress-lockdown.sh           # apply (idempotent)
#   sudo ./ops/egress-lockdown.sh --remove  # remove the rule
#   sudo ./ops/egress-lockdown.sh --status  # show it
#   sudo ./ops/egress-lockdown.sh --boot    # apply without asking Docker
#                                           # (the systemd unit, which runs
#                                           # before docker.service)
#
# deploy.sh runs this before it starts the containers and installs a systemd
# unit that re-applies it at boot, before Docker starts them. Disable
# entirely with DARKWATCH_EGRESS_LOCKDOWN=0 in /var/lib/darkwebapp/env.
#
# The rule is IPv4 only; compose creates the darknet network without IPv6
# (enable_ipv6: false). Apply and --status warn when the network has IPv6
# anyway, and say nothing when it doesn't exist yet.
set -euo pipefail

COMMENT="darkwatch-egress-lockdown"
DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

# env_val: the operator env file, else the environment, else the default.
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

SUBNET="$(env_val DARKNET_SUBNET 172.31.250.0/24)"
DW_IP="$(env_val DARKWATCH_IP 172.31.250.250)"
ENABLED="$(env_val DARKWATCH_EGRESS_LOCKDOWN 1)"

remove_rules() {
    local rule
    while rule="$(iptables -S DOCKER-USER 2>/dev/null | grep -- "--comment $COMMENT" | head -1)" \
          && [[ -n "$rule" ]]; do
        # "-A DOCKER-USER <spec>" -> "-D DOCKER-USER <spec>"
        eval "iptables -D ${rule#-A }"
    done
}

# Warn (never fail) when darknet has IPv6: the rule can't stop darkwatch
# from leaving over it. A missing network or daemon is fine (first deploy).
# Not at boot: the unit runs before docker.service, and a docker call would
# wait for a daemon that waits for this script.
warn_ipv6() {
    local v6
    v6="$(docker network inspect darkwatch_darknet -f '{{.EnableIPv6}}' 2>/dev/null || true)"
    if [[ "$v6" == "true" ]]; then
        echo "WARNING: the darkwatch_darknet network has IPv6 enabled; this rule only covers IPv4," >&2
        echo "  so darkwatch may reach the internet directly over IPv6. Recreate the network:" >&2
        echo "  sudo docker compose --profile tor --profile tg --profile setup down && sudo ./ops/deploy.sh" >&2
    fi
}

BOOT=0
case "${1:-}" in
    --remove) remove_rules; echo "egress lockdown removed"; exit 0 ;;
    --status) iptables -S DOCKER-USER 2>/dev/null | grep -- "$COMMENT" || echo "egress lockdown: not active"
              warn_ipv6; exit 0 ;;
    --boot) BOOT=1 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    "") ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

if [[ "$ENABLED" == "0" ]]; then
    remove_rules
    echo "egress lockdown disabled (DARKWATCH_EGRESS_LOCKDOWN=0)"
    exit 0
fi

# Docker creates DOCKER-USER when it starts; create it if we run first.
iptables -N DOCKER-USER 2>/dev/null || true
remove_rules
iptables -I DOCKER-USER 1 -s "$DW_IP" ! -d "$SUBNET" \
    -m conntrack ! --ctstate ESTABLISHED,RELATED \
    -m comment --comment "$COMMENT" -j DROP
echo "egress lockdown active: $DW_IP may only reach $SUBNET (plus replies)"
(( BOOT )) || warn_ipv6
