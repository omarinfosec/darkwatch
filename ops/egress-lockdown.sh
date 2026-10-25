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
#
# deploy.sh runs this after every deploy and installs a systemd unit so it
# is re-applied after a reboot. Disable entirely with
# DARKWATCH_EGRESS_LOCKDOWN=0 in /var/lib/darkwebapp/env.
set -euo pipefail

COMMENT="darkwatch-egress-lockdown"
DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

env_val() {   # read KEY from the operator env file, else the environment, else $2
    local v=""
    [[ -r "$DATA_ROOT/env" ]] && v="$(grep -E "^$1=" "$DATA_ROOT/env" | tail -1 | cut -d= -f2-)"
    echo "${v:-${!1:-$2}}"
}

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

case "${1:-}" in
    --remove) remove_rules; echo "egress lockdown removed"; exit 0 ;;
    --status) iptables -S DOCKER-USER 2>/dev/null | grep -- "$COMMENT" || echo "egress lockdown: not active"; exit 0 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
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
