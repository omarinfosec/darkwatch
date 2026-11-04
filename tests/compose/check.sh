#!/usr/bin/env bash
# Static checks on the rendered compose config (no daemon needed):
#   - darkwatch's DNS defaults to 127.0.0.1 (DNS isolation; see the comment
#     on darkwatch's `dns:` in docker-compose.yml) and DARKWATCH_DNS overrides
#     it;
#   - no other service sets `dns:` (the tunnels need the host's DNS to
#     resolve hostname Endpoints).
#   bash tests/compose/check.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
touch "$work/env"
PYTHON="${PYTHON:-python3}"

render() {   # extra env assignments as args; prints the config as JSON
    env -u DARKWATCH_DNS "$@" DARKWEBAPP_DATA_ROOT="$work" \
        docker compose --project-directory "$repo" -f "$repo/docker-compose.yml" \
        --profile tor --profile tg --profile setup config --format json
}

# Prints "<service> <dns as JSON>" for every service, sorted.
dns_of() {
    "$PYTHON" -c '
import json, sys
for name, svc in sorted(json.load(sys.stdin)["services"].items()):
    print(name, json.dumps(svc.get("dns")))'
}

got="$(render | dns_of)"
want='darkwatch ["127.0.0.1"]
setup null
tg-socks null
tor null
tunnel1 null
tunnel2 null'
if [[ "$got" != "$want" ]]; then
    printf 'FAIL default dns:\n%s\nwant:\n%s\n' "$got" "$want" >&2
    exit 1
fi
echo "ok   darkwatch dns defaults to 127.0.0.1; no other service sets dns"

got="$(render DARKWATCH_DNS=192.0.2.53 | dns_of | grep '^darkwatch ')"
[[ "$got" == 'darkwatch ["192.0.2.53"]' ]] || { echo "FAIL DARKWATCH_DNS override: $got" >&2; exit 1; }
echo "ok   DARKWATCH_DNS overrides darkwatch's dns"

echo "compose checks OK"
