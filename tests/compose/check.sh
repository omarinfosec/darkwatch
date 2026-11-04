#!/usr/bin/env bash
# Static checks on the rendered compose config (no daemon needed):
#   - darkwatch's DNS defaults to 127.0.0.1 (DNS isolation; see the comment
#     on darkwatch's `dns:` in docker-compose.yml) and DARKWATCH_DNS overrides
#     it;
#   - no other service sets `dns:` (the tunnels need the host's DNS to
#     resolve hostname Endpoints);
#   - only setup gets a non-empty SETUP_AUTH_TOKEN, and tor's environment is
#     exactly TOR_CONTROL_PASSWORD (not the whole env file);
#   - without TOR_CONTROL_PASSWORD (no .env, no --env-file) `config` fails.
#   bash tests/compose/check.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'TOR_CONTROL_PASSWORD=ci\nSETUP_AUTH_TOKEN=ci-sentinel\n' > "$work/env"
PYTHON="${PYTHON:-python3}"

# Compose prefers process env over --env-file; keep the caller's out.
compose() {   # extra env assignments, then compose args
    local assigns=()
    while [[ $# -gt 0 && "$1" == *=* ]]; do assigns+=("$1"); shift; done
    env -u DARKWATCH_DNS -u TOR_CONTROL_PASSWORD -u SETUP_AUTH_TOKEN \
        "${assigns[@]}" DARKWEBAPP_DATA_ROOT="$work" docker compose "$@"
}

render() {   # extra env assignments as args; prints the config as JSON
    compose "$@" --project-directory "$repo" -f "$repo/docker-compose.yml" \
        --env-file "$work/env" --profile tor --profile tg --profile setup \
        config --format json
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

got="$(render | "$PYTHON" -c '
import json, sys
svcs = json.load(sys.stdin)["services"]
print(" ".join(sorted(n for n, s in svcs.items()
                      if (s.get("environment") or {}).get("SETUP_AUTH_TOKEN"))))
print(" ".join(sorted(svcs["tor"].get("environment") or {})))')"
want='setup
TOR_CONTROL_PASSWORD'
if [[ "$got" != "$want" ]]; then
    printf 'FAIL env scoping (services with SETUP_AUTH_TOKEN, then tor env keys):\n%s\nwant:\n%s\n' "$got" "$want" >&2
    exit 1
fi
echo "ok   only setup gets SETUP_AUTH_TOKEN; tor gets only TOR_CONTROL_PASSWORD"

# Project directory without a .env, no --env-file: a missing or wrong .env
# link must stop compose, not start tor with an empty control password.
if out="$(compose --project-directory "$work" -f "$repo/docker-compose.yml" config -q 2>&1)"; then
    echo "FAIL compose config succeeded without TOR_CONTROL_PASSWORD" >&2
    exit 1
fi
[[ "$out" == *"TOR_CONTROL_PASSWORD unset"* ]] \
    || { echo "FAIL unexpected error without TOR_CONTROL_PASSWORD: $out" >&2; exit 1; }
echo "ok   compose config fails without TOR_CONTROL_PASSWORD"

echo "compose checks OK"
