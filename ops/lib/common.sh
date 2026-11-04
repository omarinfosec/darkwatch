# shellcheck shell=bash
# DarkWatch — helpers shared by the ops scripts. Source it; it only defines
# functions. Callers set DATA_ROOT (normally /var/lib/darkwebapp) first.

# env_val KEY DEFAULT — KEY's value from the operator env file (the last
# assignment wins), else from the process environment, else DEFAULT. An empty
# value counts as unset. Never fails, so it is safe under `set -euo pipefail`
# even when the file has no KEY= line.
env_val() {
    local v=""
    if [[ -r "$DATA_ROOT/env" ]]; then
        v="$(grep -E "^$1=" "$DATA_ROOT/env" | tail -1 | cut -d= -f2-)" || true
    fi
    echo "${v:-${!1:-$2}}"
}
