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

# setup_token_short — true when SETUP_AUTH_TOKEN is set but shorter than the
# 32 characters setup/main.py requires (it then answers every request with
# 401). Reads the env file the way setup/main.py does: the first assignment,
# surrounding whitespace stripped. Never prints the value.
setup_token_short() {
    local t=""
    if [[ -r "$DATA_ROOT/env" ]]; then
        t="$(grep -m1 -E '^SETUP_AUTH_TOKEN=' "$DATA_ROOT/env" | cut -d= -f2-)" || true
    fi
    t="${t#"${t%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
    [[ -n "$t" && ${#t} -lt 32 ]]
}
