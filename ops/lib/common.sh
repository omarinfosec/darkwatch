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

# dashboard_auth_warnings — prints one line per problem with the dashboard
# login (DARKWATCH_AUTH_TOKEN, off by default; darkwatch/web.py), nothing when
# all is well: no token while DARKWATCH_BIND_IP publishes port 8080 beyond
# loopback, or a token under the 32 characters web.py requires (it then
# answers 401). The token is read from the env file only, the last
# assignment, as compose's env_file does; never printed.
dashboard_auth_warnings() {
    local bind t=""
    bind="$(env_val DARKWATCH_BIND_IP 127.0.0.1)"
    if [[ -r "$DATA_ROOT/env" ]]; then
        t="$(grep -E '^DARKWATCH_AUTH_TOKEN=' "$DATA_ROOT/env" | tail -1 | cut -d= -f2-)" || true
    fi
    t="${t#"${t%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
    if [[ "$t" =~ ^\"(.*)\"$ || "$t" =~ ^\'(.*)\'$ ]]; then t="${BASH_REMATCH[1]}"; fi
    if [[ -z "$t" ]]; then
        case "$bind" in
            127.*|::1|"[::1]"|localhost) ;;
            *) echo "the dashboard is published on $bind:8080 with no login: anyone who can reach that address can use it. Set DARKWATCH_AUTH_TOKEN in $DATA_ROOT/env (openssl rand -hex 32), or set DARKWATCH_BIND_IP=127.0.0.1 and use an SSH tunnel" ;;
        esac
    elif (( ${#t} < 32 )); then
        echo "DARKWATCH_AUTH_TOKEN is shorter than 32 characters; the dashboard will answer 401 until you replace it (openssl rand -hex 32)"
    fi
}
