#!/usr/bin/env bash
# DarkWatch — deploy script
# Run from the repo root on the VM:
#   sudo ./ops/deploy.sh [--skip-pull] [--skip-build] [--no-egress-check]
#
# Idempotent: re-running with no changes is a no-op.

set -euo pipefail

# ─── Locate repo root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ─── Argument parsing ────────────────────────────────────────────────────────
SKIP_PULL=0
SKIP_BUILD=0
NO_EGRESS_CHECK=0
for arg in "$@"; do
    case "$arg" in
        --skip-pull)        SKIP_PULL=1 ;;
        --skip-build)       SKIP_BUILD=1 ;;
        --no-egress-check)  NO_EGRESS_CHECK=1 ;;
        -h|--help)
            sed -n '2,7p' "$0"
            exit 0 ;;
        *)
            echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────
log()  { printf '\033[1;36m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[deploy WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[deploy ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

# ─── Must run as root (docker socket + /var/lib/darkwebapp/env) ─────────────
if [[ $EUID -ne 0 ]]; then
    fail "deploy.sh must run as root (it reads /var/lib/darkwebapp/env which is 0600 root)"
fi

DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"

# ─── Pre-flight checks ──────────────────────────────────────────────────────
log "pre-flight: verifying operator state at $DATA_ROOT"

[[ -d "$DATA_ROOT" ]] || fail "$DATA_ROOT does not exist. Run ops/bootstrap.sh first."
[[ -f "$DATA_ROOT/env" ]] || fail "$DATA_ROOT/env is missing. Copy .env.example and fill it in."
[[ "$(stat -c %a "$DATA_ROOT/env")" == "600" ]] || fail "$DATA_ROOT/env permissions must be 0600 (got $(stat -c %a "$DATA_ROOT/env"))"

# Required env vars must be present in /var/lib/darkwebapp/env
required_vars=(
    DARKWEBAPP_DATA_ROOT
    DARKWATCH_BIND_IP
    TOR_CONTROL_PASSWORD
)
missing=()
for v in "${required_vars[@]}"; do
    if ! grep -qE "^${v}=.+" "$DATA_ROOT/env"; then
        missing+=("$v")
    fi
done
if (( ${#missing[@]} > 0 )); then
    fail "missing required env vars in $DATA_ROOT/env: ${missing[*]}"
fi

# WG configs: detect which tunnels are configured. Tunnels are profile-gated
# in compose; we only enable a profile when its WG config file is actually
# present. Operator can run with one tunnel, both, or neither — degraded
# functionality (no Tor crawl / no Telegram scrape) but darkwatch still starts.
COMPOSE_PROFILES_ARGS=""
TUNNEL1_CONF="$DATA_ROOT/secrets/tunnel1/wg_confs/wg0.conf"
TUNNEL2_CONF="$DATA_ROOT/secrets/tunnel2/wg_confs/wg0.conf"
if [[ -f "$TUNNEL1_CONF" ]]; then
    log "  found Tunnel 1 (Tor research) WG config — enabling 'tor' profile"
    COMPOSE_PROFILES_ARGS+=" --profile tor"
else
    log "  no Tunnel 1 WG config at $TUNNEL1_CONF — Tor crawling will be unavailable"
fi
if [[ -f "$TUNNEL2_CONF" ]]; then
    log "  found Tunnel 2 (Telegram) WG config — enabling 'tg' profile"
    COMPOSE_PROFILES_ARGS+=" --profile tg"
    if ! grep -qE '^TELEGRAM_API_ID=.+' "$DATA_ROOT/env" || \
       ! grep -qE '^TELEGRAM_API_HASH=.+' "$DATA_ROOT/env"; then
        warn "  Tunnel 2 is up but Telegram credentials are not set yet"
        warn "  add them via the Setup UI — Telegram scraping stays disabled until then"
    fi
else
    log "  no Tunnel 2 WG config at $TUNNEL2_CONF — Telegram scraping will be unavailable"
fi
if [[ -z "$COMPOSE_PROFILES_ARGS" ]]; then
    warn "  no tunnels configured — running darkwatch with NO egress isolation"
    warn "  configure a WG tunnel via the Setup UI or place a wg0.conf at one of the paths above"
fi

# Operational data dirs must exist (compose mounts them)
mkdir -p "$DATA_ROOT/darkwatch/loot" \
         "$DATA_ROOT/darkwatch/data" \
         "$DATA_ROOT/darkwatch/investigations" \
         "$DATA_ROOT/yara-private"

# Working tree must be clean (refuse to deploy uncommitted changes)
if [[ -d .git ]]; then
    if [[ -n "$(git status --porcelain)" ]]; then
        fail "git working tree is dirty. Commit or stash before deploying."
    fi
    log "git: $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"
fi

# ─── Pull latest source (unless skipped) ─────────────────────────────────────
if (( ! SKIP_PULL )) && [[ -d .git ]]; then
    log "git pull --ff-only"
    git pull --ff-only
fi

# ─── Build / pull images ─────────────────────────────────────────────────────
if (( ! SKIP_BUILD )); then
    log "docker compose build"
    docker compose $COMPOSE_PROFILES_ARGS build
fi

log "docker compose pull (third-party images only)"
docker compose pull --ignore-buildable || true  # don't fail if some images haven't been pulled before

# ─── Bring stack up ──────────────────────────────────────────────────────────
log "docker compose $COMPOSE_PROFILES_ARGS up -d --remove-orphans"
docker compose $COMPOSE_PROFILES_ARGS up -d --remove-orphans

# ─── Health verification ────────────────────────────────────────────────────
log "waiting up to 90s for darkwatch to report healthy..."
for i in $(seq 1 18); do
    if docker compose ps darkwatch --format json | grep -q '"Health":"healthy"'; then
        log "darkwatch is healthy"
        break
    fi
    if (( i == 18 )); then
        log "darkwatch did not report healthy in time. Recent logs:"
        docker compose logs --tail=40 darkwatch
        fail "darkwatch healthcheck timeout"
    fi
    sleep 5
done

# ─── Optional egress leak check (slow; can skip in dev loops) ───────────────
if (( ! NO_EGRESS_CHECK )); then
    if [[ -z "$COMPOSE_PROFILES_ARGS" ]]; then
        warn "skipping egress check — no tunnels configured yet"
    else
        log "running egress leak check"
        "$SCRIPT_DIR/verify-egress.sh" || fail "egress check failed — stack is up but may be leaking"
    fi
fi

# ─── Done ────────────────────────────────────────────────────────────────────
BIND_IP="$(grep -E '^DARKWATCH_BIND_IP=' "$DATA_ROOT/env" | head -1 | cut -d= -f2-)"
BIND_IP="${BIND_IP:-127.0.0.1}"
log "deploy complete."
log "  darkwatch:       http://${BIND_IP}:8080"
log ""
log "tail logs:    docker compose logs -f --tail=50"
log "stop stack:   docker compose down"
