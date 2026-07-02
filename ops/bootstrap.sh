#!/usr/bin/env bash
# DarkWatch — first-time VM bootstrap
# Creates /var/lib/darkwebapp/ with the right permissions for operator state.
# Idempotent — safe to re-run.
#
#   sudo ./ops/bootstrap.sh

set -euo pipefail

DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"

# UID 999 matches the `darkwatch` user baked into darkwatch/Dockerfile.
# Containers run as this UID, so any host directory the container writes
# to (loot/, data/, investigations/) needs to be owned by 999.
DARKWATCH_UID=999
DARKWATCH_GID=999

if [[ $EUID -ne 0 ]]; then
    echo "bootstrap.sh must run as root" >&2
    exit 1
fi

log()  { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap WARN]\033[0m %s\n' "$*" >&2; }

log "creating $DATA_ROOT"
# Top of tree + secrets stay root-owned: WG containers run privileged.
install -d -m 0700 -o root -g root "$DATA_ROOT"
install -d -m 0700 -o root -g root "$DATA_ROOT/secrets"
install -d -m 0700 -o root -g root "$DATA_ROOT/secrets/tunnel1"
install -d -m 0700 -o root -g root "$DATA_ROOT/secrets/tunnel1/wg_confs"
install -d -m 0700 -o root -g root "$DATA_ROOT/secrets/tunnel2"
install -d -m 0700 -o root -g root "$DATA_ROOT/secrets/tunnel2/wg_confs"

# darkwatch container runs as uid 999. Bind-mounted dirs MUST be writable
# by that uid or the first SQLite write / loot save fails.
log "creating darkwatch data dirs (owner $DARKWATCH_UID:$DARKWATCH_GID)"
install -d -m 0700 -o "$DARKWATCH_UID" -g "$DARKWATCH_GID" "$DATA_ROOT/darkwatch"
install -d -m 0700 -o "$DARKWATCH_UID" -g "$DARKWATCH_GID" "$DATA_ROOT/darkwatch/loot"
install -d -m 0700 -o "$DARKWATCH_UID" -g "$DARKWATCH_GID" "$DATA_ROOT/darkwatch/data"
install -d -m 0700 -o "$DARKWATCH_UID" -g "$DARKWATCH_GID" "$DATA_ROOT/darkwatch/investigations"
# yara-private/ is the drop-in dir for operator-specific *.yar files that
# must NOT enter the repo. Mounted into the container at /app/yara-private
# read-only; compiled at startup. Empty by design — operators drop files
# in over time. Create even on first bootstrap so the compose mount has
# something to bind.
install -d -m 0700 -o "$DARKWATCH_UID" -g "$DARKWATCH_GID" "$DATA_ROOT/darkwatch/yara-private"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# env file sentinel — copy from .env.example if missing
if [[ ! -f "$DATA_ROOT/env" ]]; then
    log "creating $DATA_ROOT/env from .env.example"
    install -m 0600 -o root -g root "$REPO_ROOT/.env.example" "$DATA_ROOT/env"
    log "  edit it now:  sudo \$EDITOR $DATA_ROOT/env"
fi

# Compose variable substitution (${DARKWATCH_BIND_IP}, etc.) reads the project-root
# .env file — symlink it to operator state so port bindings match /var/lib/darkwebapp/env.
ENV_LINK="$REPO_ROOT/.env"
if [[ ! -e "$ENV_LINK" ]]; then
    ln -sf "$DATA_ROOT/env" "$ENV_LINK"
    log "linked $ENV_LINK -> $DATA_ROOT/env"
elif [[ "$(readlink -f "$ENV_LINK" 2>/dev/null || true)" != "$(readlink -f "$DATA_ROOT/env")" ]]; then
    warn "$ENV_LINK exists but does not point at $DATA_ROOT/env — fix manually"
fi

# Setup UI runs `docker compose` through the host Docker socket — bind-mount
# paths must be host paths, not /repo inside the setup container. Write the
# real locations on every bootstrap so fresh installs and moved checkouts work.
_set_env_var() {
    local key="$1" val="$2"
    if grep -qE "^${key}=" "$DATA_ROOT/env" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${val}|" "$DATA_ROOT/env"
    else
        printf '\n%s=%s\n' "$key" "$val" >> "$DATA_ROOT/env"
    fi
}
_set_env_var DARKWATCH_HOST_REPO_ROOT "$REPO_ROOT"
_set_env_var DARKWATCH_HOST_DATA_ROOT "$DATA_ROOT"
log "host paths for Setup UI: repo=$REPO_ROOT data=$DATA_ROOT"

# SETUP_AUTH_TOKEN — generate on first bootstrap if missing/empty.
# This token gates the Setup UI (port 8082) when the operator brings up
# `docker compose --profile setup up -d setup`. Print it once so the
# operator can record it; rotate later with openssl rand -hex 32.
if grep -qE '^SETUP_AUTH_TOKEN=$' "$DATA_ROOT/env" 2>/dev/null || \
   ! grep -qE '^SETUP_AUTH_TOKEN=' "$DATA_ROOT/env" 2>/dev/null; then
    NEW_TOKEN="$(openssl rand -hex 32)"
    if grep -qE '^SETUP_AUTH_TOKEN=' "$DATA_ROOT/env"; then
        sed -i "s|^SETUP_AUTH_TOKEN=.*|SETUP_AUTH_TOKEN=${NEW_TOKEN}|" "$DATA_ROOT/env"
    else
        printf '\nSETUP_AUTH_TOKEN=%s\n' "$NEW_TOKEN" >> "$DATA_ROOT/env"
    fi
    chmod 600 "$DATA_ROOT/env"
    log ""
    log "  ════════════════════════════════════════════════════════════════"
    log "  Setup UI bearer token (record this — printed only once):"
    log ""
    log "      ${NEW_TOKEN}"
    log ""
    log "  Use it when accessing http://<bind-ip>:8082/?token=<TOKEN>"
    log "  Rotate any time with: openssl rand -hex 32 | xargs -I@ sed -i \\"
    log "    's|^SETUP_AUTH_TOKEN=.*|SETUP_AUTH_TOKEN=@|' $DATA_ROOT/env"
    log "  ════════════════════════════════════════════════════════════════"
    log ""
fi

# user.yar lives next to darkwatch.db (the code derives its path from
# the DB path, not from a separate yara-private dir). Container reads
# it as the darkwatch user, so we own it 999:999.
USER_YAR="$DATA_ROOT/darkwatch/data/user.yar"
if [[ ! -f "$USER_YAR" ]]; then
    cat > "$USER_YAR" <<'YARA'
// Place operator-specific YARA rules here.
// This file lives outside the git checkout so your specific keywords and
// targets never enter version control. The crawler reloads it on the
// next scan; no restart needed.

rule example_rule {
    strings:
        $a = "example_keyword_to_match"
    condition:
        $a
}
YARA
    chmod 0600 "$USER_YAR"
    chown "$DARKWATCH_UID:$DARKWATCH_GID" "$USER_YAR"
    log "created stub $USER_YAR"
fi

log "bootstrap complete. Next steps:"
log "  1. Edit $DATA_ROOT/env (chmod 0600 root:root)"
log "       — at minimum: DARKWATCH_BIND_IP, TOR_CONTROL_PASSWORD"
log "       — Telegram + WireGuard tunnels can be set via the Setup UI instead"
log "  2. Place WireGuard configs OR use the Setup UI (step 5):"
log "       Manual:  $DATA_ROOT/secrets/tunnel1/wg_confs/wg0.conf"
log "                $DATA_ROOT/secrets/tunnel2/wg_confs/wg0.conf"
log "       UI:      docker compose --profile setup up -d setup"
log "                http://\$DARKWATCH_BIND_IP:8082/?token=<token printed above>"
log "  3. (Optional) replace stub at $USER_YAR with real rules"
log "  4. Apply baseline hardening:  sudo ./ops/harden.sh"
log "  5. Deploy:                    sudo ./ops/deploy.sh"
