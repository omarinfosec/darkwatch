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
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source-path=SCRIPTDIR source=lib/retention-cron.sh
source "$SCRIPT_DIR/lib/retention-cron.sh"

# ─── Must run as root (docker socket + /var/lib/darkwebapp/env) ─────────────
if [[ $EUID -ne 0 ]]; then
    fail "deploy.sh must run as root (it reads /var/lib/darkwebapp/env which is 0600 root)"
fi

DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"

# Every compose call reads the operator env explicitly, so variable
# substitution (DARKWATCH_IP, DARKNET_SUBNET, passwords) can't come from
# somewhere else. Plain `docker compose` (RUNBOOK, harden-phase2's sudoers,
# the hints below) reads the repo's .env link instead, which pre-flight checks.
dc() { docker compose --env-file "$DATA_ROOT/env" "$@"; }

# ─── Pre-flight checks ──────────────────────────────────────────────────────
log "pre-flight: verifying operator state at $DATA_ROOT"

[[ -d "$DATA_ROOT" ]] || fail "$DATA_ROOT does not exist. Run ops/bootstrap.sh first."
[[ -f "$DATA_ROOT/env" ]] || fail "$DATA_ROOT/env is missing. Copy .env.example and fill it in."
[[ "$(stat -c %a "$DATA_ROOT/env")" == "600" ]] || fail "$DATA_ROOT/env permissions must be 0600 (got $(stat -c %a "$DATA_ROOT/env"))"

# The repo's .env must be a link to the operator env. If it points elsewhere,
# plain `docker compose` puts darkwatch on a different address from the one
# the egress lockdown restricts (and starts tg-socks without its password).
# Catches a wrong target, a dangling link and a copied file.
ENV_LINK="$REPO_ROOT/.env"
if [[ ! -e "$ENV_LINK" && ! -L "$ENV_LINK" ]]; then
    ln -s "$(readlink -f "$DATA_ROOT/env")" "$ENV_LINK"
    log "  linked $ENV_LINK -> $DATA_ROOT/env"
elif [[ "$(readlink -f "$ENV_LINK" 2>/dev/null || true)" != "$(readlink -f "$DATA_ROOT/env")" ]]; then
    fail "$ENV_LINK is not a link to $DATA_ROOT/env (it resolves to '$(readlink -f "$ENV_LINK" 2>/dev/null || true)'). Fix: sudo ln -sfn $DATA_ROOT/env $ENV_LINK"
fi

# tunnel1/2 run the kill switch from /custom-cont-init.d at start; without
# the exec bit it doesn't load and the tunnels never turn healthy.
KILLSWITCH="$REPO_ROOT/tunnels/killswitch/10-killswitch.sh"
[[ -x "$KILLSWITCH" ]] || fail "$KILLSWITCH is not executable. Fix: sudo chmod 755 $KILLSWITCH (and check 'git config core.fileMode')"

# Secrets that newer versions need. Generated once, kept in the env file.
ensure_secret() {
    local key="$1"
    if ! grep -qE "^${key}=.+" "$DATA_ROOT/env"; then
        local val; val="$(openssl rand -hex 24)"
        if grep -qE "^${key}=" "$DATA_ROOT/env"; then
            sed -i "s|^${key}=.*|${key}=${val}|" "$DATA_ROOT/env"
        else
            printf '\n%s=%s\n' "$key" "$val" >> "$DATA_ROOT/env"
        fi
        log "  generated $key"
    fi
}
ensure_secret TG_SOCKS_PASSWORD   # tg-socks proxy login (Telegram tunnel)
# Upgrades don't re-run bootstrap, so repeat its short-token warning here.
if setup_token_short; then
    warn "SETUP_AUTH_TOKEN is shorter than 32 characters; the Setup UI will answer 401 until you replace it (openssl rand -hex 32)"
fi

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
# The dashboard's login is opt-in. Warn, without failing, when it is reachable
# beyond loopback without one (a private VPN may be the only way in).
while IFS= read -r msg; do
    warn "$msg"
done < <(dashboard_auth_warnings)

# WireGuard configs placed by hand skip the Setup UI's validation. The kill
# switch assumes a full-tunnel config, so check the same rules here that
# setup/main.py:_validate_wg_config enforces (keep the two in sync).
check_wg_conf() {   # $1 = wg0.conf; prints "FAIL ..." / "WARN ..." lines
    awk '
        { sub(/#.*/, "") }
        !/=/ { next }
        {
            key = $0; sub(/=.*/, "", key); gsub(/[ \t\r]/, "", key)
            val = $0; sub(/^[^=]*=/, "", val); gsub(/[ \t\r]/, "", val)
            k = tolower(key)
        }
        k == "table" && tolower(val) != "auto" {
            print "FAIL " key " = " val " (traffic would bypass the tunnel; remove the line)"
        }
        k == "fwmark" { print "FAIL " key " = " val " (breaks the kill switch; remove the line)" }
        k ~ /^(pre|post)(up|down)$/ {
            print "WARN " key " hook runs as root inside the tunnel container (the Setup UI refuses hooks)"
        }
        k == "allowedips" && ("," val ",") ~ /,0\.0\.0\.0\/0,/ { full = 1 }
        END { if (!full) print "FAIL no AllowedIPs includes 0.0.0.0/0 (split-tunnel configs are not supported)" }
    ' "$1"
}
wg_problems=0
for conf in "$DATA_ROOT"/secrets/tunnel{1,2}/wg_confs/wg0.conf; do
    [[ -f "$conf" ]] || continue
    while IFS= read -r line; do
        case "$line" in
            FAIL*) warn "  $conf: ${line#FAIL }"; wg_problems=1 ;;
            WARN*) warn "  $conf: ${line#WARN }" ;;
        esac
    done < <(check_wg_conf "$conf")
done
(( ! wg_problems )) || fail "WireGuard config check failed (see above). Fix the file or paste it into the Setup UI."

# WG configs: detect which tunnels are configured. Tunnels are profile-gated
# in compose; we only enable a profile when its WG config file is actually
# present. Operator can run with one tunnel, both, or neither — degraded
# functionality (no Tor crawl / no Telegram scrape) but darkwatch still starts.
COMPOSE_PROFILES_ARGS=""
VERIFY_ARGS=()
TUNNEL1_CONF="$DATA_ROOT/secrets/tunnel1/wg_confs/wg0.conf"
TUNNEL2_CONF="$DATA_ROOT/secrets/tunnel2/wg_confs/wg0.conf"
if [[ -f "$TUNNEL1_CONF" ]]; then
    log "  found Tunnel 1 (Tor research) WG config — enabling 'tor' profile"
    COMPOSE_PROFILES_ARGS+=" --profile tor"
    VERIFY_ARGS+=(--tor)
else
    log "  no Tunnel 1 WG config at $TUNNEL1_CONF — Tor crawling will be unavailable"
fi
if [[ -f "$TUNNEL2_CONF" ]]; then
    log "  found Tunnel 2 (Telegram) WG config — enabling 'tg' profile"
    COMPOSE_PROFILES_ARGS+=" --profile tg"
    VERIFY_ARGS+=(--tg)
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

# Operational data dirs must exist and be writable by the container user
# (uid 999). Re-running bootstrap is idempotent and gets ownership right —
# a plain `mkdir -p` here would leave root-owned dirs darkwatch can't write.
# config.d (the local config override) is new in v0.4.0.
for d in darkwatch/loot darkwatch/data darkwatch/investigations darkwatch/yara-private config.d; do
    if [[ ! -d "$DATA_ROOT/$d" ]]; then
        log "  $DATA_ROOT/$d missing — re-running bootstrap"
        "$SCRIPT_DIR/bootstrap.sh"
        break
    fi
done

# Working tree must be clean (refuse to deploy uncommitted changes).
# Untracked files are ignored: bootstrap's .env symlink lives in the repo root.
if [[ -d .git ]]; then
    dirty="$(git status --porcelain --untracked-files=no)"
    if [[ -n "$dirty" ]]; then
        git status --short --untracked-files=no >&2
        # Local settings belong in the override file, not the tracked config.
        if [[ "$(cut -c4- <<<"$dirty")" == "darkwatch/config.json" ]]; then
            fail "darkwatch/config.json has local edits. Move the settings you changed into $DATA_ROOT/config.d/config.local.json (merged over config.json; see ops/RUNBOOK.md, \"Local config overrides\"), then run: sudo git checkout darkwatch/config.json"
        fi
        fail "git working tree has uncommitted changes. Commit or stash before deploying."
    fi
    log "git: $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"
fi

# ─── Pull latest source (unless skipped) ─────────────────────────────────────
# Bash keeps running the deploy.sh it started with, so after a pull that
# changes the code, restart once as the new script (--skip-pull and the env
# flag stop a second restart).
if (( ! SKIP_PULL )) && [[ -d .git ]]; then
    log "git pull --ff-only"
    old_head="$(git rev-parse HEAD)"
    git pull --ff-only
    new_head="$(git rev-parse HEAD)"
    if [[ "$new_head" != "$old_head" && -z "${DARKWATCH_DEPLOY_REEXEC:-}" ]]; then
        log "code updated (${old_head:0:7} -> ${new_head:0:7}): restarting the new deploy.sh"
        export DARKWATCH_DEPLOY_REEXEC=1
        exec bash "$SCRIPT_DIR/deploy.sh" --skip-pull "$@"   # bash: no exec bit needed
    fi
fi

# ─── Pull / build images ─────────────────────────────────────────────────────
log "docker compose pull (third-party images only)"
dc $COMPOSE_PROFILES_ARGS pull --ignore-buildable --quiet \
    || warn "image pull failed — continuing with locally cached images"

# Build every locally built image, not only the enabled profiles': the Setup
# UI starts tor itself after Tunnel 1 is saved (and can't build it), and a
# setup image that is never rebuilt keeps running old code.
if (( ! SKIP_BUILD )); then
    log "docker compose build (darkwatch, tor, setup)"
    dc $COMPOSE_PROFILES_ARGS --profile tor --profile setup build
fi

# ─── Network migration ───────────────────────────────────────────────────────
# v0.3 pins the darknet subnet (egress lockdown needs a fixed address for
# darkwatch) and v0.3.1 makes it IPv4-only (enable_ipv6: false, marked by the
# org.darkwatch.ipv4-only label). Compose can't swap a network that a
# container outside the enabled profiles (a running Setup UI) still uses, so
# when either differs, recreate it here, once: `down` stops the containers of
# every profile and removes the network; `up` below creates the new one.
want_subnet="$(env_val DARKNET_SUBNET 172.31.250.0/24)"
have_subnet="$(docker network inspect darkwatch_darknet \
    -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)"
have_v4only="$(docker network inspect darkwatch_darknet \
    -f '{{index .Labels "org.darkwatch.ipv4-only"}}' 2>/dev/null || true)"
if [[ -n "$have_subnet" && "$have_subnet" != "$want_subnet" ]]; then
    log "darknet subnet changes ($have_subnet -> $want_subnet): recreating the network"
    dc --profile tor --profile tg --profile setup down
elif [[ -n "$have_subnet" && "$have_v4only" != "true" ]]; then
    log "darknet network predates the IPv4-only setting: recreating it (once)"
    dc --profile tor --profile tg --profile setup down
fi

# ─── Block darkwatch's direct internet access (host firewall) ───────────────
# Before `up`, so darkwatch never runs without the rule. It matches on
# darkwatch's fixed address, so the container and network needn't exist yet.
"$SCRIPT_DIR/egress-lockdown.sh" || fail "could not apply egress lockdown"
# Re-apply after reboots (iptables rules don't persist on their own). The unit
# runs before docker.service, which starts the containers (restart policy),
# and after the host firewalls, whose start can flush iptables rules.
# WantedBy=docker.service: wherever Docker starts, the rule goes in first.
# reenable, not enable: it drops the links an older unit file asked for.
UNIT="${DW_SYSTEMD_UNIT_DIR:-/etc/systemd/system}/darkwatch-egress-lockdown.service"
if command -v systemctl >/dev/null 2>&1; then
    unit_body="[Unit]
Description=DarkWatch: block the darkwatch container's direct internet access
Before=docker.service
After=firewalld.service ufw.service

[Service]
Type=oneshot
ExecStart=$SCRIPT_DIR/egress-lockdown.sh --boot
RemainAfterExit=yes

[Install]
WantedBy=docker.service
"
    if ! printf '%s' "$unit_body" | cmp -s - "$UNIT"; then
        printf '%s' "$unit_body" > "$UNIT"
        systemctl daemon-reload
        systemctl reenable --quiet darkwatch-egress-lockdown.service
        log "installed darkwatch-egress-lockdown.service (applies the rule at boot, before Docker)"
    fi
fi

# Nightly ops/retention.sh (/etc/cron.d/darkwatch-retention). Here and not
# only in install.sh, which existing VMs never rerun; it also drops the
# crontab line older RUNBOOKs had operators add. Only warns on failure.
install_retention_cron "$REPO_ROOT" "$DATA_ROOT"

# ─── Bring stack up ──────────────────────────────────────────────────────────
# Tunnel sidecars wait for their WireGuard container to report a handshake;
# if that never happens `up` fails. Show why instead of dying silently.
log "docker compose $COMPOSE_PROFILES_ARGS up -d --remove-orphans"
if ! dc $COMPOSE_PROFILES_ARGS up -d --remove-orphans; then
    dc $COMPOSE_PROFILES_ARGS ps -a >&2 || true
    for svc in tunnel1 tunnel2; do
        if docker ps -a --format '{{.Names}}' | grep -qx "$svc"; then
            warn "last $svc logs:"
            docker logs --tail=20 "$svc" >&2 || true
        fi
    done
    fail "docker compose up failed. An unhealthy tunnel usually means the WG config is wrong, the VPN endpoint is unreachable (no handshake), or the kill switch didn't load: check 'docker logs tunnelN 2>&1 | grep -E \"custom-init|killswitch\"', and that tunnels/killswitch/10-killswitch.sh is owned by root and executable. '[killswitch] could not resolve endpoint' means the Endpoint hostname did not resolve at start: fix DNS on the host or use an IP Endpoint."
fi

# A running Setup UI keeps its old container (and code) until recreated.
# Refresh it onto the image just built; never start one that is stopped.
if [[ "$(docker inspect -f '{{.State.Running}}' setup 2>/dev/null || true)" == "true" ]]; then
    log "Setup UI is running: refreshing it"
    # Optional: a failure here must not stop the health wait and the egress probe.
    dc --profile setup up -d --no-deps setup \
        || warn "could not refresh the Setup UI; run: docker compose --profile setup up -d --build setup"
fi

# ─── Health verification ────────────────────────────────────────────────────
log "waiting up to 120s for darkwatch to report healthy..."
for i in $(seq 1 60); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' darkwatch 2>/dev/null || echo missing)"
    if [[ "$status" == "healthy" ]]; then
        log "darkwatch is healthy"
        break
    fi
    if (( i == 60 )); then
        log "darkwatch did not report healthy in time (status: $status). Recent logs:"
        dc logs --tail=40 darkwatch
        fail "darkwatch healthcheck timeout"
    fi
    sleep 2
done

# ─── Is the lockdown really in effect? ──────────────────────────────────────
# Runs even with no tunnels configured: that is when a leak matters most.
# The flag comes from env_val (env file, else the process environment), the
# same lookup egress-lockdown.sh uses.
lockdown="$(env_val DARKWATCH_EGRESS_LOCKDOWN 1)"
if [[ "$lockdown" == "0" ]]; then
    warn "egress lockdown is DISABLED (DARKWATCH_EGRESS_LOCKDOWN=0): darkwatch can reach the internet directly"
    [[ "$(env_val DARKWATCH_DNS 127.0.0.1)" != 127.0.0.1 ]] \
        || warn "DARKWATCH_EGRESS_LOCKDOWN=0 but DARKWATCH_DNS is unset: darkwatch can't resolve clearnet names, so the in-app IP-leak check fails and direct alerts don't send; set DARKWATCH_DNS to a resolver in the env file"
else
    # Docker adds this jump when it starts; without it DOCKER-USER is never
    # consulted (e.g. Docker running with "iptables": false).
    iptables -C FORWARD -j DOCKER-USER 2>/dev/null \
        || warn "FORWARD has no jump to DOCKER-USER: the egress lockdown rule is not consulted"
    # A real resolver is dropped by the lockdown, so lookups would stall.
    [[ "$(env_val DARKWATCH_DNS 127.0.0.1)" == 127.0.0.1 ]] \
        || fail "DARKWATCH_DNS is set while the egress lockdown is on: leave it unset in the env file (darkwatch's lookups would stall on a dropped resolver), then re-run deploy"
    log "probing darkwatch's direct internet access (http://1.1.1.1)"
    if docker exec darkwatch curl -s --max-time 5 -o /dev/null http://1.1.1.1 2>/dev/null; then
        fail "darkwatch reached http://1.1.1.1 DIRECTLY although the egress lockdown is on. Check: sudo ./ops/egress-lockdown.sh --status; sudo iptables -S FORWARD | grep DOCKER-USER"
    elif curl -s --max-time 5 -o /dev/null http://1.1.1.1 2>/dev/null; then
        log "  darkwatch has no direct internet route (the host does)"
    else
        warn "direct-egress probe inconclusive: the host can't reach http://1.1.1.1 either"
    fi
fi

# ─── Optional egress leak check (slow; can skip in dev loops) ───────────────
if (( ! NO_EGRESS_CHECK )); then
    if [[ -z "$COMPOSE_PROFILES_ARGS" ]]; then
        warn "skipping egress check — no tunnels configured yet"
    else
        log "running egress leak check"
        "$SCRIPT_DIR/verify-egress.sh" "${VERIFY_ARGS[@]}" || fail "egress check failed — stack is up but may be leaking"
    fi
fi

# ─── Done ────────────────────────────────────────────────────────────────────
BIND_IP="$(env_val DARKWATCH_BIND_IP 127.0.0.1)"
log "deploy complete."
log "  darkwatch:       http://${BIND_IP}:8080"
log ""
log "tail logs:    docker compose logs -f --tail=50"
log "stop stack:   docker compose down"
