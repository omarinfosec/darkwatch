#!/usr/bin/env bash
# DarkWatch — interactive installer
#
# Single-command bootstrap for a fresh VM. Walks the operator through:
#   1. prereq check
#   2. operator state directory (/var/lib/darkwebapp/)
#   3. env file population
#   4. optional baseline hardening (UFW, fail2ban, sshd, postgres, CUPS)
#   5. first deploy (auto-enables tunnel profiles based on what WG configs exist)
#   6. URLs + setup-UI token printed at the end
#
# Run on the VM as root:
#   sudo ./ops/install.sh
#
# Non-interactive (CI / Ansible / scripted re-runs):
#   sudo ./ops/install.sh --yes --skip-hardening
#
# Flags:
#   --yes              answer "yes" to all confirmations
#   --skip-hardening   don't run ops/harden.sh (you can run it later)
#   --skip-deploy      stop after bootstrap + env (you'll docker compose yourself)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"

# ─── Flags ──────────────────────────────────────────────────────────────────
ASSUME_YES=0
SKIP_HARDENING=0
SKIP_DEPLOY=0
for arg in "$@"; do
    case "$arg" in
        --yes|-y)         ASSUME_YES=1 ;;
        --skip-hardening) SKIP_HARDENING=1 ;;
        --skip-deploy)    SKIP_DEPLOY=1 ;;
        -h|--help)        sed -n '2,21p' "$0"; exit 0 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

# ─── Logging ────────────────────────────────────────────────────────────────
B='\033[1m'; C='\033[1;36m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'
hdr()  { printf "\n${B}══ %s ══${N}\n" "$*"; }
log()  { printf "${C}[install]${N} %s\n" "$*"; }
ok()   { printf "${G}  ✓${N} %s\n" "$*"; }
warn() { printf "${Y}  ⚠${N} %s\n" "$*" >&2; }
fail() { printf "${R}[install ERROR]${N} %s\n" "$*" >&2; exit 1; }
ask()  {
    local prompt="$1" default="${2:-y}"
    if (( ASSUME_YES )); then echo "yes (--yes)"; return 0; fi
    local hint="[Y/n]"; [[ "$default" == "n" ]] && hint="[y/N]"
    read -rp "  ${prompt} ${hint} " ans
    ans="${ans:-$default}"
    [[ "$ans" =~ ^[Yy] ]]
}

[[ $EUID -eq 0 ]] || fail "must run as root (sudo ./ops/install.sh)"

# ═══════════════════════════════════════════════════════════════════════════
hdr "1. Pre-flight checks"
# ═══════════════════════════════════════════════════════════════════════════

# Docker
if ! command -v docker >/dev/null; then
    fail "docker not found. Install: curl -fsSL https://get.docker.com | sh"
fi
ok "docker $(docker --version | awk '{print $3}' | tr -d ,)"

if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose v2 plugin missing. Install via the Docker Engine package."
fi
ok "docker compose $(docker compose version --short)"

# Repo location — bootstrap records the real path in env for the Setup UI.
if [[ "$REPO_ROOT" != "/opt/darkwebapp" ]]; then
    warn "repo is at $REPO_ROOT (not /opt/darkwebapp) — OK; bootstrap wrote DARKWATCH_HOST_REPO_ROOT"
else
    ok "repo: $REPO_ROOT"
fi

# ═══════════════════════════════════════════════════════════════════════════
hdr "2. Operator state directory"
# ═══════════════════════════════════════════════════════════════════════════

if [[ -d "$DATA_ROOT" ]]; then
    ok "$DATA_ROOT already exists — running bootstrap (idempotent)"
else
    log "creating $DATA_ROOT and seeding state"
fi
"$SCRIPT_DIR/bootstrap.sh"

# Extract the auto-generated SETUP_AUTH_TOKEN for printing at the end
SETUP_TOKEN="$(grep -E '^SETUP_AUTH_TOKEN=' "$DATA_ROOT/env" 2>/dev/null | head -1 | cut -d= -f2-)"

# ═══════════════════════════════════════════════════════════════════════════
hdr "3. Configure env file"
# ═══════════════════════════════════════════════════════════════════════════

# Detect host private IP, optionally bind dashboards to it
PRIV_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

current_bind=$(grep -E '^DARKWATCH_BIND_IP=' "$DATA_ROOT/env" | head -1 | cut -d= -f2-)
if [[ "$current_bind" == "127.0.0.1" || -z "$current_bind" ]]; then
    if [[ -n "$PRIV_IP" && "$PRIV_IP" != "127.0.0.1" ]]; then
        log "Host private IP detected: $PRIV_IP"
        if ask "Bind dashboards to $PRIV_IP instead of 127.0.0.1?" "n"; then
            sed -i "s|^DARKWATCH_BIND_IP=.*|DARKWATCH_BIND_IP=$PRIV_IP|" "$DATA_ROOT/env"
            ok "DARKWATCH_BIND_IP=$PRIV_IP"
        else
            ok "DARKWATCH_BIND_IP=127.0.0.1 (reach via SSH tunnel)"
        fi
    else
        warn "leaving DARKWATCH_BIND_IP=127.0.0.1"
        warn "reach dashboards via SSH tunnel:"
        warn "    ssh -L 8080:localhost:8080 -L 8081:localhost:8081 -L 8082:localhost:8082 -p 6245 root@<vm>"
    fi
fi

# Generate TOR_CONTROL_PASSWORD if missing
if ! grep -qE '^TOR_CONTROL_PASSWORD=.+' "$DATA_ROOT/env"; then
    pw="$(openssl rand -hex 32)"
    sed -i "s|^TOR_CONTROL_PASSWORD=.*|TOR_CONTROL_PASSWORD=$pw|" "$DATA_ROOT/env"
    ok "generated TOR_CONTROL_PASSWORD (32 bytes)"
fi

log ""
log "env file ready. Optional values you may want to fill in later:"
log "    $DATA_ROOT/env"
log "  - TELEGRAM_API_ID, TELEGRAM_API_HASH  (optional — set via Setup UI when you want Telegram scraping)"
log "  - TELEGRAM_ALERT_BOT_TOKEN, SLACK_WEBHOOK_URL  (optional alerts)"
log "All of these can also be set later via the Setup UI."

# ═══════════════════════════════════════════════════════════════════════════
hdr "4. Tunnels (the two WireGuard egress paths)"
# ═══════════════════════════════════════════════════════════════════════════

T1="$DATA_ROOT/secrets/tunnel1/wg_confs/wg0.conf"
T2="$DATA_ROOT/secrets/tunnel2/wg_confs/wg0.conf"

[[ -f "$T1" ]] && ok "Tunnel 1 (Tor research)        configured at $T1" || warn "Tunnel 1 (Tor research)        NOT configured"
[[ -f "$T2" ]] && ok "Tunnel 2 (Telegram research)   configured at $T2" || warn "Tunnel 2 (Telegram research)   NOT configured"

if [[ ! -f "$T1" && ! -f "$T2" ]]; then
    log ""
    log "No tunnels configured. You can either:"
    log "  (a) place WG configs at the paths above before deploying, OR"
    log "  (b) deploy now, then configure via the Setup UI (recommended for first run)"
fi

# ═══════════════════════════════════════════════════════════════════════════
hdr "5. Baseline VM hardening (optional)"
# ═══════════════════════════════════════════════════════════════════════════

if (( SKIP_HARDENING )); then
    ok "skipped (--skip-hardening)"
elif ask "Run ops/harden.sh now (UFW + fail2ban + sshd tightening + Postgres lockdown + CUPS off)?" "y"; then
    if [[ -t 0 ]] && ! (( ASSUME_YES )); then
        log "showing dry-run first…"
        "$SCRIPT_DIR/harden.sh" --dry-run
        echo
        if ask "Apply for real?" "y"; then
            "$SCRIPT_DIR/harden.sh"
        else
            ok "skipped (you said no)"
        fi
    else
        "$SCRIPT_DIR/harden.sh"
    fi
else
    ok "skipped"
fi

# ═══════════════════════════════════════════════════════════════════════════
hdr "6. Deploy"
# ═══════════════════════════════════════════════════════════════════════════

if (( SKIP_DEPLOY )); then
    ok "skipped (--skip-deploy)"
else
    "$SCRIPT_DIR/deploy.sh"
fi

# ═══════════════════════════════════════════════════════════════════════════
hdr "7. Done"
# ═══════════════════════════════════════════════════════════════════════════

BIND_IP=$(grep -E '^DARKWATCH_BIND_IP=' "$DATA_ROOT/env" | cut -d= -f2-)
BIND_IP="${BIND_IP:-127.0.0.1}"

ok "Dashboards:"
echo "      DarkWatch:       http://$BIND_IP:8080/"
echo "      Recon dashboard: http://$BIND_IP:8081/"
echo
ok "Bring up the Setup UI to configure tunnels + Telegram from your browser:"
echo "      docker compose --profile setup up -d setup"
echo "      open http://$BIND_IP:8082/?token=$SETUP_TOKEN"
echo "      docker compose --profile setup stop setup    # bring it down when done"
echo
ok "Day-to-day:"
echo "      ssh deploy@<vm>"
echo "      cd /opt/darkwebapp"
echo "      sudo ./ops/deploy.sh           # pull + build + up + healthcheck + egress verify"
echo "      sudo ./ops/verify-egress.sh    # confirm Tor + TG egress isolation"
echo "      docker compose logs -f darkwatch"
echo
ok "Operator runbook: $REPO_ROOT/ops/RUNBOOK.md"
