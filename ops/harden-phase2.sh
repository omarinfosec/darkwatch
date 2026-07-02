#!/usr/bin/env bash
# DarkWatch — Phase 2 hardening
#
# Creates a non-root `deploy` user with scoped sudo for ops work, copies
# root's authorized SSH keys to it, and (after verification) disables
# root SSH login. After Phase 2:
#   - You SSH as `deploy` (same key as before)
#   - You run `sudo ./ops/deploy.sh` (and other ops scripts) — sudoers
#     allows them; nothing else
#   - You run `docker ...` directly (deploy is in the docker group)
#   - Root SSH is denied (recovery via console only)
#
# Usage on the VM:
#   sudo ./ops/harden-phase2.sh --check        # preview only
#   sudo ./ops/harden-phase2.sh --create       # create deploy user, leave root SSH alone
#   sudo ./ops/harden-phase2.sh --lock-root    # disable root SSH (REQUIRES deploy user already verified)
#   sudo ./ops/harden-phase2.sh --apply        # both --create and --lock-root in one shot
#
# The split exists so you can verify SSH-as-deploy from another machine
# BEFORE locking root out. Recommended flow:
#   1. sudo ./ops/harden-phase2.sh --create
#   2. From your laptop: ssh deploy@<vm> -p 6245 'date'   (must succeed)
#   3. sudo ./ops/harden-phase2.sh --lock-root
#   4. From your laptop, IMMEDIATELY: ssh deploy@<vm> -p 6245 'date'
#      - If it works: sudo systemctl stop sshd-rollback.timer
#      - If it fails: do nothing — the timer auto-restores in 2 min
#      - root SSH should be denied either way

set -euo pipefail

DEPLOY_USER="deploy"
SSH_PORT="${SSH_PORT:-6245}"
DARKWEBAPP_REPO="${DARKWEBAPP_REPO:-/opt/darkwebapp}"

MODE=""
case "${1:-}" in
    --check)     MODE=check ;;
    --create)    MODE=create ;;
    --lock-root) MODE=lock ;;
    --apply)     MODE=apply ;;
    -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "usage: $0 --check | --create | --lock-root | --apply" >&2; exit 2 ;;
esac

log()  { printf '\033[1;36m[phase2]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[phase2 WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[phase2 ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "must run as root"

# ─── 1. Create deploy user ─────────────────────────────────────────────────
create_deploy_user() {
    if id "$DEPLOY_USER" >/dev/null 2>&1; then
        log "user '$DEPLOY_USER' already exists — leaving as is"
    else
        log "creating user '$DEPLOY_USER'"
        useradd -m -s /bin/bash "$DEPLOY_USER"
        # Lock the password — key auth only
        passwd -l "$DEPLOY_USER" >/dev/null
    fi

    # Add to docker group so `docker ...` works without sudo
    if getent group docker >/dev/null; then
        if ! id -nG "$DEPLOY_USER" | grep -qw docker; then
            log "adding '$DEPLOY_USER' to docker group"
            usermod -aG docker "$DEPLOY_USER"
        fi
    else
        warn "no 'docker' group on this host — install docker first"
    fi
}

# ─── 2. Copy root's authorized_keys to deploy ──────────────────────────────
provision_ssh_keys() {
    if [[ ! -f /root/.ssh/authorized_keys ]]; then
        fail "/root/.ssh/authorized_keys missing — can't propagate keys to deploy"
    fi
    install -d -m 0700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
    install -m 0600 -o "$DEPLOY_USER" -g "$DEPLOY_USER" \
            /root/.ssh/authorized_keys "/home/$DEPLOY_USER/.ssh/authorized_keys"
    log "installed authorized_keys at /home/$DEPLOY_USER/.ssh/authorized_keys"
}

# ─── 3. Sudoers — scoped to ops work only ──────────────────────────────────
write_sudoers() {
    local target=/etc/sudoers.d/40-darkwatch-deploy
    cat > /tmp/sudoers-deploy <<EOF
# Managed by DarkWatch ops/harden-phase2.sh — do not edit by hand.
# Scoped sudo for the deploy user so ops scripts and docker commands work
# without giving full root.

# Ops scripts in the repo. Note: deploy.sh, harden.sh, etc. are scripts
# we control; they're trusted. If you add new scripts, they're covered.
${DEPLOY_USER} ALL=(root) NOPASSWD: ${DARKWEBAPP_REPO}/ops/*.sh

# Git pull / fetch only — operator can update the repo without sudo
# everywhere else. -C scopes the operation to the repo dir.
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/git -C ${DARKWEBAPP_REPO} pull *
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/git -C ${DARKWEBAPP_REPO} pull
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/git -C ${DARKWEBAPP_REPO} fetch *
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/git -C ${DARKWEBAPP_REPO} fetch
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/git -C ${DARKWEBAPP_REPO} status
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/git -C ${DARKWEBAPP_REPO} log *

# Read-only inspection of operator state (env file is 0600 root)
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/cat /var/lib/darkwebapp/env
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/grep * /var/lib/darkwebapp/env
EOF
    visudo -cf /tmp/sudoers-deploy >/dev/null \
        || fail "sudoers syntax invalid — refusing to install"
    install -m 0440 -o root -g root /tmp/sudoers-deploy "$target"
    rm -f /tmp/sudoers-deploy
    log "installed scoped sudoers at $target"
}

# ─── 4. Lock root SSH ──────────────────────────────────────────────────────
# Why this is more careful than it looks:
#
# 1. We edit /etc/ssh/sshd_config DIRECTLY (not via a drop-in). Some
#    distros don't have an Include directive that auto-loads files in
#    /etc/ssh/sshd_config.d/, so a drop-in is silent dead-weight on those
#    boxes. Editing the main file always works.
#
# 2. We schedule a `systemd-run --on-active=2min` self-cancelling rollback
#    that restores the backup if anything goes wrong. If the operator
#    can't SSH in within 2 min to confirm, they automatically get their
#    old config back instead of being locked out.
#
# This was learned the hard way: a previous version of this script reloaded
# sshd without a rollback timer, the service failed to come up, and the
# operator had to recover via console.
lock_root_ssh() {
    if ! id "$DEPLOY_USER" >/dev/null 2>&1; then
        fail "user '$DEPLOY_USER' doesn't exist — run --create first"
    fi
    if [[ ! -f /home/$DEPLOY_USER/.ssh/authorized_keys ]]; then
        fail "/home/$DEPLOY_USER/.ssh/authorized_keys missing — won't lock root SSH without a verified replacement path"
    fi

    local CFG=/etc/ssh/sshd_config
    local STAMP="$(date +%s)"
    local BAK="${CFG}.bak.${STAMP}"

    log "backing up $CFG → $BAK"
    cp "$CFG" "$BAK"

    log "editing $CFG: PermitRootLogin yes → PermitRootLogin no"
    if grep -qE "^PermitRootLogin " "$CFG"; then
        sed -i 's|^PermitRootLogin .*|PermitRootLogin no|' "$CFG"
    else
        echo "PermitRootLogin no" >> "$CFG"
    fi

    log "validating new config"
    sshd -t || { cp "$BAK" "$CFG"; fail "sshd config invalid — reverted from backup"; }

    log "scheduling 2-min auto-rollback (cancel manually after verifying access)"
    # If anything goes wrong, this restores the backup and restarts sshd.
    # Cancel manually with: systemctl stop sshd-rollback.timer
    cat > /tmp/sshd-rollback.sh <<EOF
#!/bin/bash
cp "$BAK" "$CFG"
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
EOF
    chmod 0700 /tmp/sshd-rollback.sh
    systemd-run --on-active=2min --unit=sshd-rollback /tmp/sshd-rollback.sh

    log "reloading sshd"
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null

    log ""
    log "  ════════════════════════════════════════════════════════════════"
    log "  ROOT SSH LOCK applied. AUTO-ROLLBACK in 2 min if not cancelled."
    log ""
    log "  From a SECOND machine, verify deploy SSH works:"
    log "    ssh ${DEPLOY_USER}@<vm> -p ${SSH_PORT} 'date'"
    log ""
    log "  If that succeeds, cancel the auto-rollback NOW:"
    log "    sudo systemctl stop sshd-rollback.timer"
    log ""
    log "  If it fails / you're locked out, do nothing — the timer reverts."
    log "  ════════════════════════════════════════════════════════════════"
}

# ─── Main dispatch ─────────────────────────────────────────────────────────
case "$MODE" in
    check)
        log "(check mode) would do:"
        log "  1. create user '$DEPLOY_USER' (or skip if exists)"
        log "  2. add '$DEPLOY_USER' to docker group"
        log "  3. copy /root/.ssh/authorized_keys → /home/$DEPLOY_USER/.ssh/authorized_keys"
        log "  4. write scoped sudoers at /etc/sudoers.d/40-darkwatch-deploy"
        log "  5. (if --lock-root or --apply) PermitRootLogin no in sshd drop-in"
        ;;
    create)
        create_deploy_user
        provision_ssh_keys
        write_sudoers
        log ""
        log "deploy user ready. Verify SSH from another machine BEFORE locking root:"
        log "    ssh ${DEPLOY_USER}@<vm> -p ${SSH_PORT}"
        log "Once verified, run:"
        log "    sudo ./ops/harden-phase2.sh --lock-root"
        ;;
    lock)
        lock_root_ssh
        ;;
    apply)
        create_deploy_user
        provision_ssh_keys
        write_sudoers
        log ""
        log "deploy user ready. Locking root SSH next."
        lock_root_ssh
        ;;
esac

log "phase2 ($MODE) complete."
