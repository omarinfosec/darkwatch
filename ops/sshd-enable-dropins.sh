#!/usr/bin/env bash
# DarkWatch — make sshd actually load /etc/ssh/sshd_config.d/*.conf
#
# Some VMs (this one's an example) ship a default /etc/ssh/sshd_config that
# does NOT have an `Include /etc/ssh/sshd_config.d/*.conf` directive. The
# result: drop-in config files in /etc/ssh/sshd_config.d/ are silently
# ignored. Anything `harden.sh` thought it had set via the drop-in
# (PasswordAuthentication=no, MaxAuthTries=3, X11Forwarding=no, etc.) has
# never actually been in effect.
#
# This script adds the Include directive at the top of main sshd_config so
# the existing 99-darkwatch-hardening.conf drop-in starts applying. To
# survive a bad config, it schedules a systemd-run auto-rollback timer
# that restores the backup in 2 min unless cancelled.
#
# Critically, this script first STRIPS `PermitRootLogin no` from the
# drop-in (so this change alone doesn't lock root out). The root-SSH-lock
# step is separate (see ops/harden-phase2.sh --lock-root).
#
# Usage on the VM:
#   sudo ./ops/sshd-enable-dropins.sh --check    # preview only
#   sudo ./ops/sshd-enable-dropins.sh --apply    # do it (with rollback timer)

set -euo pipefail

CFG=/etc/ssh/sshd_config
DROPIN=/etc/ssh/sshd_config.d/99-darkwatch-hardening.conf
INCLUDE_LINE='Include /etc/ssh/sshd_config.d/*.conf'

MODE=""
case "${1:-}" in
    --check) MODE=check ;;
    --apply) MODE=apply ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "usage: $0 --check | --apply" >&2; exit 2 ;;
esac

log()  { printf '\033[1;36m[sshd-fix]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[sshd-fix WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[sshd-fix ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "must run as root"

# ─── Pre-flight ─────────────────────────────────────────────────────────────
if grep -qE "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d" "$CFG"; then
    log "Include directive already present — drop-ins are loading. Nothing to do."
    log "current effective sshd config (relevant directives):"
    sshd -T | grep -iE 'permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|allowtcpforwarding|kbdinteractive' | sed 's/^/  /'
    exit 0
fi

if [[ ! -f "$DROPIN" ]]; then
    warn "drop-in $DROPIN does not exist — adding Include without it is harmless but pointless"
fi

log "current effective sshd config (BEFORE the change):"
sshd -T | grep -iE 'permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|allowtcpforwarding|kbdinteractive' | sed 's/^/  /'

if [[ "$MODE" == check ]]; then
    log ""
    log "(check) would do:"
    log "  1. backup $CFG → $CFG.bak.<ts>"
    log "  2. strip 'PermitRootLogin no' from $DROPIN (root lock is a separate step)"
    log "  3. insert '$INCLUDE_LINE' at line 1 of $CFG"
    log "  4. sshd -t → validate"
    log "  5. systemd-run --on-active=2min sshd-rollback → restore backup if not cancelled"
    log "  6. systemctl reload ssh"
    log "  7. operator verifies access from another machine, then:"
    log "       sudo systemctl stop sshd-rollback.timer"
    exit 0
fi

# ─── Apply mode ─────────────────────────────────────────────────────────────
STAMP="$(date +%s)"
BAK_CFG="${CFG}.bak.${STAMP}"
BAK_DROPIN="${DROPIN}.bak.${STAMP}"

log "1. backup main config → $BAK_CFG"
cp "$CFG" "$BAK_CFG"

if [[ -f "$DROPIN" ]] && grep -qE "^[[:space:]]*PermitRootLogin" "$DROPIN"; then
    log "2. backup + strip PermitRootLogin from $DROPIN (deferred to --lock-root)"
    cp "$DROPIN" "$BAK_DROPIN"
    sed -i "/^[[:space:]]*PermitRootLogin/d" "$DROPIN"
fi

log "3. inserting Include directive at line 1 of $CFG"
sed -i "1i ${INCLUDE_LINE}" "$CFG"

log "4. validating new config"
if ! sshd -t 2>/tmp/sshd-validate.err; then
    warn "sshd -t failed; reverting"
    cp "$BAK_CFG" "$CFG"
    [[ -f "$BAK_DROPIN" ]] && cp "$BAK_DROPIN" "$DROPIN"
    cat /tmp/sshd-validate.err >&2
    fail "config invalid; reverted from backup"
fi

log "5. scheduling 2-min auto-rollback"
cat > /tmp/sshd-rollback.sh <<EOF
#!/bin/bash
# Auto-restore the sshd config to the pre-change state.
cp "$BAK_CFG" "$CFG"
[[ -f "$BAK_DROPIN" ]] && cp "$BAK_DROPIN" "$DROPIN"
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
EOF
chmod 0700 /tmp/sshd-rollback.sh
systemd-run --on-active=2min --unit=sshd-rollback /tmp/sshd-rollback.sh

log "6. reloading sshd"
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null

log ""
log "  ════════════════════════════════════════════════════════════════"
log "  sshd reloaded. Auto-rollback in 2 min if NOT cancelled."
log ""
log "  From a second shell / machine, verify SSH still works:"
log "      ssh -p 6245 deploy@<vm> 'date'"
log "      ssh -p 6245 root@<vm>   'date'"
log ""
log "  Effective config now:"
sshd -T | grep -iE 'permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|allowtcpforwarding|kbdinteractive' | sed 's/^/      /'
log ""
log "  If access works → cancel rollback NOW:"
log "      sudo systemctl stop sshd-rollback.timer"
log ""
log "  If access broke → do nothing, the timer reverts in <2 min"
log "  ════════════════════════════════════════════════════════════════"
