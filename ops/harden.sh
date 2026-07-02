#!/usr/bin/env bash
# DarkWatch — baseline VM hardening
# Idempotent. Re-run after any compose change to re-validate port bindings.
#
#   sudo ./ops/harden.sh [--dry-run]
#
# Implements baseline VM hardening:
#   - UFW default-deny + allow SSH + WG outbound
#   - fail2ban sshd jail (ssh on 6245)
#   - disable CUPS
#   - PostgreSQL bind to 127.0.0.1
#   - sshd: PasswordAuthentication no, PubkeyAuthentication yes
#   - unattended-upgrades for security

set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

log()  { printf '\033[1;36m[harden]\033[0m %s\n' "$*"; }
run()  { if (( DRY_RUN )); then echo "  DRY: $*"; else eval "$@"; fi; }
warn() { printf '\033[1;33m[harden WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[harden ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "must run as root"

SSH_PORT="${SSH_PORT:-6245}"

# ─── 1. UFW ──────────────────────────────────────────────────────────────────
log "installing ufw fail2ban unattended-upgrades"
run "apt-get update -qq"
run "DEBIAN_FRONTEND=noninteractive apt-get install -yqq ufw fail2ban unattended-upgrades sqlite3"

log "configuring UFW"
run "ufw --force reset"
run "ufw default deny incoming"
run "ufw default allow outgoing"
run "ufw allow ${SSH_PORT}/tcp comment 'sshd'"
# WireGuard outbound (egress)
run "ufw allow out 51820/udp comment 'wireguard egress'"
# Docker NAT to internet egress (containers need DNS + outbound)
# Note: Docker manages its own iptables; UFW interaction can be quirky.
# We use ufw-docker pattern: only the host IP+port bindings matter.
run "ufw --force enable"

# ─── 2. fail2ban (sshd on custom port) ──────────────────────────────────────
log "configuring fail2ban for sshd on port ${SSH_PORT}"
cat > /tmp/jail-sshd.conf <<EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
backend  = systemd
maxretry = 3
findtime = 600
bantime  = 3600
EOF
if (( ! DRY_RUN )); then
    install -m 0644 /tmp/jail-sshd.conf /etc/fail2ban/jail.d/sshd-custom.conf
    rm -f /tmp/jail-sshd.conf
    systemctl enable --now fail2ban
    systemctl restart fail2ban
fi

# ─── 3. CUPS off ─────────────────────────────────────────────────────────────
log "disabling CUPS (no need for printing on a headless server)"
run "systemctl disable --now cups cups-browsed 2>/dev/null || true"

# ─── 4. sshd config ──────────────────────────────────────────────────────────
# This is the part of the script that has the most "I broke SSH and locked
# myself out" failure mode, so it's defensive on three axes:
#
#   1. We write the directives to a drop-in (99-darkwatch-hardening.conf)
#      so they're easy to read, diff, and revert with a single rm.
#   2. We DETECT whether main /etc/ssh/sshd_config has an `Include` for
#      the drop-in directory. If it doesn't, the drop-in is dead weight —
#      sshd will silently ignore everything we write there. This was a
#      real failure on one VM during initial deploy. We add the Include
#      directive automatically (with backup + rollback safety).
#   3. Before reloading sshd, we schedule a 2-minute systemd-run timer
#      that auto-restores the previous config if not cancelled. Operator
#      verifies SSH still works from a second shell, then cancels the
#      timer. If the new config locks them out, the auto-revert fires and
#      they don't lose access.
log "tightening sshd config"
SSHD_DROPIN=/etc/ssh/sshd_config.d/99-darkwatch-hardening.conf
SSHD_MAIN=/etc/ssh/sshd_config

cat > /tmp/sshd-darkwatch.conf <<EOF
# Managed by DarkWatch ops/harden.sh
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
LoginGraceTime 30s
EOF

if (( ! DRY_RUN )); then
    install -m 0644 /tmp/sshd-darkwatch.conf "$SSHD_DROPIN"
    rm -f /tmp/sshd-darkwatch.conf

    # Check whether main sshd_config has an Include directive that would
    # actually cause our drop-in to be loaded.
    if grep -qE "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d" "$SSHD_MAIN"; then
        log "  Include directive present in $SSHD_MAIN — drop-in will load"
    else
        log "  no Include directive in $SSHD_MAIN — adding it (drop-in won't load otherwise)"
        STAMP="$(date +%s)"
        BAK_MAIN="${SSHD_MAIN}.bak.${STAMP}"
        cp "$SSHD_MAIN" "$BAK_MAIN"
        sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" "$SSHD_MAIN"

        # Validate before scheduling reload
        sshd -t || {
            warn "sshd config invalid after adding Include; reverting"
            cp "$BAK_MAIN" "$SSHD_MAIN"
            rm -f "$SSHD_DROPIN"
            fail "sshd validation failed; rolled back"
        }

        # Schedule auto-rollback in case the reload + new config break
        # SSH access in a way the validator didn't catch.
        cat > /tmp/sshd-rollback.sh <<EOF
#!/bin/bash
cp "$BAK_MAIN" "$SSHD_MAIN"
rm -f "$SSHD_DROPIN"
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
EOF
        chmod 0700 /tmp/sshd-rollback.sh
        systemd-run --on-active=2min --unit=sshd-rollback /tmp/sshd-rollback.sh
        warn "  scheduled 2-min auto-rollback. AFTER this returns, verify SSH from"
        warn "  a SECOND machine, then cancel: sudo systemctl stop sshd-rollback.timer"
    fi

    # Validate the combined config one more time (dropin + main)
    sshd -t || fail "sshd config invalid after applying hardening drop-in"
    systemctl reload ssh || systemctl reload sshd || warn "could not reload sshd"

    # Confirm directives are actually in effect — sshd -T reflects the
    # parsed runtime config. If a directive we set isn't here, something
    # upstream of our drop-in is overriding it (e.g., main config has
    # PermitRootLogin yes). Surface that loudly.
    log "  effective sshd config (sample of what we just set):"
    sshd -T 2>/dev/null | grep -iE 'passwordauthentication|maxauthtries|x11forwarding|allowtcpforwarding|kbdinteractive' | sed 's/^/    /'
    eff_pwauth=$(sshd -T 2>/dev/null | awk '/passwordauthentication/{print $2}')
    if [[ "$eff_pwauth" != "no" ]]; then
        warn "  PasswordAuthentication is '$eff_pwauth', expected 'no'"
        warn "  Likely cause: main $SSHD_MAIN has 'PasswordAuthentication yes' overriding our drop-in"
        warn "  Fix: edit $SSHD_MAIN to comment out the conflicting line, then re-run this script"
    fi
fi

# ─── 5. PostgreSQL bind to 127.0.0.1 ────────────────────────────────────────
log "checking PostgreSQL bind address"
PG_CONFS="$(find /etc/postgresql -name 'postgresql.conf' 2>/dev/null || true)"
for conf in $PG_CONFS; do
    log "  $conf"
    if (( DRY_RUN )); then
        echo "  DRY: would set listen_addresses = 'localhost' in $conf"
    else
        sed -i.bak -E "s/^[# ]*listen_addresses\s*=.*/listen_addresses = 'localhost'/" "$conf"
        # If the directive isn't present at all, append it
        grep -qE "^listen_addresses" "$conf" || echo "listen_addresses = 'localhost'" >> "$conf"
    fi
done
if [[ -n "$PG_CONFS" ]] && (( ! DRY_RUN )); then
    systemctl restart postgresql || warn "postgres restart failed; check manually"
fi

# ─── 6. unattended-upgrades for security ────────────────────────────────────
log "enabling unattended security upgrades"
cat > /tmp/50unattended-darkwatch <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF
if (( ! DRY_RUN )); then
    install -m 0644 /tmp/50unattended-darkwatch /etc/apt/apt.conf.d/52darkwatch-security
    rm -f /tmp/50unattended-darkwatch
    systemctl enable --now unattended-upgrades
fi

# ─── 7. Sanity report ────────────────────────────────────────────────────────
log "hardening done. Current state:"
ufw status verbose | head -20
echo ""
systemctl is-active fail2ban && echo "fail2ban: active" || echo "fail2ban: NOT active"
systemctl is-active cups 2>/dev/null && echo "cups: STILL active (problem)" || echo "cups: disabled"
echo ""
log "remaining manual items (Phase 2):"
log "  - create non-root 'deploy' user with sudoers scope"
log "  - disable PermitRootLogin in sshd"
log "  - LUKS-encrypt /var/lib/darkwebapp (if disk theft is a concern)"
log "  - restrict dashboard bind IP and SSH access to operator networks only"
