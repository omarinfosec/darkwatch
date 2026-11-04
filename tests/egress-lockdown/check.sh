#!/usr/bin/env bash
# Exercise ops/egress-lockdown.sh against real iptables in a throwaway
# network namespace, with a temp data root and docker stubbed out.
# Needs: unshare (user + net namespaces), iptables.
#   bash tests/egress-lockdown/check.sh
#   UNSHARE="sudo unshare -n" bash tests/egress-lockdown/check.sh   # CI
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# Re-run inside a fresh network namespace: its own, empty iptables.
if [[ -z "${DW_LOCKDOWN_NS:-}" ]]; then
    # CI runners block unprivileged user namespaces: UNSHARE="sudo unshare -n".
    unshare_cmd=(${UNSHARE:-unshare -rn})
    exec "${unshare_cmd[@]}" env DW_LOCKDOWN_NS=1 PATH="$PATH" bash "${BASH_SOURCE[0]}"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0
ok()  { echo "ok   $*"; pass=$((pass + 1)); }
die() { echo "FAIL $*" >&2; [[ -f "$work/out" ]] && sed 's/^/    | /' "$work/out" >&2
        iptables -S DOCKER-USER 2>&1 | sed 's/^/    iptables: /' >&2; exit 1; }

# docker stub: the IPv6 check's `network inspect` (STUB_V6 unset = no network).
mkdir -p "$work/bin" "$work/data"
cat > "$work/bin/docker" <<'EOF'
#!/bin/sh
echo "docker $*" >> "$DOCKER_LOG"
[ -n "${STUB_V6:-}" ] || exit 1
echo "$STUB_V6"
EOF
chmod 755 "$work/bin/docker"
export PATH="$work/bin:$PATH" DOCKER_LOG="$work/docker.log"
export DARKWEBAPP_DATA_ROOT="$work/data"
: > "$work/data/env"

lockdown() {   # args go to egress-lockdown.sh; sets rc, output in $work/out
    : > "$DOCKER_LOG"
    set +e
    "$repo/ops/egress-lockdown.sh" "$@" > "$work/out" 2>&1
    rc=$?
    set -e
}
spec() {   # the full rule, as egress-lockdown.sh builds it
    echo "-s $1/32 ! -d $2 -m conntrack ! --ctstate RELATED,ESTABLISHED -m comment --comment darkwatch-egress-lockdown -j DROP"
}
rules() { iptables -S DOCKER-USER 2>/dev/null | grep -c -- '--comment darkwatch-egress-lockdown' || true; }
DEFAULT="$(spec 172.31.250.250 172.31.250.0/24)"

# ─── apply (twice) ──────────────────────────────────────────────────────────
iptables -S DOCKER-USER >/dev/null 2>&1 && die "fixture: namespace already has DOCKER-USER"
lockdown
[[ $rc -eq 0 ]] || die "first apply exited $rc"
iptables -A DOCKER-USER -j RETURN   # what Docker appends; must survive
lockdown
[[ $rc -eq 0 ]] || die "second apply exited $rc"
[[ "$(rules)" == 1 ]] || die "two applies must leave exactly one rule (got $(rules))"
# shellcheck disable=SC2086  # the spec is a list of iptables words
iptables -C DOCKER-USER $DEFAULT || die "rule does not match the full spec"
[[ "$(iptables -S DOCKER-USER | sed -n 2p)" == "-A DOCKER-USER $DEFAULT" ]] || die "rule must be first in DOCKER-USER"
iptables -C DOCKER-USER -j RETURN || die "other DOCKER-USER rules must be kept"
ok "creates DOCKER-USER when missing; two applies leave one rule, first, matching the full spec"

lockdown --status
[[ $rc -eq 0 ]] && grep -qxF -- "-A DOCKER-USER $DEFAULT" "$work/out" || die "--status must print the rule"
ok "--status prints the rule"

# ─── remove and the off switch ──────────────────────────────────────────────
lockdown --remove
[[ $rc -eq 0 && "$(rules)" == 0 ]] || die "--remove must leave 0 rules"
iptables -C DOCKER-USER -j RETURN || die "--remove must keep other rules"
lockdown --status
grep -q "not active" "$work/out" || die "--status after --remove must say 'not active'"
ok "--remove leaves 0 rules (others kept); --status says so"

lockdown; [[ "$(rules)" == 1 ]] || die "re-apply failed"
echo "DARKWATCH_EGRESS_LOCKDOWN=0" > "$work/data/env"
lockdown
[[ $rc -eq 0 && "$(rules)" == 0 ]] || die "LOCKDOWN=0 in the env file must remove the rule"
: > "$work/data/env"
lockdown; [[ "$(rules)" == 1 ]] || die "re-apply failed"
DARKWATCH_EGRESS_LOCKDOWN=0 lockdown
[[ $rc -eq 0 && "$(rules)" == 0 ]] || die "LOCKDOWN=0 in the environment must remove the rule"
ok "DARKWATCH_EGRESS_LOCKDOWN=0 (env file or environment) removes the rule"

# ─── custom subnet and address ──────────────────────────────────────────────
lockdown
printf 'DARKNET_SUBNET=10.99.7.0/24\nDARKWATCH_IP=10.99.7.9\n' > "$work/data/env"
lockdown
[[ $rc -eq 0 && "$(rules)" == 1 ]] || die "custom values: want exactly one rule (got $(rules))"
# shellcheck disable=SC2046
iptables -C DOCKER-USER $(spec 10.99.7.9 10.99.7.0/24) || die "custom DARKNET_SUBNET/DARKWATCH_IP not in the rule"
lockdown --status
grep -qF -- "-s 10.99.7.9/32 ! -d 10.99.7.0/24" "$work/out" || die "--status must show the custom values"
: > "$work/data/env"
ok "custom DARKNET_SUBNET / DARKWATCH_IP show up in the rule (and replace the old one)"

# ─── IPv6 on darknet: warn, never fail ──────────────────────────────────────
lockdown
[[ $rc -eq 0 ]] && ! grep -q WARNING "$work/out" || die "missing network: no warning, rc 0"
grep -q 'network inspect darkwatch_darknet' "$DOCKER_LOG" || die "apply must check the network"
STUB_V6=false lockdown
[[ $rc -eq 0 ]] && ! grep -q WARNING "$work/out" || die "IPv4-only network: no warning, rc 0"
STUB_V6=true lockdown
[[ $rc -eq 0 && "$(rules)" == 1 ]] || die "IPv6 network: apply must still succeed"
grep -q "WARNING: the darkwatch_darknet network has IPv6 enabled" "$work/out" || die "IPv6 network: apply must warn"
STUB_V6=true lockdown --status
[[ $rc -eq 0 ]] && grep -q "has IPv6 enabled" "$work/out" || die "IPv6 network: --status must warn"
STUB_V6=true lockdown --boot
[[ $rc -eq 0 && "$(rules)" == 1 ]] || die "--boot must apply the rule"
[[ ! -s "$DOCKER_LOG" ]] || die "--boot must not call docker (the unit runs before docker.service)"
ok "IPv6 on darknet warns (apply, --status) without failing; no network is fine; --boot skips docker"

echo "egress lockdown checks OK ($pass)"
