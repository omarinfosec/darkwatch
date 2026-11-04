#!/usr/bin/env bash
# Exercise ops/deploy.sh and ops/bootstrap.sh against a throwaway copy of
# ops/ with docker, systemctl, iptables, curl, egress-lockdown.sh and
# verify-egress.sh stubbed out. Every docker, systemctl, iptables and lockdown
# call is recorded in one log, in order, so the checks can assert what deploy
# would have run and when. Needs root (bootstrap chowns to uid 999):
#   sudo bash tests/ops/check.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root: sudo bash $0" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
ok()   { echo "ok   $*"; pass=$((pass + 1)); }
die()  { echo "FAIL $*" >&2; [[ -f "$work/out" ]] && sed 's/^/    | /' "$work/out" >&2; exit 1; }

# ─── Stubs ──────────────────────────────────────────────────────────────────
mkdir -p "$work/bin"
cat > "$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_LOG"
case "$1" in
    inspect)
        case "$3" in
            *Health*)  echo healthy ;;
            *Running*) [[ "$4" == setup && -n "${STUB_SETUP_STATE:-}" ]] || exit 1
                       echo "$STUB_SETUP_STATE" ;;
        esac ;;
    network) [[ -n "${STUB_HAVE_SUBNET:-}" ]] || exit 1
             case "$*" in
                 *Labels*)     echo "${STUB_NET_LABEL-true}" ;;
                 *EnableIPv6*) echo false ;;
                 *)            echo "$STUB_HAVE_SUBNET" ;;
             esac ;;
    compose) [[ -n "${STUB_SETUP_UP_FAILS:-}" && "$*" == *"up -d --no-deps setup"* ]] && exit 1 ;;
    # The direct-egress probe: blocked (curl's timeout) unless STUB_DW_EGRESS.
    exec)    [[ -n "${STUB_DW_EGRESS:-}" ]] || exit 28 ;;
esac
exit 0
EOF
printf '#!/bin/sh\necho "systemctl $*" >> "$DOCKER_LOG"\n' > "$work/bin/systemctl"
cat > "$work/bin/iptables" <<'EOF'
#!/usr/bin/env bash
echo "iptables $*" >> "$DOCKER_LOG"
[[ "$*" == "-C FORWARD -j DOCKER-USER" && -n "${STUB_NO_FORWARD_JUMP:-}" ]] && exit 1
exit 0
EOF
# No root crontab; writing one would be a bug here (the retention cron goes
# to DW_CRON_DIR and the legacy-line cleanup has nothing to remove).
printf '#!/bin/sh\n[ "$1" = -l ] || echo "crontab $*" >> "$DOCKER_LOG"\nexit 1\n' > "$work/bin/crontab"
# The host side of the probe (positive control): online unless STUB_HOST_OFFLINE.
printf '#!/bin/sh\n[ -z "$STUB_HOST_OFFLINE" ] || exit 28\n' > "$work/bin/curl"
chmod 755 "$work/bin/docker" "$work/bin/systemctl" "$work/bin/iptables" "$work/bin/curl" "$work/bin/crontab"
export PATH="$work/bin:$PATH" DOCKER_LOG="$work/docker.log"

# A fresh tree per case: ops/ (lockdown + verify stubbed), .env.example and
# the kill switch (deploy checks its exec bit). No .git, so no pull/clean
# check (the self-update case at the end makes its own checkout).
new_tree() {
    T="$work/case$((++case_n))"
    mkdir -p "$T/repo/tunnels/killswitch" "$T/units" "$T/cron.d"
    cp -a "$repo/ops" "$repo/.env.example" "$T/repo/"
    cp -a "$repo/tunnels/killswitch/10-killswitch.sh" "$T/repo/tunnels/killswitch/"
    printf '#!/bin/sh\necho "lockdown stub"\necho "lockdown-stub $*" >> "$DOCKER_LOG"\n' > "$T/repo/ops/egress-lockdown.sh"
    printf '#!/bin/sh\necho "verify stub $*"\n' > "$T/repo/ops/verify-egress.sh"
    D="$T/data"
    : > "$DOCKER_LOG"
    unset STUB_SETUP_STATE STUB_HAVE_SUBNET STUB_SETUP_UP_FAILS STUB_NET_LABEL \
          STUB_DW_EGRESS STUB_HOST_OFFLINE STUB_NO_FORWARD_JUMP DARKWATCH_EGRESS_LOCKDOWN DARKWATCH_DNS
}
real_lockdown() { cp -a "$repo/ops/egress-lockdown.sh" "$T/repo/ops/"; }   # iptables stays stubbed
case_n=0

# Bootstrap the data root and fill the required values (as an operator would).
# .env.example leaves DARKNET_SUBNET / DARKWATCH_IP commented out.
seed() {
    DARKWEBAPP_DATA_ROOT="$D" "$T/repo/ops/bootstrap.sh" > "$work/out" 2>&1 || die "bootstrap failed"
    sed -i -e "s|^DARKWEBAPP_DATA_ROOT=.*|DARKWEBAPP_DATA_ROOT=$D|" \
           -e "s|^TOR_CONTROL_PASSWORD=.*|TOR_CONTROL_PASSWORD=testpw|" "$D/env"
}

deploy() {   # extra args are passed to deploy.sh; sets rc
    : > "$DOCKER_LOG"
    set +e
    DARKWEBAPP_DATA_ROOT="$D" DW_SYSTEMD_UNIT_DIR="$T/units" DW_CRON_DIR="$T/cron.d" \
        "$T/repo/ops/deploy.sh" --skip-pull "$@" > "$work/out" 2>&1
    rc=$?
    set -e
}
expect_ok()   { [[ $rc -eq 0 ]] || die "$1: deploy exited $rc"; grep -q "deploy complete" "$work/out" || die "$1: no 'deploy complete'"; }
expect_fail() { [[ $rc -ne 0 ]] || die "$1: deploy should have failed"; grep -qF -- "$2" "$work/out" || die "$1: missing message: $2"; }
no_compose()  { ! grep -q '^compose' "$DOCKER_LOG" || die "$1: docker compose ran before the check"; }

WG_KEY="$(printf 'A%.0s' {1..43})="
wg_conf() {   # $1 = tunnel number, rest = extra lines; full-tunnel by default
    local f="$D/secrets/tunnel$1/wg_confs/wg0.conf"; shift
    printf '[Interface]\nPrivateKey = %s\nAddress = 10.2.0.2/32\n%s\n[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\n' \
        "$WG_KEY" "$(printf '%s\n' "$@")" "$WG_KEY" > "$f"
    grep -qi '^AllowedIPs' "$f" || echo "AllowedIPs = 0.0.0.0/0, ::/0" >> "$f"
}

# ─── env_val (ops/lib/common.sh) ────────────────────────────────────────────
mkdir -p "$work/ev"
printf 'A=file\nA=last\nB=\n' > "$work/ev/env"
got="$(DATA_ROOT="$work/ev" A=proc B=proc C=proc bash -euo pipefail -c '
    source "$1"; env_val A d; env_val B d; env_val C d; env_val D d; env_val D ""; echo end' _ "$repo/ops/lib/common.sh")"
[[ "$got" == $'last\nproc\nproc\nd\n\nend' ]] || die "env_val: got $(printf %q "$got")"
ok "env_val: file (last wins), then environment, then default; safe under set -e"

# ─── bootstrap ──────────────────────────────────────────────────────────────
new_tree; seed
for d in "" /darkwatch /darkwatch/loot /darkwatch/data /darkwatch/investigations /darkwatch/yara-private; do
    want="700 999:999"; [[ -z "$d" ]] && want="700 0:0"
    [[ "$(stat -c '%a %u:%g' "$D$d")" == "$want" ]] || die "bootstrap: $D$d is $(stat -c '%a %u:%g' "$D$d"), want $want"
done
[[ "$(stat -c '%a %u:%g' "$D/config.d")" == "750 0:999" ]] || die "bootstrap: config.d is $(stat -c '%a %u:%g' "$D/config.d"), want 750 0:999"
[[ "$(stat -c %a "$D/env")" == 600 ]] || die "bootstrap: env not 0600"
[[ "$(readlink -f "$T/repo/.env")" == "$(readlink -f "$D/env")" ]] || die "bootstrap: .env link"
ok "bootstrap creates 0700 dirs (uid 999 for darkwatch/), a root-owned config.d and links .env"

rm "$T/repo/.env"; echo x > "$T/repo/.env"
set +e; DARKWEBAPP_DATA_ROOT="$D" "$T/repo/ops/bootstrap.sh" > "$work/out" 2>&1; rc=$?; set -e
[[ $rc -ne 0 ]] && grep -q "not a link to" "$work/out" || die "bootstrap: a copied .env must be an error"
ok "bootstrap fails on a .env that is not the link"

# A hand-set SETUP_AUTH_TOKEN under 32 characters is kept but warned about,
# by bootstrap and by deploy (upgrades don't re-run bootstrap). Never echoed.
new_tree; seed
grep -qE '^SETUP_AUTH_TOKEN=[0-9a-f]{64}$' "$D/env" || die "bootstrap: generated token is not 64 hex characters"
DARKWEBAPP_DATA_ROOT="$D" "$T/repo/ops/bootstrap.sh" > "$work/out" 2>&1 || die "bootstrap re-run failed"
grep -q "shorter than 32" "$work/out" && die "bootstrap: warned about a 64-character token"
deploy
expect_ok "64-character token"
grep -q "shorter than 32" "$work/out" && die "deploy: warned about a 64-character token"
short_tok="handset0123456789abcdefghijklmn"   # 31 characters
sed -i "s|^SETUP_AUTH_TOKEN=.*|SETUP_AUTH_TOKEN=$short_tok  |" "$D/env"
DARKWEBAPP_DATA_ROOT="$D" "$T/repo/ops/bootstrap.sh" > "$work/out" 2>&1 || die "bootstrap failed on a short token"
grep -q "SETUP_AUTH_TOKEN is shorter than 32 characters" "$work/out" || die "bootstrap: no warning for a short token"
grep -qF "$short_tok" "$work/out" && die "bootstrap: printed the token"
grep -qF "SETUP_AUTH_TOKEN=$short_tok" "$D/env" || die "bootstrap: replaced a hand-set token"
deploy
expect_ok "short token"
grep -q "SETUP_AUTH_TOKEN is shorter than 32 characters" "$work/out" || die "deploy: no warning for a short token"
grep -qF "$short_tok" "$work/out" && die "deploy: printed the token"
sed -i "s|^SETUP_AUTH_TOKEN=.*|SETUP_AUTH_TOKEN=${short_tok}x|" "$D/env"   # exactly 32
DARKWEBAPP_DATA_ROOT="$D" "$T/repo/ops/bootstrap.sh" > "$work/out" 2>&1 || die "bootstrap failed on a 32-character token"
grep -q "shorter than 32" "$work/out" && die "bootstrap: warned about a 32-character token"
ok "bootstrap and deploy warn about a SETUP_AUTH_TOKEN under 32 characters without printing it"

# The dashboard login (DARKWATCH_AUTH_TOKEN) is opt-in: deploy warns, without
# failing, when port 8080 is published beyond loopback with no token, and
# about a token under 32 characters. Never echoed.
new_tree; seed
deploy
expect_ok "loopback bind, no dashboard token"
grep -q "with no login\|DARKWATCH_AUTH_TOKEN" "$work/out" && die "deploy: dashboard auth warning on a loopback bind"
for bind in 10.8.0.5 0.0.0.0 "::"; do
    sed -i "s|^DARKWATCH_BIND_IP=.*|DARKWATCH_BIND_IP=$bind|" "$D/env"
    deploy
    expect_ok "bind $bind, no dashboard token"
    grep -qF "the dashboard is published on $bind:8080 with no login" "$work/out" || die "deploy: no warning for bind $bind without a token"
done
printf 'DARKWATCH_AUTH_TOKEN=\n' >> "$D/env"
deploy
grep -q "with no login" "$work/out" || die "deploy: an empty DARKWATCH_AUTH_TOKEN= line silenced the warning"
dash_tok="$(printf 'd%.0s' {1..64})"
printf 'DARKWATCH_AUTH_TOKEN="%s"\n' "$dash_tok" >> "$D/env"   # last line wins, quotes stripped
deploy
expect_ok "bind :: with a dashboard token"
grep -q "with no login\|DARKWATCH_AUTH_TOKEN" "$work/out" && die "deploy: warned although a 64-character dashboard token is set"
sed -i '/^DARKWATCH_AUTH_TOKEN=/d' "$D/env"
short_dash="dashtok0123456789abcdefghijklmn"   # 31 characters
printf 'DARKWATCH_AUTH_TOKEN=%s \n' "$short_dash" >> "$D/env"
sed -i "s|^DARKWATCH_BIND_IP=.*|DARKWATCH_BIND_IP=127.0.0.1|" "$D/env"
deploy
expect_ok "short dashboard token"
grep -q "DARKWATCH_AUTH_TOKEN is shorter than 32 characters" "$work/out" || die "deploy: no warning for a short dashboard token"
grep -qF "$short_dash" "$work/out" && die "deploy: printed the dashboard token"
ok "deploy warns about a dashboard published beyond loopback without DARKWATCH_AUTH_TOKEN, and about a short one"

# install.sh: binding the dashboard to the private IP offers to generate
# DARKWATCH_AUTH_TOKEN (default yes), warns when declined, and never prints it.
printf '#!/bin/sh\necho 10.8.0.5 192.0.2.7\n' > "$work/bin/hostname"; chmod 755 "$work/bin/hostname"
install() {   # $1 = answers on stdin, rest = extra flags; sets rc
    local answers="$1"; shift
    set +e
    printf '%b' "$answers" | DARKWEBAPP_DATA_ROOT="$D" DW_CRON_DIR="$T/cron.d" \
        "$T/repo/ops/install.sh" --skip-hardening --skip-deploy "$@" > "$work/out" 2>&1
    rc=$?
    set -e
    [[ $rc -eq 0 ]] || die "install.sh exited $rc"
}
dash_tok_of() { grep -E '^DARKWATCH_AUTH_TOKEN=' "$D/env" | tail -1 | cut -d= -f2- || true; }
new_tree; install 'y\ny\n'
grep -q '^DARKWATCH_BIND_IP=10.8.0.5$' "$D/env" || die "install: bind not set to the private IP"
tok="$(dash_tok_of)"
[[ "$tok" =~ ^[0-9a-f]{64}$ ]] || die "install: no 64-hex DARKWATCH_AUTH_TOKEN after answering yes"
grep -qF "$tok" "$work/out" && die "install: printed the dashboard token"
grep -q "sign in with DARKWATCH_AUTH_TOKEN" "$work/out" || die "install: no sign-in hint at the end"
deploy
grep -q "with no login\|DARKWATCH_AUTH_TOKEN" "$work/out" && die "deploy: warned after install generated a dashboard token"
new_tree; install 'y\nn\n'
[[ -z "$(dash_tok_of)" ]] || die "install: set DARKWATCH_AUTH_TOKEN although declined"
grep -q 'the dashboard has no login' "$work/out" || die "install: no warning when the dashboard token is declined"
grep -q 'README, "Dashboard login"' "$work/out" || die "install: the warning must point at README \"Dashboard login\""
new_tree; install '' --yes
[[ "$(dash_tok_of)" =~ ^[0-9a-f]{64}$ ]] || die "install --yes: no dashboard token with a non-loopback bind"
new_tree; install 'n\n'
grep -q '^DARKWATCH_BIND_IP=127.0.0.1$' "$D/env" || die "install: bind changed although declined"
[[ -z "$(dash_tok_of)" ]] || die "install: set DARKWATCH_AUTH_TOKEN on a loopback bind"
grep -q "DARKWATCH_AUTH_TOKEN" "$work/out" && die "install: asked about the dashboard token on a loopback bind"
rm "$work/bin/hostname"
ok "install.sh offers DARKWATCH_AUTH_TOKEN when it binds the dashboard beyond loopback"

# ─── default env (no DARKNET_SUBNET) reaches the end ────────────────────────
new_tree; seed
grep -q '^DARKNET_SUBNET=' "$D/env" && die "fixture: env should not set DARKNET_SUBNET"
deploy
expect_ok "env without DARKNET_SUBNET"
ok "env without DARKNET_SUBNET reaches 'deploy complete'"

grep -q '^compose' "$DOCKER_LOG" || die "no compose calls recorded"
if grep '^compose' "$DOCKER_LOG" | grep -vq -- "--env-file $D/env"; then
    grep '^compose' "$DOCKER_LOG" | grep -v -- "--env-file" >&2; die "compose call without --env-file"
fi
ok "every compose call passes --env-file"

build="$(grep '^compose.* build' "$DOCKER_LOG")" || die "no compose build"
[[ "$build" == *"--profile tor"* && "$build" == *"--profile setup"* ]] || die "build must include tor and setup: $build"
up="$(grep '^compose.* up -d --remove-orphans' "$DOCKER_LOG")" || die "no compose up"
[[ "$up" != *"--profile"* ]] || die "up must only use the detected profiles: $up"
grep -q '^compose.* pull' "$DOCKER_LOG" && ! grep '^compose.* pull' "$DOCKER_LOG" | grep -q -- --profile \
    || die "pull must only use the detected profiles"
ok "build covers tor + setup; pull and up use only the detected profiles"
grep -q -- ' down' "$DOCKER_LOG" && die "down ran without a subnet change"
unit="$T/units/darkwatch-egress-lockdown.service"
[[ -f "$unit" ]] || die "lockdown unit not installed"
ok "lockdown unit installed into DW_SYSTEMD_UNIT_DIR"

line_of() { grep -n -m1 -- "$1" "$DOCKER_LOG" | cut -d: -f1; }
up_at="$(line_of 'up -d --remove-orphans')"
[[ -n "$(line_of '^lockdown-stub')" && "$(line_of '^lockdown-stub')" -lt "$up_at" ]] \
    || die "the egress lockdown must be applied before compose up"
[[ -n "$(line_of '^systemctl reenable')" && "$(line_of '^systemctl reenable')" -lt "$up_at" ]] \
    || die "the lockdown unit must be installed before compose up"
ok "lockdown applied and its unit installed before compose up"

for want in "Before=docker.service" "After=firewalld.service ufw.service" "WantedBy=docker.service" \
            "ExecStart=$T/repo/ops/egress-lockdown.sh --boot"; do
    grep -qxF -- "$want" "$unit" || die "unit: missing '$want'"
done
grep -qE '^(Requires|After)=docker' "$unit" && die "unit must not require or follow docker.service"
grep -q '^systemctl reenable --quiet darkwatch-egress-lockdown.service' "$DOCKER_LOG" \
    || die "unit must be enabled with reenable"
ok "unit runs before docker.service, after the host firewalls, WantedBy=docker.service"

cron="$T/cron.d/darkwatch-retention"
[[ -f "$cron" ]] || die "retention cron not installed into DW_CRON_DIR"
grep -qx "DARKWEBAPP_DATA_ROOT=$D" "$cron" && grep -q " root /bin/bash $T/repo/ops/retention\.sh >> " "$cron" \
    || die "retention cron: $(cat "$cron")"
grep -q '^crontab' "$DOCKER_LOG" && die "deploy must not write a crontab when there is no legacy line"
ok "deploy installs the retention cron (cron.d, this checkout's retention.sh, this data root)"

[[ "$(grep -c '^TG_SOCKS_PASSWORD=' "$D/env")" == 1 ]] || die "TG_SOCKS_PASSWORD must appear once"
pw="$(grep '^TG_SOCKS_PASSWORD=' "$D/env" | cut -d= -f2-)"
[[ ${#pw} -ge 32 ]] || die "TG_SOCKS_PASSWORD not generated"
deploy
expect_ok "second deploy"
[[ "$(grep -c '^TG_SOCKS_PASSWORD=' "$D/env")" == 1 && "$(grep '^TG_SOCKS_PASSWORD=' "$D/env" | cut -d= -f2-)" == "$pw" ]] \
    || die "TG_SOCKS_PASSWORD changed on redeploy"
ok "TG_SOCKS_PASSWORD filled exactly once and kept"
grep -q '^systemctl' "$DOCKER_LOG" && die "an unchanged unit must not be rewritten or re-enabled"
ok "an unchanged unit is left alone on redeploy"

deploy --skip-build
expect_ok "--skip-build"
grep -q '^compose.* build' "$DOCKER_LOG" && die "--skip-build still built"
ok "--skip-build skips the build"

# An install from before v0.4.0 has no config.d: deploy re-runs bootstrap.
rmdir "$D/config.d"
deploy --skip-build
expect_ok "missing config.d"
[[ "$(stat -c '%a %u:%g' "$D/config.d")" == "750 0:999" ]] || die "deploy did not recreate config.d"
ok "deploy creates a missing config.d (via bootstrap)"

# ─── subnet migration and Setup UI refresh ──────────────────────────────────
STUB_HAVE_SUBNET=172.20.0.0/16 deploy
expect_ok "subnet change"
grep -q -- "^compose --env-file $D/env --profile tor --profile tg --profile setup down" "$DOCKER_LOG" \
    || die "subnet change must recreate the network"
STUB_HAVE_SUBNET=172.31.250.0/24 deploy
grep -q -- ' down' "$DOCKER_LOG" && die "down ran although the subnet matches the default"
ok "network recreated only when the subnet differs (default 172.31.250.0/24)"
STUB_HAVE_SUBNET=172.31.250.0/24 STUB_NET_LABEL="" deploy
expect_ok "pre-IPv4-only network"
grep -q -- "^compose --env-file $D/env --profile tor --profile tg --profile setup down" "$DOCKER_LOG" \
    || die "a network without the org.darkwatch.ipv4-only label must be recreated"
ok "a network from before enable_ipv6: false is recreated"

STUB_SETUP_STATE=true deploy
expect_ok "running setup"
grep -q -- "^compose --env-file $D/env --profile setup up -d --no-deps setup" "$DOCKER_LOG" \
    || die "a running Setup UI must be refreshed"
for state in false ""; do
    STUB_SETUP_STATE="$state" deploy
    expect_ok "stopped setup"
    grep -q 'up -d --no-deps setup' "$DOCKER_LOG" && die "a stopped/absent Setup UI must stay down"
done
ok "running Setup UI refreshed; stopped or absent one left alone"

STUB_SETUP_STATE=true STUB_SETUP_UP_FAILS=1 deploy
expect_ok "setup refresh fails"
grep -q "lockdown stub" "$work/out" || die "a failed Setup UI refresh must not skip the egress lockdown"
grep -q "could not refresh the Setup UI" "$work/out" || die "a failed Setup UI refresh must warn"
grep -q '^exec darkwatch curl' "$DOCKER_LOG" || die "a failed Setup UI refresh must not skip the egress probe"
ok "a failed Setup UI refresh only warns; lockdown and probe still run"

# ─── egress lockdown flag and the direct-egress probe ───────────────────────
# The real egress-lockdown.sh (iptables stubbed), so its iptables calls show.
# No tunnels are configured here: the probe must run anyway.
new_tree; seed; real_lockdown
echo "DARKWATCH_EGRESS_LOCKDOWN=0" >> "$D/env"
STUB_DW_EGRESS=1 deploy
expect_ok "LOCKDOWN=0 in env file, darkwatch connects"
grep -q 'iptables -I DOCKER-USER' "$DOCKER_LOG" && die "LOCKDOWN=0 (env file) must not insert the rule"
grep -q "egress lockdown is DISABLED" "$work/out" || die "LOCKDOWN=0 (env file) must warn"
ok "LOCKDOWN=0 in the env file: rule not inserted, warning, deploy completes"

new_tree; seed; real_lockdown
DARKWATCH_EGRESS_LOCKDOWN=0 STUB_DW_EGRESS=1 deploy
expect_ok "LOCKDOWN=0 in process env, darkwatch connects"
grep -q 'iptables -I DOCKER-USER' "$DOCKER_LOG" && die "LOCKDOWN=0 (process env) must not insert the rule"
grep -q "egress lockdown is DISABLED" "$work/out" || die "LOCKDOWN=0 (process env) must warn"
ok "LOCKDOWN=0 in the process environment only: same"

# With the lockdown off, darkwatch needs a real DARKWATCH_DNS to resolve
# clearnet names (direct alerts, the in-app IP-leak check).
grep -qF "DARKWATCH_DNS is unset" "$work/out" || die "LOCKDOWN=0 without DARKWATCH_DNS must warn"
new_tree; seed; real_lockdown
printf 'DARKWATCH_EGRESS_LOCKDOWN=0\nDARKWATCH_DNS=192.0.2.53\n' >> "$D/env"
STUB_DW_EGRESS=1 deploy
expect_ok "LOCKDOWN=0 with DARKWATCH_DNS"
grep -qF "DARKWATCH_DNS is unset" "$work/out" && die "LOCKDOWN=0 with DARKWATCH_DNS set must not warn about it"
ok "LOCKDOWN=0 warns about an unset DARKWATCH_DNS, and only then"

new_tree; seed; real_lockdown
STUB_DW_EGRESS=1 deploy
expect_fail "lockdown on, darkwatch connects" "darkwatch reached http://1.1.1.1 DIRECTLY"
grep -q 'deploy complete' "$work/out" && die "a leaking darkwatch must not reach 'deploy complete'"
ok "lockdown on and darkwatch connects directly: deploy fails"

deploy
expect_ok "lockdown on, darkwatch blocked"
ins_at="$(line_of '^iptables -I DOCKER-USER 1 -s 172.31.250.250 ! -d 172.31.250.0/24')"
[[ -n "$ins_at" && "$ins_at" -lt "$(line_of 'up -d --remove-orphans')" ]] || die "rule must be inserted before compose up"
grep -q '^exec darkwatch curl -s --max-time 5 -o /dev/null http://1.1.1.1' "$DOCKER_LOG" || die "probe did not run"
grep -q "darkwatch has no direct internet route" "$work/out" || die "blocked probe must be reported"
grep -q "inconclusive\|DOCKER-USER: the egress" "$work/out" && die "unexpected probe warning"
ok "lockdown on and darkwatch blocked: deploy completes"

STUB_HOST_OFFLINE=1 deploy
expect_ok "host offline"
grep -q "probe inconclusive" "$work/out" || die "host offline must make the probe inconclusive"
ok "host can't connect either: inconclusive warning only"

STUB_NO_FORWARD_JUMP=1 deploy
expect_ok "no FORWARD jump"
grep -q "FORWARD has no jump to DOCKER-USER" "$work/out" || die "missing FORWARD jump must warn"
ok "missing FORWARD -> DOCKER-USER jump warns"

# With the lockdown on, a real DARKWATCH_DNS is dropped and stalls lookups;
# deploy must fail on it itself (no tunnels here, so no verify-egress run).
new_tree; seed; real_lockdown
echo "DARKWATCH_DNS=9.9.9.9" >> "$D/env"
deploy
expect_fail "lockdown on with DARKWATCH_DNS" "DARKWATCH_DNS is set while the egress lockdown is on"
new_tree; seed; real_lockdown
DARKWATCH_DNS=9.9.9.9 deploy --no-egress-check
expect_fail "lockdown on with DARKWATCH_DNS (process env)" "DARKWATCH_DNS is set while the egress lockdown is on"
ok "lockdown on with a real DARKWATCH_DNS: deploy fails without the egress check"

# ─── env file pre-flight ────────────────────────────────────────────────────
new_tree; seed; rm "$D/env"
deploy
expect_fail "missing env" "env is missing"; no_compose "missing env"
new_tree; seed; chmod 644 "$D/env"
deploy
expect_fail "0644 env" "must be 0600"; no_compose "0644 env"
ok "missing or 0644 env file fails"

# ─── .env link pre-flight ───────────────────────────────────────────────────
new_tree; seed; ln -sfn "$T/elsewhere-env" "$T/repo/.env"; cp "$D/env" "$T/elsewhere-env"
deploy
expect_fail "wrong .env target" "is not a link to"; no_compose "wrong .env target"
new_tree; seed; ln -sfn "$T/nowhere/env" "$T/repo/.env"
deploy
expect_fail "dangling .env" "is not a link to"; no_compose "dangling .env"
new_tree; seed; rm "$T/repo/.env"; cp "$D/env" "$T/repo/.env"
deploy
expect_fail "copied .env" "is not a link to"; no_compose "copied .env"
ok "wrong, dangling or copied .env fails before any compose call"
new_tree; seed; rm "$T/repo/.env"
deploy
expect_ok "missing .env"
[[ -L "$T/repo/.env" && "$(readlink -f "$T/repo/.env")" == "$(readlink -f "$D/env")" ]] || die "missing .env not linked"
ok "missing .env gets linked"

# ─── kill switch exec bit ───────────────────────────────────────────────────
new_tree; seed; chmod 644 "$T/repo/tunnels/killswitch/10-killswitch.sh"
deploy
expect_fail "kill switch not executable" "10-killswitch.sh is not executable"; no_compose "kill switch"
ok "non-executable kill switch fails"

# ─── wg0.conf checks ────────────────────────────────────────────────────────
new_tree; seed
wg_conf 1; wg_conf 2 "Table = auto"
deploy
expect_ok "valid wg confs"
grep -q -- "--profile tor --profile tg up -d" "$DOCKER_LOG" || die "both tunnel profiles should be enabled"
grep -q "wg0.conf: " "$work/out" && die "valid wg confs should not warn"
ok "full-tunnel wg0.conf files (Table = auto) pass"

for bad in "Table = off|Table = off" "Table = 1234|Table = 1234" "FwMark = 0xca6c|FwMark = 0xca6c" \
           "fwmark = off|fwmark = off" "AllowedIPs = 10.0.0.0/8|no AllowedIPs includes 0.0.0.0/0" \
           "AllowedIPs = 10.0.0.0/0, ::/0|no AllowedIPs includes 0.0.0.0/0"; do
    new_tree; seed
    wg_conf 2 "${bad%%|*}"
    deploy
    expect_fail "wg: ${bad%%|*}" "${bad#*|}"; no_compose "wg: ${bad%%|*}"
done
new_tree; seed
printf '[Interface]\nPrivateKey = %s\n[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\n' "$WG_KEY" "$WG_KEY" \
    > "$D/secrets/tunnel1/wg_confs/wg0.conf"
deploy
expect_fail "wg: no AllowedIPs" "no AllowedIPs includes 0.0.0.0/0"
ok "Table other than auto, FwMark and split-tunnel AllowedIPs fail"

new_tree; seed
wg_conf 1 "PostUp = echo hi" "PreDown = echo bye" "# Table = off"
deploy
expect_ok "wg hooks"
grep -q "PostUp hook" "$work/out" && grep -q "PreDown hook" "$work/out" || die "hooks should warn"
ok "Pre/Post hooks only warn; commented-out lines are ignored"

# ─── self-update: a pull that changes deploy.sh restarts it once ────────────
# A git checkout at v1 pulls a v2 whose deploy.sh logs a marker. The rest of
# the deploy must come from v2, and v1 must stop at the restart.
new_tree
export GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1
git config --global user.name test; git config --global user.email test@example.invalid
git config --global init.defaultBranch main; git config --global safe.directory "*"  # CI: cp -a keeps the runner uid
mv "$T/repo" "$T/origin"
git -C "$T/origin" init -q && git -C "$T/origin" add -A && git -C "$T/origin" commit -qm v1
git clone -q "$T/origin" "$T/repo"
sed -i 's|^source "\$SCRIPT_DIR/lib/common.sh"$|&\nlog "deploy.sh v2 running (args: $*)"|' "$T/origin/ops/deploy.sh"
grep -q 'deploy.sh v2 running' "$T/origin/ops/deploy.sh" || die "fixture: v2 marker not inserted"
git -C "$T/origin" commit -qam v2
seed
self_deploy() {   # like deploy(), but lets deploy.sh pull
    : > "$DOCKER_LOG"
    set +e
    DARKWEBAPP_DATA_ROOT="$D" DW_SYSTEMD_UNIT_DIR="$T/units" DW_CRON_DIR="$T/cron.d" \
        "$T/repo/ops/deploy.sh" "$@" > "$work/out" 2>&1
    rc=$?
    set -e
}
self_deploy --skip-build
expect_ok "self-update"
[[ "$(git -C "$T/repo" rev-parse HEAD)" == "$(git -C "$T/origin" rev-parse HEAD)" ]] || die "self-update: repo not pulled"
grep -q "restarting the new deploy.sh" "$work/out" || die "self-update: no restart logged"
[[ "$(grep -c 'deploy.sh v2 running (args: --skip-pull --skip-build)' "$work/out")" == 1 ]] \
    || die "self-update: v2 must run exactly once, with --skip-pull and the original args"
[[ "$(grep -c 'pre-flight: verifying' "$work/out")" == 2 ]] || die "self-update: expected v1 + one v2 run"
[[ "$(grep -c 'deploy complete' "$work/out")" == 1 ]] || die "self-update: deploy completed more than once"
grep -q '^compose.* build' "$DOCKER_LOG" && die "self-update: --skip-build was not passed on"
[[ "$(grep -c '^compose.* up -d --remove-orphans' "$DOCKER_LOG")" == 1 ]] || die "self-update: compose up must run once"
ok "a pull that changes the code restarts the new deploy.sh once, with --skip-pull and the original args"

self_deploy
expect_ok "up-to-date pull"
grep -q "restarting" "$work/out" && die "up-to-date pull must not restart"
[[ "$(grep -c 'deploy.sh v2 running (args: )' "$work/out")" == 1 ]] || die "up-to-date pull: v2 must run once"
ok "a pull with no new commits does not restart"

# A pulled deploy.sh without the exec bit (core.fileMode=false, copied tree)
# must still restart: the restart runs it through bash.
sed -i 's|deploy.sh v2 running|deploy.sh v3 running|' "$T/origin/ops/deploy.sh"
chmod -x "$T/origin/ops/deploy.sh"
git -C "$T/origin" commit -qam v3
self_deploy --skip-build
expect_ok "self-update without exec bit"
[[ -x "$T/repo/ops/deploy.sh" ]] && die "fixture: pulled deploy.sh should not be executable"
[[ "$(grep -c 'deploy.sh v3 running (args: --skip-pull --skip-build)' "$work/out")" == 1 ]] \
    || die "self-update without exec bit: v3 must run exactly once"
ok "the restart does not need deploy.sh's exec bit"

# ─── dirty checkout: local config.json edits ────────────────────────────────
# Only darkwatch/config.json modified: deploy refuses and points at the
# override file. Any other dirty file: the plain message, no hint.
new_tree
mkdir -p "$T/repo/darkwatch"
cp -a "$repo/darkwatch/config.json" "$T/repo/darkwatch/"
git -C "$T/repo" init -q && git -C "$T/repo" add -A && git -C "$T/repo" commit -qm v1
seed
sed -i 's/"max_threads": [0-9]*/"max_threads": 1/' "$T/repo/darkwatch/config.json"
git -C "$T/repo" diff --quiet && die "fixture: config.json not modified"
deploy
expect_fail "dirty config.json" "darkwatch/config.json has local edits"; no_compose "dirty config.json"
grep -qF "$D/config.d/config.local.json" "$work/out" && grep -qF "git checkout darkwatch/config.json" "$work/out" \
    || die "dirty config.json: the hint must name the override file and the checkout"
git -C "$T/repo" add darkwatch/config.json
deploy
expect_fail "staged config.json" "darkwatch/config.json has local edits"
echo "# local" >> "$T/repo/.env.example"
deploy
expect_fail "dirty config.json and another file" "git working tree has uncommitted changes"; no_compose "two dirty files"
grep -q "config.local.json" "$work/out" && die "the override hint is only for a dirty config.json alone"
git -C "$T/repo" checkout -q HEAD -- darkwatch/config.json && git -C "$T/repo" reset -q
git -C "$T/repo" diff --quiet HEAD -- darkwatch/config.json || die "fixture: config.json not restored"
git -C "$T/repo" diff --quiet HEAD -- .env.example && die "fixture: .env.example not modified"
deploy
expect_fail "other dirty file" "git working tree has uncommitted changes"
grep -q "config.local.json" "$work/out" && die "the override hint is only for a dirty config.json"
ok "a checkout dirty only in darkwatch/config.json is refused with a pointer to config.local.json"

echo "ops checks OK ($pass)"
