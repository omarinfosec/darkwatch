#!/usr/bin/env bash
# Exercise ops/deploy.sh and ops/bootstrap.sh against a throwaway copy of
# ops/ with docker, systemctl, egress-lockdown.sh and verify-egress.sh
# stubbed out. Every docker call is recorded, so the checks can assert what
# deploy would have run. Needs root (bootstrap chowns to uid 999):
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
    network) [[ -n "${STUB_HAVE_SUBNET:-}" ]] || exit 1; echo "$STUB_HAVE_SUBNET" ;;
    compose) [[ -n "${STUB_SETUP_UP_FAILS:-}" && "$*" == *"up -d --no-deps setup"* ]] && exit 1 ;;
esac
exit 0
EOF
printf '#!/bin/sh\nexit 0\n' > "$work/bin/systemctl"
chmod 755 "$work/bin/docker" "$work/bin/systemctl"
export PATH="$work/bin:$PATH" DOCKER_LOG="$work/docker.log"

# A fresh tree per case: ops/ (lockdown + verify stubbed), .env.example and
# the kill switch (deploy checks its exec bit). No .git, so no pull/clean check.
new_tree() {
    T="$work/case$((++case_n))"
    mkdir -p "$T/repo/tunnels/killswitch" "$T/units"
    cp -a "$repo/ops" "$repo/.env.example" "$T/repo/"
    cp -a "$repo/tunnels/killswitch/10-killswitch.sh" "$T/repo/tunnels/killswitch/"
    printf '#!/bin/sh\necho "lockdown stub"\n' > "$T/repo/ops/egress-lockdown.sh"
    printf '#!/bin/sh\necho "verify stub $*"\n' > "$T/repo/ops/verify-egress.sh"
    D="$T/data"
    : > "$DOCKER_LOG"
    unset STUB_SETUP_STATE STUB_HAVE_SUBNET STUB_SETUP_UP_FAILS
}
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
    DARKWEBAPP_DATA_ROOT="$D" DW_SYSTEMD_UNIT_DIR="$T/units" \
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
[[ "$(stat -c %a "$D/env")" == 600 ]] || die "bootstrap: env not 0600"
[[ "$(readlink -f "$T/repo/.env")" == "$(readlink -f "$D/env")" ]] || die "bootstrap: .env link"
ok "bootstrap creates 0700 dirs (uid 999 for darkwatch/) and links .env"

rm "$T/repo/.env"; echo x > "$T/repo/.env"
set +e; DARKWEBAPP_DATA_ROOT="$D" "$T/repo/ops/bootstrap.sh" > "$work/out" 2>&1; rc=$?; set -e
[[ $rc -ne 0 ]] && grep -q "not a link to" "$work/out" || die "bootstrap: a copied .env must be an error"
ok "bootstrap fails on a .env that is not the link"

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
[[ -f "$T/units/darkwatch-egress-lockdown.service" ]] || die "lockdown unit not installed"
ok "lockdown unit installed into DW_SYSTEMD_UNIT_DIR"

[[ "$(grep -c '^TG_SOCKS_PASSWORD=' "$D/env")" == 1 ]] || die "TG_SOCKS_PASSWORD must appear once"
pw="$(grep '^TG_SOCKS_PASSWORD=' "$D/env" | cut -d= -f2-)"
[[ ${#pw} -ge 32 ]] || die "TG_SOCKS_PASSWORD not generated"
deploy
expect_ok "second deploy"
[[ "$(grep -c '^TG_SOCKS_PASSWORD=' "$D/env")" == 1 && "$(grep '^TG_SOCKS_PASSWORD=' "$D/env" | cut -d= -f2-)" == "$pw" ]] \
    || die "TG_SOCKS_PASSWORD changed on redeploy"
ok "TG_SOCKS_PASSWORD filled exactly once and kept"

deploy --skip-build
expect_ok "--skip-build"
grep -q '^compose.* build' "$DOCKER_LOG" && die "--skip-build still built"
ok "--skip-build skips the build"

# ─── subnet migration and Setup UI refresh ──────────────────────────────────
STUB_HAVE_SUBNET=172.20.0.0/16 deploy
expect_ok "subnet change"
grep -q -- "^compose --env-file $D/env --profile tor --profile tg --profile setup down" "$DOCKER_LOG" \
    || die "subnet change must recreate the network"
STUB_HAVE_SUBNET=172.31.250.0/24 deploy
grep -q -- ' down' "$DOCKER_LOG" && die "down ran although the subnet matches the default"
ok "network recreated only when the subnet differs (default 172.31.250.0/24)"

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
ok "a failed Setup UI refresh only warns; lockdown still applied"

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

echo "ops checks OK ($pass)"
