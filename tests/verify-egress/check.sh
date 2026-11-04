#!/usr/bin/env bash
# Exercise ops/verify-egress.sh against stubbed docker, iptables and curl.
# The stubs answer like a healthy stack (both tunnels, lockdown rule for
# darkwatch's address, DNS isolated); each case breaks one thing through a
# STUB_* variable and checks the verdict and message. Needs root (the script
# refuses to run otherwise):
#   sudo bash tests/verify-egress/check.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root: sudo bash $0" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
ok()  { echo "ok   $*"; pass=$((pass + 1)); }
die() { echo "FAIL $*" >&2; [[ -f "$work/out" ]] && sed 's/^/    | /' "$work/out" >&2; exit 1; }

# ─── Stubs ──────────────────────────────────────────────────────────────────
mkdir -p "$work/bin"
cat > "$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    ps) printf '%s\n' darkwatch tunnel1 tor tunnel2 tg-socks ;;
    inspect)
        case "$*" in
            *NetworkMode*)          echo darkwatch_darknet ;;
            *'range $k,$v'*)        echo "darkwatch_darknet " ;;
            *NetworkSettings.Networks*) echo "${STUB_DW_IP-172.31.250.250}" ;;
            *) exit 1 ;;
        esac ;;
    exec)
        shift
        [[ "$1" == -i ]] && shift
        ctr="$1"; shift
        case "$ctr $*" in
            "darkwatch python "*) shift; exec python3 "$@" ;;
            *"tunnel1:9050"*)  echo '{"IsTor": true, "IP": "198.51.100.1"}' ;;
            *"tunnel2:1080"*)  echo "${STUB_TG_EXIT-203.0.113.2}" ;;
            *"http://1.1.1.1"*) [[ -n "${STUB_DW_EGRESS:-}" ]] || exit 28 ;;
            "tunnel"*" iptables "*) ;;
            "darkwatch cat /etc/resolv.conf") cat "$STUB_DW_RESOLV" ;;
            "tunnel2 cat /etc/resolv.conf")   printf 'nameserver %s\n' "${STUB_T2_NS-10.2.0.1}" ;;
            "darkwatch timeout 10 getent hosts example.com")
                [[ -n "${STUB_DW_RESOLVES:-}" ]] || exit "${STUB_GETENT_RC:-2}"
                echo "93.184.215.14 example.com" ;;
            "darkwatch timeout 10 getent hosts tunnel"*)
                [[ "$*" != *"${STUB_NO_NAME:-none}"* ]] || exit 2
                echo "172.31.250.2 tunnel" ;;
            *) echo "docker stub: unexpected exec $ctr $*" >&2; exit 99 ;;
        esac ;;
    *) echo "docker stub: unexpected $*" >&2; exit 99 ;;
esac
EOF
cat > "$work/bin/iptables" <<'EOF'
#!/usr/bin/env bash
[[ "$*" == "-S DOCKER-USER" ]] || exit 1
echo "-N DOCKER-USER"
[[ -n "${STUB_NO_RULE:-}" ]] || echo "-A DOCKER-USER -s ${STUB_RULE_IP:-172.31.250.250}/32 ! -d 172.31.250.0/24 -m conntrack ! --ctstate RELATED,ESTABLISHED -m comment --comment darkwatch-egress-lockdown -j DROP"
echo "-A DOCKER-USER -j RETURN"
EOF
# The host side: its own IP (for the TG comparison) and the positive control.
cat > "$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
[[ -z "${STUB_HOST_OFFLINE:-}" ]] || exit 28
case "$*" in
    *api.ipify.org*)
        [[ -n "${STUB_HOST_IP-192.0.2.7}" ]] || exit 28
        # An HTTP error page: curl -f prints nothing and exits 22.
        if [[ -n "${STUB_HOST_HTTP_ERR:-}" ]]; then
            [[ " $* " == *" -f"* ]] && exit 22
            echo "<html>503 Service Unavailable</html>"; exit 0
        fi
        echo "${STUB_HOST_IP-192.0.2.7}" ;;
esac
exit 0
EOF
chmod 755 "$work/bin/"*
export PATH="$work/bin:$PATH"

# Docker 26+ resolv.conf for a container with `dns: 127.0.0.1`.
resolv() {   # $1 = ExtServers value, or "" for no footer (Docker 24/25)
    printf 'nameserver 127.0.0.11\noptions ndots:0\n' > "$work/resolv"
    [[ -z "$1" ]] || printf "\n# Based on host file: '/etc/resolv.conf' (internal resolver)\n# ExtServers: %s\n# Overrides: [nameservers]\n" "$1" >> "$work/resolv"
}
export STUB_DW_RESOLV="$work/resolv"

D="$work/data"
mkdir -p "$D/secrets/tunnel1/wg_confs" "$D/secrets/tunnel2/wg_confs"
touch "$D/secrets/tunnel1/wg_confs/wg0.conf" "$D/secrets/tunnel2/wg_confs/wg0.conf"
printf 'TG_SOCKS_PASSWORD=pw\n' > "$D/env"; chmod 600 "$D/env"

verify() {   # sets rc; output in $work/out
    set +e
    DARKWEBAPP_DATA_ROOT="$D" bash "$repo/ops/verify-egress.sh" "$@" > "$work/out" 2>&1
    rc=$?
    set -e
}
expect_pass() { [[ $rc -eq 0 ]] || die "$1: verify exited $rc"; }
expect_fail() { [[ $rc -ne 0 ]] || die "$1: verify should have failed"; grep -qF -- "$2" "$work/out" || die "$1: missing message: $2"; }
has()         { grep -qF -- "$2" "$work/out" || die "$1: missing message: $2"; }

# Runs every case with a clean slate of STUB_* settings.
reset() {
    unset STUB_DW_IP STUB_TG_EXIT STUB_DW_EGRESS STUB_T2_NS STUB_DW_RESOLVES STUB_GETENT_RC \
          STUB_NO_NAME STUB_NO_RULE STUB_RULE_IP STUB_HOST_OFFLINE STUB_HOST_IP STUB_HOST_HTTP_ERR \
          DARKWATCH_EGRESS_LOCKDOWN DARKWATCH_DNS
    resolv "[127.0.0.1]"
    printf 'TG_SOCKS_PASSWORD=pw\n' > "$D/env"
}

# ─── healthy stack ──────────────────────────────────────────────────────────
reset; verify
expect_pass "healthy"
for m in "DOCKER-USER has the egress-lockdown rule for darkwatch (172.31.250.250)" \
         "darkwatch has no direct internet route (the host does)" \
         "tg-socks exit IP differs from the host's IP" \
         "darkwatch's DNS upstream is 127.0.0.1 in its own namespace" \
         "darkwatch can't resolve clearnet names" \
         "darkwatch resolves tunnel1" "darkwatch resolves tunnel2" \
         "tunnel2 resolves names through the VPN's resolver"; do
    has "healthy" "$m"
done
grep -q "no leak path\|inconclusive" "$work/out" && die "healthy: unexpected message"
ok "healthy stack passes every check"

# ─── 5b: lockdown rule and direct-egress probe ──────────────────────────────
reset; STUB_NO_RULE=1 verify
expect_fail "rule removed" "no egress-lockdown rule in DOCKER-USER for darkwatch's address 172.31.250.250"
ok "egress-lockdown.sh --remove (no rule) fails 5b"

reset; STUB_DW_IP=172.31.250.9 verify
expect_fail "rule for another IP" "no egress-lockdown rule in DOCKER-USER for darkwatch's address 172.31.250.9"
ok "a rule for an address darkwatch doesn't run on fails"

reset; STUB_DW_IP="" verify
expect_fail "no IP" "could not read darkwatch's IP address"
ok "an unreadable darkwatch IP fails"

reset; STUB_DW_EGRESS=1 verify
expect_fail "direct egress" "darkwatch reached http://1.1.1.1 DIRECTLY"
ok "darkwatch reaching an IP literal directly fails"

reset; STUB_HOST_OFFLINE=1 verify
has "host offline" "direct-egress probe inconclusive"
has "host offline" "could not fetch the host's own IP"
expect_pass "host offline"
ok "host offline: probe inconclusive and no host-IP comparison, warnings only"

for how in file env; do
    reset
    if [[ $how == file ]]; then echo "DARKWATCH_EGRESS_LOCKDOWN=0" >> "$D/env"; else export DARKWATCH_EGRESS_LOCKDOWN=0; fi
    STUB_NO_RULE=1 STUB_DW_EGRESS=1 STUB_DW_RESOLVES=1 verify
    expect_pass "LOCKDOWN=0 ($how)"
    has "LOCKDOWN=0 ($how)" "skipped: egress lockdown disabled by DARKWATCH_EGRESS_LOCKDOWN=0"
    has "LOCKDOWN=0 ($how)" "skipped clearnet DNS checks"
    has "LOCKDOWN=0 ($how)" "DARKWATCH_EGRESS_LOCKDOWN=0 but DARKWATCH_DNS is unset"
done
ok "LOCKDOWN=0 (env file or environment) skips 5b and the clearnet DNS checks"

for how in file env; do
    reset
    echo "DARKWATCH_EGRESS_LOCKDOWN=0" >> "$D/env"
    if [[ $how == file ]]; then echo "DARKWATCH_DNS=192.0.2.53" >> "$D/env"; else export DARKWATCH_DNS=192.0.2.53; fi
    resolv "[192.0.2.53]"; STUB_DW_RESOLVES=1 verify
    expect_pass "LOCKDOWN=0 + DNS ($how)"
    grep -qF "DARKWATCH_DNS is unset" "$work/out" && die "LOCKDOWN=0 + DNS ($how): unexpected DARKWATCH_DNS warning"
done
reset; echo "DARKWATCH_EGRESS_LOCKDOWN=0" >> "$D/env"; echo "DARKWATCH_DNS=127.0.0.1" >> "$D/env"; verify
has "LOCKDOWN=0 + DNS=127.0.0.1" "DARKWATCH_DNS is unset"
ok "LOCKDOWN=0 warns that darkwatch can't resolve clearnet names until DARKWATCH_DNS is set"

# ─── 3: TG exit vs host IP ──────────────────────────────────────────────────
reset; STUB_TG_EXIT=192.0.2.7 verify
expect_fail "tg == host" "tg-socks exit IP == the host's IP (192.0.2.7)"
ok "TG exit IP equal to the host's IP fails"

reset; STUB_HOST_IP="" verify
expect_pass "host IP unknown"
has "host IP unknown" "could not fetch the host's own IP"
ok "an unavailable host IP only warns"

for c in "STUB_HOST_HTTP_ERR=1" "STUB_HOST_IP=<html>blocked</html>"; do
    reset; export "$c"; verify
    expect_pass "host page ($c)"
    has "host page ($c)" "could not fetch the host's own IP"
    grep -qF "exit IP differs from the host's IP" "$work/out" && die "host page ($c): compared a non-IP"
done
reset; STUB_TG_EXIT="<html>blocked</html>" verify
expect_pass "tg page"
has "tg page" "could not fetch tg-socks' exit IP as an address"
grep -qF "exit IP differs from the host's IP" "$work/out" && die "tg page: compared a non-IP"
ok "an HTTP error or a non-IP answer on either side is not compared"

# ─── 6: DNS ─────────────────────────────────────────────────────────────────
reset; resolv "[host(127.0.0.53)]"; verify
expect_fail "host() upstream" "darkwatch's DNS is resolved from the HOST namespace ([host(127.0.0.53)])"
ok "ExtServers with host(...) fails"

reset; resolv "[192.0.2.53]"; verify
expect_fail "other upstream" "darkwatch's DNS upstream is [192.0.2.53], expected [127.0.0.1]"
ok "ExtServers other than [127.0.0.1] fails"

reset; resolv ""; verify
expect_pass "no footer"
has "no footer" "ExtServers: (no footer)"
ok "no ExtServers footer (Docker 24/25): the lookup test decides"

reset; STUB_DW_RESOLVES=1 verify
expect_fail "clearnet resolves" "darkwatch resolved example.com"
ok "a clearnet name that resolves in darkwatch fails"

reset; STUB_GETENT_RC=126 verify
expect_fail "lookup test broken" "could not run the DNS lookup test in darkwatch (exit 126)"
reset; STUB_GETENT_RC=124 verify
expect_pass "lookup timeout"
has "lookup timeout" "timed out after 10 s"
ok "a lookup test that can't run fails; one that times out warns"

for t in tunnel1 tunnel2; do
    reset; STUB_NO_NAME=$t verify
    expect_fail "no $t name" "darkwatch can't resolve $t"
done
ok "tunnel1 / tunnel2 names must resolve in darkwatch"

reset; STUB_T2_NS=127.0.0.11 verify
expect_pass "tunnel2 embedded DNS"
has "tunnel2 embedded DNS" "tunnel2 resolves names through Docker's embedded DNS (127.0.0.11)"
reset; STUB_T2_NS=127.0.0.11 STUB_NO_NAME=tunnel2 verify --tor
expect_pass "--tor only"
grep -q "resolves tunnel2\|resolve tunnel2\|tunnel2 resolves" "$work/out" && die "--tor only: tunnel2 must not be checked"
ok "tunnel2 on Docker's embedded DNS warns when TG is checked, and only then"

echo "verify-egress checks OK ($pass)"
