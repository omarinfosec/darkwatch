#!/usr/bin/env bash
# Assert the WireGuard kill switch (tunnels/killswitch/10-killswitch.sh):
# with the tunnel down, internet-bound traffic must be REJECTED instead of
# leaving through the Docker bridge (the host's IP); everything that should
# work (tunnel up, darknet peers, WG's own marked packets) must not be.
# Inbound, the VPN side must not reach the SOCKS port; hostname Endpoints
# must be pinned in /etc/hosts before egress closes.
# Needs: unshare (user + net namespaces), iptables, python3 with pyroute2.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
py="${PYTHON:-python3}"
# CI runners block unprivileged user namespaces: UNSHARE="sudo unshare -n".
unshare_cmd=(${UNSHARE:-unshare -rn})
off="$("${unshare_cmd[@]}" "$py" "$here/run_ns.py" off)"
on="$("${unshare_cmd[@]}" "$py" "$here/run_ns.py" on)"
on_glibc="$("${unshare_cmd[@]}" "$py" "$here/run_ns.py" on-glibc)"
peer_off="$("${unshare_cmd[@]}" "$py" "$here/run_ns.py" peer-off)"
peer_on="$("${unshare_cmd[@]}" "$py" "$here/run_ns.py" peer-on)"
printf '%s\n\n' "$off" "$on" "$on_glibc" "$peer_off" "$peer_on"
expect() { grep -qF -- "$2" <<<"$1" || { echo "FAIL: expected: $2" >&2; exit 1; }; }
line()   { grep -qxF -- "$2" <<<"$1" || { echo "FAIL: expected line: $2" >&2; exit 1; }; }
reject() { ! grep -qF -- "$2" <<<"$1" || { echo "FAIL: unexpected: $2" >&2; exit 1; }; }
expect "$off" "[off] tunnel DOWN internet 1.1.1.1      : allowed"   # the leak, without the switch
expect "$on"  "[killswitch] IPv4: only wg*, lo, fwmark 0xca6c and 172.31.250.2/24 may egress; nothing may connect in via wg*"
# Same probe as the kill switch: when ip6tables works there, it must be applied.
if "${unshare_cmd[@]}" ip6tables -L OUTPUT -n >/dev/null 2>&1; then
    expect "$on" "[killswitch] IPv6: same policy applied"
    expect "$on" "[on] ip6tables hooks: OUTPUT->DW_KILLSWITCH x1, INPUT->DW_KS_IN x1"
fi
expect "$on"  "[on] iptables hooks: OUTPUT->DW_KILLSWITCH x1, INPUT->DW_KS_IN x1"   # after two runs
expect "$on"  "[on] tunnel UP   internet 1.1.1.1      : allowed"
expect "$on"  "[on] tunnel UP   darknet 172.31.250.250 : allowed"
expect "$on"  "[on] tunnel UP   WG endpoint (marked)  : allowed"
expect "$on"  "[on] tunnel DOWN internet 1.1.1.1      : REJECTED"
expect "$on"  "[on] tunnel DOWN darknet 172.31.250.250 : allowed"
# Hostname Endpoints: pinned once, stale pin replaced, failures logged, IP literals not looked up.
# Resolvers as on Alpine/musl: no getent ahostsv4, `getent hosts` gives dual-stack names as IPv6 only.
for ep in "vpn.example.test -> 203.0.113.7" "dual.example.test -> 203.0.113.8" "extra.example.test -> 203.0.113.9"; do
    expect "$on"       "[killswitch] pinned endpoint $ep"
    expect "$on_glibc" "[killswitch] pinned endpoint $ep"   # glibc: getent ahostsv4
done
expect "$on"  "[killswitch] could not resolve endpoint nx.example.test"
line   "$on"  "[on] hosts: 127.0.0.1	localhost"
line   "$on"  "[on] hosts: 203.0.113.7 vpn.example.test # dw-killswitch endpoint"
line   "$on"  "[on] hosts: 203.0.113.8 dual.example.test # dw-killswitch endpoint"
line   "$on"  "[on] hosts: 203.0.113.9 extra.example.test # dw-killswitch endpoint"
reject "$on"  "198.51.100.9"
reject "$on"  "2001:db8::8"
[[ "$(grep -c '^\[on\] hosts: .*vpn.example.test' <<<"$on")" == 1 ]] || { echo "FAIL: vpn.example.test pinned more than once" >&2; exit 1; }
expect "$on"  "[on] looked up: dual.example.test extra.example.test nx.example.test vpn.example.test"
# Appended pins start on their own line when the hosts file lacks a final newline.
line   "$on_glibc" "[on-glibc] hosts: 127.0.0.1	localhost"
line   "$on_glibc" "[on-glibc] hosts: 203.0.113.7 vpn.example.test # dw-killswitch endpoint"
# Inbound: the VPN peer must not reach tor's SocksPort; nothing else changes.
expect "$peer_off" "[peer-off] VPN peer -> tunnel 10.2.0.2:9050     : connected"   # the exposure, without the switch
expect "$peer_on"  "[peer-on] VPN peer -> tunnel 10.2.0.2:9050     : blocked"
expect "$peer_on"  "[peer-on] darknet  -> tunnel 172.31.250.2:9050 : connected"
expect "$peer_on"  "[peer-on] tunnel   -> VPN 10.2.0.1:443 via wg0 : connected"
expect "$peer_on"  "[peer-on] loopback -> 127.0.0.1:9050           : connected"
echo "kill switch OK"
