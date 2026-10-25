#!/usr/bin/env bash
# Assert the WireGuard kill switch (tunnels/killswitch/10-killswitch.sh):
# with the tunnel down, internet-bound traffic must be REJECTED instead of
# leaving through the Docker bridge (the host's IP); everything that should
# work (tunnel up, darknet peers, WG's own marked packets) must not be.
# Needs: unshare (user + net namespaces), iptables, python3 with pyroute2.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
py="${PYTHON:-python3}"
# CI runners block unprivileged user namespaces: UNSHARE="sudo unshare -n".
unshare_cmd=(${UNSHARE:-unshare -rn})
off="$("${unshare_cmd[@]}" "$py" "$here/run_ns.py" off)"
on="$("${unshare_cmd[@]}" "$py" "$here/run_ns.py" on)"
printf '%s\n\n%s\n' "$off" "$on"
expect() { grep -qF -- "$2" <<<"$1" || { echo "FAIL: expected: $2" >&2; exit 1; }; }
expect "$off" "[off] tunnel DOWN internet 1.1.1.1      : allowed"   # the leak, without the switch
expect "$on"  "[on] tunnel UP   internet 1.1.1.1      : allowed"
expect "$on"  "[on] tunnel UP   darknet 172.31.250.250 : allowed"
expect "$on"  "[on] tunnel UP   WG endpoint (marked)  : allowed"
expect "$on"  "[on] tunnel DOWN internet 1.1.1.1      : REJECTED"
expect "$on"  "[on] tunnel DOWN darknet 172.31.250.250 : allowed"
echo "kill switch OK"
