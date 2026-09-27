#!/usr/bin/env bash
# Healthy only once Tor has actually built a circuit. The previous check
# (SOCKS port accepts a connection) passed immediately at startup and kept
# passing with a dead tunnel, before Tor could reach the network at all.
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/9051
printf 'AUTHENTICATE "%s"\r\nGETINFO status/circuit-established\r\nQUIT\r\n' \
    "${TOR_CONTROL_PASSWORD:?}" >&3
timeout 4 grep -q 'circuit-established=1' <&3
