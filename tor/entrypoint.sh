#!/usr/bin/env bash
# Generate /etc/tor/run/torrc from environment, then exec tor.
# Required env: TOR_CONTROL_PASSWORD (any non-empty string).

set -euo pipefail

TORRC=/etc/tor/run/torrc

if [[ -z "${TOR_CONTROL_PASSWORD:-}" ]]; then
    echo "[tor entrypoint] FATAL: TOR_CONTROL_PASSWORD is unset." >&2
    echo "[tor entrypoint]   Set it in /var/lib/darkwebapp/env (host) so it" >&2
    echo "[tor entrypoint]   propagates here via compose env_file." >&2
    exit 1
fi

# `tor --hash-password` writes one line: 16:....
HASH="$(tor --hash-password "$TOR_CONTROL_PASSWORD" | tail -1)"

cat > "$TORRC" <<EOF
# Auto-generated at container start by entrypoint.sh.
# Do not edit — overwritten on every run.

# Daemonization off — tor runs in the foreground for docker.
RunAsDaemon 0

# Where Tor keeps its consensus, descriptors, etc.
DataDirectory /var/lib/tor

# SOCKS for darkwatch's HTTP fetcher and Playwright. Bound on all
# interfaces in this netns so other darknet bridge containers reach it
# at tunnel1:9050.
SocksPort 0.0.0.0:9050 IsolateDestAddr IsolateDestPort

# Control port for NEWNYM circuit rotation between investigations.
ControlPort 0.0.0.0:9051
HashedControlPassword $HASH
CookieAuthentication 0

# Don't leak which circuits we're using to logs.
SafeLogging 1

# Conservative: no relay role.
ExitRelay 0
ClientOnly 1
EOF

echo "[tor entrypoint] torrc generated; ControlPort password authentication enabled."
exec "$@"
