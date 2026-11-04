#!/usr/bin/env bash
# Smoke tests for the built darkwatch, setup and tor images. CI runs this in
# the `images` job (.github/workflows/images.yml) after `docker build`; on a
# host with Docker, run it after a build (deploy.sh tags the same names):
#
#   sudo bash tests/images/smoke.sh
#
# Every container runs with --network none: nothing here needs the network,
# so an import that tries to reach out fails instead of passing by luck, and
# the timeout turns a hang into a failure. --init puts tini at PID 1 so the
# SIGTERM from timeout reaches python (PID 1 ignores it otherwise), and a
# container that still outlives the docker CLI is removed by name.
set -euo pipefail

DARKWATCH_IMAGE="${DARKWATCH_IMAGE:-darkwatch:local}"
SETUP_IMAGE="${SETUP_IMAGE:-darkwatch-setup:local}"
TOR_IMAGE="${TOR_IMAGE:-darkwatch-tor:local}"
SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-180}"

fail=0
n=0
run() {
    local name="$1"; shift
    local cname="smoke-$$-$((n += 1))"
    echo "── $name"
    if timeout --kill-after=10 "$SMOKE_TIMEOUT" \
        docker run --rm --init --network none --name "$cname" "$@"; then
        echo "   ok"
    else
        echo "   FAIL: $name (rc=$?)" >&2
        docker rm -f "$cname" >/dev/null 2>&1 || true
        fail=1
    fi
}

# A module missing from the image (the Dockerfile COPY line) or an import
# that blocks on the network fails here.
run "darkwatch: import darkwatch, dw_db, dw_telegram, threat_intel, web" \
    "$DARKWATCH_IMAGE" python -c 'import darkwatch, dw_db, dw_telegram, threat_intel, web'

# Importing web starts no background thread (darkwatch/tests/
# test_web_startup.py); `python web.py`, the image's CMD, must start the
# health refresh and both monitor schedulers before it serves. Flask.run is
# stubbed, so nothing listens; os._exit skips the daemon threads' shutdown.
run "darkwatch: python web.py starts the background services" \
    -w /app "$DARKWATCH_IMAGE" python -c '
import os, runpy, sys, threading, flask
def check(self, *a, **kw):
    names = {t.name for t in threading.enumerate()}
    missing = {"health-refresh", "MonitorScheduler", "TelegramMonitor"} - names
    print("threads:", ", ".join(sorted(names)), flush=True)
    if missing:
        print("missing:", ", ".join(sorted(missing)), file=sys.stderr, flush=True)
    os._exit(1 if missing else 0)
flask.Flask.run = check
sys.argv = ["web.py"]
runpy.run_path("web.py", run_name="__main__")
sys.exit("web.py returned without calling app.run()")
'

# The two wheel-only native packages (Dockerfile --only-binary). Telethon
# silently falls back to pure-Python AES without cryptg, so check that it
# picked cryptg up, round-trip one block, and run one YARA match.
run "darkwatch: cryptg and yara-python" \
    "$DARKWATCH_IMAGE" python -c '
import os, yara
from telethon.crypto import aes
assert aes.cryptg is not None, "Telethon is not using cryptg"
key, iv, block = os.urandom(32), os.urandom(32), os.urandom(32)
assert aes.AES.decrypt_ige(aes.AES.encrypt_ige(block, key, iv), key, iv) == block
rules = yara.compile(source="rule smoke { strings: $a = \"darkwatch\" condition: $a }")
assert [m.rule for m in rules.match(data=b"xx darkwatch xx")] == ["smoke"]
print("cryptg", aes.cryptg.__name__, "yara", yara.__version__)
'

# ScreenshotEngine logs a failed Firefox launch and returns (None, None)
# instead of raising, so only the files themselves prove the browser works.
# The thumbnail also proves Pillow can read the PNG.
run "darkwatch: offline screenshot" \
    "$DARKWATCH_IMAGE" python -c '
import os, sys
from darkwatch import ScreenshotEngine
eng = ScreenshotEngine("/tmp/smoke/screenshots", mode="offline")
try:
    shot, thumb = eng.capture("<html><body><h1>darkwatch smoke</h1></body></html>",
                              "http://smoke.invalid/")
finally:
    if eng._browser:
        eng._browser.close()
    if eng._playwright:
        eng._playwright.stop()
for label, path in (("screenshot", shot), ("thumbnail", thumb)):
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        sys.exit(f"{label} missing or empty: {path!r}")
    print(f"{label}: {os.path.basename(path)} ({os.path.getsize(path)} bytes)")
'

# What ops/retention.sh runs in the container (docker exec -w /app ...): the
# CLI parses and the database steps run, here on a fresh database.
run "darkwatch: retention CLI" \
    -w /app -e DARKWATCH_CONFIG=/app/config.json \
    "$DARKWATCH_IMAGE" python darkwatch.py --retention --dry-run

# main.py refuses to import without a token; any value will do here.
run "setup: import main" \
    -e SETUP_AUTH_TOKEN=x "$SETUP_IMAGE" python -c 'import main'
run "setup: docker compose plugin" \
    "$SETUP_IMAGE" docker compose version

run "tor: tor --version" \
    --entrypoint tor "$TOR_IMAGE" --version

# The image runs as debian-tor and the healthcheck needs bash, timeout and
# grep. `id` lands in the log: ops/deploy.sh re-owns the tor-data volume when
# the uid changes with the base image. A fresh tor-data volume is copied from
# the image's /var/lib/tor, owner included, so the tor package must ship it
# owned by debian-tor. One `command -v` per name: dash's exit status only
# reflects the first of several.
run "tor: debian-tor user and healthcheck.sh" \
    --entrypoint /bin/sh "$TOR_IMAGE" -c '
set -e
id
[ "$(id -un)" = debian-tor ]
test -x /usr/local/bin/healthcheck.sh
for c in bash timeout grep; do command -v "$c" >/dev/null; done
test -w /etc/tor/run
[ -d /var/lib/tor ] && [ -O /var/lib/tor ]
'
echo "── tor: HEALTHCHECK runs healthcheck.sh"
if docker image inspect -f '{{json .Config.Healthcheck.Test}}' "$TOR_IMAGE" \
        | grep -q '/usr/local/bin/healthcheck.sh'; then
    echo "   ok"
else
    echo "   FAIL: the tor image's HEALTHCHECK does not run healthcheck.sh" >&2
    fail=1
fi

# The entrypoint templates torrc (tor --hash-password) and tor accepts it,
# without touching the network.
run "tor: entrypoint writes a torrc tor accepts" \
    -e TOR_CONTROL_PASSWORD=smoke "$TOR_IMAGE" tor -f /etc/tor/run/torrc --verify-config

if [ "$fail" -ne 0 ]; then
    echo "image smoke tests FAILED" >&2
    exit 1
fi
echo "image smoke tests passed"
