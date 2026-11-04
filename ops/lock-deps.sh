#!/usr/bin/env bash
# DarkWatch — hash-locked Python dependencies for the darkwatch and Setup UI
# images.
#
# Each image pins its direct dependencies by hand in requirements.in. This
# script resolves them, and everything they pull in, into requirements.lock
# with a SHA-256 for every file on PyPI, using a pinned uv. The Dockerfiles
# and CI install the lock with `pip install --require-hashes`, so a package
# that is swapped or re-uploaded on PyPI fails the install.
#
#   ./ops/lock-deps.sh             # re-lock after editing a requirements.in
#   ./ops/lock-deps.sh --upgrade   # also move unpinned transitive deps to
#                                  # their newest versions
#   ./ops/lock-deps.sh --check     # offline: every name==version in each
#                                  # requirements.in is in its lock (CI)
#
# The locks are resolved for CPython 3.11 on x86_64 Linux, which is what the
# images run. Commit each requirements.in together with its requirements.lock.
#
# Needs: uv $UV_VERSION on PATH, or python3 with venv and pip and PyPI
# access, to fetch it into a throwaway venv. --check needs neither.

set -euo pipefail

UV_VERSION=0.11.32
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCKED_DIRS=(darkwatch setup)

MODE=lock
UPGRADE=()
case "${1:-}" in
    --check)   MODE=check ;;
    --upgrade) UPGRADE=(--upgrade) ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    "") ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

log() { printf '\033[1;36m[lock-deps]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[lock-deps]\033[0m %s\n' "$*" >&2; }

# Prints "name==version" for each requirement in an .in file (name
# normalized as in PEP 503, extras dropped), or for each pinned package line
# of a lock. Prints "UNPINNED <line>" for an .in line that is not
# name[extras]==version.
pins() {
    awk '
        { sub(/#.*/, ""); gsub(/^[ \t]+|[ \t\\]+$/, "") }
        $0 == "" || /^--/ { next }
        match($0, /^[A-Za-z0-9._-]+(\[[^]]*\])?==[A-Za-z0-9.!+_-]+$/) {
            # Two plain subs: GNU awk rejects "[[=]" (it reads "[=" as the
            # start of an equivalence class), mawk accepts it.
            name = $0; sub(/\[.*/, "", name); sub(/=.*/, "", name)
            name = tolower(name); gsub(/[-_.]+/, "-", name)
            ver = $0; sub(/.*==/, "", ver)
            print name "==" ver; next
        }
        { print "UNPINNED " $0 }
    ' "$1"
}

check() {
    local d in lock fail=0 missing
    for d in "${LOCKED_DIRS[@]}"; do
        in="$ROOT/$d/requirements.in"
        lock="$ROOT/$d/requirements.lock"
        if [[ ! -f "$in" ]]; then
            err "$d/requirements.in is missing"
            fail=1; continue
        fi
        if [[ ! -f "$lock" ]]; then
            err "$d/requirements.lock is missing; run ./ops/lock-deps.sh"
            fail=1; continue
        fi
        if pins "$in" | grep '^UNPINNED ' | sed "s|^UNPINNED |$d/requirements.in: not pinned as name==version: |" >&2; then
            fail=1
        fi
        # Pins in the .in that the lock does not contain.
        missing="$(LC_ALL=C comm -23 \
            <(pins "$in" | grep -v '^UNPINNED ' | LC_ALL=C sort -u) \
            <(grep -E '^[A-Za-z0-9]' "$lock" | pins /dev/stdin | LC_ALL=C sort -u))"
        if [[ -n "$missing" ]]; then
            err "$d/requirements.lock is behind $d/requirements.in (run ./ops/lock-deps.sh):"
            sed 's/^/    /' <<<"$missing" >&2
            fail=1
        else
            log "$d/requirements.lock matches $d/requirements.in"
        fi
    done
    return "$fail"
}

if [[ "$MODE" == check ]]; then
    check
    exit $?
fi

# The pinned uv: the one on PATH if it is that version, else a throwaway venv.
uv=uv
if [[ "$(uv --version 2>/dev/null | awk '{print $2}')" != "$UV_VERSION" ]]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    log "fetching uv $UV_VERSION into a throwaway venv"
    python3 -m venv "$tmp/venv"
    "$tmp/venv/bin/pip" install --quiet --disable-pip-version-check "uv==$UV_VERSION"
    uv="$tmp/venv/bin/uv"
fi

cd "$ROOT"
for d in "${LOCKED_DIRS[@]}"; do
    log "resolving $d/requirements.in -> $d/requirements.lock"
    "$uv" pip compile --quiet "${UPGRADE[@]}" \
        --python-version 3.11 --python-platform linux --generate-hashes \
        --custom-compile-command "./ops/lock-deps.sh" \
        "$d/requirements.in" -o "$d/requirements.lock"
done
check
