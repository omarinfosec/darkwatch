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
# The locks are resolved for CPython 3.13 (PYTHON_VERSION below) on x86_64
# Linux, the interpreter of the images' python:3.13-slim-trixie base. Each
# is resolved again for aarch64 Linux, and the run fails if that gives a
# different lock, so one lock serves both architectures (its hashes cover
# every file of each locked version, the wheels for both included). Commit
# each requirements.in together with its requirements.lock.
#
# Needs: uv $UV_VERSION on PATH, or python3 with venv and pip and PyPI
# access, to fetch it into a throwaway venv. --check needs neither.

set -euo pipefail

UV_VERSION=0.11.32
# The images' Python (the FROM line of darkwatch/ and setup/Dockerfile) and
# the platforms they run on; the first one writes the lock.
PYTHON_VERSION=3.13
PLATFORMS=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCKED_DIRS=(darkwatch setup)

MODE=lock
UPGRADE=()
case "${1:-}" in
    --check)   MODE=check ;;
    --upgrade) UPGRADE=(--upgrade) ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
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

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The pinned uv: the one on PATH if it is that version, else a throwaway venv.
uv=uv
if [[ "$(uv --version 2>/dev/null | awk '{print $2}')" != "$UV_VERSION" ]]; then
    log "fetching uv $UV_VERSION into a throwaway venv"
    python3 -m venv "$tmp/venv"
    "$tmp/venv/bin/pip" install --quiet --disable-pip-version-check "uv==$UV_VERSION"
    uv="$tmp/venv/bin/uv"
fi

compile() {   # platform, requirements.in, output; extra args after
    local plat="$1" in="$2" out="$3"
    shift 3
    "$uv" pip compile --quiet "$@" \
        --python-version "$PYTHON_VERSION" --python-platform "$plat" --generate-hashes \
        --custom-compile-command "./ops/lock-deps.sh" \
        "$in" -o "$out"
}

cd "$ROOT"
differs=0
for d in "${LOCKED_DIRS[@]}"; do
    log "resolving $d/requirements.in -> $d/requirements.lock (CPython $PYTHON_VERSION, ${PLATFORMS[0]})"
    compile "${PLATFORMS[0]}" "$d/requirements.in" "$d/requirements.lock" "${UPGRADE[@]}"
    # Re-resolve from a copy of the new lock: uv keeps the versions it finds
    # in the output file, so a difference means the platform needs another
    # version or package, not that a newer release appeared in between.
    for plat in "${PLATFORMS[@]:1}"; do
        cp "$d/requirements.lock" "$tmp/other.lock"
        compile "$plat" "$d/requirements.in" "$tmp/other.lock"
        if ! cmp -s "$d/requirements.lock" "$tmp/other.lock"; then
            err "$d/requirements.in resolves differently on $plat; one lock cannot serve both platforms:"
            diff "$d/requirements.lock" "$tmp/other.lock" | sed 's/^/    /' >&2 || true
            differs=1
        fi
    done
done
check
exit "$differs"
