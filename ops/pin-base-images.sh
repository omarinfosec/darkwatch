#!/usr/bin/env bash
# DarkWatch — Dockerfile FROM digest pinner.
#
# Sibling to ops/pin-images.sh (which handles compose `image:` lines).
# This script handles Dockerfile `FROM` lines — the base images for
# the locally-built services (darkwatch, setup, tor).
#
# Run on the VM:
#   sudo ./ops/pin-base-images.sh --check     # preview
#   sudo ./ops/pin-base-images.sh --apply     # rewrite Dockerfiles, no prompt
#   sudo ./ops/pin-base-images.sh             # show diff, prompt
#
# After --apply, rebuild:
#   docker compose build && docker compose --profile setup up -d --force-recreate
#
# Re-run monthly. Commit the resulting Dockerfile changes so the deploy
# is reproducible.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DOCKERFILES=(
    "$REPO_ROOT/darkwatch/Dockerfile"
    "$REPO_ROOT/setup/Dockerfile"
    "$REPO_ROOT/tor/Dockerfile"
)

MODE=ask
case "${1:-}" in
    --apply) MODE=apply ;;
    --check) MODE=check ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    "") ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

log()  { printf '\033[1;36m[pin-base]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[pin-base WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pin-base ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker not in PATH"

# ─── Find FROM tags in each Dockerfile ─────────────────────────────────────
# Skip:
#   - Already-pinned (contains @sha256:)
#   - $VAR-style refs (these need substitution; punt for now)

declare -A SEEN_PULLS  # cache: tag -> digest
declare -A FILE_REPLACEMENTS  # file => "old -> new" pairs newline-joined

for df in "${DOCKERFILES[@]}"; do
    [[ -f "$df" ]] || { warn "skip $df (not found)"; continue; }
    log "scanning $df"
    # Match: FROM <ref> [AS stage]
    while IFS= read -r line; do
        # Strip comments + trim
        clean=$(printf '%s' "$line" | sed 's|#.*$||' | xargs)
        [[ -z "$clean" ]] && continue
        # Only FROM lines
        [[ "$clean" =~ ^FROM[[:space:]]+ ]] || continue
        # Extract just the image ref (between FROM and optional AS)
        ref=$(printf '%s' "$clean" | awk '{print $2}')
        # Skip if already pinned
        if [[ "$ref" == *"@sha256:"* ]]; then
            log "    already pinned: $ref"
            continue
        fi
        # Skip variable refs
        if [[ "$ref" == *"\$"* ]]; then
            warn "    variable ref skipped: $ref"
            continue
        fi
        log "    pinning: $ref"
        if [[ -z "${SEEN_PULLS[$ref]:-}" ]]; then
            docker pull --quiet "$ref" >/dev/null
            digest="$(docker inspect --format='{{index .RepoDigests 0}}' "$ref" 2>/dev/null || true)"
            if [[ -z "$digest" || "$digest" == "<no value>" ]]; then
                warn "    no digest captured for $ref — skipping"
                continue
            fi
            # digest looks like: python@sha256:...
            # We want: python:3.11-slim-bookworm@sha256:...  (keep the human-readable tag)
            # If $ref has a tag, append @sha256 to it. If not, replace.
            sha_only=$(printf '%s' "$digest" | sed 's|^[^@]*||')   # @sha256:...
            new_ref="${ref}${sha_only}"
            SEEN_PULLS[$ref]="$new_ref"
            log "      → $new_ref"
        else
            new_ref="${SEEN_PULLS[$ref]}"
            log "      → $new_ref (cached)"
        fi
        # Schedule replacement in this file
        FILE_REPLACEMENTS[$df]+="$ref|$new_ref"$'\n'
    done < "$df"
done

if (( ${#FILE_REPLACEMENTS[@]} == 0 )); then
    log "nothing to pin (everything already pinned, or no Dockerfiles found)"
    exit 0
fi

# ─── Apply replacements to a tmp tree, show diff ───────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

for df in "${!FILE_REPLACEMENTS[@]}"; do
    rel="${df#$REPO_ROOT/}"
    mkdir -p "$TMPDIR/$(dirname "$rel")"
    cp "$df" "$TMPDIR/$rel"
    while IFS='|' read -r old new; do
        [[ -z "$old" ]] && continue
        esc_old=$(printf '%s' "$old" | sed 's|[\/&]|\\&|g')
        esc_new=$(printf '%s' "$new" | sed 's|[\/&]|\\&|g')
        sed -i "s|^FROM[[:space:]]\+${esc_old}\b|FROM ${esc_new}|" "$TMPDIR/$rel"
    done <<< "${FILE_REPLACEMENTS[$df]}"
done

log ""
log "diff to apply:"
echo "─────────────────────────────────────"
for df in "${!FILE_REPLACEMENTS[@]}"; do
    rel="${df#$REPO_ROOT/}"
    { diff -u "$df" "$TMPDIR/$rel" || true; } | head -40
done
echo "─────────────────────────────────────"

# ─── Apply or prompt ───────────────────────────────────────────────────────
apply_changes() {
    for df in "${!FILE_REPLACEMENTS[@]}"; do
        rel="${df#$REPO_ROOT/}"
        cp "$TMPDIR/$rel" "$df"
        log "wrote $df"
    done
    log ""
    log "next: docker compose build && docker compose --profile setup up -d --force-recreate"
}

case "$MODE" in
    check)
        log "(check mode) not writing changes"
        ;;
    apply)
        apply_changes
        ;;
    ask)
        echo
        read -rp "Apply changes? [y/N] " ans
        if [[ "$ans" =~ ^[Yy] ]]; then apply_changes; else log "no changes written"; fi
        ;;
esac
