#!/usr/bin/env bash
# DarkWatch — image digest pinner.
#
# Pulls the third-party images currently referenced by tag in
# docker-compose.yml, captures the SHA256 digest of each, and rewrites the
# compose file so that next deploy uses image@sha256:<digest>.
#
# Run on the VM (where the docker daemon lives):
#   sudo ./ops/pin-images.sh           # pins, prints diff, requires confirmation
#   sudo ./ops/pin-images.sh --apply   # pins + writes (no prompt)
#   sudo ./ops/pin-images.sh --check   # dry-run; show what would change
#
# Re-run after every monthly upgrade. Commit the resulting compose file
# change so the deploy is reproducible.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE="$REPO_ROOT/docker-compose.yml"

MODE=ask
case "${1:-}" in
    --apply) MODE=apply ;;
    --check) MODE=check ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    "") ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

log()  { printf '\033[1;36m[pin-images]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[pin-images WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pin-images ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[[ -f "$COMPOSE" ]] || fail "no docker-compose.yml at $COMPOSE"
command -v docker >/dev/null || fail "docker not in PATH"

# ─── Find tagged images in compose ─────────────────────────────────────────
# Skip:
#   - locally-built images (look up by `build:` clause; we don't pin those —
#     they're built from this repo's source)
#   - images already pinned to @sha256:...

mapfile -t TARGETS < <(
    awk '
      /^[[:space:]]*build:/                      { in_build = 1; next }
      /^[[:space:]]*[a-zA-Z]/ && in_build        { in_build = 0 }
      /^[[:space:]]*image:[[:space:]]+/ && !in_build {
          sub(/^[[:space:]]*image:[[:space:]]+/, "")
          # Strip trailing comment FIRST (comments may contain @sha256:
          # in instructional text — must not confuse the pinned-check).
          sub(/[[:space:]]*#.*/, "")
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
          # Skip already-pinned (the actual ref contains @sha256:)
          if ($0 ~ /@sha256:/) next
          # Skip our local images
          if ($0 ~ /:local$/) next
          print
      }
    ' "$COMPOSE"
)

if (( ${#TARGETS[@]} == 0 )); then
    log "no unpinned third-party images in $COMPOSE — nothing to do"
    exit 0
fi

log "images to pin:"
for t in "${TARGETS[@]}"; do echo "    $t"; done

# ─── Pull each image, capture digest ───────────────────────────────────────
declare -A NEW_REF
for tag in "${TARGETS[@]}"; do
    log "pulling $tag"
    docker pull --quiet "$tag" >/dev/null
    digest="$(docker inspect --format='{{index .RepoDigests 0}}' "$tag" 2>/dev/null || true)"
    if [[ -z "$digest" || "$digest" == "<no value>" ]]; then
        warn "no digest captured for $tag (image not pulled from a registry?)"
        continue
    fi
    # digest looks like: linuxserver/wireguard@sha256:abc...
    # We want the same form back.
    NEW_REF["$tag"]="$digest"
    log "  → $digest"
done

# ─── Build a sed expression set ────────────────────────────────────────────
TMP="$(mktemp)"
cp "$COMPOSE" "$TMP"
for tag in "${!NEW_REF[@]}"; do
    new="${NEW_REF[$tag]}"
    # Escape any awkward chars (slashes are common)
    esc_old=$(printf '%s' "$tag" | sed 's|[\/&]|\\&|g')
    esc_new=$(printf '%s' "$new" | sed 's|[\/&]|\\&|g')
    sed -i.bak "s|image:[[:space:]]\+${esc_old}\$|image: ${esc_new}|" "$TMP" 2>/dev/null || true
    # Also handle lines with trailing comments
    sed -i.bak "s|image:[[:space:]]\+${esc_old}\([[:space:]]\+#.*\)\$|image: ${esc_new}\1|" "$TMP" 2>/dev/null || true
done
rm -f "$TMP.bak"

if diff -q "$COMPOSE" "$TMP" >/dev/null; then
    warn "no changes generated (sed may not have matched — investigate manually)"
    rm -f "$TMP"
    exit 1
fi

log ""
log "diff to apply:"
echo "─────────────────────────────────────"
# `diff` exits 1 on difference, which trips `set -o pipefail` → script
# dies before the case statement below. `|| true` prevents that.
{ diff -u "$COMPOSE" "$TMP" || true; } | head -80
echo "─────────────────────────────────────"

# ─── Apply or prompt ───────────────────────────────────────────────────────
case "$MODE" in
    check)
        log "(check mode) not writing changes"
        rm -f "$TMP"
        ;;
    apply)
        cp "$TMP" "$COMPOSE"
        rm -f "$TMP"
        log "wrote $COMPOSE"
        log "next: docker compose pull && docker compose up -d --force-recreate"
        ;;
    ask)
        echo
        read -rp "Apply changes to $COMPOSE? [y/N] " ans
        if [[ "$ans" =~ ^[Yy] ]]; then
            cp "$TMP" "$COMPOSE"
            rm -f "$TMP"
            log "wrote $COMPOSE"
            log "next: docker compose pull && docker compose up -d --force-recreate"
        else
            log "no changes written"
            rm -f "$TMP"
        fi
        ;;
esac
