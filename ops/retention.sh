#!/usr/bin/env bash
# DarkWatch — retention enforcement
# Run nightly via cron:
#   0 3 * * * /opt/darkwebapp/ops/retention.sh >> /var/log/darkwatch-retention.log 2>&1

set -euo pipefail

DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"
LOOT="$DATA_ROOT/darkwatch/loot"
NOW="$(date -u +%FT%TZ)"

log() { printf '[%s] %s\n' "$NOW" "$*"; }

[[ -d "$LOOT" ]] || { log "no loot dir at $LOOT — nothing to do"; exit 0; }

SCREENSHOT_DAYS="${RETENTION_SCREENSHOT_DAYS:-90}"
PAGE_DAYS="${RETENTION_PAGE_DAYS:-90}"
REPORT_DAYS="${RETENTION_REPORT_DAYS:-365}"

prune() {
    local subdir="$1" days="$2" pattern="$3"
    [[ -d "$LOOT/$subdir" ]] || return 0
    local before count
    before=$(find "$LOOT/$subdir" -name "$pattern" -type f | wc -l)
    find "$LOOT/$subdir" -name "$pattern" -type f -mtime "+$days" -print -delete | while read -r f; do
        sha="$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || echo unknown)"
        log "PURGED $subdir: $f sha256=$sha (>$days days)"
    done || true
    local after
    after=$(find "$LOOT/$subdir" -name "$pattern" -type f | wc -l)
    count=$(( before - after ))
    log "$subdir: $before -> $after files ($count purged, $days-day window)"
}

log "retention run start (data_root=$DATA_ROOT)"
prune screenshots "$SCREENSHOT_DAYS" "*.png"
prune screenshots "$SCREENSHOT_DAYS" "*.jpg"
prune pages       "$PAGE_DAYS"       "*.html"
prune reports     "$REPORT_DAYS"     "*.json"
prune reports     "$REPORT_DAYS"     "*.txt"
log "retention run done"
