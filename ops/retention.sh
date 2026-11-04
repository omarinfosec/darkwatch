#!/usr/bin/env bash
# DarkWatch — retention enforcement
# Runs nightly from /etc/cron.d/darkwatch-retention, which ops/deploy.sh (and
# ops/install.sh) install and keep up to date: see ops/lib/retention-cron.sh.
# By hand, as root:
#   sudo ./ops/retention.sh [--dry-run]
#
# 1. Prunes old files under loot/: screenshots, thumbnails, saved pages,
#    reports and downloaded Telegram media (never the channel and user
#    avatars under tg-media/channels/ and tg-media/users/).
# 2. Then, if the darkwatch container is running, applies the database
#    retention inside it (darkwatch.py --retention): deletes old monitor
#    events, sets old page text snapshots to NULL (the newest of each page
#    stays), sets the paths of pruned files to NULL and checkpoints the WAL.
#    Page and finding rows are never deleted.
# Windows, in days, from the env file (else the environment):
#   RETENTION_SCREENSHOT_DAYS (90), RETENTION_PAGE_DAYS (90),
#   RETENTION_REPORT_DAYS (365), RETENTION_TG_MEDIA_DAYS (180);
#   RETENTION_MONITOR_EVENTS_DAYS, RETENTION_TEXT_SNAPSHOT_DAYS (default:
#   darkwatch's config "retention", 180 and 365; 0 turns the step off).
#   A file window of 0 is NOT off: it removes every file older than a day.
# Exit status: 0 when done, also when darkwatch is not running (the database
# step is skipped with a warning); 3 when the database step failed (the
# files were still pruned); 2 on bad arguments or windows.
# Nothing it deletes or sets to NULL can be undone.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

DATA_ROOT="${DARKWEBAPP_DATA_ROOT:-/var/lib/darkwebapp}"
LOOT="$DATA_ROOT/darkwatch/loot"
NOW="$(date -u +%FT%TZ)"

PURGED="purged"; RUN_NOTE=""
if (( DRY_RUN )); then PURGED="would be purged"; RUN_NOTE=", dry run: nothing is changed"; fi

log()  { printf '[%s] %s\n' "$NOW" "$*"; }
warn() { printf '[%s] WARN %s\n' "$NOW" "$*" >&2; }

days_val() {   # KEY DEFAULT — a whole number of days, or exit 2
    local v
    v="$(env_val "$1" "$2")"
    [[ -z "$v" || "$v" =~ ^[0-9]+$ ]] || { warn "$1 must be a whole number of days (got '$v')"; exit 2; }
    echo "$v"
}
SCREENSHOT_DAYS="$(days_val RETENTION_SCREENSHOT_DAYS 90)"
PAGE_DAYS="$(days_val RETENTION_PAGE_DAYS 90)"
REPORT_DAYS="$(days_val RETENTION_REPORT_DAYS 365)"
TG_MEDIA_DAYS="$(days_val RETENTION_TG_MEDIA_DAYS 180)"
MONITOR_EVENTS_DAYS="$(days_val RETENTION_MONITOR_EVENTS_DAYS "")"
TEXT_SNAPSHOT_DAYS="$(days_val RETENTION_TEXT_SNAPSHOT_DAYS "")"

# prune SUBDIR DAYS PATTERN [SKIP_DIR...] — delete files under loot/SUBDIR
# matching PATTERN and older than DAYS, leaving loot/SUBDIR/SKIP_DIR alone.
prune() {
    local subdir="$1" days="$2" pattern="$3"; shift 3
    local root="$LOOT/$subdir" skip=() d
    [[ -d "$root" ]] || return 0
    for d in "$@"; do skip+=(-path "$root/$d" -prune -o); done
    local before purged=0 f sha
    before="$(find "$root" "${skip[@]}" -name "$pattern" -type f -printf . | wc -c)"
    # Hash BEFORE deleting (hashing after -delete always logged "unknown"),
    # and use NUL-separated names so odd filenames can't break the loop.
    while IFS= read -r -d '' f; do
        if (( DRY_RUN )); then
            log "WOULD PURGE $subdir: $f (>$days days)"
            purged=$((purged + 1))
            continue
        fi
        # Best effort: a file deleted meanwhile (the dashboard's URL delete,
        # an overlapping run) must not abort the run under set -e.
        sha="$(sha256sum -- "$f" 2>/dev/null | awk '{print $1}')" || sha=""
        if rm -f -- "$f"; then
            log "PURGED $subdir: $f sha256=${sha:-unknown} (>$days days)"
            purged=$((purged + 1))
        fi
    done < <(find "$root" "${skip[@]}" -name "$pattern" -type f -mtime "+$days" -print0)
    log "$subdir/$pattern: $before files, $purged $PURGED ($days-day window)"
}

log "retention run start (data_root=$DATA_ROOT$RUN_NOTE)"

# ─── 1. Files ────────────────────────────────────────────────────────────────
# First, and whatever happens to the database step: the files are most of
# the disk use. The database step then clears the paths of what went here.
if [[ -d "$LOOT" ]]; then
    prune screenshots "$SCREENSHOT_DAYS" "*.png"
    prune screenshots "$SCREENSHOT_DAYS" "*.jpg"
    prune pages       "$PAGE_DAYS"       "*.html"
    prune thumbnails  "$SCREENSHOT_DAYS" "*.jpg"
    prune thumbnails  "$SCREENSHOT_DAYS" "*.png"
    prune reports     "$REPORT_DAYS"     "*.json"
    prune reports     "$REPORT_DAYS"     "*.txt"
    # Downloaded message media, one directory per channel. Avatars stay:
    # channels/ (shown for every tracked channel) and users/ (profile photos).
    prune tg-media    "$TG_MEDIA_DAYS"   "*" channels users
else
    warn "no loot dir at $LOOT: no files to prune"
fi

# ─── 2. Database (inside the darkwatch container) ───────────────────────────
db_rc=0
running="$(docker inspect -f '{{.State.Running}}' darkwatch 2>/dev/null || true)"
if [[ "$running" != "true" ]]; then
    warn "darkwatch is not running: database retention skipped (it runs inside the container; the next run catches up)"
else
    db_args=(--retention)
    if (( DRY_RUN )); then db_args+=(--dry-run); fi
    if [[ -n "$MONITOR_EVENTS_DAYS" ]]; then db_args+=(--monitor-events-days "$MONITOR_EVENTS_DAYS"); fi
    if [[ -n "$TEXT_SNAPSHOT_DAYS" ]]; then db_args+=(--text-snapshot-days "$TEXT_SNAPSHOT_DAYS"); fi
    log "database: docker exec darkwatch python darkwatch.py ${db_args[*]}"
    if docker exec -w /app darkwatch python darkwatch.py "${db_args[@]}"; then
        log "database retention done"
    else
        db_rc=$?
        warn "database retention failed (exit $db_rc); the files above were pruned. Check 'docker logs darkwatch' and re-run: sudo $SCRIPT_DIR/retention.sh"
    fi
fi

log "retention run done"
# A distinct status, so cron mail or a wrapper can tell a database failure
# from a clean run.
(( db_rc == 0 )) || exit 3
