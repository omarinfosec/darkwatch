#!/usr/bin/env bash
# Exercise ops/retention.sh and ops/lib/retention-cron.sh with docker and
# crontab stubbed: file pruning (tg-media avatars kept), the guarded
# database step and its exit codes, and the cron.d install that replaces the
# legacy crontab line. No root needed:
#   bash tests/retention/check.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
ok()  { echo "ok   $*"; pass=$((pass + 1)); }
die() { echo "FAIL $*" >&2; [[ -f "$work/out" ]] && sed 's/^/    | /' "$work/out" >&2; exit 1; }

# ─── Stubs ──────────────────────────────────────────────────────────────────
# docker: `inspect` prints STUB_RUNNING (absent container: fails, as docker
# does); `exec` is logged and exits STUB_EXEC_RC.
mkdir -p "$work/bin"
cat > "$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_LOG"
case "$1" in
    inspect) [[ -n "${STUB_RUNNING:-}" ]] || { echo "Error: No such object: darkwatch" >&2; exit 1; }
             echo "$STUB_RUNNING" ;;
    exec)    exit "${STUB_EXEC_RC:-0}" ;;
esac
EOF
# crontab: the "installed" crontab is the file $CRONTAB_FILE.
cat > "$work/bin/crontab" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    -l) [[ -f "$CRONTAB_FILE" ]] || { echo "no crontab for root" >&2; exit 1; }
        cat "$CRONTAB_FILE" ;;
    -)  cat > "$CRONTAB_FILE" ;;
    *)  echo "crontab stub: unsupported $*" >&2; exit 2 ;;
esac
EOF
chmod 755 "$work/bin/docker" "$work/bin/crontab"
export PATH="$work/bin:$PATH" DOCKER_LOG="$work/docker.log" CRONTAB_FILE="$work/crontab"

# ─── retention.sh ───────────────────────────────────────────────────────────
D="$work/data"; L="$D/darkwatch/loot"
seed() {   # old (400 days) and new files in every pruned dir, plus avatars
    rm -rf "$D"
    mkdir -p "$L"/{screenshots,thumbnails,pages,reports} "$L"/tg-media/{chan,channels,users}
    local f
    for f in screenshots/old.png thumbnails/old.jpg pages/old.html reports/old.json \
             tg-media/chan/old.mp4 "tg-media/chan/odd name" tg-media/channels/old.jpg tg-media/users/old.jpg; do
        echo old > "$L/$f"; touch -d '400 days ago' "$L/$f"
    done
    for f in screenshots/new.png thumbnails/new.jpg pages/new.html reports/new.json \
             tg-media/chan/new.mp4 tg-media/channels/new.jpg tg-media/users/new.jpg; do
        echo new > "$L/$f"
    done
    printf 'TOR_CONTROL_PASSWORD=x\n' > "$D/env"
}
run() {   # extra args to retention.sh; sets rc
    : > "$DOCKER_LOG"
    set +e
    DARKWEBAPP_DATA_ROOT="$D" bash "$repo/ops/retention.sh" "$@" > "$work/out" 2>&1
    rc=$?
    set -e
}
left() { (cd "$L" && find . -type f | sort | tr '\n' ' '); }

seed
run
[[ $rc -eq 0 ]] || die "darkwatch absent: retention.sh exited $rc, want 0"
grep -q "darkwatch is not running: database retention skipped" "$work/out" || die "no warning for a stopped darkwatch"
grep -q '^exec' "$DOCKER_LOG" && die "docker exec ran although darkwatch is not running"
want="./pages/new.html ./reports/new.json ./screenshots/new.png ./tg-media/chan/new.mp4 ./tg-media/channels/new.jpg ./tg-media/channels/old.jpg ./tg-media/users/new.jpg ./tg-media/users/old.jpg ./thumbnails/new.jpg "
[[ "$(left)" == "$want" ]] || die "files left: $(left)"
grep -q "PURGED tg-media: $L/tg-media/chan/odd name sha256=[0-9a-f]\{64\} " "$work/out" || die "tg-media purge not logged with its hash"
ok "darkwatch absent: exits 0, still prunes old files (tg-media too, avatars in channels/ and users/ kept)"

seed
STUB_RUNNING=false run
[[ $rc -eq 0 ]] || die "darkwatch stopped: exited $rc"
grep -q "database retention skipped" "$work/out" || die "darkwatch stopped: no skip warning"
grep -q '^exec' "$DOCKER_LOG" && die "darkwatch stopped: docker exec ran"
[[ "$(left)" == "$want" ]] || die "darkwatch stopped: files left: $(left)"
ok "darkwatch stopped (Running=false): exits 0, files pruned, database step skipped"

seed
STUB_RUNNING=true run
[[ $rc -eq 0 ]] || die "darkwatch running: exited $rc"
[[ "$(grep '^exec' "$DOCKER_LOG")" == "exec -w /app darkwatch python darkwatch.py --retention" ]] \
    || die "database step: $(grep '^exec' "$DOCKER_LOG" || echo none)"
purged_at="$(grep -n 'PURGED' "$work/out" | tail -1 | cut -d: -f1)"
db_at="$(grep -n 'database: docker exec' "$work/out" | cut -d: -f1)"
[[ -n "$purged_at" && -n "$db_at" && "$purged_at" -lt "$db_at" ]] || die "files must be pruned before the database step"
[[ "$(left)" == "$want" ]] || die "darkwatch running: files left: $(left)"
ok "darkwatch running: files pruned first, then darkwatch.py --retention runs inside it"

seed
printf 'RETENTION_MONITOR_EVENTS_DAYS=90\nRETENTION_TEXT_SNAPSHOT_DAYS=0\nRETENTION_TG_MEDIA_DAYS=500\n' >> "$D/env"
STUB_RUNNING=true run --dry-run
[[ $rc -eq 0 ]] || die "dry run: exited $rc"
grep -q -- "^exec -w /app darkwatch python darkwatch.py --retention --dry-run --monitor-events-days 90 --text-snapshot-days 0$" "$DOCKER_LOG" \
    || die "dry run / env windows not passed on: $(grep '^exec' "$DOCKER_LOG" || echo none)"
[[ "$(find "$L" -type f | wc -l)" == 15 ]] || die "dry run removed files: $(left)"
grep -q "WOULD PURGE pages: $L/pages/old.html" "$work/out" || die "dry run: pages not listed"
grep -q "WOULD PURGE tg-media" "$work/out" && die "RETENTION_TG_MEDIA_DAYS=500 from the env file not applied"
ok "--dry-run deletes nothing and is passed on; windows come from the env file"

seed
STUB_RUNNING=true STUB_EXEC_RC=1 run
[[ $rc -eq 3 ]] || die "database failure: exited $rc, want 3"
grep -q "database retention failed (exit 1)" "$work/out" || die "database failure not reported"
[[ "$(left)" == "$want" ]] || die "database failure: files left: $(left)"
grep -q "retention run done" "$work/out" || die "database failure: run did not finish"
ok "database step fails: warning, exit 3, files still pruned"

seed
echo "RETENTION_PAGE_DAYS=ninety" >> "$D/env"
run
[[ $rc -eq 2 ]] || die "bad window: exited $rc, want 2"
[[ "$(find "$L" -type f | wc -l)" == 15 ]] || die "bad window: files removed"
ok "a window that is not a number stops before deleting anything (exit 2)"

seed; rm -rf "$L"
STUB_RUNNING=true run
[[ $rc -eq 0 ]] || die "no loot dir: exited $rc"
grep -q '^exec' "$DOCKER_LOG" || die "no loot dir: database step skipped"
ok "no loot dir: files skipped, database step still runs"

# A file that goes between find and its hash (a URL deleted in the
# dashboard, an overlapping run): sha256sum fails, the run goes on.
seed
mkdir -p "$work/shabin"
cat > "$work/shabin/sha256sum" <<'EOF'
#!/usr/bin/env bash
case "$2" in
    */pages/old.html) rm -f -- "$2"; echo "sha256sum: $2: No such file or directory" >&2; exit 1 ;;
esac
exec "$REAL_SHA256SUM" "$@"
EOF
chmod 755 "$work/shabin/sha256sum"
REAL_SHA256SUM="$(command -v sha256sum)" PATH="$work/shabin:$PATH" STUB_RUNNING=true run
[[ $rc -eq 0 ]] || die "file gone before its hash: exited $rc, want 0"
grep -q "PURGED pages: $L/pages/old.html sha256=unknown " "$work/out" || die "file gone before its hash: not logged as purged with sha256=unknown"
[[ "$(left)" == "$want" ]] || die "file gone before its hash: files left: $(left)"
grep -q '^exec' "$DOCKER_LOG" || die "file gone before its hash: database step skipped"
ok "a file gone before its hash: logged sha256=unknown, the other prunes and the database step still run"

# ─── retention-cron.sh ──────────────────────────────────────────────────────
C="$work/cron.d"
install_cron() {   # sets rc; output in $work/out
    set +e
    DW_CRON_DIR="$C" bash -c '
        set -euo pipefail
        log()  { echo "LOG $*"; }
        warn() { echo "WARN $*" >&2; }
        source "$1/ops/lib/retention-cron.sh"
        install_retention_cron "$1" "$2"' _ "$repo" "$D" > "$work/out" 2>&1
    rc=$?
    set -e
}
mkdir -p "$C"
cat > "$CRONTAB_FILE" <<EOF
# m h dom mon dow command
0 3 * * * /opt/darkwebapp/ops/retention.sh >> /var/log/darkwatch-retention.log 2>&1
*/5 * * * * /usr/local/bin/unrelated-job --flag
0 4 * * * DARKWEBAPP_DATA_ROOT=/srv/dw $repo/ops/retention.sh
EOF
install_cron
[[ $rc -eq 0 ]] || die "cron install exited $rc"
install_cron
[[ $rc -eq 0 ]] || die "second cron install exited $rc"
grep -q '^LOG installed' "$work/out" && die "an unchanged cron file must not be rewritten"
[[ "$(ls -A "$C")" == "darkwatch-retention" ]] || die "cron dir holds: $(ls -A "$C" | tr '\n' ' ')"
f="$C/darkwatch-retention"
[[ "$(grep -c 'retention\.sh' "$f")" == 1 ]] || die "want exactly one cron.d entry"
[[ "$(stat -c %a "$f")" == 644 ]] || die "cron file mode $(stat -c %a "$f"), want 644"
[[ "$(tail -c1 "$f" | od -An -c | tr -d ' ')" == '\n' ]] || die "cron file has no trailing newline"
grep -qx "SHELL=/bin/bash" "$f" || die "no SHELL=/bin/bash"
grep -qx "DARKWEBAPP_DATA_ROOT=$D" "$f" || die "no DARKWEBAPP_DATA_ROOT=$D"
path_line="$(grep '^PATH=' "$f")" || die "no PATH line"
docker_dir="$(dirname "$(command -v docker)")"
[[ ":${path_line#PATH=}:" == *":$docker_dir:"* && ":${path_line#PATH=}:" == *":/usr/bin:"* ]] \
    || die "PATH does not reach docker ($docker_dir): $path_line"
grep -qE "^[0-9]+ [0-9]+ \* \* \* root /bin/bash $repo/ops/retention\.sh >> /var/log/darkwatch-retention\.log 2>&1$" "$f" \
    || die "job line: $(grep retention.sh "$f")"
[[ "$(grep -c 'retention\.sh' "$CRONTAB_FILE" || true)" == 0 ]] || die "legacy crontab lines left: $(cat "$CRONTAB_FILE")"
grep -qxF "*/5 * * * * /usr/local/bin/unrelated-job --flag" "$CRONTAB_FILE" || die "unrelated job removed"
grep -qxF "# m h dom mon dow command" "$CRONTAB_FILE" || die "crontab comment removed"
ok "cron install, twice: one cron.d entry (root, SHELL, PATH with docker, data root, real path, 0644, newline); legacy crontab lines gone, unrelated job kept"

chmod 600 "$f"
install_cron
[[ "$(stat -c %a "$f")" == 644 ]] || die "a wrong mode must be fixed"
rm -f "$CRONTAB_FILE"
install_cron
[[ $rc -eq 0 && ! -e "$CRONTAB_FILE" ]] || die "no crontab: rc=$rc"
ok "a wrong mode is fixed; no root crontab is fine"

echo "0 3 * * * $repo/ops/retention.sh" > "$CRONTAB_FILE"
install_cron
[[ $rc -eq 0 && -f "$CRONTAB_FILE" && ! -s "$CRONTAB_FILE" ]] || die "a crontab with only the legacy line must end up empty"
ok "a crontab holding only the legacy line ends up empty"

rm -rf "$C"
echo "0 3 * * * $repo/ops/retention.sh" > "$CRONTAB_FILE"
install_cron
[[ $rc -eq 0 ]] || die "missing cron dir must not fail (rc=$rc)"
grep -q "^WARN $C does not exist" "$work/out" || die "missing cron dir: no warning"
[[ ! -e "$C" ]] || die "missing cron dir was created"
grep -q 'retention\.sh' "$CRONTAB_FILE" || die "the legacy line must stay while no cron.d job replaces it"
ok "missing cron dir: warning only, and the legacy crontab line stays"

# Both installers call it: existing VMs only ever run deploy.sh.
for f in install deploy; do
    grep -qx '[[:space:]]*install_retention_cron "$REPO_ROOT" "$DATA_ROOT"' "$repo/ops/$f.sh" \
        || die "ops/$f.sh does not call install_retention_cron"
done
ok "install.sh and deploy.sh both install the retention cron"

echo "retention checks OK ($pass)"
