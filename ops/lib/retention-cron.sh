# shellcheck shell=bash
# DarkWatch — install the nightly ops/retention.sh cron job. Source it; it
# only defines functions. Used by both ops/install.sh and ops/deploy.sh:
# existing VMs never rerun install.sh, so deploy must install it too.
# Callers define log and warn. Needs root.

# install_retention_cron REPO_ROOT DATA_ROOT
# Writes /etc/cron.d/darkwatch-retention (DW_CRON_DIR overrides the
# directory, for tests) and then removes the manual crontab line older
# RUNBOOKs had operators add (any root crontab line matching
# /ops/retention\.sh), keeping every other job. Idempotent; never fails, so
# a cron problem cannot stop a deploy.
install_retention_cron() {
    local repo_root="$1" data_root="$2"
    local dir="${DW_CRON_DIR:-/etc/cron.d}"
    # No dot in the name: cron skips files in cron.d whose name has one.
    local file="$dir/darkwatch-retention"
    local script="$repo_root/ops/retention.sh"

    if [[ ! -d "$dir" ]]; then
        warn "$dir does not exist (is cron installed?): nightly retention not scheduled; run $script by hand or from your scheduler"
        return 0
    fi
    # cron would split the command at a % and can't take a newline.
    if [[ "$script$data_root" == *[%$'\n']* ]]; then
        warn "repo or data path contains '%' or a newline: nightly retention not scheduled"
        return 0
    fi

    # cron's default PATH (/usr/bin:/bin) may not reach docker.
    local path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" docker_dir
    docker_dir="$(dirname "$(command -v docker 2>/dev/null || echo /usr/bin/docker)")"
    [[ ":$path:" == *":$docker_dir:"* ]] || path="$docker_dir:$path"

    # Run through bash: a checkout without exec bits (core.fileMode=false,
    # a copied tree) would otherwise fail every night with only a log line.
    local body
    body="# DarkWatch nightly retention. Rewritten by every ops/deploy.sh run from
# ops/lib/retention-cron.sh; set the RETENTION_* windows in $data_root/env.
SHELL=/bin/bash
PATH=$path
DARKWEBAPP_DATA_ROOT=$data_root
17 3 * * * root /bin/bash $(printf '%q' "$script") >> /var/log/darkwatch-retention.log 2>&1
"
    if ! printf '%s' "$body" | cmp -s - "$file" \
            || [[ "$(stat -c %a "$file")" != 644 ]]; then
        local tmp
        # Written beside the target, then renamed: cron never reads a
        # half-written file. The temp name has a dot, so cron skips it.
        if tmp="$(mktemp "$dir/.darkwatch-retention.XXXXXX")" \
                && printf '%s' "$body" > "$tmp" && chmod 0644 "$tmp" \
                && mv -f "$tmp" "$file"; then
            log "installed $file (nightly ops/retention.sh)"
        else
            [[ -n "${tmp:-}" ]] && rm -f "$tmp"
            warn "could not write $file: nightly retention not scheduled"
            return 0
        fi
    fi

    # Only now that the cron.d job exists: drop the legacy crontab line, so
    # retention neither runs twice nor stops running.
    command -v crontab >/dev/null 2>&1 || return 0
    local current kept
    current="$(crontab -l 2>/dev/null)" || return 0     # no crontab
    grep -q '/ops/retention\.sh' <<<"$current" || return 0
    kept="$(grep -v '/ops/retention\.sh' <<<"$current" || true)"
    if { [[ -z "$kept" ]] || printf '%s\n' "$kept"; } | crontab -; then
        log "removed the old ops/retention.sh line from root's crontab (now in $file)"
    else
        warn "could not remove the old ops/retention.sh line from root's crontab: run 'sudo crontab -e' and delete it, or retention runs twice"
    fi
}
