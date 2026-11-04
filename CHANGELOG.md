# Changelog

## Unreleased

### Upgrade notes
- Telethon 1.45 upgrades the Telegram login file
  (`/var/lib/darkwebapp/darkwatch/data/telegram.session`) to its version 8
  format the first time it opens it. An older image (Telethon 1.36, v0.3.1
  and earlier) cannot open the file after that: every Telegram call fails
  with `ValueError: too many values to unpack (expected 5)`. Before you
  deploy, stop darkwatch and copy the file, keeping its owner and mode (it is
  the account login, readable only by its owner; keep the copy root-only):
  `sudo docker compose stop darkwatch && sudo cp -p
  /var/lib/darkwebapp/darkwatch/data/telegram.session
  /root/telegram.session.pre-upgrade` (from `/opt/darkwebapp`). The full
  backup in `ops/RUNBOOK.md` includes it; the database-only hot backup does
  not. If you roll back, stop darkwatch, copy the file back with `cp -p`
  before starting the old image, or log in to Telegram again with the QR
  code.

### Upgrades
- Telethon 1.36 → 1.45.0 with python-socks 3.2.1 (both images);
  `async-timeout` is no longer installed (python-socks only needs it on
  Python older than 3.11). cryptg 0.4 → 0.6.0, yara-python 4.5.1 → 4.5.4,
  requests 2.34.2, beautifulsoup4 4.15.0, qrcode 8.2, prometheus-client
  0.26.0; Setup UI: python-multipart 0.0.33, docker 7.2.0.
- `/metrics` now advertises the Prometheus text format as
  `text/plain; version=1.0.0; charset=utf-8` (it was `version=0.0.4`).
  Prometheus accepts both; check any other scraper that matches on the
  header. The header also no longer carries `charset=utf-8` twice.
- The darkwatch image installs cryptg and yara-python from wheels only
  (`pip install --only-binary=cryptg,yara-python`): a pin with no wheel for
  the build platform fails the build instead of trying a source build
  (cryptg's needs Rust, which the image does not have).

### Fixed
- Forum-topic labels on Telegram messages keep working on Telethon 1.45,
  where `GetForumTopicsRequest` lives in `messages` and takes `peer=` (it
  was in `channels` with `channel=`). A failed topic fetch is now logged as
  a warning instead of at debug level; the messages are still stored,
  without topic labels.
- The crawler only follows links whose host ends in `.onion` over http or
  https. It used to accept any link containing `.onion` in the host part,
  such as `<x>.onion.evil.com` or `<x>.onion@evil.com`; those were already
  dropped before fetching because a site crawl stays on the seed host, so
  nothing left the target. A malformed link such as `http://[::1` on a
  page is now skipped; it used to end that site's crawl with an error.

### Internal
- The image smoke test (`tests/images/smoke.sh`) also checks the two native
  wheels: Telethon must pick up cryptg (it silently falls back to slow
  pure-Python AES without it), an AES-IGE round trip must succeed, and a
  YARA rule must compile and match.
- New CI workflow `images` (`.github/workflows/images.yml`) builds the
  darkwatch, setup and tor images and smoke-tests them with the new
  `tests/images/smoke.sh`, every container under `--network none` and a
  timeout: darkwatch imports `darkwatch`, `threat_intel` and `web` and takes
  an offline screenshot (the test checks that the PNG and its thumbnail
  exist and are non-empty, because a failed Firefox launch is only logged);
  setup imports `main` and runs `docker compose version`; tor runs
  `tor --version`. It runs on pushes to main, weekly, and on every pull
  request, skipping the build when a PR changes nothing under `darkwatch/`,
  `setup/`, `tor/` or `tests/images/` or `.github/workflows/images.yml`
  (a rename counts under both its old and new path), so the `images` check
  can be required. Run the smoke tests on a host after a build with
  `sudo bash tests/images/smoke.sh`.
- The darkwatch Dockerfile copies every top-level `*.py` module instead of a
  fixed list, so a new module cannot be left out of the image.
- The Release workflow runs the full CI workflow first (`ci.yml` is now
  callable through `workflow_call`) and publishes only if it passes. A
  manual run is only accepted on `main`; on any other branch both jobs are
  skipped. A pushed tag must point at a commit on `main`
  (`git merge-base --is-ancestor`), otherwise nothing is published. The
  workflow's GITHUB_TOKEN is read-only except in the release job.
- CI runs the test suites on Python 3.13 as well as 3.11 (the images'
  version). The 3.11 checks keep their names (`Tests (darkwatch)`,
  `Tests (setup)`); the new ones are `Tests (darkwatch, Python 3.13)` and
  `Tests (setup, Python 3.13)`, which you can add to the required checks.
  The `datetime.utcnow()` calls, deprecated since Python 3.12, are replaced
  by a naive-UTC `utcnow()` helper in `darkwatch.py`; stored timestamps keep
  their format.
- New CI job `Secret scan (gitleaks)` scans the full git history with
  gitleaks v8.30.1, built from the pinned module version whose `h1:` hash is
  checked first. `.gitleaks.toml` extends gitleaks' default rules and only
  allowlists `setup/tests/test_validators.py` (synthetic WireGuard keys).
- Hash-locked Python dependencies. Each image's hand-pinned direct
  dependencies moved from `requirements.txt` to `requirements.in`
  (`darkwatch/`, `setup/`), and the new `ops/lock-deps.sh` resolves them
  with a pinned uv (0.11.32, `uv pip compile --python-version 3.11
  --python-platform linux --generate-hashes`) into `requirements.lock`:
  every package, transitive ones included, at one version with the SHA-256
  of each of its files. Both Dockerfiles and the CI test jobs install the
  lock with `pip install --require-hashes`, so a file that does not match
  its hash fails the build; CI installs `requirements-dev.txt` (no hashes)
  in its own step. CI fails when a lock is behind its `requirements.in`
  (`ops/lock-deps.sh --check`: every `name==version` there must be in the
  lock), and `tests/lock-deps/check.sh` tests the script with uv stubbed.
  The locks are resolved for x86_64 Linux; they carry the hashes of every
  file of each version, but building the images on arm64 is untested.
  stem and pyaes ship only source archives: those archives are
  hash-checked, the setuptools pip fetches to build them is not. Dependabot
  updates `requirements.in` only; run `./ops/lock-deps.sh` on its PR branch
  (RUNBOOK, "Update Python dependencies").
- New weekly workflow `Dependency audit` runs pip-audit 2.10.1 separately on
  each image's `requirements.lock` (every package the image installs) and
  on `requirements-dev.txt` (also on pull requests that change a
  requirements file, and by hand).
- Dependabot now also opens one weekly grouped PR for the pinned pip
  requirements and one for the Dockerfile base images, limited to new
  digests of the current tags (no major or minor version moves). The
  third-party images in `docker-compose.yml` are pinned by digest only,
  which Dependabot cannot track, so they are not covered yet.
- shellcheck in CI now fails on warnings, not only errors, and also covers
  `darkwatch/scan.sh`. The warnings it found are fixed with no change in
  behaviour (`harden.sh --dry-run` output is identical).
- New `tests/workflows/check.sh` (run in CI) checks the release, CI,
  Dependabot and audit settings above and runs the release job's steps
  against throwaway repositories with `gh` stubbed.
- Regression tests for shipped fixes and the core crawl rules:
  `darkwatch/tests/test_crawl.py` (only the target onion host is fetched,
  Referer only within that host, `max_pages`, `max_depth`, the per-domain
  circuit breaker, the stop event, link extraction); the screenshot browser's
  launch options (Firefox prefs, `socks5h://` to `socks5://`, the dead proxy
  in offline mode) and NEWNYM dialling the resolved ControlPort IP;
  `/loot/tg-media` (sandboxed forced download for `.html`, inline `.png`,
  404 for traversal); the findings, keywords and channel CSV exports and the
  channel zip's `messages.csv`, requested by URL; and Setup's Telegram
  credential check against a fake client (five outcomes, the Tunnel 2 proxy
  passed through). The dashboard test fixture no longer leaks
  `DARKWATCH_CONFIG` and `DARKWATCH_BIND_IP` into later test modules.

## v0.3.1 — 2026-11-04

Fix release. v0.3.0's deploy.sh stopped silently on default installs and
never rebuilt the Setup UI; upgrade as described below.

### Upgrade notes
- From v0.2.0 or v0.3.0, pull first and then deploy:
  `sudo git -C /opt/darkwebapp pull --ff-only && sudo ./ops/deploy.sh` (from
  `/opt/darkwebapp`).
  A v0.2.0 or v0.3.0 `deploy.sh` that does the pull itself keeps running its
  own old code (v0.3.0's exits silently after the build). If you already ran
  plain `deploy.sh`, run it again and check that it prints "deploy complete".
  Then verify: `systemctl is-enabled darkwatch-egress-lockdown` prints
  `enabled`, `sudo grep -c '^TG_SOCKS_PASSWORD=.\+' /var/lib/darkwebapp/env`
  prints 1, and `sudo docker image inspect darkwatch-setup:local -f
  '{{.Created}}'` shows a time after you started this upgrade (not the
  v0.2.0/v0.3.0 install date). From this release on,
  `deploy.sh` restarts itself after a pull, so later upgrades need no extra
  step.
- Take a backup before upgrading; the RUNBOOK has new "Back up and restore"
  and "Roll back a release" sections.
- `deploy.sh` now refuses to run when the repo's `.env` is not a link to
  `/var/lib/darkwebapp/env` (a wrong target, a dangling link or a copied
  file). Fix it with `sudo ln -sfn /var/lib/darkwebapp/env /opt/darkwebapp/.env`.
  `bootstrap.sh` treats the same case as an error instead of a warning.
- `deploy.sh` fails on a hand-placed `wg0.conf` with a `Table` other than
  `auto`, any `FwMark`, or no `AllowedIPs` that includes `0.0.0.0/0`. Pre/Post
  hooks only produce a warning.
- The first deploy after upgrading builds the tor and Setup UI images too, so
  it takes longer; later builds come from the cache.
- The first deploy also recreates the `darknet` network once (it is now
  IPv4-only), so every container, a running Setup UI included, stops briefly.
  Start the Setup UI again afterwards if you need it.
- After the first deploy, `darkwatch-egress-lockdown.service` runs before
  `docker.service` at boot. After the next reboot, check that
  `systemctl show -p ActiveEnterTimestampMonotonic --value darkwatch-egress-lockdown`
  is non-zero and less than
  `systemctl show -p ExecMainStartTimestampMonotonic --value docker` (the
  RUNBOOK has a snippet). Docker's own `ActiveEnterTimestamp` comes after it
  has restarted the containers, so it cannot show the order.
- The tunnel healthchecks changed, so the first deploy recreates tunnel1 and
  tunnel2, which restarts tor and tg-socks once.
- darkwatch now runs with `dns: 127.0.0.1`, so the first deploy recreates it.
  Afterwards, on Docker 26 or later, `sudo docker exec darkwatch cat
  /etc/resolv.conf` contains the line `# ExtServers: [127.0.0.1]` and no
  `host(`. Leave the new `DARKWATCH_DNS` unset. darkwatch can no longer
  resolve clearnet names itself, so if you run with
  `DARKWATCH_EGRESS_LOCKDOWN=0` (which `alerts.allow_direct` also needs to
  send directly), set `DARKWATCH_DNS` to a real resolver in the env file, or
  direct alerts and the in-app IP-leak check fail. Set a real resolver only
  with the lockdown off: while it is on, `verify-egress.sh` and `deploy.sh`
  fail on any other `DARKWATCH_DNS`.
- The Setup UI rejects a WireGuard config without a `DNS =` line. Check that
  a hand-placed tunnel2 `wg0.conf` has one; `verify-egress.sh` warns when
  tunnel2 still resolves through Docker's embedded DNS.
- The first start after upgrading adds three indexes on the `pages` table
  (`content_hash`, `(url_id, scanned_at)`, `(url_id, page_url)`); this takes
  about a second per 150k pages. They are not UNIQUE, so a rolled-back
  release still runs against the database.
- Every `docker compose` command now needs `TOR_CONTROL_PASSWORD` (tor gets
  it by variable substitution instead of the whole env file) and fails with
  "TOR_CONTROL_PASSWORD unset: is the repo .env linked to the operator env
  file?" without it. `install.sh` generates it and `deploy.sh` already
  requires it; run plain `docker compose` from `/opt/darkwebapp` with the
  `.env` link in place, or pass `--env-file /var/lib/darkwebapp/env`. The
  first deploy recreates tor and darkwatch.

### Security
- The tunnel kill switch also drops new connections that arrive through
  WireGuard (`DW_KS_IN` in `INPUT`, IPv4 and IPv6), so the VPN side can no
  longer reach Tor's SOCKS and control ports. Replies to the tunnel's own
  connections still get in. The tunnel healthchecks and `verify-egress.sh`
  require it.
- darkwatch's DNS lookups can no longer be answered by the host. Without a
  `dns:` setting, Docker sent darkwatch's non-service lookups to the host's
  resolvers, and a loopback one (dnsmasq, unbound, bind on 127.0.0.1) was
  queried from the host's namespace, past the egress lockdown. darkwatch now
  has `dns: ["${DARKWATCH_DNS:-127.0.0.1}"]`: Docker dials that from
  darkwatch's own namespace, where nothing answers, so clearnet lookups fail
  in milliseconds while `tunnel1` and `tunnel2` still resolve. The tunnels
  keep the host's DNS, which hostname Endpoints need.
- The Setup UI requires a `DNS =` line in WireGuard configs, so tg-socks
  resolves Telegram's names through the VPN instead of Docker's embedded DNS.
- The dashboard's `ip_leak` gate fails when the egress lockdown is missing.
  It passed whenever the direct IP lookup failed, and with darkwatch's DNS
  isolated that lookup always fails, lockdown or not. With the lockdown on it
  now opens TCP connections to `1.1.1.1:443` and `9.9.9.9:443` (2 s timeout,
  no DNS, independent of the Tor check) and passes only when both time out
  or fail with no route or `EPERM`. A completed connection fails the gate
  with "run sudo ./ops/egress-lockdown.sh"; `ECONNREFUSED` fails it too and
  says so, since the lockdown drops and never refuses. The detail shows each
  probe's errno. Both probes run in parallel with the other health checks,
  so with the lockdown on the gate takes about 2 s.
  With `DARKWATCH_EGRESS_LOCKDOWN=0` it keeps the old, weaker comparison of
  the Tor exit IP with the direct IP.
- Saves in the Setup UI recreate containers with the current env file. The
  Setup UI passed its own environment, loaded from the env file when the
  Setup UI was created, to `docker compose`, which prefers it over
  `--env-file`. A save could then put darkwatch back on an old
  `DARKWATCH_IP` outside the lockdown rule, or start tg-socks and tor with an
  old `TG_SOCKS_PASSWORD` or `TOR_CONTROL_PASSWORD`. It now passes only
  `PATH`, `HOME`, locale, `TZ`, `TMPDIR`, `DOCKER_*`, the proxy variables and
  its host paths.
- The dashboard's request guard also covers GET requests. It checked only
  writes, so a page the operator visited could trigger a live Telegram user
  lookup (`<img src=".../api/telegram/user/...?download=1">`) or an export
  through the operator's browser. Any request with `Sec-Fetch-Site:
  cross-site` now gets 403, except a top-level navigation to `/` (a link to
  the dashboard). An `Origin` header on any method must name an allowed host,
  and `Origin: null` is rejected. Same-origin, same-site and header-less
  requests (curl, healthchecks, Prometheus) are unaffected. The user lookup's
  `photo_limit` is clamped to 1-50 and a non-number is a 400, not a 500.
- The dashboard and the Setup UI send `X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin` on
  every response, so neither can be framed (clickjacking). Dashboard
  `/api/*` responses (findings, Telegram data, exports, screenshots) and all
  Setup UI responses except `/static/` are `Cache-Control: no-store`.
  Downloaded Telegram media keeps its own sandbox CSP.
- Failed alerts no longer log the Telegram bot token or webhook secrets.
  requests/urllib3 quote the target URL or its path in their errors ("Max
  retries exceeded with url: /bot<token>/sendMessage"), and those went to the
  container log at ERROR, percent-encoded when the token or webhook held a
  space, a newline or non-ASCII. Alert errors now keep only the scheme and
  host and name the exception type (`ConnectionError`, `InvalidURL`...);
  errors other than connection failures (an invalid or scheme-less URL, a
  read timeout) are scrubbed too and are not retried on the next route. If alerts ever
  failed and the logs left the VM, rotate the bot token (BotFather
  `/revoke`) and the Slack/Discord webhooks.
- tor gets only `TOR_CONTROL_PASSWORD`, not the whole env file (alert tokens,
  Telegram credentials, `SETUP_AUTH_TOKEN`), and darkwatch gets
  `SETUP_AUTH_TOKEN` blanked; only the Setup UI has the Setup UI's token.
- The Telegram session file (a full login to the account) is set to 0600
  whenever a client is built and after every login, including the QR login
  with a 2FA password, which left it at the umask's 0644. Existing 0644 files
  are fixed on the next Telegram call.

### Fixed
- `verify-egress.sh` checks that are real:
  - The direct-egress check (5b) requires the lockdown rule for the address
    darkwatch actually has (from `docker inspect`) and probes the IP literal
    `http://1.1.1.1`, with the host as positive control ("inconclusive" when
    the host can't connect either). It used to probe `https://api.ipify.org`
    only; with darkwatch's DNS isolated that name never resolves, so the
    probe would pass with no lockdown at all. It is skipped when
    `DARKWATCH_EGRESS_LOCKDOWN=0` (env file or environment), which it read
    from the env file only.
  - The DNS check (6) passed on any resolv.conf with `127.0.0.11`, including
    a leaking one. It now fails, unless `DARKWATCH_EGRESS_LOCKDOWN=0`, when
    darkwatch's resolv.conf shows a `host(` upstream or an `ExtServers` other
    than `[127.0.0.1]`, or when `example.com` resolves inside darkwatch. It
    (and `deploy.sh`, even without tunnels or with `--no-egress-check`)
    fails when `DARKWATCH_DNS` is set to anything but 127.0.0.1 while the
    lockdown is on, since the dropped resolver would stall darkwatch's
    lookups without a leak to detect. It also fails when `tunnel1` / `tunnel2` don't resolve there, and warns when
    tunnel2 resolves through Docker's embedded DNS while Telegram is checked.
    With `DARKWATCH_EGRESS_LOCKDOWN=0` it (and `deploy.sh`) warns when
    `DARKWATCH_DNS` is unset, since darkwatch then can't resolve clearnet
    names.
  - The Telegram exit IP is compared with the host's own IP, only when both
    answers are IPv4 addresses (an error page only warns).
- Tunnels with a hostname `Endpoint` (as the Setup UI's example shows) never
  completed a handshake since v0.3.0: once the kill switch was on, the name
  could not be resolved. The kill switch now resolves hostname Endpoints
  while egress is still open and pins them in the container's `/etc/hosts`,
  using the IPv4 address even for names that also have an IPv6 one (Alpine's
  `getent hosts` returns only the IPv6 address, so it asks `nslookup -type=a`
  first).
  An Endpoint that doesn't resolve is logged as
  `[killswitch] could not resolve endpoint` and the switch is applied anyway;
  `deploy.sh`'s failure hint names that line.
- `deploy.sh` restarts itself once after a `git pull` that changes the code,
  so the rest of the deploy runs the new script instead of the old one bash
  had already loaded.
- `deploy.sh` exited silently after the build when the env file had no
  `DARKNET_SUBNET=` line (the default), so the stack never started and the
  egress lockdown and its systemd unit were never installed.
- `deploy.sh` builds every locally built image (darkwatch, tor, setup), not
  only the enabled profiles'. Upgraded VMs no longer keep running an old Setup
  UI, and saving Tunnel 1 in the Setup UI no longer fails on a fresh install
  for want of the tor image. A running Setup UI is refreshed onto the new
  image; a stopped one stays stopped.
- Every compose call in `deploy.sh` passes `--env-file /var/lib/darkwebapp/env`,
  so a wrong `.env` link can no longer put darkwatch on a different address
  from the one the egress lockdown restricts.
- `install.sh` no longer exits when the env file lacks `SETUP_AUTH_TOKEN` or
  `DARKWATCH_BIND_IP`.
- The Setup UI rejects a WireGuard config with no `AllowedIPs` line, as
  `deploy.sh` already did, instead of saving it and having the next deploy
  refuse it.
- A failed refresh of a running Setup UI only warns; it no longer stops
  `deploy.sh` before the health wait and the egress checks.
- `deploy.sh` checks that the tunnel kill switch is executable, and its
  "compose up failed" hint points at the `custom-init` / `killswitch` logs.
- The documented Setup UI command is now
  `docker compose --profile setup up -d --build setup`, so it never starts a
  stale image.
- The egress lockdown is applied before the containers start, on deploy and
  at boot: `deploy.sh` applies it and installs its systemd unit before
  `docker compose up`, and the unit now runs before `docker.service`
  (`WantedBy=docker.service`, after firewalld/ufw) instead of after it, so
  darkwatch no longer runs unrestricted until the rule is in place. The unit
  is installed with `systemctl reenable` (dropping the old
  `multi-user.target` link) and only rewritten when it changed.
- `deploy.sh` checks that the lockdown works: it fails when darkwatch can
  reach `http://1.1.1.1` directly, also with no tunnels configured, using the
  host as a positive control ("inconclusive" when the host can't connect
  either). It warns when `FORWARD` has no jump to `DOCKER-USER`, and when
  `DARKWATCH_EGRESS_LOCKDOWN=0` (read from the env file or the environment,
  like `egress-lockdown.sh`) it warns and skips the probe.
- The `darknet` network is IPv4-only (`enable_ipv6: false`), so a Docker
  daemon that enables IPv6 by default can't give darkwatch a route around the
  IPv4 lockdown rule. `egress-lockdown.sh` and `--status` warn when the
  network has IPv6 anyway.
- Saving Tunnel 1 in the Setup UI before the tor image exists returns 409
  saying the config was saved and to run `sudo ./ops/deploy.sh` (which builds
  the image and starts tunnel1 + tor) instead of a compose build error.
  Tunnel saves run `docker compose up --no-build`, since the Setup UI cannot
  build images. Other image check failures, such as an unreachable Docker
  daemon, still show the compose error.
- A rescan (`/api/rescan`, the auto-rescan) no longer deletes findings. It
  purged every finding on a page URL and re-derived them from each stored
  snapshot's stripped text, so findings from older versions of a page and
  from the raw-HTML pass (attributes, comments, `<meta>`) were lost for good.
  A rescan now only adds findings: rows it matches again keep their
  `occurrence_count` and `last_seen_at` (a raised rule score still raises
  their score and severity, never lowers them), its `findings` count is
  the number of new rows, and it never lowers a page's cached severity. Findings of
  YARA rules that were deleted since are kept as well; delete them in the
  dashboard if you no longer want them. Findings already lost to earlier
  rescans cannot be recovered except from a backup.
- The dashboard no longer freezes on large databases. `pages` had no
  indexes, so `/api/urls`, the findings list and the dedup check run for
  every scanned page and Telegram message each scanned the whole table
  (`/api/urls` took 43 s at realistic Telegram volume; now under 200 ms).

### Internal
- `tests/killswitch` fails when the kill switch script fails (it ignored the
  exit code, which hid an IPv6 failure caused by the `ip` shim returning IPv4
  addresses), checks the IPv4 and IPv6 log lines, the Endpoint pinning (with
  musl- and glibc-like resolvers) and a rerun, and adds a test with darknet
  and VPN peers in their own namespaces. It no longer writes
  `tests/killswitch/.bin/`; delete that directory if an older run left it.
- `ops/lib/common.sh` holds the `env_val` helper shared by `deploy.sh`,
  `egress-lockdown.sh` and `verify-egress.sh`.
- New `tests/ops/check.sh` runs `deploy.sh` and `bootstrap.sh` against
  stubbed docker/systemctl in CI, including a self-update from a local git
  remote, the lockdown order and the direct-egress probe.
- New `tests/egress-lockdown/check.sh` runs `egress-lockdown.sh` against real
  iptables in a network namespace in CI.
- New `tests/verify-egress/check.sh` runs `verify-egress.sh` against stubbed
  docker, iptables and curl in CI; new `tests/compose/check.sh` asserts in CI
  that darkwatch's `dns` is `127.0.0.1` and that no other service sets one.
- `scan_tg_message` links the Telegram message to the page id `add_page`
  returns instead of re-selecting it by content hash outside the database
  lock. New `darkwatch/tests/test_db_integrity.py` checks the query plans
  of the hot `pages` queries and the rescan behaviour.
- New `darkwatch/tests/test_secret_handling.py` drives failed alerts through
  refusing proxies and an invalid URL and checks that no log record at any
  level holds the token or webhook path, and checks the session file mode
  for every login path. `tests/compose/check.sh` checks that only setup has
  a non-empty `SETUP_AUTH_TOKEN`, that tor's environment is exactly
  `TOR_CONTROL_PASSWORD`, and that `config` fails without it; CI's compose
  config step passes an env file with both.
- CI: `actions/checkout` and `actions/setup-python` are pinned to commit
  SHAs (v7.0.1, v7.1.0; Node 24) and check out without persisting the token.
  A new `.github/dependabot.yml` proposes action updates in one monthly PR.
- CI installs the test tools from the new `requirements-dev.txt` (`pytest`,
  `httpx2`) in their own step, runs pytest with `-rs`, and installs a pinned
  `shellcheck-py==0.11.0.1`. The Setup UI auth tests now run with `httpx2`
  (Starlette's preferred TestClient backend) and fall back to `httpx`; they
  skipped the whole file when only `httpx2` was installed.
- The `shellcheck_py` wheel committed at the repo root is removed and `*.whl`
  is ignored.

## v0.3.0 — 2026-10-25

Leak-hardening release: nothing can reach the internet from the host's IP
any more, even if a tunnel drops.

### Upgrade notes
- `deploy.sh` generates a new `TG_SOCKS_PASSWORD` and recreates the Docker
  network once (it now has a fixed subnet, `172.31.250.0/24`; override with
  `DARKNET_SUBNET` / `DARKWATCH_IP` if that collides with a host network).
- `deploy.sh` installs `darkwatch-egress-lockdown.service`, a host firewall
  rule that keeps the darkwatch container off the internet except through
  the tunnels. Opt out with `DARKWATCH_EGRESS_LOCKDOWN=0`.
- Alerts (Telegram bot, Slack, Discord, webhooks) now go out through the
  Telegram tunnel, falling back to Tor. Set `alerts.allow_direct: true` in
  `config.json` only if you want them sent from the host.
- WireGuard configs must be full-tunnel (`AllowedIPs` includes `0.0.0.0/0`);
  `Table` and `FwMark` are no longer accepted.

### Security
- Kill switch in tunnel1/tunnel2: if a WireGuard tunnel drops, Tor and
  Telegram traffic is rejected instead of leaving via the host's IP. Tunnels
  only report healthy once it is in place; verify-egress checks it.
- The Setup UI no longer accepts `Table = off` (which made traffic bypass
  the tunnel), and never contacts Telegram directly: the credential check
  runs only through the tunnel (no direct retry, no check without a tunnel).
- darkwatch container's direct internet access blocked on the host;
  alerts routed through the tunnels.
- The tg-socks proxy now requires a password.
- Screenshot browser: no redirects (they bypassed the same-origin filter),
  no DNS prefetch / preconnect / pings, localhost proxied, and offline mode
  runs behind a dead proxy.
- tor and tg-socks drop all capabilities; Setup gets no-new-privileges and
  no longer restarts on its own; container logs are size-capped.
- Dependency updates: requests 2.33.0, Flask 3.1.3, Jinja2 3.1.6,
  python-multipart 0.0.31.

### Upgrades
- Playwright 1.47 → 1.64.1 (its bundled Firefox renders hostile pages);
  FastAPI 0.115 → 0.162 / Starlette 1.10 (fixes unauthenticated DoS bugs in
  the Setup UI); Pillow 10.4 → 13.0; lxml 5.3 → 6.1; uvicorn 0.54.
- Docker Compose (Setup UI) 2.29 → 2.40.3, checksum-verified; Docker CLI
  base 27 → 29.
- Base images re-pinned to current digests (python:3.11-slim-bookworm,
  debian:bookworm-slim, linuxserver/wireguard) for a month of OS patches.

### Fixes
- A malformed `Content-Length` no longer aborts a site crawl (second copy of
  the check); downloads have a total time limit; PDF text is HTML-escaped.

## v0.2.0 — 2026-09-27

Reliability and security release. No config migration is needed, but see
**Upgrade notes**.

### Upgrade notes
- On the VM, `main` was rewritten once. Before your next deploy, run once:
  `cd /opt/darkwebapp && sudo git fetch origin && sudo git reset --hard origin/main`
- The dashboard now answers only requests addressed to localhost or
  `DARKWATCH_BIND_IP`. Reaching it through a reverse proxy? Add the proxy's
  hostname to `DARKWATCH_ALLOWED_HOSTS` in `/var/lib/darkwebapp/env`.
- Telegram refuses to connect without the tunnel2 proxy. Set
  `telegram.allow_direct=true` only if you really want direct connections.

### Security
- Dashboard: blocks DNS-rebinding and cross-site requests (Host allowlist +
  Origin / Sec-Fetch-Site checks on writes).
- Setup UI: rejects WireGuard `PostUp`/`PreUp`/`PostDown`/`PreDown` hooks
  (they ran as root in the tunnel containers); CSRF protection; the token is
  no longer logged or kept in the URL / sessionStorage; atomic env-file writes.
- Telegram media from channels is served as a download unless it's a raster
  image (stored XSS via HTML/SVG files).
- CSV exports neutralize spreadsheet formulas; YARA `include` is disabled.
- `harden.sh` no longer locks you out (SSH port auto-detected), keeps
  `ssh -L` working, and its sshd settings now actually take effect over
  cloud-init drop-ins; root-login lock verified after reload.
- Build downloads (esbuild, Tailwind, React, docker compose) are
  checksum-verified; Setup image base pinned by digest.

### Fixes
- `deploy.sh` no longer fails right after install; one-tunnel setups pass the
  egress check; clearer errors when a tunnel won't come up.
- Live dashboard logs no longer disappear (healthcheck drained the queue).
- Tor circuit rotation (NEWNYM) works; Tor healthcheck waits for a circuit;
  Tor guard state persists across deploys.
- Telegram: live listener no longer drops every message; login no longer
  times out during long Tor crawls (separate lock); "since" date filter in
  search fixed; `%`/`_` in keywords match literally; scam/fake channels rank
  last; search results mark fuzzy matches.
- Setup UI applies edited WireGuard configs (recreates the tunnel).
- Threat-intel feeds keep their last good rules when one feed fails.
- `retention.sh` logs real hashes and prunes thumbnails;
  `pre-public-check.sh` actually fails when it finds secrets.

### Project
- GitHub Actions CI: tests, shellcheck, compose validation.
- Tagging `vX.Y.Z` publishes a GitHub Release from this changelog.
- Docs (README, RUNBOOK, env template, tunnel docs) match the code.

## v0.1.0

Initial public release.
