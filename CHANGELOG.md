# Changelog

## Unreleased

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
