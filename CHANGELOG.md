# Changelog

## Unreleased

### Upgrade notes
- From v0.3.0, pull first and then deploy without pulling:
  `sudo git -C /opt/darkwebapp pull --ff-only`, then
  `sudo ./ops/deploy.sh --skip-pull`. A v0.3.0 `deploy.sh` that does the pull
  itself keeps running its own old code and exits silently after the build.
  If you already ran it that way, run `deploy.sh` again and check that it
  prints "deploy complete".
- `deploy.sh` now refuses to run when the repo's `.env` is not a link to
  `/var/lib/darkwebapp/env` (a wrong target, a dangling link or a copied
  file). Fix it with `sudo ln -sfn /var/lib/darkwebapp/env /opt/darkwebapp/.env`.
  `bootstrap.sh` treats the same case as an error instead of a warning.
- `deploy.sh` fails on a hand-placed `wg0.conf` with a `Table` other than
  `auto`, any `FwMark`, or no `AllowedIPs` that includes `0.0.0.0/0`. Pre/Post
  hooks only produce a warning.
- The first deploy after upgrading builds the tor and Setup UI images too, so
  it takes longer; later builds come from the cache.

### Fixed
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
  `deploy.sh` before the health wait and the egress lockdown.
- `deploy.sh` checks that the tunnel kill switch is executable, and its
  "compose up failed" hint points at the `custom-init` / `killswitch` logs.
- The documented Setup UI command is now
  `docker compose --profile setup up -d --build setup`, so it never starts a
  stale image.

### Internal
- `ops/lib/common.sh` holds the `env_val` helper shared by `deploy.sh`,
  `egress-lockdown.sh` and `verify-egress.sh`.
- New `tests/ops/check.sh` runs `deploy.sh` and `bootstrap.sh` against
  stubbed docker/systemctl in CI.

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
