# Changelog

## Unreleased

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
