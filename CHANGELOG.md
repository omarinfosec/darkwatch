# Changelog

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
