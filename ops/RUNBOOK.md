# DarkWatch — Operator Runbook

Day-to-day operations on a deployed DarkWatch VM. First-time setup: [`README.md`](../README.md#quick-install) (`sudo ./ops/install.sh` on the VM).

---

## Common operations

### Deploy a code change
```bash
# from your dev machine
git push origin main

# on the VM
ssh deploy@<vm>          # root SSH is disabled after harden-phase2.sh --lock-root
cd /opt/darkwebapp
sudo ./ops/deploy.sh
```

`deploy.sh` is idempotent. It refuses to run if tracked files have uncommitted changes, if required env vars are missing, or if the env file isn't 0600. Missing WG configs don't block it — they just leave the matching `tor` / `tg` profile off.

### Check the egress isolation
```bash
sudo ./ops/verify-egress.sh            # auto-detects configured tunnels
sudo ./ops/verify-egress.sh --tor      # or check one path explicitly
```
Checks only the tunnels that are configured. Confirms: Tor sees Tor, Tor exit ≠ Telegram exit, darkwatch container doesn't share host network. Run after every deploy and weekly otherwise.

### Tail logs
```bash
sudo docker compose logs -f --tail=50
sudo docker compose logs -f darkwatch  # one service
```

### Restart one service
```bash
sudo docker compose restart darkwatch
```

### Rebuild after changing the Dockerfile
```bash
sudo ./ops/deploy.sh   # the deploy script always runs `compose build`
```

### Stop everything
```bash
sudo docker compose down
```
Containers go away; the `tor-data` volume (Tor guard state) and the bind-mounted `/var/lib/darkwebapp/` data persist.

### See what crawls have run
```bash
sudo sqlite3 /var/lib/darkwebapp/darkwatch/data/darkwatch.db \
   "SELECT * FROM findings ORDER BY found_at DESC LIMIT 20"
```

### Disk usage
```bash
sudo du -sh /var/lib/darkwebapp/*
```

---

## Maintenance schedule

| Cadence    | Task                                                       |
|------------|------------------------------------------------------------|
| Nightly    | `ops/retention.sh` purges old `loot/` content (cron job)    |
| Weekly     | `ops/verify-egress.sh` (manual)                             |
| Weekly     | Review `fail2ban-client status sshd` for SSH brute-force    |
| Monthly    | `docker scout cves` against pinned images; bump if needed   |
| Monthly    | `pip-audit -r darkwatch/requirements.txt` (if local)        |
| Monthly    | Review who can SSH to the VM and reach dashboard bind IP |
| Quarterly  | Rotate Telegram session (regen api credentials, delete old) |
| Quarterly  | Rotate WireGuard configs                                    |
| Yearly     | Re-evaluate `loot/` retention windows against actual usage  |

---

## Cron setup

Install on first deploy:
```bash
sudo crontab -l 2>/dev/null > /tmp/cron.bak || true
echo '0 3 * * * /opt/darkwebapp/ops/retention.sh >> /var/log/darkwatch-retention.log 2>&1' >> /tmp/cron.bak
sudo crontab /tmp/cron.bak
rm /tmp/cron.bak
```

---

## Incident playbooks

### "Egress check failed: Tor and TG exits are the same IP"

WG is routing both tunnels through the same exit. Give the two configs different VPN regions (or providers). Easiest: paste the new configs into the Setup UI, which recreates the affected tunnel. See `tunnels/tunnel1/wg_confs/wg0.conf.example` for the shape.

Manually (as root, since `deploy`'s sudo is scoped to ops scripts and docker):
```bash
$EDITOR /var/lib/darkwebapp/secrets/tunnel1/wg_confs/wg0.conf
$EDITOR /var/lib/darkwebapp/secrets/tunnel2/wg_confs/wg0.conf
sudo docker compose up -d --force-recreate tunnel1 tor tunnel2 tg-socks
sudo ./ops/verify-egress.sh
```

### "darkwatch is unhealthy after deploy"
```bash
sudo docker compose logs --tail=100 darkwatch
sudo docker compose ps
```
darkwatch doesn't depend on the tunnels and its healthcheck (`/healthz`) is liveness only, so an unhealthy darkwatch is an app or startup error — read its logs.

### "deploy failed: tunnel1/tunnel2 is unhealthy"
A tunnel is healthy only after a WireGuard handshake. No handshake means a wrong key/endpoint or a blocked UDP port; `deploy.sh` prints the tunnel's last logs.
```bash
sudo docker compose logs tunnel1 | tail -30
sudo docker exec tunnel1 wg show wg0
```

### "I committed a secret by mistake"
1. Stop. Don't push.
2. `git reset --soft HEAD~1` to uncommit (keeps changes staged).
3. Move the secret out of the file. Recommit.
4. If you already pushed: rotate the secret (new key/token), force-push only if the repo is still private and you're sure no one else pulled, otherwise live with the leak and treat the value as burned.

### "I lost SSH access to the VM"
You'll need console access via the VM provider.
- Then: regenerate a key, paste public half into `~/.ssh/authorized_keys`, regenerate via `ops/harden.sh` if firewall rules look wrong.

---

## Environment cheat sheet

| Variable                 | Where read                       | Required |
|--------------------------|----------------------------------|----------|
| `DARKWEBAPP_DATA_ROOT`   | docker-compose, deploy.sh        | yes      |
| `DARKWATCH_BIND_IP`      | docker-compose port mappings     | yes      |
| `TELEGRAM_API_ID`        | darkwatch (Telethon)             | optional (Setup UI; needed for TG scrape) |
| `TELEGRAM_API_HASH`      | darkwatch (Telethon)             | optional (Setup UI; needed for TG scrape) |
| `TOR_CONTROL_PASSWORD`   | darkwatch (NEWNYM) + tor sidecar | yes (auto-generated by install.sh) |
| `SETUP_AUTH_TOKEN`       | Setup UI                         | yes (auto-generated by bootstrap.sh) |
| `DARKWATCH_ALLOWED_HOSTS` | darkwatch Host-header allowlist | optional (reverse proxy name) |
| `TELEGRAM_ALERT_BOT_TOKEN` | alerting                       | optional |
| `TELEGRAM_ALERT_CHAT_ID` | alerting                         | optional |
| `SLACK_WEBHOOK_URL`      | alerting                         | optional |

All live in `/var/lib/darkwebapp/env` (root:root, 0600). Compose reads them via `env_file:`.

---

## Contact

Security-sensitive issues: [GitHub private vulnerability reporting](https://github.com/omarinfosec/darkwatch/security/advisories/new).
