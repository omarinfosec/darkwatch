# DarkWatch — Operator Runbook

Day-to-day operations on a deployed DarkWatch VM. First-time setup: [`README.md`](../README.md#quick-install) (`sudo ./ops/install.sh` on the VM).

---

## Common operations

### Deploy a code change
```bash
# from your dev machine
git push origin main

# on the VM
ssh root@<vm>
cd /opt/darkwebapp
sudo ./ops/deploy.sh
```

`deploy.sh` is idempotent. It refuses to run if the working tree is dirty, if env vars are missing, or if WG configs aren't in place.

### Check the egress isolation
```bash
sudo ./ops/verify-egress.sh
```
Confirms: Tor sees Tor, Tor exit ≠ Telegram exit, darkwatch container doesn't share host network. Run after every deploy and weekly otherwise.

### Tail logs
```bash
docker compose logs -f --tail=50
docker compose logs -f darkwatch       # one service
```

### Restart one service
```bash
docker compose restart darkwatch
```

### Rebuild after changing the Dockerfile
```bash
sudo ./ops/deploy.sh   # the deploy script always runs `compose build`
```

### Stop everything
```bash
docker compose down
```
Containers go away; named volumes and `/var/lib/darkwebapp/` data persist.

### See what crawls have run
```bash
sqlite3 /var/lib/darkwebapp/darkwatch/data/darkwatch.db \
   "SELECT * FROM findings ORDER BY created_at DESC LIMIT 20"
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

WG is routing both tunnels through the same exit. Edit the two configs to use different ProtonVPN regions. See `vpn/templates/peer.conf` for shape.

```bash
sudo $EDITOR /var/lib/darkwebapp/secrets/tunnel1/wg0.conf
sudo $EDITOR /var/lib/darkwebapp/secrets/tunnel2/wg0.conf
sudo docker compose restart tunnel1 tunnel2
sudo ./ops/verify-egress.sh
```

### "darkwatch is unhealthy after deploy"
```bash
docker compose logs --tail=100 darkwatch
docker compose ps
```
Most common: WG tunnel didn't come up → tor/tg-socks can't start → darkwatch can't egress.

```bash
docker compose logs tunnel1 | tail -30
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
| `TOR_CONTROL_PASSWORD`   | darkwatch (NEWNYM rotation)      | yes      |
| `TELEGRAM_ALERT_BOT_TOKEN` | alerting                       | optional |
| `SLACK_WEBHOOK_URL`      | alerting                         | optional |

All live in `/var/lib/darkwebapp/env` (root:root, 0600). Compose reads them via `env_file:`.

---

## Contact

Security-sensitive issues: [GitHub private vulnerability reporting](https://github.com/omarinfosec/darkwatch/security/advisories/new).
