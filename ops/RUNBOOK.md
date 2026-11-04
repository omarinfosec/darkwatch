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

`deploy.sh` pulls first; when the pull brings new commits it restarts itself once (with `--skip-pull`), so the rest of the deploy runs the new code. Take a [backup](#back-up-and-restore) before every upgrade.

**Upgrading from v0.2.0 or v0.3.0:** those versions' `deploy.sh` doesn't restart after its pull. It keeps running its own old code, and v0.3.0's exits silently after the build, without starting the stack or applying the egress lockdown. Pull first, then deploy:
```bash
sudo git -C /opt/darkwebapp pull --ff-only && sudo ./ops/deploy.sh
```
If you already ran the old `deploy.sh`, run it again and check that it prints "deploy complete". Then verify:
```bash
systemctl is-enabled darkwatch-egress-lockdown                  # enabled
sudo grep -c '^TG_SOCKS_PASSWORD=.\+' /var/lib/darkwebapp/env   # 1
sudo docker image inspect darkwatch-setup:local -f '{{.Created}}' # after you started this upgrade, not the v0.2.0/v0.3.0 install date
```

`deploy.sh` is idempotent. It refuses to run if tracked files have uncommitted changes, if required env vars are missing, if the env file isn't 0600, if the repo's `.env` is not a link to `/var/lib/darkwebapp/env` (it creates the link when missing), or if a `wg0.conf` is not full-tunnel (`Table` other than `auto`, any `FwMark`, or no `AllowedIPs` with `0.0.0.0/0`). Missing WG configs don't block it — they just leave the matching `tor` / `tg` profile off. It rebuilds every locally built image (darkwatch, tor, setup) and refreshes the Setup UI if it is running; a stopped Setup UI stays stopped.

The plain `sudo docker compose …` commands below read their settings through that `.env` link.

### Check the egress isolation
```bash
sudo ./ops/verify-egress.sh            # auto-detects configured tunnels
sudo ./ops/verify-egress.sh --tor      # or check one path explicitly
```
Checks only the tunnels that are configured. Confirms: Tor sees Tor, Tor exit ≠ Telegram exit, Telegram exit ≠ the host's own IP, darkwatch isn't on the host network, the lockdown rule covers darkwatch's actual address and it can't reach `http://1.1.1.1` (the host is the positive control), and the DNS isolation below holds. Run after every deploy and weekly otherwise.

### Check the leak protections
```bash
sudo ./ops/egress-lockdown.sh --status          # darkwatch: no direct internet
sudo docker exec tunnel1 iptables -S DW_KILLSWITCH   # tunnel kill switch
sudo docker exec tunnel1 iptables -S DW_KS_IN        # inbound drop on wg0
```
`verify-egress.sh` checks all of these. Three layers stop the host's real IP from leaking:
- **Tunnel kill switch** (`tunnels/killswitch/10-killswitch.sh`): inside tunnel1/tunnel2, nothing may leave except through WireGuard, so if a tunnel drops, Tor and Telegram traffic is rejected instead of exiting via Docker's NAT. The tunnels only report healthy (and tor / tg-socks only start) once it is in place. It also drops new connections arriving through WireGuard, so the VPN side can't reach Tor's SOCKS and control ports. A hostname `Endpoint` is resolved once at tunnel start, before egress closes, and pinned in the container's `/etc/hosts` (`docker logs tunnel1 2>&1 | grep killswitch` shows it); if the VPN changes that address, recreate the tunnel with its sidecar (`sudo docker compose up -d --force-recreate tunnel1 tor`, or `tunnel2 tg-socks`).
- **Egress lockdown** (`ops/egress-lockdown.sh`): a host firewall rule so the darkwatch container can only talk to the darknet subnet (the proxies). Alerts go out through the Telegram tunnel, falling back to Tor; set `alerts.allow_direct` in `config.json` only if you accept them leaving from the host. Before every scan the dashboard's `ip_leak` check opens TCP connections to `1.1.1.1:443` and `9.9.9.9:443` and refuses to start (403, `ip_leak` in the failed list) if either connects or is refused (`ECONNREFUSED`: the lockdown drops, so a refusal means the packet got out); only timeouts, no-route errors and `EPERM` pass. With `DARKWATCH_EGRESS_LOCKDOWN=0` it only compares the Tor exit IP with darkwatch's direct IP, which is a much weaker check.
- **DNS isolation** (`dns: 127.0.0.1` on darkwatch in `docker-compose.yml`): darkwatch resolves only the service names (`tunnel1`, `tunnel2`); every other lookup goes to 127.0.0.1 inside its own namespace and fails at once. Without it, Docker would send those lookups to the host's resolver, and a loopback one (dnsmasq, unbound, bind) answers them from the host, past the lockdown. Leave `DARKWATCH_DNS` unset; set a real resolver only with `DARKWATCH_EGRESS_LOCKDOWN=0` (which `alerts.allow_direct` also needs to send directly), where darkwatch needs one for direct alerts and the in-app IP-leak check. With the lockdown on, `verify-egress.sh` and `deploy.sh` fail on any other `DARKWATCH_DNS`. On Docker 26 and later, `sudo docker exec darkwatch cat /etc/resolv.conf` contains the line `# ExtServers: [127.0.0.1]` and no `host(`; `host(` there means darkwatch was not recreated with the current compose file (run `sudo ./ops/deploy.sh`). Docker 24/25 write no such line; `verify-egress.sh` then relies on a lookup of `example.com` failing. The tunnels keep the host's DNS (they need it for hostname Endpoints) until WireGuard is up; after that tunnel2 uses the `DNS =` line of its `wg0.conf`, which the Setup UI requires and `verify-egress.sh` warns about when it is missing.

`deploy.sh` applies the lockdown before it starts the containers, and its `darkwatch-egress-lockdown` unit re-applies it at boot before `docker.service` starts them. After each deploy it probes `http://1.1.1.1` from darkwatch (the host is the positive control) and fails if darkwatch connects. After a reboot:
```bash
sudo iptables -S DOCKER-USER | grep darkwatch-egress-lockdown          # the rule
systemctl list-dependencies --after docker.service | grep darkwatch-egress-lockdown  # ordered before Docker
# Lockdown active before dockerd started (microseconds since boot; 0 = never active):
lock=$(systemctl show -p ActiveEnterTimestampMonotonic --value darkwatch-egress-lockdown)
dock=$(systemctl show -p ExecMainStartTimestampMonotonic --value docker)
[ "$lock" -gt 0 ] && [ "$lock" -lt "$dock" ] && echo "lockdown first" || echo "LOCKDOWN NOT FIRST"
```
The rule is IPv4 only, and compose keeps the `darknet` network IPv4-only. `egress-lockdown.sh` and `--status` warn if it has IPv6 anyway (an older network): run `sudo docker compose --profile tor --profile tg --profile setup down && sudo ./ops/deploy.sh` to recreate it.

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
sudo ./ops/deploy.sh   # builds darkwatch, tor and setup (skip with --skip-build)
```
To check the built images without touching the running stack (offline
imports, an offline screenshot, `tor --version`; the same tests CI runs):
```bash
sudo bash tests/images/smoke.sh
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

### Back up and restore
Back up before every upgrade or rollback. Run these as root (the deploy user's sudo rights don't cover `tar`). Check that `/root` has room for the data first:
```bash
cd /opt/darkwebapp
df -h /root
du -sh /var/lib/darkwebapp/{env,secrets} /var/lib/darkwebapp/darkwatch/{data,investigations,yara-private}

docker compose stop darkwatch setup
tar -C /var/lib/darkwebapp -czf /root/dw-$(git describe --tags)-$(date +%F).tgz \
    env secrets darkwatch/data darkwatch/investigations darkwatch/yara-private
chmod 600 /root/dw-*.tgz
docker compose start darkwatch       # start setup too only if you were using it
```
- Before upgrading to v0.4.0, add `darkwatch/loot` to the `tar` list: that backup is the only way to get back data that v0.4.0's retention removes.
- `darkwatch/data` holds the database, `telegram.session` (the Telegram login: whoever has it can use the account) and `user.yar` (your keyword rules). `env` and `secrets` hold every password and WireGuard key. Keep the archive root-only and off shared storage.
- **Never `cp` the live database.** It runs in WAL mode, and a plain copy of the running file can miss every committed row that is still in the `-wal` file.

Hot alternative, database only, without stopping darkwatch:
```bash
docker exec darkwatch sqlite3 /app/data/darkwatch.db ".backup /app/data/pre-upgrade.db"
mv /var/lib/darkwebapp/darkwatch/data/pre-upgrade.db /root/dw-pre-upgrade-$(date +%F).db
chmod 600 /root/dw-pre-upgrade-*.db
```
This does not cover `env`, `secrets`, `telegram.session` or `user.yar`.

Restore (discards everything collected after the backup):
```bash
cd /opt/darkwebapp
docker compose stop darkwatch setup
rm -f /var/lib/darkwebapp/darkwatch/data/darkwatch.db-wal /var/lib/darkwebapp/darkwatch/data/darkwatch.db-shm
tar -C /var/lib/darkwebapp -xzpf /root/dw-<version>-<date>.tgz
./ops/deploy.sh --skip-pull
```
To restore a hot `.backup` file instead, copy it over `/var/lib/darkwebapp/darkwatch/data/darkwatch.db` at the `rm` step, then `chown 999:999` it. Removing the `-wal` / `-shm` files matters either way: a leftover newer WAL could be replayed onto the restored database.

### Roll back a release
Take a [backup](#back-up-and-restore) first. As root, for example back to v0.3.0:
```bash
cd /opt/darkwebapp
grep -c '^DARKNET_SUBNET=' /var/lib/darkwebapp/env   # must print 1 or more (see below)
git checkout v0.3.0
docker compose --profile setup stop setup            # see below
./ops/deploy.sh --skip-pull
systemctl reenable darkwatch-egress-lockdown
systemctl list-dependencies --reverse darkwatch-egress-lockdown
docker inspect darkwatch -f '{{.Image}}'             # must equal the next line
docker image inspect darkwatch:local -f '{{.Id}}'
```
- **`DARKNET_SUBNET=` must be in the env file.** Without it the v0.3.0 `deploy.sh` exits silently right after the build and leaves the newer code running. Append `DARKNET_SUBNET=172.31.250.0/24` (the default) if the `grep` prints 0.
- Stop the Setup UI before the deploy: v0.3.0's compose file changes the `darknet` network back, and compose can't recreate it while the Setup UI still uses it.
- Use `reenable`, not `enable`: it resets the unit's links to what the old unit file asks for, while `enable` would leave links a newer version added (such as a `docker.service.wants` link) in place. `list-dependencies --reverse` shows what still pulls the unit in.
- If the two image IDs differ, darkwatch is still running the newer image: run `docker compose up -d darkwatch` and compare again.
- Run `git checkout main` before the next upgrade. The checkout leaves a detached HEAD, and `git pull --ff-only` (and so `deploy.sh`) fails on it.
- Database: v0.3.0 runs on a v0.3.1 database as is (the indexes v0.3.1 adds are not UNIQUE), so no restore is needed. Going back past v0.4.0's retention, which removes data, is only possible by restoring the backup taken before v0.4.0.

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
A tunnel is healthy only after a WireGuard handshake. No handshake means a wrong key/endpoint or a blocked UDP port; `deploy.sh` prints the tunnel's last logs. `[killswitch] could not resolve endpoint` there means the Endpoint hostname did not resolve when the tunnel started: fix DNS on the host and recreate the tunnel with its sidecar (`sudo docker compose up -d --force-recreate tunnel1 tor`), or use an IP Endpoint.
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
| `TG_SOCKS_PASSWORD`      | tg-socks login (darkwatch, Setup UI, verify-egress) | yes (auto-generated by deploy.sh) |
| `DARKNET_SUBNET` / `DARKWATCH_IP` | compose network, egress lockdown | optional (defaults 172.31.250.0/24 / .250) |
| `DARKWATCH_EGRESS_LOCKDOWN` | egress-lockdown.sh, deploy.sh's direct-egress probe, verify-egress.sh, darkwatch IP-leak gate | optional (default 1 = on) |
| `DARKWATCH_DNS`          | darkwatch's `dns:` in compose     | leave at default (127.0.0.1); a real resolver only with `DARKWATCH_EGRESS_LOCKDOWN=0`, which `alerts.allow_direct` also needs (verify-egress.sh and deploy.sh fail on any other value while the lockdown is on) |
| `TELEGRAM_ALERT_BOT_TOKEN` | alerting                       | optional |
| `TELEGRAM_ALERT_CHAT_ID` | alerting                         | optional |
| `SLACK_WEBHOOK_URL`      | alerting                         | optional |

All live in `/var/lib/darkwebapp/env` (root:root, 0600). darkwatch and the Setup UI get the whole file via `env_file:` (darkwatch with `SETUP_AUTH_TOKEN` blanked); tor gets only `TOR_CONTROL_PASSWORD`, through compose variable substitution. Every `docker compose` command therefore needs `TOR_CONTROL_PASSWORD` from the repo's `.env` link or `--env-file`, and fails with "TOR_CONTROL_PASSWORD unset" without it.

---

## Contact

Security-sensitive issues: [GitHub private vulnerability reporting](https://github.com/omarinfosec/darkwatch/security/advisories/new).
