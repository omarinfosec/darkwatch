# Tunnel 2 — Telegram egress path

Place a WireGuard client config from a **different** provider or region
than Tunnel 1 (the Tor path) at:

```
/var/lib/darkwebapp/secrets/tunnel2/wg_confs/wg0.conf
```

(or paste it into the Setup UI). Both tunnels use the filename `wg0.conf`;
each runs in its own network namespace, so the `wg0` interfaces don't
collide. The files in this repo directory are templates only; real configs
never enter the repo.

This tunnel carries ONLY Telegram traffic, via the `tg-socks` SOCKS5
sidecar on `tunnel2:1080`. It must never share an exit IP with the Tor
path; `ops/verify-egress.sh` checks that. Telegram refuses to connect at
all when no proxy is configured, so it can't fall back to the host's IP.

If no config is present, `deploy.sh` leaves the `tg` compose profile off:
`tunnel2` and `tg-socks` aren't started, Telegram scraping is unavailable,
and the dashboard's health panel shows the Telegram VPN check as failed.

## After adding the config

```bash
sudo ./ops/deploy.sh                          # enables --profile tg
sudo docker exec tunnel2 wg show wg0          # expect a recent handshake
sudo ./ops/verify-egress.sh --tg              # exit IP differs from Tor's
```
