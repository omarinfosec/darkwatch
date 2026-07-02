# Telegram VPN

Drop a WireGuard client config for a **different** provider / region than
`./vpn/` (which is the Tor-side tunnel) into `wg_confs/wgt0.conf`.

The `t` in the filename means "telegram" — it disambiguates from the
Tor-side tunnel inside the container (`wg show` will list `wgt0` so it's
obvious which one is which). The `linuxserver/wireguard` image brings up
every `*.conf` in `wg_confs/` as an interface named after the file.

This tunnel is used ONLY by Telegram scraping traffic (via the `tg-socks`
SOCKS5 sidecar on port 1080). It must never share an exit IP with the
Tor path — separation is the whole point.

If this directory has no config, the `tunnel2` container will boot
in a degraded state and Telegram scraping won't work. Darkwatch's
`/api/health` will report `tg_vpn: down`.

## After dropping the config

```
docker compose up -d tunnel2 tg-socks
docker compose logs --tail 20 tunnel2   # confirm "wgt0 up"
docker exec tunnel2 wg show              # interface should show handshake
docker exec tunnel2 curl -s --max-time 10 https://api.ipify.org
                                              # should report your TG-VPN exit IP
```
