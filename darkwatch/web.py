"""DarkWatch — Flask API backend.

Serves the React SPA (index.html) and exposes JSON endpoints that drive
the UI: scan control, live status/logs, findings, URL list, report
generation, and — importantly — a pre-scan security gate that refuses
to run a scan unless Tor, the VPN, the IP-leak check, and DNS-over-Tor
all pass.
"""

import csv
import io
import json
import logging
import os
import queue
import random
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timedelta

import requests
from flask import Flask, abort, jsonify, request, send_file, Response

from darkwatch import (DarkWebCrawler, TelegramScraper, TelegramLiveListener,
                        load_config, setup_logging, onion_url_error,
                        __version__, PLAYWRIGHT_AVAILABLE, TELETHON_AVAILABLE)
from threat_intel import ThreatIntelFeed


# ─── Boot ────────────────────────────────────────────────────────────────────

setup_logging()
logging.getLogger("werkzeug").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

CONFIG_PATH = os.environ.get("DARKWATCH_CONFIG", "config.json")
_config = load_config(CONFIG_PATH)
_crawler = DarkWebCrawler(_config)
# Single shared Telegram scraper. Dormant until the operator has set
# api_id/api_hash in config.json and completed the phone/code login via the
# Telegram tab. All network traffic is routed through the `tg-socks` sidecar
# (separate WireGuard tunnel from the Tor path).
_tg = TelegramScraper(_config)
# The DB is the source of truth for user keywords — rebuild user.yar from
# it on every boot so the generated file always matches the DB.
_crawler.scanner.regenerate_user_rules(_crawler.db.list_keywords())
log = logging.getLogger("darkwatch.web")

app = Flask(__name__,
            static_folder=os.path.join(os.path.dirname(__file__), "static"),
            static_url_path="/static")

# ─── Shared state (single scan at a time) ────────────────────────────────────

_state_lock = threading.Lock()
# Serializes actual crawler work (scan thread + monitor scheduler share
# one Playwright browser and one DB connection). Separate from
# `_state_lock` so API reads stay fast during long scans.
_crawl_lock = threading.Lock()
_scan_thread = None
_stop_event = threading.Event()
_log_queue: "queue.Queue[str]" = queue.Queue(maxsize=10000)
_progress = {"completed": 0, "total": 0}
_scan_started_at = None
_health_cache = {"data": None, "ts": 0.0}
_HEALTH_TTL = 10.0   # seconds
_HEALTH_REFRESH_INTERVAL = 60   # background full recheck (keeps cache warm)
_health_refresh_stop = threading.Event()
_health_refresh_thread = None


def _health_refresh_loop():
    """Keep the health cache fresh so dashboard refreshes don't flash stale
    failures while a new 20s check runs."""
    log.info("Health refresh loop started (interval=%ss)", _HEALTH_REFRESH_INTERVAL)
    while not _health_refresh_stop.is_set():
        try:
            _get_health(fresh=True)
        except Exception as e:
            log.warning("background health refresh failed: %s", e)
        _health_refresh_stop.wait(_HEALTH_REFRESH_INTERVAL)
    log.info("Health refresh loop stopped")


def _start_health_refresh_thread():
    global _health_refresh_thread
    if _health_refresh_thread and _health_refresh_thread.is_alive():
        return
    _health_refresh_stop.clear()
    _health_refresh_thread = threading.Thread(
        target=_health_refresh_loop, name="health-refresh", daemon=True)
    _health_refresh_thread.start()

# Monitoring scheduler — single background thread, ticks every MONITOR_TICK
# seconds. Per-URL interval is stored on the urls table; the scheduler
# applies a ±MONITOR_JITTER fraction of randomness when scheduling the
# next check, so the operator's polling pattern can't be fingerprinted by
# the target site.
_monitor_thread = None
_monitor_stop = threading.Event()
MONITOR_TICK = 30          # seconds between scheduler wake-ups
MONITOR_JITTER = 0.25      # fraction (±25% of interval)

# In-process counters for /metrics. Small enough to stay in memory; the
# DB already records scan_log rows so we don't need to persist these.
# Counters are monotonic-since-boot; a Prometheus rate() query derives
# per-second throughput.
_counters = {
    "scans_started": 0,
    "scans_completed": 0,
    "scans_errored": 0,
    "rescans": 0,
    "threat_intel_refreshes": 0,
    "findings_new": 0,   # unique new findings (not dedup-bumps)
}
_counters_lock = threading.Lock()


def _bump(name, n=1):
    with _counters_lock:
        _counters[name] = _counters.get(name, 0) + n

# Real-time live listener. Off by default; enable via config.telegram.live_enabled.
# When on, a persistent Telethon session fires an events.NewMessage handler for
# every tracked channel. Handler enqueues; a consumer thread drains the queue
# under _crawl_lock and scans exactly like _monitor_tg_channel would.
_tg_live = None                          # TelegramLiveListener instance
_tg_live_queue: "queue.Queue" = queue.Queue(maxsize=500)
_tg_live_consumer_thread = None
_tg_live_stop = threading.Event()


class QueueLogHandler(logging.Handler):
    """Pushes formatted log records into an in-memory queue for /api/status."""

    def emit(self, record):
        try:
            _log_queue.put_nowait(self.format(record))
        except queue.Full:
            # Drop the oldest to keep the most recent lines visible.
            try:
                _log_queue.get_nowait()
                _log_queue.put_nowait(self.format(record))
            except Exception:
                pass


_queue_handler = QueueLogHandler()
_queue_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                                              datefmt="%H:%M:%S"))
logging.getLogger("darkwatch").addHandler(_queue_handler)


# ─── Security gate ───────────────────────────────────────────────────────────

TOR_CHECK_URL = "http://check.torproject.org/api/ip"
# Multiple echo services. Tor exits get rate-limited / blocked by any
# single provider unpredictably — hitting the first-that-answers is far
# more reliable than one hard-coded endpoint. HTTP where supported
# (avoids TLS handshake time over slow Tor circuits); all services return
# plain text or JSON with the caller's IP.
IP_ECHO_SERVICES = [
    ("http://api.ipify.org",                   "text"),   # plain body
    ("http://ifconfig.me/ip",                  "text"),
    ("http://icanhazip.com",                   "text"),
    ("http://checkip.amazonaws.com",           "text"),
    ("https://api64.ipify.org?format=json",    "json-ip"),
]
ONION_CANARY = ("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6"
                "twagswzczad.onion/")


def _fetch_ip(proxies=None, timeout=5):
    """Return a public IP string via the first echo service that answers.
    Tries each endpoint once with a short per-service timeout. Returns
    (ip, used_service) on success, (None, last_error_str) otherwise."""
    import re
    ip_re = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    last_err = None
    for url, kind in IP_ECHO_SERVICES:
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout)
            if not r.ok:
                last_err = f"{url} HTTP {r.status_code}"; continue
            body = r.text.strip()
            if kind == "json-ip":
                try: ip = r.json().get("ip")
                except Exception: ip = None
            else:
                m = ip_re.search(body)
                ip = m.group(0) if m else None
            if ip:
                return ip, url
            last_err = f"{url} no IP in response"
        except Exception as e:
            last_err = f"{url}: {type(e).__name__}"
            continue
    return None, last_err or "no services answered"


def _tor_proxies():
    cfg = _crawler.config["proxy"]
    url = f"{cfg['type']}://{cfg['host']}:{cfg['port']}"
    return {"http": url, "https": url}


def _check_tor():
    """Full identity check — GO via Tor and confirm IsTor=true.
    Use only for the security gate; too expensive for frequent polling.
    `exit_ip` is stashed on the result so _check_ip_leak can reuse it
    instead of making a second (slow, flaky) request over Tor."""
    try:
        r = requests.get(TOR_CHECK_URL, proxies=_tor_proxies(), timeout=10)
        data = r.json()
        ok = r.status_code == 200 and bool(data.get("IsTor"))
        ip = data.get("IP", "?")
        return {"ok": ok,
                "detail": f"IsTor={data.get('IsTor')}, exit {ip}",
                "exit_ip": ip if ok else None}
    except Exception as e:
        return {"ok": False, "detail": f"Tor check failed: {e}",
                "exit_ip": None}


def _check_tor_alive():
    """Cheap SOCKS-port liveness probe — safe to poll every few seconds
    without hitting check.torproject.org (which rate-limits)."""
    cfg = _crawler.config["proxy"]
    try:
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=2):
            return {"ok": True, "detail": f"SOCKS {cfg['host']}:{cfg['port']} reachable (liveness only)"}
    except Exception as e:
        return {"ok": False, "detail": f"SOCKS unreachable: {e}"}


def _check_vpn():
    """Verify Tunnel 1 is on the docker network.

    ICMP ping is unavailable — darkwatch runs with cap_drop ALL — so we probe
    the Tor SOCKS port on tunnel1 instead (same path scans use).
    """
    cfg = _crawler.config["proxy"]
    host = cfg.get("host", "tunnel1")
    port = int(cfg.get("port", 9050))
    try:
        with socket.create_connection((host, port), timeout=3):
            return {"ok": True, "detail": f"{host}:{port} reachable (Tunnel 1 / Tor SOCKS)"}
    except OSError as e:
        if getattr(e, "errno", None) in (-2, -3) or "name resolution" in str(e).lower():
            return {
                "ok": False,
                "detail": (
                    f"{host} not running — save Tunnel 1 in Setup UI or run "
                    "sudo ./ops/deploy.sh on the VM"
                ),
            }
        return {"ok": False, "detail": f"VPN check failed: {e}"}


def _check_ip_leak(tor_result):
    """Compare the Tor exit IP against the container's 'direct' egress IP.

    The darkwatch container is on the compose `darknet` network behind
    ProtonVPN, so 'direct' should be the VPN's IP — not the host's real
    IP. A leak looks like: tor_exit == direct_ip (same route).

    Tor exit IP is READ from the _check_tor() result instead of
    re-fetched — fixing the previous flakiness where ipify over Tor
    timed out and tanked the whole security gate. The direct probe
    tries multiple echo services with short per-service timeouts.

    Accepts either the full result dict (new shape) or the legacy
    string (fallback) so the gate doesn't break on partial upgrades.
    We fail closed on timeout.
    """
    # Accept both shapes for back-compat.
    if isinstance(tor_result, dict):
        tor_ip = tor_result.get("exit_ip")
    else:
        import re
        m = re.search(r"exit (\S+)", str(tor_result) or "")
        tor_ip = m.group(1) if m else None

    if not tor_ip:
        return {"ok": False,
                "detail": "no Tor exit IP to compare against "
                          "(tor probe failed earlier)"}

    direct_ip, direct_err = _fetch_ip(proxies=None, timeout=5)
    if not direct_ip:
        return {"ok": False,
                "detail": f"direct IP fetch failed (fail-closed): {direct_err}"}

    if tor_ip == direct_ip:
        return {"ok": False,
                "detail": f"LEAK: tor_exit == direct ({tor_ip})"}
    return {"ok": True,
            "detail": f"tor_exit {tor_ip} ≠ direct {direct_ip}"}


def _check_dns():
    """Confirm DNS-over-Tor by reaching a known onion via socks5h://.

    New (fresh) onion circuits can take 20-30s to build; we use HEAD
    (minimal bytes), bump timeout to 30s, and retry once after a 2s
    pause. A pure timeout after both attempts is tagged as "slow, not
    leaking" — the parent `secure` flag already excludes `dns`
    (see _run_health_checks) so Tor-scale latency doesn't block scans.
    A non-timeout error (SOCKS refused / resolution error / HTTP error)
    is still a hard fail."""
    last = None
    for attempt in (1, 2):
        try:
            r = requests.head(ONION_CANARY, proxies=_tor_proxies(),
                              timeout=30, allow_redirects=False)
            return {"ok": True,
                    "detail": f"onion canary HEAD {r.status_code}"}
        except (requests.ConnectTimeout, requests.ReadTimeout) as e:
            last = e
            time.sleep(2)
        except Exception as e:
            return {"ok": False, "detail": f"DNS-over-Tor error: {e}"}
    return {"ok": False,
            "detail": f"onion canary timed out x2 (tor may be slow): {last}"}


def _check_playwright():
    return {"ok": PLAYWRIGHT_AVAILABLE,
            "detail": "firefox installed" if PLAYWRIGHT_AVAILABLE
            else "playwright not importable — screenshots disabled"}


def _check_tg_vpn():
    """Cheap reachability probe for the Telegram-side SOCKS5 sidecar.
    Green if tg-socks accepts a TCP connection on port 1080. Doesn't
    validate that the WireGuard tunnel is actually carrying traffic —
    that only fails visibly when Telethon tries to connect."""
    if not _tg.configured() and not _tg.proxy_host:
        return {"ok": False, "detail": "telegram not configured"}
    host, port = _tg.proxy_host, _tg.proxy_port
    try:
        with socket.create_connection((host, port), timeout=2):
            return {"ok": True, "detail": f"SOCKS {host}:{port} reachable"}
    except Exception as e:
        return {"ok": False, "detail": f"TG SOCKS unreachable: {e}"}


def _run_health_checks():
    """Run all six checks concurrently, each with a per-check timeout."""
    checks = {
        "tor": _check_tor,
        "vpn": _check_vpn,
        "dns": _check_dns,
        "playwright": _check_playwright,
        "tg_vpn": _check_tg_vpn,
    }
    results = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {name: ex.submit(fn) for name, fn in checks.items()}
        for name, fut in futs.items():
            try:
                results[name] = fut.result(timeout=20)
            except FuturesTimeout:
                results[name] = {"ok": False, "detail": "timed out"}
            except Exception as e:
                results[name] = {"ok": False, "detail": f"error: {e}"}
    # IP-leak must run after Tor to share connection pools sensibly.
    results["ip_leak"] = _check_ip_leak(results["tor"])
    # `dns` (onion canary) is required for scans — clearnet exit via Tor
    # can pass while .onion resolution still fails (v2 deprecation, slow
    # circuits). `playwright` and `tg_vpn` stay advisory.
    results["secure"] = all(
        results[k]["ok"] for k in ("tor", "vpn", "ip_leak", "dns")
    )
    results["checked_at"] = datetime.utcnow().isoformat() + "Z"
    return results


def _get_health(fresh=False):
    now = time.time()
    if not fresh and _health_cache["data"] and now - _health_cache["ts"] < _HEALTH_TTL:
        return _health_cache["data"]
    data = _run_health_checks()
    _health_cache["data"] = data
    _health_cache["ts"] = now
    return data


def _quick_health():
    """Cheap liveness — SOCKS port + VPN ping. Safe to poll every few seconds
    during a scan without incurring rate-limit or timeout flakiness from
    check.torproject.org."""
    results = {"tor": _check_tor_alive(), "vpn": _check_vpn()}
    results["secure"] = results["tor"]["ok"] and results["vpn"]["ok"]
    results["checked_at"] = datetime.utcnow().isoformat() + "Z"
    return results


# ─── Scan thread ─────────────────────────────────────────────────────────────

def _run_scan(urls, depth):
    """Spawned on POST /api/scan. One thread at a time, enforced via the
    `_scan_thread.is_alive()` check in route_scan(). Shares the crawler
    instance with the monitor scheduler — serialized via `_crawl_lock`."""
    global _scan_started_at
    with _state_lock:
        _scan_started_at = time.time()
        _progress["completed"] = 0
        _progress["total"] = len(urls)

    started_at = datetime.now().isoformat()
    total_pages = 0
    total_findings = 0
    total_errors = 0
    _bump("scans_started")
    log.info(f"Scan starting: {len(urls)} URL(s), depth {depth}")
    try:
        for i, url in enumerate(urls):
            if _stop_event.is_set():
                log.info("Scan aborted by stop event")
                break
            if not url.startswith("http"):
                url = f"http://{url}"
            try:
                _crawler.db.add_url(url, source="web-ui")
                row = _crawler.db.conn.execute(
                    "SELECT id FROM urls WHERE url = ?", (url,)
                ).fetchone()
                if not row:
                    log.error(f"Could not add {url} to DB")
                    total_errors += 1
                    continue
                url_id = row[0]
                # NEWNYM between targets (best-effort)
                if i > 0:
                    _crawler.rotate_tor_circuit()
                # Serialize all crawler work so monitor ticks can't race
                # with us on the same Playwright browser / session.
                with _crawl_lock:
                    pages, findings = _crawler.crawl_site(
                        url_id, url, stop_event=_stop_event, max_depth=depth)
                _crawler.db.update_scan(url_id, 200 if pages > 0 else 404)
                if pages == 0:
                    _crawler.db.increment_fail(url_id)
                total_pages += pages
                total_findings += findings
                log.info(f"Done {url}: {pages} pages, {findings} findings")
            except Exception as e:
                log.error(f"Error scanning {url}: {e}")
                total_errors += 1
            with _state_lock:
                _progress["completed"] = i + 1
    finally:
        finished_at = datetime.now().isoformat()
        try:
            _crawler.db.log_scan(
                started_at, finished_at, len(urls),
                total_pages, total_findings, total_errors)
        except Exception as e:
            log.error(f"log_scan failed: {e}")
        # Reset progress so the UI doesn't display stale bars after finish.
        with _state_lock:
            _progress["completed"] = 0
            _progress["total"] = 0
            _scan_started_at = None
        _bump("scans_completed" if total_errors == 0 else "scans_errored")
        _bump("findings_new", total_findings)
        log.info(f"Scan thread finished ({total_pages} pages, "
                 f"{total_findings} findings, {total_errors} errors)")


# ─── Monitoring scheduler ────────────────────────────────────────────────────

def _next_check_at(interval_min):
    """Compute the next-check timestamp with ±MONITOR_JITTER randomization.
    Randomized to avoid a fixed cadence the target site could correlate."""
    base = interval_min * 60
    jitter = base * MONITOR_JITTER
    delay = max(60, base + random.uniform(-jitter, jitter))   # never < 60s
    return (datetime.utcnow() + timedelta(seconds=delay)).isoformat()


def _monitor_tg_channel(url_id):
    """Incremental Telegram channel scrape: pull messages newer than
    tg_last_msg_id, scan each, record a monitor event. Runs under
    _crawl_lock (caller).

    Adds a randomized 0-15 s pre-fetch delay on top of the scheduler's
    existing ±25% next_check_at jitter, so the scheduler wake-up time and
    the actual Telegram round-trip aren't perfectly correlated (harder to
    fingerprint as an automated poll pattern)."""
    info = _crawler.db.get_tg_channel(url_id)
    if not info:
        log.error(f"[monitor] tg channel {url_id} missing TG metadata")
        return 0, 0
    username = info["tg_username"]
    jitter_s = random.uniform(0, 15)
    if jitter_s > 1:
        log.info(f"[monitor] telegram @{username} — pre-fetch jitter {jitter_s:.1f}s")
    if _monitor_stop.wait(jitter_s):
        return 0, 0  # operator stopped during jitter
    log.info(f"[monitor] telegram @{username}")
    msgs = _tg.fetch_new_messages(
        info["tg_channel_id"],
        since_msg_id=info.get("tg_last_msg_id"),
        limit=_tg.scrape_limit,
        username=username)
    findings = 0
    latest = info.get("tg_last_msg_id") or 0
    for m in msgs:
        findings += _crawler.scan_tg_message(url_id, username, m)
        if m["msg_id"] > latest:
            latest = m["msg_id"]
    if msgs:
        _crawler.db.update_tg_last_msg_id(url_id, latest)
    log.info(f"[monitor] telegram @{username}: {len(msgs)} new, "
             f"{findings} finding(s)")
    return len(msgs), findings


def _monitor_one(url_id, url):
    """Single-URL monitored check. Branches on the url's source — Tor
    crawl for .onion rows, Telegram fetch for tg:// rows."""
    try:
        # Look up the source once so the monitor loop doesn't have to.
        row = _crawler.db.conn.execute(
            "SELECT source FROM urls WHERE id = ?", (url_id,)
        ).fetchone()
        source = row[0] if row else None

        if source == "telegram":
            # Separate path — scraper uses its own SOCKS tunnel; crawl_site
            # (Tor + Playwright) isn't relevant here.
            with _crawl_lock:
                pages, findings = _monitor_tg_channel(url_id)
            status = 200 if pages > 0 else 0
            _crawler.db.update_scan(url_id, status)
            row = _crawler.db.conn.execute(
                "SELECT id FROM pages WHERE url_id = ? "
                "ORDER BY scanned_at DESC LIMIT 1", (url_id,)
            ).fetchone()
            page_id = row[0] if row else None
            _crawler.db.add_monitor_event(
                url_id, status=status, pages=pages,
                findings=findings, page_id=page_id)
            return

        # Default (legacy) path: .onion crawl via Tor.
        log.info(f"[monitor] checking {url}")
        # Serialize with manual scans — the crawler's Playwright browser
        # and requests.Session are thread-bound / non-reentrant.
        with _crawl_lock:
            pages, findings = _crawler.crawl_site(
                url_id, url, stop_event=_monitor_stop, max_depth=0)
        status = 200 if pages > 0 else 0
        _crawler.db.update_scan(url_id, status)
        # Pick the most recent page row for THIS url_id — that's what the
        # screenshot belongs to.
        row = _crawler.db.conn.execute(
            "SELECT id FROM pages WHERE url_id = ? "
            "ORDER BY scanned_at DESC LIMIT 1", (url_id,)
        ).fetchone()
        page_id = row[0] if row else None
        _crawler.db.add_monitor_event(
            url_id, status=status, pages=pages,
            findings=findings, page_id=page_id)
        log.info(f"[monitor] {url}: {pages} page(s), {findings} finding(s)")
    except Exception as e:
        log.error(f"[monitor] {url} failed: {e}")
        _crawler.db.add_monitor_event(
            url_id, status=0, pages=0, findings=0, note=str(e)[:200])


def _maybe_auto_rescan():
    """Invoked once per monitor tick. If config.crawler.auto_rescan_hours
    is >0 and the last rescan is older than that, fire a rescan in the
    background. Guarded by last_rescan_at in ops_state so a restart
    doesn't trigger an immediate rescan every boot."""
    global _rescan_thread
    hours = getattr(_crawler, "auto_rescan_hours", 0) or 0
    if hours <= 0:
        return
    if _rescan_thread is not None and _rescan_thread.is_alive():
        return
    last = _crawler.db.ops_get("last_rescan_at")
    due = True
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
            due = (datetime.utcnow() - last_dt) >= timedelta(hours=hours)
        except Exception:
            due = True
    if not due:
        return
    log.info(f"[auto-rescan] cadence {hours}h elapsed — firing background rescan")
    _rescan_thread = threading.Thread(
        target=_run_rescan, args=(None,),
        name="AutoRescanWorker", daemon=True)
    _rescan_thread.start()


def _monitor_loop():
    """Background scheduler. Wakes every MONITOR_TICK seconds, runs any
    URL whose next_check_at has passed, schedules the next check.

    Skips ticks where:
      - A manual scan is running (don't fight for the crawler).
      - The security gate is not green (don't ever scan unsafely)."""
    log.info(f"Monitor scheduler started (tick={MONITOR_TICK}s, jitter=±{int(MONITOR_JITTER*100)}%)")
    while not _monitor_stop.is_set():
        try:
            # Don't run while a manual scan owns the crawler.
            with _state_lock:
                manual_running = (_scan_thread is not None
                                  and _scan_thread.is_alive())
            if manual_running:
                _monitor_stop.wait(MONITOR_TICK)
                continue

            # Auto-rescan scheduler: cheap check every tick, the function
            # itself rate-limits against last_rescan_at so there's no
            # extra bookkeeping here.
            _maybe_auto_rescan()

            due = _crawler.db.get_monitored_due(datetime.utcnow().isoformat())
            if due:
                # Hard security gate — same posture as manual scans.
                health = _quick_health()
                if not health.get("secure"):
                    log.warning(f"[monitor] {len(due)} URL(s) due but security gate is down — skipping")
                    _monitor_stop.wait(MONITOR_TICK)
                    continue

                for u in due:
                    if _monitor_stop.is_set():
                        break
                    _monitor_one(u["id"], u["url"])
                    # Schedule the NEXT check with random jitter.
                    _crawler.db.schedule_next_check(
                        u["id"], _next_check_at(u["interval_min"]))
        except Exception as e:
            log.error(f"[monitor] loop error: {e}")
        _monitor_stop.wait(MONITOR_TICK)
    log.info("Monitor scheduler stopped")


def _start_monitor_thread():
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        return
    _monitor_thread = threading.Thread(
        target=_monitor_loop, name="MonitorScheduler", daemon=True)
    _monitor_thread.start()


# ── Real-time live-listener wiring ─────────────────────────────────────────

def _tg_live_on_message(channel_id, username, msg):
    """Listener callback — runs in the listener's asyncio thread. MUST
    return fast: just enqueue, drain elsewhere."""
    try:
        _tg_live_queue.put_nowait({"channel_id": channel_id,
                                   "username": username, "msg": msg})
    except queue.Full:
        log.warning("[tg-live] queue full — dropping event")


def _tg_live_consumer():
    """Drain the live-event queue, scan each message under _crawl_lock.
    Same scan path as _monitor_tg_channel but one message at a time."""
    while not _tg_live_stop.is_set():
        try:
            ev = _tg_live_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            # Map channel_id → url_id via the DB.
            row = _crawler.db.conn.execute(
                "SELECT id, tg_username FROM urls "
                "WHERE tg_channel_id = ? LIMIT 1",
                (ev["channel_id"],)).fetchone()
            if not row:
                continue
            url_id, uname = row[0], row[1]
            with _crawl_lock:
                _crawler.scan_tg_message(url_id, uname, ev["msg"])
                # Advance the high-water mark so the polling scheduler
                # doesn't re-fetch this message.
                info = _crawler.db.get_tg_channel(url_id)
                if info and (info.get("tg_last_msg_id") or 0) < ev["msg"]["msg_id"]:
                    _crawler.db.update_tg_last_msg_id(url_id, ev["msg"]["msg_id"])
            log.info(f"[tg-live] scanned @{uname} #{ev['msg']['msg_id']}")
        except Exception as e:
            log.error(f"[tg-live] consumer error: {e}")


def _start_tg_live():
    """Bootstrap the live listener + consumer. Idempotent."""
    global _tg_live, _tg_live_consumer_thread
    tg_cfg = _config.get("telegram", {})
    if not tg_cfg.get("live_enabled"):
        return
    if not _tg.configured():
        log.info("[tg-live] skipped — telegram not configured")
        return
    if _tg_live:
        return
    channels = _crawler.db.get_url_rows(limit=1000, source="telegram") or []
    ids = [c["tg_channel_id"] for c in channels if c.get("tg_channel_id")]
    _tg_live_stop.clear()
    _tg_live_consumer_thread = threading.Thread(
        target=_tg_live_consumer, name="TgLiveConsumer", daemon=True)
    _tg_live_consumer_thread.start()
    _tg_live = TelegramLiveListener(
        _tg, on_message=_tg_live_on_message, channel_ids=ids)
    _tg_live.start()
    log.info(f"[tg-live] enabled — watching {len(ids)} channel(s)")


def _refresh_tg_live_channels():
    """Call after add/delete of a TG channel so the live listener's
    filter set stays in sync with the DB."""
    if _tg_live is None: return
    channels = _crawler.db.get_url_rows(limit=1000, source="telegram") or []
    ids = [c["tg_channel_id"] for c in channels if c.get("tg_channel_id")]
    _tg_live.set_channels(ids)


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_file(os.path.join(os.path.dirname(__file__), "index.html"))


@app.route("/metrics")
def route_metrics():
    """Prometheus scrape endpoint. Exposes DarkWatch-specific gauges +
    counters so the operator can graph scan throughput, finding rates,
    and Telegram rate-limiter pressure in Grafana. prometheus_client is
    an optional dep; if missing, return a plain-text explanation so a
    misconfigured scraper sees a helpful body instead of a 500."""
    try:
        from prometheus_client import (
            Gauge, Counter, CollectorRegistry, generate_latest,
            CONTENT_TYPE_LATEST)
    except ImportError:
        return Response("prometheus_client not installed\n",
                        mimetype="text/plain"), 503

    # Per-request registry — avoids global-counter weirdness with Flask's
    # multi-threaded runner. Gauges snapshot current state; counters on
    # this endpoint would be pointless since they reset per request.
    reg = CollectorRegistry()
    stats = _crawler.db.get_stats()
    g_urls      = Gauge("darkwatch_urls_total", "Tracked URLs", registry=reg)
    g_pages     = Gauge("darkwatch_pages_total", "Scanned pages", registry=reg)
    g_findings  = Gauge("darkwatch_findings_total", "Findings", registry=reg)
    g_critical  = Gauge("darkwatch_findings_critical", "Critical findings", registry=reg)
    g_monitored = Gauge("darkwatch_urls_monitored", "Monitored URLs", registry=reg)
    g_urls.set(stats.get("total_urls", 0))
    g_pages.set(stats.get("total_pages", 0))
    g_findings.set(stats.get("total_findings", 0))
    g_critical.set(stats.get("critical_findings", 0))
    g_monitored.set(stats.get("monitored_urls", 0))

    # Scan state.
    with _state_lock:
        running = _scan_thread is not None and _scan_thread.is_alive()
    g_scan = Gauge("darkwatch_scan_running",
                   "1 if a scan is currently running",
                   registry=reg)
    g_scan.set(1 if running else 0)

    # Telegram pressure — one gauge per channel, labeled by channel_id.
    g_tg_press = Gauge("darkwatch_tg_calls_1h",
                       "Telethon calls in the last hour",
                       ["channel_id"], registry=reg)
    for row in _tg.channel_pressure_report(limit=50):
        g_tg_press.labels(channel_id=str(row["channel_id"])) \
                  .set(row["calls_1h"])

    # Live listener.
    g_live_q = Gauge("darkwatch_tg_live_queue_depth",
                     "Pending real-time events awaiting scan",
                     registry=reg)
    g_live_q.set(_tg_live_queue.qsize())

    # Screenshot worker queue — a growing depth means selective
    # screenshotting is still being outrun by the scan loop.
    worker = getattr(_crawler, "screenshot_worker", None)
    if worker is not None:
        g_ss_q = Gauge("darkwatch_screenshot_queue_depth",
                       "Pending screenshot capture requests",
                       registry=reg)
        g_ss_q.set(worker.qsize())
        g_ss_done = Gauge("darkwatch_screenshot_processed_total",
                           "Screenshots rendered since boot",
                           registry=reg)
        g_ss_done.set(worker.processed)
        g_ss_drop = Gauge("darkwatch_screenshot_dropped_total",
                           "Screenshot requests dropped (queue full)",
                           registry=reg)
        g_ss_drop.set(worker.dropped)

    # In-process counters.
    with _counters_lock:
        snap = dict(_counters)
    for key, val in snap.items():
        g = Gauge(f"darkwatch_{key}_total",
                  f"Cumulative {key.replace('_',' ')}", registry=reg)
        g.set(val)

    # Per-category URL error breakdown (timeout / tor_down / http_4xx / ...).
    g_url_err = Gauge("darkwatch_urls_by_error_category",
                      "URLs grouped by most recent fetch error category",
                      ["category"], registry=reg)
    try:
        for cat, n in _crawler.db.error_category_counts().items():
            g_url_err.labels(category=cat).set(n)
    except Exception:
        pass

    return Response(generate_latest(reg), mimetype=CONTENT_TYPE_LATEST)


@app.route("/api/ui-config")
def route_ui_config():
    """Small bundle of UI-facing deployment settings (no secrets)."""
    setup_port = int(os.environ.get("SETUP_HOST_PORT", "8082"))
    host = (request.host or "localhost").split(":")[0]
    reports_dir = _crawler.reports_dir
    has_report = False
    try:
        has_report = any(
            f.endswith(".json")
            for f in os.listdir(reports_dir)
        )
    except OSError:
        pass
    return jsonify({
        "version": __version__,
        "setup_port": setup_port,
        "setup_url": f"http://{host}:{setup_port}/",
        "has_report": has_report,
    })


@app.route("/api/health")
def route_health():
    fresh = request.args.get("fresh") == "1"
    return jsonify(_get_health(fresh=fresh))


@app.route("/api/health/quick")
def route_health_quick():
    return jsonify(_quick_health())


@app.route("/api/status")
def route_status():
    # Drain the log queue.
    new_logs = []
    while True:
        try:
            new_logs.append(_log_queue.get_nowait())
        except queue.Empty:
            break

    with _state_lock:
        running = _scan_thread is not None and _scan_thread.is_alive()
        # Snapshot progress atomically alongside `running` so the UI
        # doesn't render "idle but 3/10 done" during the scan shutdown window.
        if running:
            progress = dict(_progress)
            elapsed = int(time.time() - _scan_started_at) \
                      if _scan_started_at else 0
        else:
            progress = {"completed": 0, "total": 0}
            elapsed = 0

    return jsonify({
        "running": running,
        "stats": _crawler.db.get_stats(),
        "new_logs": new_logs,
        "progress": progress,
        "elapsed_seconds": elapsed,
    })


@app.route("/api/scan", methods=["POST"])
def route_scan():
    global _scan_thread
    body = request.get_json(silent=True) or {}
    raw_urls = body.get("urls") or []
    depth = int(body.get("depth") or _crawler.max_depth)

    urls = [u.strip() for u in raw_urls if isinstance(u, str) and u.strip()]
    if not urls:
        return jsonify({"error": "no URLs provided"}), 400

    bad_onions = [{"url": u, "error": err} for u in urls
                  if (err := onion_url_error(u))]
    if bad_onions:
        return jsonify({"error": "invalid .onion URL(s) — v2 onions no longer work",
                        "details": bad_onions}), 400

    # Phase 1: brief lock — bail early if a scan is already running so we
    # don't waste 20s on a health check we can't act on.
    with _state_lock:
        if _scan_thread is not None and _scan_thread.is_alive():
            return jsonify({"error": "scan already running"}), 409

    # Phase 2: NO lock — slow fresh health check. Other endpoints stay
    # responsive while the operator's Start click is being verified.
    health = _get_health(fresh=True)
    if not health.get("secure"):
        failed = [k for k in ("tor", "vpn", "ip_leak", "dns")
                  if not health.get(k, {}).get("ok")]
        return jsonify({
            "error": f"security gate failed: {', '.join(failed) or 'unknown'}",
            "detail": health,
        }), 403

    # Phase 3: re-acquire and spawn — re-check the running flag in case
    # another caller raced in during the unlocked phase 2.
    with _state_lock:
        if _scan_thread is not None and _scan_thread.is_alive():
            return jsonify({"error": "scan already running"}), 409
        _stop_event.clear()
        _scan_thread = threading.Thread(
            target=_run_scan, args=(urls, depth), daemon=True)
        _scan_thread.start()

    return jsonify({"started": True, "urls": len(urls), "depth": depth}), 202


@app.route("/api/stop", methods=["POST"])
def route_stop():
    _stop_event.set()
    return jsonify({"stopped": True})


# ── Bulk rescan ─────────────────────────────────────────────────────────────
# Re-runs YARA rules across every stored page's text_snapshot without
# re-fetching the target. The operator uses this after adding new
# keywords (or pulling fresh threat intel) to backfill findings on
# already-scraped pages. Runs in a worker thread so the HTTP call
# returns immediately with an accepted status — poll /api/status or
# /metrics to watch progress.

_rescan_thread = None
_rescan_stop = threading.Event()
_rescan_last = {"started_at": None, "finished_at": None,
                 "scanned": 0, "findings": 0, "skipped": 0}


def _run_rescan(url_id=None):
    global _rescan_last
    _rescan_last = {"started_at": datetime.utcnow().isoformat(),
                    "finished_at": None,
                    "scanned": 0, "findings": 0, "skipped": 0}
    try:
        with _crawl_lock:
            result = _crawler.rescan_pages(url_id=url_id)
        _rescan_last.update(result)
        _bump("rescans")
        _bump("findings_new", result.get("findings", 0))
    except Exception as e:
        log.error(f"rescan failed: {e}")
        _rescan_last["error"] = str(e)
    finally:
        _rescan_last["finished_at"] = datetime.utcnow().isoformat()


@app.route("/api/rescan", methods=["POST"])
def route_rescan():
    """Run YARA rules against every stored page (or just the pages of a
    single url_id). Non-blocking; returns 202 with the accepted scope.
    One rescan at a time (409 if one is already running)."""
    global _rescan_thread
    body = request.get_json(silent=True) or {}
    url_id = body.get("url_id")
    try:
        url_id = int(url_id) if url_id is not None else None
    except Exception:
        return jsonify({"error": "url_id must be integer"}), 400
    if _rescan_thread is not None and _rescan_thread.is_alive():
        return jsonify({"error": "rescan already running"}), 409
    _rescan_stop.clear()
    _rescan_thread = threading.Thread(
        target=_run_rescan, args=(url_id,),
        name="RescanWorker", daemon=True)
    _rescan_thread.start()
    return jsonify({"started": True, "scope":
                    "all" if url_id is None else f"url_id={url_id}"}), 202


@app.route("/api/rescan/status")
def route_rescan_status():
    running = _rescan_thread is not None and _rescan_thread.is_alive()
    return jsonify({"running": running, "last": _rescan_last})


# ── Threat-intel refresh ────────────────────────────────────────────────────

_intel_thread = None
_intel_last = {"started_at": None, "finished_at": None, "result": None}


def _run_threat_intel_refresh():
    global _intel_last
    _intel_last = {"started_at": datetime.utcnow().isoformat(),
                    "finished_at": None, "result": None}
    try:
        feeds_cfg = _config.get("threat_intel", {}).get("feeds")
        tif = ThreatIntelFeed(
            _crawler.intel_rules_path,
            feeds=feeds_cfg,
            proxies=_crawler.proxies,
            timeout=int(_config.get("threat_intel", {}).get("timeout", 30)))
        result = tif.refresh()
        if result.get("updated"):
            # Recompile into the scanner so the next scan sees new rules.
            _crawler.scanner.load_intel_rules(_crawler.intel_rules_path)
        _intel_last["result"] = result
        _bump("threat_intel_refreshes")
    except Exception as e:
        log.error(f"threat_intel refresh error: {e}")
        _intel_last["result"] = {"error": str(e)}
    finally:
        _intel_last["finished_at"] = datetime.utcnow().isoformat()


@app.route("/api/threat-intel/refresh", methods=["POST"])
def route_threat_intel_refresh():
    """Fetch configured threat-intel feeds and rebuild the intel YARA
    rule file. Non-blocking — results poll via /api/threat-intel/status."""
    global _intel_thread
    if _intel_thread is not None and _intel_thread.is_alive():
        return jsonify({"error": "refresh already running"}), 409
    _intel_thread = threading.Thread(
        target=_run_threat_intel_refresh,
        name="ThreatIntelRefresh", daemon=True)
    _intel_thread.start()
    return jsonify({"started": True}), 202


@app.route("/api/threat-intel/status")
def route_threat_intel_status():
    running = _intel_thread is not None and _intel_thread.is_alive()
    return jsonify({"running": running, "last": _intel_last})


@app.route("/api/findings")
def route_findings():
    severity = request.args.get("severity")
    min_score = int(request.args.get("min_score") or 0)
    # Cursor + page size: pass the last finding id from the previous page
    # as ?before_id= to fetch older rows. Default page is the newest 100;
    # UI requests bigger pages by raising ?limit= (capped server-side).
    try:
        limit = max(1, min(500, int(request.args.get("limit") or 100)))
    except Exception:
        limit = 100
    try:
        before_id = request.args.get("before_id")
        before_id = int(before_id) if before_id else None
    except Exception:
        before_id = None
    # Optional FP filter: ?max_fp=40 hides findings the heuristic scored
    # as >=40 probability-of-false-positive.
    try:
        raw = request.args.get("max_fp")
        max_fp = int(raw) if raw is not None else None
    except Exception:
        max_fp = None
    findings = _crawler.db.get_findings(
        min_score=min_score, limit=limit + 1,
        before_id=before_id, severity=severity,
        max_fp_score=max_fp)
    has_more = len(findings) > limit
    if has_more: findings = findings[:limit]
    # Surface relative thumbnail URLs for the UI.
    for f in findings:
        pid = f.get("page_id")
        f["thumbnail_url"] = f"/api/thumbnail/{pid}" if pid and f.get("thumbnail_path") else None
        f["screenshot_url"] = f"/api/screenshot/{pid}" if pid and f.get("screenshot_path") else None
    next_cursor = findings[-1]["id"] if findings and has_more else None
    return jsonify({"findings": findings,
                    "has_more": has_more,
                    "next_cursor": next_cursor,
                    "limit": limit})


@app.route("/api/findings/<int:finding_id>", methods=["DELETE"])
def route_delete_finding(finding_id):
    n = _crawler.db.delete_finding(finding_id)
    if n == 0:
        abort(404)
    return jsonify({"deleted": n})


@app.route("/api/findings", methods=["DELETE"])
def route_delete_findings():
    severity = request.args.get("severity")
    min_score = request.args.get("min_score")
    min_score = int(min_score) if min_score is not None else None
    n = _crawler.db.delete_findings(severity=severity, min_score=min_score)
    return jsonify({"deleted": n})


@app.route("/api/findings.csv")
def route_findings_csv():
    findings = _crawler.db.get_findings(min_score=0, limit=5000)
    buf = io.StringIO()
    cols = ["found_at", "severity", "score", "rule_name", "rule_type",
            "page_url", "matched_strings", "snippet"]
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow({c: f.get(c, "") for c in cols})
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="findings_{datetime.utcnow():%Y%m%d_%H%M%S}.csv"'})


@app.route("/api/urls")
def route_urls():
    try:
        limit = max(1, min(1000, int(request.args.get("limit") or 200)))
    except Exception:
        limit = 200
    try:
        offset = max(0, int(request.args.get("offset") or 0))
    except Exception:
        offset = 0
    source = request.args.get("source") or None
    rows = _crawler.db.get_url_rows(limit=limit, source=source, offset=offset)
    total = _crawler.db.count_url_rows(source=source)
    return jsonify({"urls": rows, "total": total,
                    "offset": offset, "limit": limit,
                    "has_more": (offset + len(rows)) < total})


@app.route("/api/targets-file")
def route_targets_file():
    """Return the contents of loot/targets.txt as a JSON list — one URL
    per element, comments (#-prefixed) and blank lines stripped. Used by
    the Scan tab's 'Import from targets.txt' button."""
    path = os.path.join(_crawler.loot_dir, "targets.txt")
    if not os.path.isfile(path):
        return jsonify({"urls": [], "error": "targets.txt not found"}), 404
    urls = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except Exception as e:
        return jsonify({"urls": [], "error": str(e)}), 500
    return jsonify({"urls": urls})


@app.route("/api/rules")
def route_rules():
    return jsonify(_crawler.scanner.list_rules())


@app.route("/api/rules/delete", methods=["POST"])
def route_rules_delete():
    """Delete deletable rules: keyword-backed user.yar rules and/or custom files."""
    body = request.get_json(silent=True) or {}
    names = body.get("names")
    if not isinstance(names, list) or not names:
        return jsonify({"error": "names must be a non-empty list of rule names"}), 400
    result = _crawler.scanner.delete_rules(names, _crawler.db)
    return jsonify({"ok": True, "names": names, **result})


@app.route("/api/yara/custom", methods=["POST"])
def route_yara_custom_add():
    """Add a custom YARA rule file under yara-private (rejects duplicates)."""
    body = request.get_json(silent=True) or {}
    content = body.get("content") or ""
    filename = body.get("filename") or body.get("name") or ""
    try:
        saved = _crawler.scanner.save_custom_rule(content, filename)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.error("custom yara save failed: %s", e)
        return jsonify({"error": "failed to save custom rule"}), 500
    return jsonify({"ok": True, "filename": saved})


# ─── Telegram routes ─────────────────────────────────────────────────────────
# Single-operator flow: set api_id / api_hash in config.json, click Connect
# Telegram in the UI, enter phone, receive code, enter code. Session persists
# in /app/data/telegram.session across container restarts. All Telethon
# network I/O goes through the `tg-socks` sidecar (separate WireGuard
# tunnel from the Tor path) — see _check_tg_vpn.

@app.route("/api/telegram/status")
def route_tg_status():
    s = _tg.status()
    s["live_enabled"] = bool(_config.get("telegram", {}).get("live_enabled"))
    s["live_running"] = bool(_tg_live and _tg_live._thread
                             and _tg_live._thread.is_alive())
    s["live_queue"]   = _tg_live_queue.qsize()
    s["pressure"]     = _tg.channel_pressure_report(limit=10)
    return jsonify(s)


@app.route("/api/telegram/auth/start", methods=["POST"])
def route_tg_auth_start():
    body = request.get_json(silent=True) or {}
    phone = (body.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone is required"}), 400
    if not _tg.configured():
        return jsonify({"error": "telegram not configured (set api_id/api_hash)"}), 400
    with _crawl_lock:
        r = _tg.auth_send_code(phone)
    if not r.get("ok"):
        return jsonify({"error": r.get("error", "auth_send_code failed")}), 400
    return jsonify({"ok": True, "phone_code_hash": r["phone_code_hash"]})


@app.route("/api/telegram/auth/confirm", methods=["POST"])
def route_tg_auth_confirm():
    body = request.get_json(silent=True) or {}
    phone = (body.get("phone") or "").strip()
    code = (body.get("code") or "").strip()
    password = body.get("password")
    phone_code_hash = body.get("phone_code_hash")
    if not phone or not code:
        return jsonify({"error": "phone and code are required"}), 400
    with _crawl_lock:
        r = _tg.auth_confirm(phone, code, password=password,
                              phone_code_hash=phone_code_hash)
    if not r.get("ok"):
        status = 401 if r.get("error") == "2fa_password_required" else 400
        return jsonify(r), status
    return jsonify(r)


@app.route("/api/telegram/auth/logout", methods=["POST"])
def route_tg_auth_logout():
    with _crawl_lock:
        r = _tg.logout()
    return jsonify(r)


@app.route("/api/telegram/auth/qr/start", methods=["POST"])
def route_tg_auth_qr_start():
    """Start a QR-code login. Returns {token, url, qr_svg}. The client
    renders qr_svg; the user scans it with their Telegram mobile app.
    Poll /api/telegram/auth/qr/status?token=… until authenticated.
    """
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    r = _tg.auth_qr_start()
    if r.get("error") and not r.get("url"):
        return jsonify(r), 400
    r["qr_svg"] = _render_qr_svg(r["url"]) if r.get("url") else None
    return jsonify(r)


@app.route("/api/telegram/auth/qr/status")
def route_tg_auth_qr_status():
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "token is required"}), 400
    r = _tg.auth_qr_status(token)
    return jsonify(r)


@app.route("/api/telegram/auth/qr/password", methods=["POST"])
def route_tg_auth_qr_password():
    body = request.get_json(silent=True) or {}
    token = body.get("token")
    password = body.get("password")
    if not token or not password:
        return jsonify({"error": "token and password required"}), 400
    with _crawl_lock:
        r = _tg.auth_qr_password(token, password)
    return jsonify(r), (200 if r.get("ok") else 400)


def _render_qr_svg(data):
    """Pure-Python QR encoder. No external calls (external QR services
    would leak the one-time login URL; we refuse to hand that to a
    third party). Requires the `qrcode` package (added in Dockerfile).
    Returns an SVG string or None on failure."""
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except ImportError:
        log.warning("qrcode library not available — returning null SVG")
        return None
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                            box_size=10, border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(image_factory=SvgPathImage)
        import io as _io
        buf = _io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception as e:
        log.warning(f"QR render failed: {e}")
        return None


@app.route("/api/telegram/channels", methods=["POST"])
def route_tg_add_channel():
    body = request.get_json(silent=True) or {}
    ident = (body.get("identifier") or "").strip()
    if not ident:
        return jsonify({"error": "identifier is required"}), 400
    with _crawl_lock:
        info = _tg.resolve_channel(ident)
    if info.get("error"):
        return jsonify(info), 400
    url_id = _crawler.db.upsert_tg_channel(
        username=info["username"],
        channel_id=info["channel_id"],
        title=info.get("title"),
        subscribers=info.get("subscribers"),
        about=info.get("about"),
        verified=info.get("verified"),
        scam=info.get("scam"),
        kind=info.get("kind"),
        is_private=info.get("is_private"),
    )
    _refresh_tg_live_channels()
    return jsonify({"id": url_id, **info}), 201


@app.route("/api/telegram/channels/<int:url_id>/details")
def route_tg_channel_details(url_id):
    """Enriched channel profile: creation date, admin count, pinned msg,
    linked discussion group, slowmode config, antispam flag, and
    best-effort creator identity (user_id / @handle / display name /
    phone if visible).

    Query params:
      refresh=1   — force a fresh MTProto call even if we have cached
                    details from a recent fetch. Default: use cache when
                    fetched <1h ago.
    """
    if not _crawler.db.url_exists(url_id):
        abort(404)
    cached = _crawler.db.get_tg_channel(url_id)
    if not cached:
        return jsonify({"error": "not a telegram channel"}), 400
    refresh = (request.args.get("refresh") or "0") in ("1", "true", "yes")
    fetched_at = cached.get("tg_details_fetched_at")
    # Cache ttl: 1h. Avoids re-hitting MTProto on every UI expand.
    cache_fresh = False
    if fetched_at and not refresh:
        try:
            ft = datetime.fromisoformat(fetched_at.replace("Z", ""))
            cache_fresh = (datetime.utcnow() - ft).total_seconds() < 3600
        except Exception:
            pass
    if cache_fresh:
        return jsonify({"source": "cache", **_slim_details_from_cache(cached)})
    if not _tg.configured() or not _tg.status().get("authenticated"):
        # Return what we have from DB rather than erroring — the UI
        # still needs SOMETHING to render.
        return jsonify({"source": "cache", "stale": True,
                        **_slim_details_from_cache(cached)})
    photo_dir = os.path.join(_crawler.loot_dir, "tg-media", "channels")
    with _crawl_lock:
        r = _tg.get_channel_details(
            cached["tg_channel_id"], username=cached.get("tg_username"),
            photo_dest_dir=photo_dir)
    if r.get("error"):
        return jsonify({"source": "cache", "stale": True,
                        "error": r["error"],
                        **_slim_details_from_cache(cached)}), 200
    _crawler.db.update_tg_channel_details(url_id, r)
    # Decorate with a servable URL for the avatar.
    if r.get("photo_path"):
        r["photo_url"] = f"/loot/tg-media/{r['photo_path']}"
    return jsonify({"source": "live", **r})


@app.route("/api/telegram/channels/<int:url_id>/links")
def route_tg_channel_links(url_id):
    """Aggregate links found in every stored message of a channel:
      - forwards   (channels this one forwards from)
      - telegram   (t.me links + @mentions in message bodies)
      - external   (non-Telegram URLs grouped by host)
    """
    if not _crawler.db.url_exists(url_id):
        abort(404)
    info = _crawler.db.get_tg_channel(url_id)
    if not info:
        return jsonify({"error": "not a telegram channel"}), 400
    return jsonify(_crawler.db.extract_channel_links(url_id))


def _slim_details_from_cache(row):
    """Reshape a cached `urls` row into the same dict shape
    get_channel_details returns, so the UI handler is identical whether
    data came from DB cache or from a live fetch."""
    photo_path = row.get("tg_photo_path")
    return {
        "channel_id": row.get("tg_channel_id"),
        "title":      row.get("tg_title") or row.get("title"),
        "photo_path": photo_path,
        "photo_url":  f"/loot/tg-media/{photo_path}" if photo_path else None,
        "username":   row.get("tg_username"),
        "subscribers": row.get("tg_subscribers"),
        "about":      row.get("tg_about"),
        "kind":       row.get("tg_kind"),
        "is_private": bool(row.get("tg_is_private")),
        "verified":   bool(row.get("tg_verified")),
        "scam":       bool(row.get("tg_scam")),
        "created":    row.get("tg_created"),
        "admins_count": row.get("tg_admins_count"),
        "online_count": row.get("tg_online_count"),
        "linked_chat_id": row.get("tg_linked_chat_id"),
        "migrated_from": row.get("tg_migrated_from"),
        "slowmode_seconds": row.get("tg_slowmode_seconds"),
        "pinned_msg_id": row.get("tg_pinned_msg_id"),
        "participants_hidden": bool(row.get("tg_participants_hidden")),
        "antispam":   bool(row.get("tg_antispam")),
        "ttl_period": row.get("tg_ttl_period"),
        "restricted_reason": row.get("tg_restricted_reason"),
        "creator": ({
            "user_id":  row.get("tg_creator_id"),
            "username": row.get("tg_creator_username"),
            "name":     row.get("tg_creator_name"),
            "phone":    row.get("tg_creator_phone"),
            "bot":      bool(row.get("tg_creator_bot")),
            "premium":  bool(row.get("tg_creator_premium")),
        } if row.get("tg_creator_id") else None),
        "fetched_at": row.get("tg_details_fetched_at"),
    }


@app.route("/api/telegram/channels/<int:url_id>/messages")
def route_tg_channel_messages(url_id):
    """Recent messages for a channel, with rich metadata + any matching
    findings folded in. Used by the UI's expandable channel row."""
    if not _crawler.db.url_exists(url_id):
        abort(404)
    try:
        limit = int(request.args.get("limit") or 50)
    except Exception:
        limit = 50
    msgs = _crawler.db.list_tg_messages(url_id, limit=limit)
    return jsonify(msgs)


@app.route("/api/telegram/channels/<int:url_id>/scrape", methods=["POST"])
def route_tg_scrape(url_id):
    """One-shot historical pull. Runs under _crawl_lock so it can't race a
    monitor tick or a manual .onion scan. For channels the operator wants
    monitored continuously they should toggle the monitor on instead."""
    if not _crawler.db.url_exists(url_id):
        abort(404)
    info = _crawler.db.get_tg_channel(url_id)
    if not info:
        return jsonify({"error": "not a telegram channel"}), 400
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    # Surface auth failures up-front instead of returning "fetched: 0" —
    # that silent shape is the #1 source of "scraper not working" reports.
    status = _tg.status()
    if not status.get("authenticated"):
        return jsonify({"error": "telegram not authenticated — "
                                  "sign in via the Telegram tab"}), 401
    body = request.get_json(silent=True) or {}
    # Supported sizes: 100 / 500 / 1000 / all. "all" caps at 5000 so a
    # rogue channel can't DoS us. "deep" chunks through in 500-message
    # batches so the rate limiter paces fairly.
    raw_limit = body.get("limit")
    deep = bool(body.get("deep"))
    if raw_limit == "all":
        total_cap = 5000
    else:
        try: total_cap = max(1, min(5000, int(raw_limit or 200)))
        except Exception: total_cap = 200
    batch_size = 500 if deep or total_cap > 500 else total_cap
    username = info.get("tg_username")
    log.info(f"[tg-scrape] @{username} cap={total_cap} batch={batch_size} deep={deep}")
    fetched_total = 0
    found = 0
    latest_id = info.get("tg_last_msg_id") or 0
    with _crawl_lock:
        # min_id cursor walks BACKWARD through history. On the first
        # batch we fetch the newest N; subsequent batches use max_id
        # to keep walking back. Current fetch_new_messages doesn't
        # expose max_id — simplest multi-batch impl: loop with offset
        # reduction by the last msg_id seen.
        earliest_seen = None
        while fetched_total < total_cap:
            remaining = total_cap - fetched_total
            this_batch = min(batch_size, remaining)
            msgs = _tg.fetch_new_messages(
                info["tg_channel_id"],
                since_msg_id=None,
                limit=this_batch,
                username=username,
                before_msg_id=earliest_seen)
            if not msgs: break
            for m in msgs:
                found += _crawler.scan_tg_message(url_id, username, m)
                if m["msg_id"] > (latest_id or 0):
                    latest_id = m["msg_id"]
                if earliest_seen is None or m["msg_id"] < earliest_seen:
                    earliest_seen = m["msg_id"]
            fetched_total += len(msgs)
            if len(msgs) < this_batch:
                break   # channel history exhausted
        if latest_id:
            _crawler.db.update_tg_last_msg_id(url_id, latest_id)
        # Deep mode ALSO re-runs rules over everything we've stored so
        # newly-added keywords catch up. Idempotent — purges prior
        # findings on each message before re-evaluating.
        rescan_findings = 0
        if deep:
            r = _crawler.rescan_tg_channel(url_id)
            rescan_findings = r.get("findings", 0)
            log.info(f"[tg-scrape] @{username} rescan scanned={r['scanned']} "
                     f"found={rescan_findings}")
    _crawler.db.update_scan(url_id, 200 if fetched_total else 404)
    log.info(f"[tg-scrape] @{username} fetched={fetched_total} findings={found}")
    if not fetched_total:
        reason = _tg.last_fetch_error or (
            "Telegram returned an empty result set. "
            "For private channels, make sure your Telegram account is a "
            "member (use the Join button).")
        return jsonify({"fetched": 0, "findings": 0,
                        "last_msg_id": latest_id,
                        "warning": f"no messages returned — {reason}"})
    return jsonify({"fetched": fetched_total,
                    "findings": found + rescan_findings,
                    "rescan_findings": rescan_findings if deep else None,
                    "last_msg_id": latest_id,
                    "deep": deep})


@app.route("/api/telegram/channels/<int:url_id>/join", methods=["POST"])
def route_tg_join(url_id):
    """Join the channel with the operator's Telegram account. Required
    for private channels and useful for public channels where Telegram's
    "not a member" gate limits what iter_messages returns. The body may
    include {invite_hash: "..."} for invite-link joins."""
    if not _crawler.db.url_exists(url_id):
        abort(404)
    info = _crawler.db.get_tg_channel(url_id)
    if not info:
        return jsonify({"error": "not a telegram channel"}), 400
    if not _tg.configured() or not _tg.status().get("authenticated"):
        return jsonify({"error": "telegram not authenticated"}), 401
    body = request.get_json(silent=True) or {}
    invite_hash = (body.get("invite_hash") or "").strip() or None
    with _crawl_lock:
        r = _tg.join_channel(info["tg_channel_id"],
                             username=info.get("tg_username"),
                             invite_hash=invite_hash)
    if r.get("ok"):
        _crawler.db.set_tg_membership(url_id, True)
        log.info(f"[tg-join] @{info.get('tg_username')} "
                 f"via={r.get('joined_via')}")
    return jsonify(r), (200 if r.get("ok") else 400)


@app.route("/api/telegram/channels/<int:url_id>/leave", methods=["POST"])
def route_tg_leave(url_id):
    """Leave a channel the operator's account is currently in."""
    if not _crawler.db.url_exists(url_id):
        abort(404)
    info = _crawler.db.get_tg_channel(url_id)
    if not info:
        return jsonify({"error": "not a telegram channel"}), 400
    if not _tg.configured() or not _tg.status().get("authenticated"):
        return jsonify({"error": "telegram not authenticated"}), 401
    with _crawl_lock:
        r = _tg.leave_channel(info["tg_channel_id"],
                              username=info.get("tg_username"))
    if r.get("ok"):
        _crawler.db.set_tg_membership(url_id, False)
        log.info(f"[tg-leave] @{info.get('tg_username')}")
    return jsonify(r), (200 if r.get("ok") else 400)


@app.route("/api/telegram/channels/<int:url_id>/rescan", methods=["POST"])
def route_tg_rescan(url_id):
    """Re-run YARA rules over every stored message for this channel.
    Use after adding new keywords — without this, old messages stay
    unevaluated because `pages.content_hash` dedup skips them on
    re-scrape."""
    if not _crawler.db.url_exists(url_id):
        abort(404)
    info = _crawler.db.get_tg_channel(url_id)
    if not info:
        return jsonify({"error": "not a telegram channel"}), 400
    with _crawl_lock:
        r = _crawler.rescan_tg_channel(url_id)
    log.info(f"[tg-rescan] @{info.get('tg_username')} "
             f"scanned={r['scanned']} findings={r['findings']}")
    return jsonify(r)


@app.route("/api/telegram/discover")
def route_tg_discover():
    """Find channels / groups / users matching a free-text query via the
    global Telegram directory. Results include metadata useful for
    deciding whether to click-to-add: title, subscribers, verified /
    scam flags, kind (channel / megagroup / group)."""
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    q = (request.args.get("q") or "").strip()
    try:
        limit = max(1, min(50, int(request.args.get("limit") or 30)))
    except Exception:
        limit = 30
    with _crawl_lock:
        r = _tg.search_directory(q, limit=limit)
    if r.get("error"):
        return jsonify(r), 400
    return jsonify(r)


@app.route("/api/telegram/discover/smart")
def route_tg_discover_smart():
    """Clever global-channel discovery. Runs query-expansion variants +
    mines forwards/mentions in already-tracked channels + ranks. Query
    params:

      q              (required)  — free-text search
      limit                      — max channels returned (default 30)
      mode           safe|thorough  — sets rate-limiter + budget
      variants                   — cap on expanded variants (default 6)
      mine_forwards  0|1         — include forward-from-tracked stage
    """
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    q = (request.args.get("q") or "").strip()
    if len(q) < 3:
        return jsonify({"error": "query must be at least 3 characters"}), 400
    try:
        limit = max(1, min(60, int(request.args.get("limit") or 30)))
    except Exception:
        limit = 30
    try:
        max_variants = max(1, min(10, int(request.args.get("variants") or 6)))
    except Exception:
        max_variants = 6
    mine_forwards = (request.args.get("mine_forwards") or "1") not in ("0", "false", "no")
    mode = (request.args.get("mode") or "safe").lower()
    mode = "thorough" if mode == "thorough" else "safe"

    tracked = _crawler.db.get_url_rows(limit=500, source="telegram") or []
    tracked_slim = [{"channel_id": t.get("tg_channel_id"),
                     "username":   t.get("tg_username")}
                    for t in tracked if t.get("tg_channel_id")]

    with _crawl_lock:
        _tg.set_mode(mode)
        r = _tg.smart_discover(
            q, limit=limit, max_variants=max_variants,
            tracked_channels=tracked_slim,
            mine_forwards=mine_forwards,
        )
    if r.get("error"):
        return jsonify(r), 400

    # Annotate with already-tracked flag for UI (don't double-add).
    tracked_ids = {t["channel_id"] for t in tracked_slim}
    tracked_handles = {(t["username"] or "").lower()
                       for t in tracked_slim if t.get("username")}
    for c in r.get("channels", []):
        c["already_tracked"] = (
            c.get("id") in tracked_ids
            or (c.get("username") or "").lower() in tracked_handles)
    return jsonify(r)


@app.route("/api/telegram/user/<handle>")
def route_tg_user_lookup(handle):
    """OSINT user lookup. Returns profile card + profile-photo history.
    Query params:
      photos=0      — skip historical photo enumeration
      download=1    — also download each historic photo to /loot/tg-media/users/
    """
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    photos = (request.args.get("photos") or "1") not in ("0", "false", "no")
    download = (request.args.get("download") or "0") in ("1", "true", "yes")
    dest = os.path.join(_crawler.loot_dir, "tg-media", "users") if download else None
    with _crawl_lock:
        info = _tg.lookup_user(
            handle, photo_history=photos,
            photo_history_limit=int(request.args.get("photo_limit") or 10),
            photo_dest_dir=dest)
    if info.get("error"):
        return jsonify(info), 400
    # Rewrite local paths to be URL-servable.
    if download:
        for p in info.get("photos") or []:
            if p.get("path"):
                p["url"] = f"/loot/tg-media/users/{p['path']}"
    return jsonify(info)


@app.route("/api/telegram/search")
def route_tg_search():
    """OSINT-smart search. Query params:

      q          (required)   — keyword / phrase to find
      scope      local|channel|all (default local)
      channel_id               — required when scope=channel
      since                    — ISO date; min message date
      limit                    — per-channel result cap (default 50)

    - `local`   : instantly searches every message already in tg_messages.
    - `channel` : fires a native Telegram search inside one channel (hits
                  messages we haven't scraped yet). Slower (~1s + network).
    - `all`     : same as `channel` but looped over every monitored TG
                  channel. Slowest; caller should expect several seconds.
    """
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"error": "q is required"}), 400
    scope = request.args.get("scope") or "local"
    since = request.args.get("since") or None
    try:
        limit = int(request.args.get("limit") or 50)
    except Exception:
        limit = 50

    if scope == "local":
        rows = _crawler.db.search_tg_messages_local(
            q, limit=limit, min_date_iso=since)
        return jsonify({"scope": "local", "hits": len(rows), "results": rows})

    if not _tg.configured():
        return jsonify({"error": "telegram not configured for live scope"}), 400

    if scope == "channel":
        try:
            url_id = int(request.args.get("channel_id") or 0)
        except Exception:
            url_id = 0
        info = _crawler.db.get_tg_channel(url_id)
        if not info:
            return jsonify({"error": "channel_id not a known tg channel"}), 400
        with _crawl_lock:
            msgs = _tg.search_in_channel(
                info["tg_channel_id"], q, limit=limit, min_date_iso=since,
                username=info.get("tg_username"))
        # Enrich with channel_username so the UI can build t.me links.
        for m in msgs:
            m["channel_username"] = info["tg_username"]
        return jsonify({"scope": "channel", "hits": len(msgs),
                        "results": msgs})

    if scope == "all":
        channels = _crawler.db.get_url_rows(limit=500, source="telegram")
        out = []
        with _crawl_lock:
            for ch in channels:
                if not ch.get("tg_channel_id"):
                    continue
                hits = _tg.search_in_channel(
                    ch["tg_channel_id"], q,
                    limit=max(5, limit // max(1, len(channels))),
                    min_date_iso=since,
                    username=ch.get("tg_username"))
                for m in hits:
                    m["channel_username"] = ch["tg_username"]
                    m["url_id"] = ch["id"]
                out.extend(hits)
        out.sort(key=lambda m: m.get("date_iso") or "", reverse=True)
        return jsonify({"scope": "all", "channels_searched": len(channels),
                        "hits": len(out), "results": out[:limit * 3]})

    return jsonify({"error": f"unknown scope: {scope}"}), 400


def _sse(event, data):
    """Format a Server-Sent Event frame."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@app.route("/api/telegram/search/deep")
def route_tg_search_deep():
    """Multi-stage OSINT-oriented deep search. Streams per-stage progress
    events via Server-Sent Events so the UI can show which stage is
    currently running + incremental results.

    Stages:
      1. Local DB — already-scraped messages (instant, O(N))
      2. Known channels live — Telethon search in every TG-source URL
      3. Forward expand — from stage 1+2 results, follow fwd_from_username
         to discover channels we didn't know about, resolve + search them
      4. Mention expand — regex-scan result text for @handle / t.me URLs,
         resolve + search
      5. Successor chain — for any discovered channel that turns out dead,
         follow its successor hints to its current backup/successor

    Query: q (required), max_hops (default 2 for stages 3+4), since (iso)
    """
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"error": "q is required"}), 400
    max_hops = max(0, min(3, int(request.args.get("max_hops") or 2)))
    since = request.args.get("since") or None
    mode = (request.args.get("mode") or "safe").lower()
    if mode not in ("safe", "thorough"): mode = "safe"

    # Load the selected mode's rate limits + per-search budget onto the
    # shared scraper. Subsequent stages consult _tg.budget_remaining() /
    # _tg._spend() so a single keyword hunt can't nuke Telegram's patience.
    budget = _tg.set_mode(mode) if _tg.configured() else 0

    tg_configured = _tg.configured()
    db = _crawler.db

    def stream():
        all_results = []
        searched_channels = set()
        discovered = []   # list of {handle, via, hits, status}
        budget_exhausted_at = None   # stage number when we ran out

        def emit(event, data):
            return _sse(event, data)

        def try_spend(n=1):
            """Deduct from the per-search budget. Returns True if allowed.
            Use before every live MTProto call that might trigger Telegram."""
            nonlocal budget_exhausted_at
            if _tg._spend(n):
                return True
            if budget_exhausted_at is None:
                budget_exhausted_at = "current"
            return False

        def search_one_channel(url_id, channel_id, username, via, stage):
            """Search a single channel via Telethon (live) — spends 1 token."""
            if channel_id in searched_channels: return 0
            if not try_spend():
                return 0
            searched_channels.add(channel_id)
            with _crawl_lock:
                msgs = _tg.search_in_channel(
                    channel_id, q, limit=50, min_date_iso=since,
                    username=username)
            for m in msgs:
                m["channel_username"] = username
                m["url_id"] = url_id
                m["_stage"] = stage
            all_results.extend(msgs)
            discovered.append({"handle": username, "via": via,
                                "hits": len(msgs), "status": "searched"})
            return len(msgs)

        yield emit("start", {"mode": mode, "budget": budget})

        yield emit("stage", {"n": 1, "name": "Local DB",
                             "message": "Searching already-scraped messages…"})
        local = db.search_tg_messages_local(q, limit=200, min_date_iso=since)
        for m in local: m["_stage"] = 1
        all_results.extend(local)
        for m in local:
            ch = m.get("channel_username")
            if ch and ch not in {d["handle"] for d in discovered}:
                discovered.append({"handle": ch, "via": "local hit",
                                    "hits": 0, "status": "known"})
        yield emit("progress", {"stage": 1, "hits": len(local),
                                 "results": local[:20]})

        if not tg_configured:
            yield emit("done", {"total_hits": len(all_results),
                                 "discovered": discovered,
                                 "note": "skipped live stages — not authenticated"})
            return

        # Stage 2: known channels via Telethon
        yield emit("stage", {"n": 2, "name": "Known channels (live)",
                             "message": "Live-searching every tracked TG channel…"})
        channels = db.get_url_rows(limit=500, source="telegram")
        s2_hits = 0
        for ch in channels:
            if _tg.budget_remaining() <= 0:
                break
            cid = ch.get("tg_channel_id")
            user = ch.get("tg_username")
            if not cid or not user: continue
            s2_hits += search_one_channel(ch["id"], cid, user,
                                            "known channel", stage=2)
            yield emit("progress", {"stage": 2,
                                     "searched": len(searched_channels),
                                     "total_hits": len(all_results),
                                     "budget_remaining": _tg.budget_remaining()})
        yield emit("stage_done", {"stage": 2, "hits": s2_hits})

        if budget_exhausted_at is not None or _tg.budget_remaining() <= 0:
            yield emit("budget_exhausted",
                       {"stage": 2, "message": "API budget spent after stage 2"})
        elif max_hops < 1:
            pass  # skip stages 3-5 by operator choice
        else:
            # Stage 3: expand via forwards (cached resolve)
            yield emit("stage", {"n": 3, "name": "Forward expand",
                                 "message": "Resolving forward-from origins…"})
            fwd_origins = {m.get("fwd_from_username") for m in all_results
                           if m.get("fwd_from_username")}
            fwd_origins = {o.lstrip("@").lower() for o in fwd_origins if o}
            known = {d["handle"].lower() for d in discovered}
            s3_hits = 0
            for name in list(fwd_origins - known)[:10]:
                if not try_spend(): break
                with _crawl_lock:
                    info = _tg.cached_resolve(name)
                if info.get("error"):
                    discovered.append({"handle": name, "via": "forward",
                                        "hits": 0,
                                        "status": f"unresolvable: {info['error']}"})
                    continue
                uid = db.upsert_tg_channel(
                    info["username"], info["channel_id"],
                    subscribers=info.get("subscribers"),
                    about=info.get("about"),
                    verified=info.get("verified"),
                    scam=info.get("scam"), kind=info.get("kind"))
                s3_hits += search_one_channel(uid, info["channel_id"],
                                                info["username"],
                                                f"forward from @{name}", stage=3)
                yield emit("progress", {"stage": 3,
                                         "searched": len(searched_channels),
                                         "total_hits": len(all_results),
                                         "budget_remaining": _tg.budget_remaining()})
            yield emit("stage_done", {"stage": 3, "hits": s3_hits,
                                       "expanded": len(fwd_origins)})

            if _tg.budget_remaining() <= 0:
                yield emit("budget_exhausted", {"stage": 3})
            else:
                # Stage 4: expand via @mentions (cached resolve)
                yield emit("stage", {"n": 4, "name": "Mention expand",
                                     "message": "Scanning result bodies for channel mentions…"})
                mentions = set()
                for m in all_results:
                    mentions |= _tg.extract_channel_mentions(m.get("text") or "")
                mentions -= {d["handle"].lower() for d in discovered}
                s4_hits = 0
                for name in list(mentions)[:max_hops * 5]:
                    if not try_spend(): break
                    with _crawl_lock:
                        info = _tg.cached_resolve(name)
                    if info.get("error"):
                        discovered.append({"handle": name, "via": "mention",
                                            "hits": 0,
                                            "status": f"unresolvable: {info['error']}"})
                        continue
                    uid = db.upsert_tg_channel(
                        info["username"], info["channel_id"],
                        subscribers=info.get("subscribers"),
                        about=info.get("about"),
                        verified=info.get("verified"),
                        scam=info.get("scam"), kind=info.get("kind"))
                    s4_hits += search_one_channel(uid, info["channel_id"],
                                                    info["username"],
                                                    "mention in text", stage=4)
                    yield emit("progress", {"stage": 4,
                                             "searched": len(searched_channels),
                                             "total_hits": len(all_results),
                                             "budget_remaining": _tg.budget_remaining()})
                yield emit("stage_done", {"stage": 4, "hits": s4_hits,
                                           "expanded": len(mentions)})

                if _tg.budget_remaining() <= 0:
                    yield emit("budget_exhausted", {"stage": 4})
                else:
                    # Stage 5: successor-chain any dead channels
                    yield emit("stage", {"n": 5, "name": "Successor chain",
                                         "message": "Following dead channels to their successors…"})
                    dead = [d for d in discovered
                            if "unresolvable" in (d.get("status") or "")]
                    chains = []
                    for d in dead[:3]:
                        if _tg.budget_remaining() <= 0: break
                        # follow_channel_chain internally spends ~3-5 tokens;
                        # we don't pre-deduct because the scraper already
                        # runs through the rate limiter.
                        chain = _tg.follow_channel_chain(d["handle"], max_hops=3)
                        chains.append({"from": d["handle"], "chain": chain})
                        if chain and chain[-1].get("status") == "alive":
                            alive = chain[-1]["handle"]
                            if alive not in {x["handle"] for x in discovered}:
                                discovered.append({"handle": alive,
                                                    "via": f"successor of @{d['handle']}",
                                                    "hits": 0,
                                                    "status": "alive"})
                    yield emit("stage_done", {"stage": 5, "chains": chains,
                                               "dead_followed": len(dead[:3])})

        # Final
        all_results.sort(key=lambda m: m.get("date_iso") or "", reverse=True)
        yield emit("done", {"total_hits": len(all_results),
                             "discovered": discovered,
                             "results": all_results[:200],
                             "budget_remaining": _tg.budget_remaining(),
                             "mode": mode})

    return Response(stream(), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no",
                             "Cache-Control": "no-cache"})


@app.route("/api/telegram/chain/<path:identifier>")
def route_tg_chain(identifier):
    """Follow a (possibly-dead) channel to its current successor.

    Returns the hop chain so the UI can render a breadcrumb. Handles
    like "@durov" / "durov" / "t.me/durov" all work — the scraper
    normalizes internally."""
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    max_hops = max(1, min(8, int(request.args.get("max_hops") or 5)))
    with _crawl_lock:
        chain = _tg.follow_channel_chain(identifier, max_hops=max_hops)
    return jsonify({"starting": identifier, "hops": len(chain),
                    "chain": chain})


@app.route("/api/telegram/channels/<int:url_id>/export.<fmt>")
def route_tg_export(url_id, fmt):
    """Export a channel's scraped messages. fmt ∈ {csv, json}."""
    if not _crawler.db.url_exists(url_id):
        abort(404)
    info = _crawler.db.get_tg_channel(url_id)
    if not info:
        return jsonify({"error": "not a telegram channel"}), 400
    # Cap to avoid nuking the server — operators who want more can call
    # Telegram directly or add pagination later.
    msgs = _crawler.db.list_tg_messages(url_id, limit=5000)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    fname = f"{info['tg_username']}_{stamp}.{fmt}"

    if fmt == "json":
        return Response(
            json.dumps({"channel": info, "messages": msgs},
                       indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    if fmt == "csv":
        import io as _io
        buf = _io.StringIO()
        cols = ["msg_id", "date_iso", "sender_username", "sender_name",
                "text", "views", "forwards", "reactions_total",
                "has_media", "media_type",
                "fwd_from_username", "reply_to_msg_id", "finding_count"]
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for m in msgs:
            w.writerow({c: m.get(c, "") for c in cols})
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    if fmt == "zip":
        # Bundle json + csv + any downloaded media into one archive — a
        # one-click "everything about this channel" download for ops
        # handoffs / legal hold / offline analysis.
        import io as _io, zipfile as _zip
        stem = f"{info['tg_username']}_{stamp}"
        buf = _io.BytesIO()
        with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as z:
            z.writestr(
                f"{stem}/messages.json",
                json.dumps({"channel": info, "messages": msgs},
                           indent=2, default=str))
            # Embedded CSV
            import io as _io2
            csv_buf = _io2.StringIO()
            cols = ["msg_id", "date_iso", "sender_username", "sender_name",
                    "text", "views", "forwards", "reactions_total",
                    "has_media", "media_type", "media_path",
                    "fwd_from_username", "reply_to_msg_id", "finding_count"]
            w = csv.DictWriter(csv_buf, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for m in msgs: w.writerow({c: m.get(c, "") for c in cols})
            z.writestr(f"{stem}/messages.csv", csv_buf.getvalue())
            # Any media that's been downloaded, nested under media/.
            media_root = os.path.join(
                _crawler.loot_dir, "tg-media", info["tg_username"] or "")
            if os.path.isdir(media_root):
                for name in sorted(os.listdir(media_root)):
                    fp = os.path.join(media_root, name)
                    if os.path.isfile(fp):
                        z.write(fp, arcname=f"{stem}/media/{name}")
            # Tiny README so the operator knows what they're looking at.
            z.writestr(
                f"{stem}/README.txt",
                f"DarkWatch Telegram channel export\n"
                f"Channel:  @{info.get('tg_username')}\n"
                f"Exported: {datetime.utcnow().isoformat()}Z\n"
                f"Messages: {len(msgs)}\n"
                f"Contents:\n"
                f"  messages.json — full metadata\n"
                f"  messages.csv  — tabular for spreadsheets\n"
                f"  media/        — downloaded attachments (if any)\n")
        return Response(
            buf.getvalue(),
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    return jsonify({"error": f"unsupported format: {fmt}"}), 400


# ─── Monitoring routes ───────────────────────────────────────────────────────

@app.route("/api/urls/<int:url_id>/monitor", methods=["PATCH"])
def route_url_set_monitor(url_id):
    if not _crawler.db.url_exists(url_id):
        abort(404)
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled"))
    interval = int(body.get("interval_min") or 60)
    if interval not in (15, 30, 60, 120, 360):
        return jsonify({"error": "invalid interval_min (allowed: 15, 30, 60, 120, 360)"}), 400
    # When enabling, schedule the FIRST check for "now" so the scheduler
    # picks it up on the next tick. Disabling clears the schedule.
    next_at = datetime.utcnow().isoformat() if enabled else None
    _crawler.db.set_monitor(url_id, enabled, interval_min=interval,
                             next_check_at=next_at)
    return jsonify({"id": url_id, "monitored": enabled,
                    "interval_min": interval, "next_check_at": next_at})


@app.route("/api/urls/monitor", methods=["PATCH"])
def route_urls_bulk_monitor():
    """Bulk toggle: body {ids: [], enabled: bool, interval_min: int}."""
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or []
    enabled = bool(body.get("enabled"))
    interval = int(body.get("interval_min") or 60)
    if not isinstance(ids, list) or not ids:
        return jsonify({"error": "ids must be a non-empty array"}), 400
    if interval not in (15, 30, 60, 120, 360):
        return jsonify({"error": "invalid interval_min"}), 400
    next_at = datetime.utcnow().isoformat() if enabled else None
    updated = 0
    for uid in ids:
        try: uid = int(uid)
        except Exception: continue
        if not _crawler.db.url_exists(uid):
            continue
        _crawler.db.set_monitor(uid, enabled,
                                 interval_min=interval, next_check_at=next_at)
        updated += 1
    return jsonify({"updated": updated, "enabled": enabled,
                    "interval_min": interval})


@app.route("/api/urls/<int:url_id>", methods=["DELETE"])
def route_url_delete(url_id):
    if not _crawler.db.url_exists(url_id):
        abort(404)
    _crawler.db.delete_url(url_id)
    _refresh_tg_live_channels()
    return jsonify({"deleted": url_id})


@app.route("/api/urls/<int:url_id>/timeline")
def route_url_timeline(url_id):
    if not _crawler.db.url_exists(url_id):
        abort(404)
    events = _crawler.db.get_url_timeline(url_id, limit=50)
    # Surface relative URLs to the screenshot/thumbnail for each event.
    for e in events:
        pid = e.get("page_id")
        e["thumbnail_url"] = f"/api/thumbnail/{pid}" if pid and e.get("thumbnail_path") else None
        e["screenshot_url"] = f"/api/screenshot/{pid}" if pid else None
    return jsonify(events)


def _regenerate_user_yara():
    """Rebuild user.yar from the DB and recompile. Called after any
    add/delete so the next scan sees the change immediately."""
    _crawler.scanner.regenerate_user_rules(_crawler.db.list_keywords())


@app.route("/api/keywords", methods=["GET"])
def route_keywords_list():
    return jsonify(_crawler.db.list_keywords())


def _validate_keyword(kw):
    """Returns (ok, error_msg). Caller handles the HTTP 400 response."""
    if not kw:
        return False, "keyword is required"
    if len(kw) > 256 or any(ord(c) < 0x20 for c in kw):
        return False, "invalid keyword (control chars not allowed; max 256 chars)"
    return True, None


@app.route("/api/keywords", methods=["POST"])
def route_keywords_add():
    """Accepts single `keyword` (back-compat) OR `keywords: []` (bulk).
    Bulk form returns {added, skipped, errors}. Single form preserves the
    original shape for back-compat."""
    body = request.get_json(silent=True) or {}
    severity = body.get("severity") or "medium"
    if severity not in ("critical", "high", "medium", "low"):
        return jsonify({"error": "invalid severity"}), 400

    # Bulk form takes priority if provided.
    bulk = body.get("keywords")
    if isinstance(bulk, list):
        # Deduplicate within the submitted batch (case-insensitive trim).
        seen = set()
        added = skipped = errors = 0
        last_err = None
        for raw in bulk:
            if not isinstance(raw, str): continue
            kw = raw.strip()
            if not kw or kw.lower() in seen:
                skipped += 1
                continue
            seen.add(kw.lower())
            ok, msg = _validate_keyword(kw)
            if not ok:
                errors += 1
                last_err = msg
                continue
            kid = _crawler.db.add_keyword(kw, severity=severity)
            if kid is None:
                skipped += 1   # already existed in DB
            else:
                added += 1
        if added:
            _regenerate_user_yara()
        return jsonify({"added": added, "skipped": skipped,
                        "errors": errors, "last_error": last_err}), 201

    # Single-keyword form
    keyword = (body.get("keyword") or "").strip()
    ok, msg = _validate_keyword(keyword)
    if not ok:
        return jsonify({"error": msg}), 400
    kid = _crawler.db.add_keyword(keyword, severity=severity)
    if kid is None:
        return jsonify({"error": "keyword already exists"}), 409
    _regenerate_user_yara()
    return jsonify({"id": kid, "keyword": keyword, "severity": severity}), 201


@app.route("/api/keywords/<int:kid>", methods=["DELETE"])
def route_keywords_delete(kid):
    n = _crawler.db.delete_keyword(kid)
    if n == 0:
        abort(404)
    _regenerate_user_yara()
    return jsonify({"deleted": n})


@app.route("/api/telegram/channels/<int:url_id>/members")
def route_tg_channel_members(url_id):
    """List participants of a group/megagroup. Broadcast channels return
    400 (API disallows). Query params:
      limit  (1-500, default 200)
      query  substring to filter usernames + names
    """
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    info = _crawler.db.get_tg_channel(url_id)
    if not info or not info.get("tg_channel_id"):
        return jsonify({"error": "not a telegram channel"}), 400
    try:
        limit = max(1, min(500, int(request.args.get("limit") or 200)))
    except Exception:
        limit = 200
    query = request.args.get("query") or None
    with _crawl_lock:
        r = _tg.list_members(info["tg_channel_id"], limit=limit, query=query,
                              username=info.get("tg_username"))
    if r.get("error"):
        return jsonify(r), 400
    return jsonify(r)


@app.route("/api/telegram/messages/<int:msg_row_id>/media", methods=["POST"])
def route_tg_message_download_media(msg_row_id):
    """Download the media attachment for a stored Telegram message. On-
    demand only (the operator clicks a button). Bulk/automatic download
    is deliberately off — CTI channels routinely post malware; unbounded
    auto-download is an exfil + abuse footgun."""
    if not _tg.configured():
        return jsonify({"error": "telegram not configured"}), 400
    row = _crawler.db.get_tg_message(msg_row_id)
    if not row:
        abort(404)
    if row.get("media_path"):
        return jsonify({"path": row["media_path"],
                        "bytes": None, "already": True})
    if not row.get("tg_channel_id"):
        return jsonify({"error": "not a telegram message"}), 400
    # One sub-dir per channel keeps download listings browsable.
    dest = os.path.join(_crawler.loot_dir, "tg-media",
                        (row.get("tg_username") or str(row["url_id"])))
    with _crawl_lock:
        r = _tg.download_message_media(
            row["tg_channel_id"], row["msg_id"], dest_dir=dest,
            username=row.get("tg_username"))
    if r.get("error"):
        return jsonify(r), 400
    rel_path = f"{row.get('tg_username') or row['url_id']}/{r['path']}"
    _crawler.db.set_tg_media(msg_row_id, rel_path, r.get("bytes"))
    return jsonify({"path": rel_path, "bytes": r.get("bytes"),
                    "type": r.get("type")})


@app.route("/loot/tg-media/<path:relpath>")
def route_tg_media_serve(relpath):
    """Serve a previously downloaded media file. Path traversal is blocked
    by send_file's abspath check; we additionally require the resolved
    path to live under loot/tg-media."""
    base = os.path.realpath(os.path.join(_crawler.loot_dir, "tg-media"))
    target = os.path.realpath(os.path.join(base, relpath))
    if not target.startswith(base + os.sep):
        abort(404)
    if not os.path.isfile(target):
        abort(404)
    return send_file(target, as_attachment=False)


@app.route("/api/keywords/export.<fmt>")
def route_keywords_export(fmt):
    """Download the user keyword library as JSON or CSV. Lets operators
    back up their list or move it between DarkWatch instances."""
    rows = _crawler.db.list_keywords() or []
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        buf = json.dumps(
            {"exported_at": datetime.utcnow().isoformat(),
             "count": len(rows), "keywords": rows},
            indent=2, default=str)
        return Response(
            buf,
            mimetype="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="keywords_{ts}.json"'})
    if fmt == "csv":
        import csv, io
        sio = io.StringIO()
        cols = ["id", "keyword", "severity", "category", "added_at"]
        w = csv.DictWriter(sio, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows: w.writerow(r)
        return Response(
            sio.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition":
                     f'attachment; filename="keywords_{ts}.csv"'})
    return jsonify({"error": "format must be 'json' or 'csv'"}), 400


@app.route("/api/report", methods=["POST"])
def route_report():
    report_path, summary_path = _crawler.generate_report(min_score=0)
    return jsonify({"report": report_path, "summary": summary_path})


@app.route("/api/report/download")
def route_report_download():
    # Pick the newest JSON report in reports_dir.
    reports = sorted(
        (f for f in os.listdir(_crawler.reports_dir) if f.endswith(".json")),
        key=lambda f: os.path.getmtime(os.path.join(_crawler.reports_dir, f)),
        reverse=True)
    if not reports:
        abort(404)
    return send_file(os.path.join(_crawler.reports_dir, reports[0]),
                     as_attachment=True)


def _safe_send(path, base_dir):
    """Send a file only if its resolved path stays inside base_dir."""
    if not path:
        abort(404)
    full = os.path.abspath(path)
    base = os.path.abspath(base_dir)
    if not full.startswith(base + os.sep):
        abort(404)
    if not os.path.isfile(full):
        abort(404)
    return send_file(full)


@app.route("/api/screenshot/<int:page_id>")
def route_screenshot(page_id):
    info = _crawler.db.get_page_screenshot(page_id)
    if not info or not info.get("screenshot_path"):
        abort(404)
    return _safe_send(info["screenshot_path"],
                      os.path.join(_crawler.loot_dir, "screenshots"))


@app.route("/api/thumbnail/<int:page_id>")
def route_thumbnail(page_id):
    info = _crawler.db.get_page_screenshot(page_id)
    if not info or not info.get("thumbnail_path"):
        abort(404)
    return _safe_send(info["thumbnail_path"], _crawler.thumbnails_dir)


# ─── Entry point ─────────────────────────────────────────────────────────────

# Stagger already-due monitored URLs on boot so the first scheduler tick
# doesn't fire N scans back-to-back after a container restart.
_staggered = _crawler.db.stagger_due_monitors(datetime.utcnow())
if _staggered:
    log.info(f"Staggering {_staggered} due monitors on boot")

_start_health_refresh_thread()
_start_monitor_thread()
_start_tg_live()


if __name__ == "__main__":
    # Threaded Flask so health checks and status polls don't block each other
    # while a scan thread is running.
    app.run(host="0.0.0.0", port=8080, threaded=True, debug=False)
