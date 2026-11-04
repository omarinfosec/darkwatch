"""
DarkWatch Telegram engine: DarkMTProto (alias TelegramScraper), its support
classes and the live listener.

Split out of darkwatch.py, which re-exports these names, so
`from darkwatch import DarkMTProto` keeps working.
"""

import os
import re
import time
import random
import logging
import threading
from datetime import timezone

# Same logger as darkwatch.py, so the log lines keep their name.
log = logging.getLogger("darkwatch")


# ─── Telegram scraper ────────────────────────────────────────────────────────

try:
    from telethon import TelegramClient
    from telethon.errors import (
        SessionPasswordNeededError, PhoneCodeInvalidError, FloodWaitError,
    )
    from telethon.tl.types import Channel, Chat
    from telethon.utils import resolve_id as tg_resolve_id
    import asyncio
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False


# ─── DarkMTProto engine support classes ──────────────────────────────────────
# These four tiny classes used to live as a scatter of attrs + methods on
# DarkMTProto. Extracting them makes the engine's shape obvious:
# rate-limit → entity-cache → per-channel pressure → fingerprint profile.
# Each piece is independently testable + swappable.

DARKMTPROTO_VERSION = "0.3"


class RateLimiter:
    """Token-bucket with jitter. Each `take()` call consumes one token,
    sleeping until one is available if the bucket is empty. A small
    always-on jitter before every call desynchronizes back-to-back calls
    so the traffic pattern doesn't look like a botnet to Telegram's
    abuse heuristics.

    Parameters default to "Safe" mode. Thorough mode swaps `.rate` /
    `.burst` / `.jitter` on the fly via DarkMTProto.set_mode()."""

    def __init__(self, rate_per_s=0.5, burst=3, jitter=0.40):
        self.rate = max(0.01, float(rate_per_s))
        self.burst = max(1, int(burst))
        self.jitter = max(0.0, min(1.0, float(jitter)))
        self._tokens = float(self.burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def take(self):
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.burst,
                                self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens < 1:
                deficit = 1 - self._tokens
                wait = deficit / self.rate
                # Apply ± jitter so two concurrent callers don't unblock in
                # lockstep.
                wait *= (1 + random.uniform(-self.jitter, self.jitter))
                time.sleep(max(0.1, wait))
                self._tokens = 0
            else:
                self._tokens -= 1
        # Always-on small jitter even when we had a token available — mimics
        # human / desktop client cadence, costs only 100-400ms per call.
        time.sleep(random.uniform(0.1, 0.4) * max(0.5, self.jitter * 2))


class EntityCache:
    """TTL + approximate-LRU dict for entity resolutions. Keyed by
    lowercased handle; stores whatever dict `resolve_channel` returned.
    Drops ~40 resolves → ~10 in a typical deep search by sharing context
    across stages."""

    def __init__(self, ttl_s=600, cap=256):
        self.ttl_s = int(ttl_s)
        self.cap = int(cap)
        self._store = {}   # key → (expiry_monotonic, value)

    def get(self, key):
        hit = self._store.get(key)
        if not hit: return None
        expiry, value = hit
        if expiry < time.monotonic():
            self._store.pop(key, None)
            return None
        return value

    def put(self, key, value):
        if len(self._store) >= self.cap:
            # Approximate LRU — drop the entry with the oldest expiry.
            # cap=256 is small enough that this scan is trivial.
            oldest = min(self._store.items(), key=lambda kv: kv[1][0])
            self._store.pop(oldest[0], None)
        self._store[key] = (time.monotonic() + self.ttl_s, value)

    def clear(self):
        self._store.clear()


class CallPressure:
    """Per-channel call tracker. Records monotonic timestamps, prunes
    opportunistically, exposes windowed counts. Used by smart_discover
    to skip hot channels and surfaced in /api/telegram/status so the
    operator can see which channels they've been hammering."""

    WINDOW_S = 3600   # 1 hour — long enough to catch bursty scraping

    def __init__(self):
        self._calls = {}   # channel_id → [monotonic_ts, ...]

    def record(self, channel_id):
        if channel_id is None: return
        now = time.monotonic()
        bucket = self._calls.setdefault(channel_id, [])
        bucket.append(now)
        cutoff = now - self.WINDOW_S
        if len(bucket) > 64 or (bucket and bucket[0] < cutoff):
            self._calls[channel_id] = [t for t in bucket if t >= cutoff]

    def count(self, channel_id, window_s=None):
        if channel_id is None: return 0
        w = window_s if window_s is not None else self.WINDOW_S
        cutoff = time.monotonic() - w
        return sum(1 for t in self._calls.get(channel_id, []) if t >= cutoff)

    def report(self, limit=20):
        now = time.monotonic()
        out = []
        for cid, stamps in self._calls.items():
            recent = [t for t in stamps if t >= now - self.WINDOW_S]
            if not recent: continue
            out.append({"channel_id": cid, "calls_1h": len(recent),
                        "last_call_s_ago": int(now - recent[-1])})
        out.sort(key=lambda r: -r["calls_1h"])
        return out[:limit]


class ClientProfile:
    """MTProto client fingerprint (device_model, system_version, app_version,
    lang codes). Picks one plausible desktop-client profile per process
    and reuses it — Telegram flags clients that *change* device_model
    mid-session as suspicious, so stability within a boot matters more
    than rotation within it. Restarts pick a new profile at random."""

    # All values are real combinations the official desktop clients emit.
    PROFILES = [
        {"device_model": "Desktop", "system_version": "Windows 10",
         "app_version":  "5.2.3 x64"},
        {"device_model": "PC 64bit", "system_version": "Windows 11",
         "app_version":  "5.3.1 x64"},
        {"device_model": "MacBookPro17,1", "system_version": "macOS 14.5",
         "app_version":  "10.12.3 arm64"},
        {"device_model": "Linux", "system_version": "Ubuntu 22.04",
         "app_version":  "4.14.9"},
        {"device_model": "Desktop", "system_version": "Windows 10",
         "app_version":  "4.16.8 x64"},
    ]

    _chosen = None

    @classmethod
    def current(cls):
        if cls._chosen is None:
            cls._chosen = random.choice(cls.PROFILES)
        return cls._chosen


class DarkMTProto:
    """The DarkMTProto engine — DarkWatch's customized, CTI-aware wrapper
    over Telethon's MTProto client. Telethon handles the wire protocol
    (DH, TL schema, DC migration, transports). DarkMTProto layers on the
    things Telethon doesn't care about and CTI operators need:

      * `RateLimiter`    — token-bucket with jitter, Safe/Thorough modes
      * `EntityCache`    — TTL + LRU de-dup for get_entity calls
      * `CallPressure`   — per-channel call tracker for fleet load balance
      * `ClientProfile`  — plausible desktop-client fingerprint rotation
      * per-search budget, FloodWait retry-once, query expansion,
        forward-mining smart discovery, live event listener

    All network traffic is forced through a dedicated SOCKS5 proxy (the
    `tg-socks` sidecar sharing the `tunnel2` WireGuard namespace)
    so Telegram traffic never shares an exit IP with the Tor path.

    Every public method goes through the rate limiter; every entity
    resolution goes through the cache. Coroutines run via asyncio.run()
    — fine for monitor-tick-cadence usage. If Telethon itself isn't
    installed, methods return safe "not available" responses so the
    rest of the app keeps working.

    Kept publicly accessible via the `TelegramScraper` alias (bottom of
    module) for backward compat with earlier imports."""

    VERSION = DARKMTPROTO_VERSION

    def __init__(self, config):
        self.config = config
        tg = config.get("telegram", {})
        self.api_id = tg.get("api_id") or ""
        self.api_hash = tg.get("api_hash") or ""
        self.session_path = tg.get("session_path") or "data/telegram.session"
        self.proxy_host = tg.get("proxy_host") or ""
        self.proxy_port = int(tg.get("proxy_port") or 1080)
        self.proxy_type = tg.get("proxy_type") or "socks5"
        # tg-socks requires a username/password (TG_SOCKS_PASSWORD).
        self.proxy_user = tg.get("proxy_user") or ""
        self.proxy_password = tg.get("proxy_password") or ""
        self.use_tor = bool(tg.get("use_tor"))
        self.scrape_limit = int(tg.get("scrape_limit_per_tick") or 100)
        # Auth round-trip state: phone_code_hash from auth_send_code has
        # to echo back in auth_confirm.
        self._pending_auth = {}

        # Engine components. Each is responsible for one concern.
        self._limiter = RateLimiter(
            rate_per_s=float(tg.get("rate_per_s", 0.5)),
            burst=int(tg.get("burst", 3)),
            jitter=float(tg.get("jitter", 0.40)),
        )
        self._entities = EntityCache(
            ttl_s=int(tg.get("entity_ttl_s", 600)), cap=256)
        self._pressure = CallPressure()
        # Channels with more calls/hour than this get skipped by
        # smart_discover's forward-mining stage.
        self.pressure_skip_threshold = int(
            tg.get("pressure_skip_threshold", 30))
        # Per-search budget (caller decrements via _spend()).
        self._budget = 0
        # Last error from fetch_new_messages — surfaced in the scrape
        # response so the UI can show WHY nothing came back, instead of
        # the generic "no messages" warning.
        self.last_fetch_error = None
        # How far the last fetch_new_messages read, counting the service
        # messages it drops (joins, pins, title changes): they use up the
        # `limit` too, so a caller walking a cursor needs these, not the
        # returned list. All 0 when the fetch failed.
        self.last_fetch_count = 0
        self.last_fetch_max_id = 0
        self.last_fetch_min_id = 0
        # Same for search_in_channel: None after a search that ran (even
        # with no hits), the reason after one that failed, so callers can
        # tell "no matches" from "never searched".
        self.last_search_error = None

    # ── Engine glue (thin delegations to support classes) ──────────────
    def _record_call(self, channel_id):
        self._pressure.record(channel_id)

    def channel_pressure(self, channel_id, window_s=3600):
        return self._pressure.count(channel_id, window_s=window_s)

    def channel_pressure_report(self, limit=20):
        return self._pressure.report(limit=limit)

    @staticmethod
    def _entity_ref(channel_id, username=None):
        """Return the Telethon entity arg we should pass. Prefers
        `@username` because contacts.resolveUsername works even when the
        session cache has no record of the peer — the bare numeric id
        silently fails on fresh/wiped sessions, which was the #1 source
        of 'scraper returns 0 messages' reports. Lives in one place so
        every call site gets the same rule."""
        return f"@{username}" if username else channel_id

    def set_mode(self, mode="safe"):
        """Swap rate-limiter + budget for a single operation (e.g. one
        deep-search run). Returns the selected budget."""
        tg = self.config.get("telegram", {})
        if mode == "thorough":
            self._limiter.rate   = float(tg.get("thorough_rate_per_s", 1.0))
            self._limiter.burst  = int(tg.get("thorough_burst", 5))
            self._limiter.jitter = float(tg.get("thorough_jitter", 0.25))
            budget = int(tg.get("thorough_max_deep_budget", 60))
        else:
            self._limiter.rate   = float(tg.get("rate_per_s", 0.5))
            self._limiter.burst  = int(tg.get("burst", 3))
            self._limiter.jitter = float(tg.get("jitter", 0.40))
            budget = int(tg.get("max_deep_budget", 25))
        self._budget = budget
        return budget

    def budget_remaining(self):
        return self._budget

    def _spend(self, n=1):
        """Decrement and return True if budget allowed it, False if exhausted.
        Deep-search stages call this BEFORE _limiter.take(); budget 0 halts
        the pipeline without making a call."""
        if self._budget <= 0:
            return False
        self._budget -= n
        return True

    # ── Entity cache ───────────────────────────────────────────────────────
    def cached_resolve(self, identifier):
        """Memoized wrapper around resolve_channel. Cache misses hit the
        rate limiter + network; hits return in microseconds. Used by
        every deep-search expansion stage."""
        key = self._normalize_identifier(identifier).lower()
        if not key: return {"error": "empty identifier"}
        cached = self._entities.get(key)
        if cached is not None:
            log.debug(f"[tg cache] hit: @{key}")
            return cached
        info = self.resolve_channel(identifier)
        if not info.get("error"):
            self._entities.put(key, info)
        return info

    def _run_coro(self, coro_fn, name="telethon_call"):
        """Gate every Telethon call through the rate limiter + give it one
        retry on short FloodWait. Long waits (>30s) mean we're genuinely
        annoying Telegram — surface them instead of holding the request
        hostage.

        Callers keep their existing try/except for the result shape they
        want; this helper only handles rate-limit / flood-wait plumbing.
        """
        self._limiter.take()
        try:
            return asyncio.run(coro_fn())
        except FloodWaitError as e:
            if e.seconds <= 30:
                wait = e.seconds + random.uniform(1, 3)
                log.warning(f"TG flood-wait {e.seconds}s on {name} "
                            f"— sleeping {wait:.0f}s then retrying once")
                time.sleep(wait)
                self._limiter.take()
                return asyncio.run(coro_fn())
            log.warning(f"TG flood-wait too long ({e.seconds}s) on {name}"
                        f" — surfacing error")
            raise

    # ── Status ─────────────────────────────────────────────────────────────
    def configured(self):
        """True iff the operator has supplied API credentials + Telethon imports."""
        return bool(TELETHON_AVAILABLE and self.api_id and self.api_hash)

    def _proxy_tuple(self):
        """Return the (type, host, port) tuple Telethon expects, or None."""
        if self.use_tor:
            # The tor sidecar shares tunnel1's netns and has no DNS name of
            # its own, so the SOCKS port lives at tunnel1:9050.
            p = self.config.get("proxy", {})
            return ("socks5", p.get("host", "tunnel1"), int(p.get("port", 9050)))
        if self.proxy_host:
            if self.proxy_user and self.proxy_password:
                # (type, host, port, rdns, username, password)
                return (self.proxy_type, self.proxy_host, self.proxy_port,
                        True, self.proxy_user, self.proxy_password)
            return (self.proxy_type, self.proxy_host, self.proxy_port)
        return None

    def _build_client(self):
        """Build a fresh TelegramClient. Never reused across calls — each
        asyncio.run() gets its own event loop, and Telethon ties a client
        to its loop. Cheap to construct (<50 ms); only expensive path is
        the first login (session file create).

        Device-fingerprint knobs (device_model / system_version /
        app_version / lang_code) come from ClientProfile.current() —
        plausible desktop-client values chosen once per process.
        Telethon's defaults are recognizable as bot traffic; blending
        in with real clients is a cheap win."""
        prof = ClientProfile.current()
        kwargs = {"session": self.session_path,
                  "api_id": int(self.api_id),
                  "api_hash": self.api_hash,
                  "device_model":   prof["device_model"],
                  "system_version": prof["system_version"],
                  "app_version":    prof["app_version"],
                  "lang_code":      "en",
                  "system_lang_code": "en-US"}
        proxy = self._proxy_tuple()
        if proxy:
            kwargs["proxy"] = proxy
        elif not self.config.get("telegram", {}).get("allow_direct"):
            # Fail closed: without a proxy Telethon connects straight from
            # the host's IP, bypassing the tunnel2 egress path. Opt in with
            # telegram.allow_direct=true only if that is really intended.
            raise RuntimeError(
                "telegram proxy not configured (telegram.proxy_host / use_tor) — "
                "refusing a direct connection; set telegram.allow_direct=true to override")
        client = TelegramClient(**kwargs)
        # Telethon creates the session file with the process umask (0644).
        # Also fixes files left that way by earlier versions.
        self._lock_down_session()
        return client

    def _lock_down_session(self):
        """chmod 0600 the session file: it holds the account's auth key,
        which is a full login to the Telegram account."""
        for p in (self.session_path, self.session_path + ".session"):
            if os.path.exists(p):
                try: os.chmod(p, 0o600)
                except Exception as e:
                    log.warning(f"TG session: couldn't chmod {p}: {e}")

    def status(self):
        """Cheap status probe. Doesn't connect to Telegram."""
        base = {"engine": "DarkMTProto", "engine_version": self.VERSION,
                "client_profile": ClientProfile.current()}
        if not TELETHON_AVAILABLE:
            return {**base, "configured": False, "authenticated": False,
                    "reason": "telethon not installed"}
        if not self.configured():
            return {**base, "configured": False, "authenticated": False,
                    "reason": "api_id / api_hash not set in config.telegram"}
        # Session file existence ≠ valid session, but it's a useful hint
        # without requiring a round-trip to Telegram.
        sess_exists = os.path.exists(self.session_path) or \
                      os.path.exists(self.session_path + ".session")
        return {**base, "configured": True,
                "authenticated": self._cached_authorized() if sess_exists else False,
                "proxy": self._proxy_tuple(),
                "use_tor": self.use_tor}

    def _cached_authorized(self, ttl=300):
        """status() is polled every ~15s per open tab; opening a fresh
        MTProto connection each time burned rate-limit tokens and produced a
        fingerprintable connect pattern. Cache the answer for `ttl` seconds,
        keyed on the session file's mtime so login/logout invalidate it."""
        try:
            mtime = max(os.path.getmtime(p) for p in
                        (self.session_path, self.session_path + ".session")
                        if os.path.exists(p))
        except ValueError:
            mtime = None
        cache = getattr(self, "_auth_cache", None)
        now = time.time()
        if cache and cache[0] == mtime and now - cache[1] < ttl:
            return cache[2]
        ok = self._check_authorized()
        self._auth_cache = (mtime, now, ok)
        return ok

    def _check_authorized(self):
        """Synchronous wrapper: is the persisted session still valid?"""
        async def _go():
            c = self._build_client()
            try:
                await c.connect()
                return await c.is_user_authorized()
            finally:
                try: await c.disconnect()
                except Exception: pass
        try:
            return bool(self._run_coro(_go, "status"))
        except Exception as e:
            log.debug(f"TG status check failed: {e}")
            return False

    # ── Auth flow ──────────────────────────────────────────────────────────
    def auth_send_code(self, phone):
        """Request Telegram to send the login code. Returns phone_code_hash
        that the operator must echo back in auth_confirm."""
        async def _go():
            c = self._build_client()
            await c.connect()
            try:
                sent = await c.send_code_request(phone)
                return sent.phone_code_hash
            finally:
                await c.disconnect()
        try:
            pch = self._run_coro(_go, "auth_send_code")
            self._pending_auth[phone] = pch
            return {"ok": True, "phone_code_hash": pch}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def auth_confirm(self, phone, code, password=None, phone_code_hash=None):
        """Complete login using the code Telegram sent to the operator."""
        phone_code_hash = phone_code_hash or self._pending_auth.get(phone)
        if not phone_code_hash:
            return {"ok": False, "error":
                    "no pending auth — call auth_send_code first"}

        async def _go():
            c = self._build_client()
            await c.connect()
            try:
                try:
                    await c.sign_in(phone=phone, code=code,
                                    phone_code_hash=phone_code_hash)
                except SessionPasswordNeededError:
                    if not password:
                        return {"ok": False,
                                "error": "2fa_password_required"}
                    await c.sign_in(password=password)
                except PhoneCodeInvalidError:
                    return {"ok": False, "error": "invalid code"}
                me = await c.get_me()
                return {"ok": True, "username": me.username,
                        "user_id": me.id, "first_name": me.first_name}
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            result = self._run_coro(_go, "auth_confirm")
            if result.get("ok"):
                self._pending_auth.pop(phone, None)
                self._lock_down_session()
            return result
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── QR-code login ─────────────────────────────────────────────────────
    # Maintained state for a single in-flight QR auth attempt. Keyed by
    # a random token so concurrent starts (e.g. two browser tabs) don't
    # stomp each other. Each entry holds {thread, url, expires_at,
    # authenticated, error}.
    _qr_sessions = None

    def _qr_sessions_dict(self):
        if self._qr_sessions is None:
            self._qr_sessions = {}
        return self._qr_sessions

    def auth_qr_start(self):
        """Start a QR-code login. Returns {token, url, expires_at}. The
        `url` is a tg://login?token=… URL that the operator's mobile
        Telegram app needs to open (by scanning a QR rendering of that
        URL). Blocking .wait() runs in a background thread so the HTTP
        response returns immediately."""
        import secrets
        sessions = self._qr_sessions_dict()
        token = secrets.token_urlsafe(8)

        # Each session runs in its own thread + event loop because
        # Telethon's QRLogin object holds a reference to its originating
        # client + loop. We can't hand it off to a different loop later.
        state = {"token": token, "url": None, "expires_at": None,
                 "authenticated": False, "error": None,
                 "needs_password": False}
        sessions[token] = state

        def _worker():
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            async def _go():
                c = self._build_client()
                await c.connect()
                try:
                    qr = await c.qr_login()
                    state["url"] = qr.url
                    state["expires_at"] = qr.expires.isoformat() \
                                          if getattr(qr, "expires", None) else None
                    try:
                        await asyncio.wait_for(qr.wait(), timeout=90)
                    except asyncio.TimeoutError:
                        state["error"] = "qr_expired"
                        return
                    except SessionPasswordNeededError:
                        state["needs_password"] = True
                        state["error"] = "2fa_password_required"
                        return
                    state["authenticated"] = True
                    self._lock_down_session()
                finally:
                    try: await c.disconnect()
                    except Exception: pass
            try:
                loop.run_until_complete(_go())
            except Exception as e:
                state["error"] = str(e)
            finally:
                try: loop.close()
                except Exception: pass

        t = threading.Thread(target=_worker, name=f"TgQR-{token}", daemon=True)
        state["thread"] = t
        t.start()
        # Wait briefly for the URL to populate — most of the time < 500ms.
        for _ in range(40):
            if state["url"] or state["error"]:
                break
            time.sleep(0.1)
        return {"token": token,
                "url": state["url"],
                "expires_at": state["expires_at"],
                "error": state["error"]}

    def auth_qr_status(self, token):
        """Poll the status of a pending QR session."""
        sessions = self._qr_sessions_dict()
        state = sessions.get(token)
        if not state:
            return {"error": "unknown token"}
        return {"url": state["url"],
                "expires_at": state["expires_at"],
                "authenticated": state["authenticated"],
                "needs_password": state["needs_password"],
                "error": state["error"]}

    def auth_qr_password(self, token, password):
        """Complete a QR login that required 2FA by submitting the
        password. Note: after the QR wait raised SessionPasswordNeeded,
        the originating client is gone. We open a fresh client and call
        sign_in(password=...) which Telethon can complete provided the
        session file retained the login temp state."""
        async def _go():
            c = self._build_client()
            await c.connect()
            try:
                await c.sign_in(password=password)
                me = await c.get_me()
                return {"ok": True, "username": getattr(me, "username", None)}
            finally:
                try: await c.disconnect()
                except Exception: pass
        try:
            r = self._run_coro(_go, "qr_password")
            if r.get("ok"):
                self._lock_down_session()
                state = self._qr_sessions_dict().get(token)
                if state: state["authenticated"] = True
            return r
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def logout(self):
        """Delete the local session file — operator re-auths next time."""
        removed = 0
        for p in (self.session_path, self.session_path + ".session"):
            try:
                os.remove(p)
                removed += 1
            except FileNotFoundError:
                pass
            except Exception as e:
                log.warning(f"TG logout: couldn't remove {p}: {e}")
        return {"ok": True, "removed": removed}

    # ── Channel ops ────────────────────────────────────────────────────────
    @staticmethod
    def _normalize_identifier(s):
        """Accept @name / name / t.me/name / https://t.me/name → bare username."""
        s = (s or "").strip()
        s = re.sub(r"^https?://", "", s)
        s = re.sub(r"^t\.me/", "", s, flags=re.I)
        s = s.lstrip("@").split("?")[0].split("/")[0]
        return s

    @staticmethod
    def _classify_entity(ent):
        """Label a Telegram entity: 'channel' (broadcast), 'megagroup'
        (large group masquerading as a Channel in MTProto), 'group'
        (legacy Chat), or 'other'."""
        if isinstance(ent, Channel):
            return "megagroup" if getattr(ent, "megagroup", False) else "channel"
        if isinstance(ent, Chat):
            return "group"
        return "other"

    def resolve_channel(self, identifier):
        """Resolve a public channel OR group by @handle / t.me URL.
        Returns rich metadata: channel_id, title, username, subscribers,
        about, verified, scam, kind. Groups are accepted — they're common
        venues for leak-posting in CTI workflows."""
        name = self._normalize_identifier(identifier)
        if not name:
            return {"error": "empty identifier"}

        async def _go():
            from telethon.tl.functions.channels import GetFullChannelRequest
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                ent = await c.get_entity(name)
                kind = DarkMTProto._classify_entity(ent)
                if kind == "other":
                    return {"error": "not a channel or group"}
                subs = getattr(ent, "participants_count", None)
                about = None
                # GetFullChannel returns .full_chat.about for the description;
                # only valid for Channel / megagroup, not legacy Chat.
                if isinstance(ent, Channel):
                    try:
                        full = await c(GetFullChannelRequest(ent))
                        about = getattr(full.full_chat, "about", None)
                        if subs is None:
                            subs = getattr(full.full_chat,
                                           "participants_count", None)
                    except Exception as e:
                        log.debug(f"TG full-channel lookup failed: {e}")
                ent_username = getattr(ent, "username", None)
                is_private = not bool(ent_username)
                created_iso = None
                try:
                    d = getattr(ent, "date", None)
                    if d: created_iso = d.isoformat()
                except Exception: pass
                restricted_reason = None
                try:
                    rr = getattr(ent, "restriction_reason", None)
                    if rr:
                        restricted_reason = "; ".join(
                            f"{getattr(r,'platform','?')}:{getattr(r,'reason','?')}"
                            for r in rr)
                except Exception: pass
                return {
                    "channel_id": ent.id,
                    "title": getattr(ent, "title", name),
                    "username": ent_username or name,
                    "subscribers": subs,
                    "about": about,
                    "created": created_iso,
                    "verified": bool(getattr(ent, "verified", False)),
                    "scam": bool(getattr(ent, "scam", False)),
                    "fake": bool(getattr(ent, "fake", False)),
                    "restricted": bool(getattr(ent, "restricted", False)),
                    "restricted_reason": restricted_reason,
                    "is_private": is_private,
                    "kind": kind,
                }
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            return {"error": str(e)}

    # ── Enriched channel details (CTI profile) ─────────────────────────
    def get_channel_details(self, channel_id, username=None,
                             photo_dest_dir=None):
        """Heavy-enrichment resolve. Returns everything resolve_channel
        does PLUS full-chat metadata (admins_count, linked_chat, slowmode,
        pinned msg, participants_hidden, antispam, ttl) AND a best-effort
        CREATOR lookup by scanning the admin list for the
        ChannelParticipantCreator entry.

        Creator lookup silently falls back to None on channels with
        hidden participants (a channel-owner privacy setting) — that's
        the expected behavior on locked-down CTI channels, surfaced to
        the UI via the `participants_hidden` flag.

        Phone is only returned when the creator has chosen to expose
        it in their privacy settings OR is in the operator's contacts.
        Almost always None for CTI targets — we return the field shape
        anyway so the UI can show "—" consistently."""
        self._record_call(channel_id)
        entity = self._entity_ref(channel_id, username)

        async def _go():
            from telethon.tl.functions.channels import (
                GetFullChannelRequest, GetParticipantsRequest)
            from telethon.tl.types import (
                ChannelParticipantsAdmins, ChannelParticipantCreator)
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                ent = await c.get_entity(entity)
                kind = DarkMTProto._classify_entity(ent)
                if kind == "other":
                    return {"error": "not a channel or group"}

                ent_username = getattr(ent, "username", None)
                is_private = not bool(ent_username)
                created_iso = None
                d = getattr(ent, "date", None)
                if d:
                    try: created_iso = d.isoformat()
                    except Exception: pass
                restricted_reason = None
                rr = getattr(ent, "restriction_reason", None) or []
                if rr:
                    restricted_reason = "; ".join(
                        f"{getattr(r,'platform','?')}:{getattr(r,'reason','?')}"
                        for r in rr)

                subs = getattr(ent, "participants_count", None)
                about = None
                admins_count = online_count = linked_chat_id = None
                migrated_from = slowmode_seconds = pinned_msg_id = None
                participants_hidden = antispam = False
                ttl_period = None
                full_ok = False
                if isinstance(ent, Channel):
                    try:
                        full = await c(GetFullChannelRequest(ent))
                        fc = full.full_chat
                        about = getattr(fc, "about", None)
                        admins_count = getattr(fc, "admins_count", None)
                        online_count = getattr(fc, "online_count", None)
                        linked_chat_id = getattr(fc, "linked_chat_id", None)
                        slowmode_seconds = getattr(fc, "slowmode_seconds", None)
                        pinned_msg_id = getattr(fc, "pinned_msg_id", None)
                        participants_hidden = bool(getattr(fc, "participants_hidden", False))
                        antispam = bool(getattr(fc, "antispam", False))
                        ttl_period = getattr(fc, "ttl_period", None)
                        mf = getattr(fc, "migrated_from_chat_id", None)
                        if mf: migrated_from = mf
                        if subs is None:
                            subs = getattr(fc, "participants_count", None)
                        full_ok = True
                    except Exception as e:
                        log.debug(f"TG full-channel lookup failed: {e}")

                # Creator lookup. Only attempt for Channel/megagroup where
                # admins are enumerable. participants_hidden=True channels
                # return empty admin lists — we'll show the flag instead.
                creator = None
                if isinstance(ent, Channel) and not participants_hidden:
                    try:
                        resp = await c(GetParticipantsRequest(
                            channel=ent,
                            filter=ChannelParticipantsAdmins(),
                            offset=0, limit=20, hash=0))
                        creator_user = None
                        for p in getattr(resp, "participants", []) or []:
                            if isinstance(p, ChannelParticipantCreator):
                                uid = getattr(p, "user_id", None)
                                creator_user = next(
                                    (u for u in getattr(resp, "users", [])
                                     if getattr(u, "id", None) == uid), None)
                                break
                        if creator_user:
                            name_parts = [
                                getattr(creator_user, "first_name", None) or "",
                                getattr(creator_user, "last_name", None) or ""]
                            creator = {
                                "user_id":  getattr(creator_user, "id", None),
                                "username": getattr(creator_user, "username", None),
                                "name":     " ".join(p for p in name_parts if p).strip() or None,
                                "phone":    getattr(creator_user, "phone", None),
                                "bot":      bool(getattr(creator_user, "bot", False)),
                                "verified": bool(getattr(creator_user, "verified", False)),
                                "scam":     bool(getattr(creator_user, "scam", False)),
                                "premium":  bool(getattr(creator_user, "premium", False)),
                                "restricted": bool(getattr(creator_user, "restricted", False)),
                            }
                    except Exception as e:
                        # Channels frequently disallow admin enumeration —
                        # debug-log and move on with None.
                        log.debug(f"TG admin enum failed for @{ent_username}: {e}")

                # Channel avatar — download once, served by the webapp
                # from /loot/tg-media/channels/<handle>.jpg.
                photo_path = None
                if photo_dest_dir and getattr(ent, "photo", None):
                    try:
                        os.makedirs(photo_dest_dir, exist_ok=True)
                        fname = (ent_username or str(ent.id)) + ".jpg"
                        saved = await c.download_profile_photo(
                            ent, file=os.path.join(photo_dest_dir, fname))
                        if saved:
                            photo_path = f"channels/{os.path.basename(saved)}"
                    except Exception as e:
                        log.debug(f"channel photo download failed: {e}")

                return {
                    "channel_id": ent.id,
                    "title": getattr(ent, "title", None),
                    "username": ent_username,
                    "subscribers": subs,
                    "about": about,
                    "kind": kind,
                    "is_private": is_private,
                    "verified": bool(getattr(ent, "verified", False)),
                    "scam":     bool(getattr(ent, "scam", False)),
                    "fake":     bool(getattr(ent, "fake", False)),
                    "restricted": bool(getattr(ent, "restricted", False)),
                    "restricted_reason": restricted_reason,
                    "created": created_iso,
                    "admins_count":       admins_count,
                    "online_count":       online_count,
                    "linked_chat_id":     linked_chat_id,
                    "migrated_from":      migrated_from,
                    "slowmode_seconds":   slowmode_seconds,
                    "pinned_msg_id":      pinned_msg_id,
                    "participants_hidden": participants_hidden,
                    "antispam":           antispam,
                    "ttl_period":         ttl_period,
                    "full_ok":            full_ok,
                    "creator":            creator,
                    "photo_path":         photo_path,
                }
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            return {"error": str(e)}

    # ── Join / leave ─────────────────────────────────────────────────────
    def join_channel(self, channel_id, username=None, invite_hash=None):
        """Join a channel or group. Two paths:
          * Public channel: pass username (or channel_id). Uses
            JoinChannelRequest — the account becomes a member, the
            channel appears in your chat list.
          * Invite link: pass invite_hash (the token after /joinchat/
            or the + prefix in modern invites). Uses ImportChatInviteRequest.

        Note: joining leaves traces in the operator's Telegram account.
        Some channels require approval (RequestJoin) — we detect that
        case and return a pending status rather than erroring.
        """
        self._record_call(channel_id)
        entity = self._entity_ref(channel_id, username)

        async def _go():
            from telethon.tl.functions.channels import JoinChannelRequest
            from telethon.tl.functions.messages import ImportChatInviteRequest
            from telethon.errors import (
                UserAlreadyParticipantError, InviteHashExpiredError,
                InviteHashInvalidError, ChannelPrivateError)
            # InviteRequestSentError was added in a later Telethon — fall
            # back to a sentinel class that never matches if unavailable,
            # so the try/except still compiles on older Telethon builds.
            try:
                from telethon.errors import InviteRequestSentError
            except ImportError:
                class InviteRequestSentError(Exception): pass
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                try:
                    if invite_hash:
                        await c(ImportChatInviteRequest(invite_hash))
                        return {"ok": True, "joined_via": "invite"}
                    ent = await c.get_entity(entity)
                    await c(JoinChannelRequest(ent))
                    return {"ok": True, "joined_via": "public"}
                except UserAlreadyParticipantError:
                    return {"ok": True, "joined_via": "already_member"}
                except InviteRequestSentError:
                    return {"ok": True, "pending_approval": True,
                            "joined_via": "request_sent"}
                except (InviteHashExpiredError, InviteHashInvalidError) as e:
                    return {"error": f"invite_invalid: {e!s}"}
                except ChannelPrivateError:
                    return {"error": "channel is private — need an invite link"}
                except Exception as e:
                    return {"error": str(e)}
            finally:
                try: await c.disconnect()
                except Exception: pass
        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            return {"error": str(e)}

    def leave_channel(self, channel_id, username=None):
        """Leave a channel the operator's account is currently in.
        Mirrors join_channel — same entity resolution rules."""
        self._record_call(channel_id)
        entity = self._entity_ref(channel_id, username)

        async def _go():
            from telethon.tl.functions.channels import LeaveChannelRequest
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                try:
                    ent = await c.get_entity(entity)
                    await c(LeaveChannelRequest(ent))
                    return {"ok": True}
                except Exception as e:
                    return {"error": str(e)}
            finally:
                try: await c.disconnect()
                except Exception: pass
        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _media_type(msg):
        """Label the media attached to a message, or None if none."""
        m = getattr(msg, "media", None)
        if m is None: return None
        # Media classes from Telethon — name them in plain English.
        kind = type(m).__name__.replace("MessageMedia", "").lower()
        return kind or "unknown"

    @staticmethod
    def _reactions_total(msg):
        r = getattr(msg, "reactions", None)
        if not r: return None
        try:
            return sum(int(getattr(x, "count", 0))
                       for x in getattr(r, "results", []) or [])
        except Exception:
            return None

    @staticmethod
    def _reactions_detail(msg):
        """Per-emoji breakdown as a JSON-serializable list:
          [{emoji: "🔥", count: 42}, {emoji: "custom:123", count: 3}, ...]

        Custom Telegram emojis (paid / premium) are rendered as
        'custom:<document_id>' since we can't emit the actual glyph. UI
        can resolve to a fallback emoji or hide them. Returns None when
        the message has no reactions block (sticker-only / channel post
        with reactions disabled)."""
        r = getattr(msg, "reactions", None)
        if not r: return None
        try:
            out = []
            for res in getattr(r, "results", []) or []:
                reaction = getattr(res, "reaction", None)
                if reaction is None: continue
                emoji = getattr(reaction, "emoticon", None)
                if not emoji:
                    doc_id = getattr(reaction, "document_id", None)
                    if doc_id is None: continue
                    emoji = f"custom:{doc_id}"
                out.append({
                    "emoji": emoji,
                    "count": int(getattr(res, "count", 0) or 0),
                })
            # Sort by count desc — most-reacted first in UI.
            out.sort(key=lambda x: -x["count"])
            return out or None
        except Exception:
            return None

    @staticmethod
    def _fwd_info(msg):
        """Return (fwd_from_username, fwd_from_msg_id) or (None, None)."""
        f = getattr(msg, "fwd_from", None)
        if not f: return (None, None)
        # .from_id can be a PeerChannel/User; we don't resolve the username
        # here (would require an extra round-trip). .from_name is the
        # broadcaster-label when sign_messages is enabled; falls back to
        # channel_post id which identifies the origin msg.
        origin = getattr(f, "from_name", None)
        msg_id = getattr(f, "channel_post", None) or getattr(f, "saved_from_msg_id", None)
        return (origin, msg_id)

    def fetch_new_messages(self, channel_id, since_msg_id=None, limit=None,
                            username=None, before_msg_id=None):
        """Return up to `limit` messages newer than `since_msg_id`. With
        `since_msg_id` they are the OLDEST `limit` messages above it,
        oldest first, so a caller that saves the highest id after each
        batch walks forward without gaps. Without it they are the newest
        `limit` messages, newest first. Each entry is a rich dict suitable
        for storage in tg_messages:

            {msg_id, date_iso, sender_id, sender_username, sender_name,
             text, views, forwards, reactions_total, has_media, media_type,
             fwd_from_username, fwd_from_msg_id, reply_to_msg_id}

        Resolution priority for the Telegram entity:
          1. `username` ("@handle") if passed — Telethon resolves this via
             contacts.resolveUsername, which NEVER requires the local
             session to already contain the entity. Most reliable.
          2. numeric `channel_id` — only works if the client session has
             seen this peer before. Fresh-session or wiped-cache failures
             silently return [] in older Telethon versions.

        Skips empty messages (pure reactions / stickers — nothing to scan).
        Skipped messages still count toward `limit`; `last_fetch_count`,
        `last_fetch_max_id` and `last_fetch_min_id` say how many messages
        were read and the highest and lowest id among them, skipped or not.
        Best-effort: returns [] on any Telethon error so the monitor loop
        never crashes. Writes a warning to the log on auth failure or
        resolution errors so the operator can see WHY it returned empty.

        Forum-channel aware: if the channel's entity has .forum=True,
        fetches the topic list once and labels each message with its
        topic_id / topic_title so the UI can group by thread."""
        limit = limit or self.scrape_limit
        self._record_call(channel_id)
        self.last_fetch_error = None
        self.last_fetch_count = 0
        self.last_fetch_max_id = 0
        self.last_fetch_min_id = 0
        # Prefer the @handle when we have it — resolve-by-username is far
        # more reliable than resolve-by-numeric-id across session resets.
        entity = self._entity_ref(channel_id, username)

        async def _go():
            # GetForumTopicsRequest moved between Telethon versions, and
            # its entity argument was renamed with it:
            #   * pinned 1.45: telethon.tl.functions.messages, peer=
            #   * 1.36 and older: telethon.tl.functions.channels, channel=
            # Both paths tried; if neither works we degrade gracefully
            # and just don't label messages with their forum topic.
            GetForumTopicsRequest, topic_peer_kw = None, None
            try:
                from telethon.tl.functions.messages \
                    import GetForumTopicsRequest
                topic_peer_kw = "peer"
            except ImportError:
                try:
                    from telethon.tl.functions.channels \
                        import GetForumTopicsRequest
                    topic_peer_kw = "channel"
                except ImportError:
                    pass
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    self.last_fetch_error = "not authenticated (session expired)"
                    log.warning("[tg] fetch_new_messages: NOT AUTHENTICATED"
                                " — session expired or never completed")
                    return []
                # Detect forum and fetch topic map (once per fetch call).
                topic_map = {}     # topic_id → title
                ent = None
                if GetForumTopicsRequest is not None:
                    try:
                        ent = await c.get_entity(entity)
                    except Exception as e:
                        # iter_messages below fails on the same entity and
                        # logs it, so debug is enough here.
                        log.debug(f"forum topic fetch skipped for {entity}: {e}")
                if ent is not None and bool(getattr(ent, "forum", False)):
                    try:
                        resp = await c(GetForumTopicsRequest(
                            offset_date=None, offset_id=0,
                            offset_topic=0, limit=100,
                            **{topic_peer_kw: ent}))
                        for t in getattr(resp, "topics", []) or []:
                            topic_map[getattr(t, "id", None)] = \
                                getattr(t, "title", None)
                    except Exception as e:
                        # Warning, not debug: a failure here drops every
                        # topic label of the fetch (a channel= / peer= mixup
                        # does it on every call), and nothing else shows it.
                        log.warning(f"[tg] forum topic fetch failed for {entity}, "
                                    f"messages stored without topic labels: "
                                    f"{type(e).__name__}: {e}")

                kwargs = {"entity": entity, "limit": limit}
                if since_msg_id:
                    kwargs["min_id"] = int(since_msg_id)
                    # Oldest first: newest first would return the newest
                    # `limit` messages above min_id and skip everything
                    # between min_id and them once the caller saves the
                    # highest id. Only with min_id: without it, reverse
                    # starts at the channel's first message.
                    kwargs["reverse"] = True
                if before_msg_id:
                    # max_id is exclusive — returns messages with id < max_id.
                    # Used by multi-batch historical scrapes to walk backward
                    # through history.
                    kwargs["max_id"] = int(before_msg_id)
                out = []
                read, max_id, min_id = 0, 0, 0
                async for msg in c.iter_messages(**kwargs):
                    if msg is None: continue
                    read += 1
                    max_id = max(max_id, msg.id)
                    min_id = min(min_id, msg.id) if min_id else msg.id
                    text = msg.message or ""
                    has_media = bool(getattr(msg, "media", None))
                    # KEEP media-only messages (photos/docs with no caption).
                    # Previous behavior dropped every uncaptioned image, so
                    # image-heavy channels looked "empty" in the UI even
                    # though they had hundreds of posts. Text-only empty
                    # messages (stickers, reactions) are still skipped.
                    if not text and not has_media:
                        continue
                    sender = msg.sender
                    fwd_user, fwd_msg = self._fwd_info(msg)
                    rt = getattr(msg, "reply_to", None)
                    reply_to = getattr(rt, "reply_to_msg_id", None) if rt else None
                    # Forum-topic id: reply_to.reply_to_top_id (if set) points at
                    # the topic root, or reply_to_msg_id on a top-level topic
                    # start message. Bail clean when not forum.
                    topic_id = None
                    if topic_map and rt is not None:
                        tid = (getattr(rt, "reply_to_top_id", None)
                               or getattr(rt, "reply_to_msg_id", None))
                        if tid in topic_map:
                            topic_id = tid
                    topic_title = topic_map.get(topic_id) if topic_id else None
                    out.append({
                        "msg_id": msg.id,
                        "date_iso": msg.date.isoformat() if msg.date else None,
                        "sender_id": getattr(sender, "id", None) if sender else None,
                        "sender_username": getattr(sender, "username", None) if sender else None,
                        "sender_name": (
                            getattr(sender, "first_name", None) or
                            getattr(sender, "title", None)
                            if sender else None),
                        "text": text,
                        "views": getattr(msg, "views", None),
                        "forwards": getattr(msg, "forwards", None),
                        "reactions_total": self._reactions_total(msg),
                        "reactions_detail": self._reactions_detail(msg),
                        "topic_id": topic_id,
                        "topic_title": topic_title,
                        "has_media": has_media,
                        "media_type": self._media_type(msg),
                        "fwd_from_username": fwd_user,
                        "fwd_from_msg_id": fwd_msg,
                        "reply_to_msg_id": reply_to,
                    })
                # Set only once the whole batch was read: after an error
                # nothing was stored, so the cursor must not move.
                self.last_fetch_count = read
                self.last_fetch_max_id, self.last_fetch_min_id = max_id, min_id
                return out
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            self.last_fetch_error = f"flood wait: {e.seconds}s"
            log.warning(f"TG flood-wait {e.seconds}s on {entity}")
            return []
        except Exception as e:
            self.last_fetch_error = f"{type(e).__name__}: {e}"
            log.warning(f"TG fetch failed for {entity}: {e}")
            return []

    # ── User lookup (OSINT) ────────────────────────────────────────────────
    def lookup_user(self, identifier, photo_history=True,
                     photo_history_limit=10, photo_dest_dir=None):
        """Return a profile card for a Telegram user.

        Operator provides a @handle, phone number, or t.me/+phone link.
        We hit `get_entity` (full user resolution) and `GetFullUserRequest`
        (bio, common chats count).

        When `photo_history=True`, enumerates up to
        `photo_history_limit` historic profile photos (via
        GetUserPhotosRequest). If `photo_dest_dir` is provided, each
        photo is downloaded and its relative path is included in the
        returned `photos` list; otherwise only IDs + dates are returned.
        Profile-photo archaeology surfaces aliases / identities the user
        previously used — a surprisingly strong OSINT signal. Returns
        {error: ...} on failure."""
        name = self._normalize_identifier(identifier)
        if not name:
            return {"error": "empty identifier"}

        async def _go():
            from telethon.tl.functions.users import GetFullUserRequest
            from telethon.tl.functions.photos import GetUserPhotosRequest
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                try:
                    ent = await c.get_entity(name)
                except Exception as e:
                    return {"error": f"resolve failed: {e}"}
                # Reject channel/group entities — those have their own panel.
                if not hasattr(ent, "first_name") and not hasattr(ent, "phone"):
                    return {"error": "not a user"}
                bio = None
                common_chats = None
                try:
                    full = await c(GetFullUserRequest(ent))
                    bio = getattr(full.full_user, "about", None)
                    common_chats = getattr(full.full_user,
                                           "common_chats_count", None)
                except Exception as e:
                    log.debug(f"full-user lookup partial: {e}")

                photos_out = []
                if photo_history:
                    try:
                        resp = await c(GetUserPhotosRequest(
                            user_id=ent, offset=0, max_id=0,
                            limit=int(photo_history_limit)))
                        for p in getattr(resp, "photos", []) or []:
                            entry = {
                                "id":   getattr(p, "id", None),
                                "date": (p.date.isoformat()
                                         if getattr(p, "date", None) else None),
                                "path": None,
                            }
                            if photo_dest_dir:
                                try:
                                    os.makedirs(photo_dest_dir, exist_ok=True)
                                    saved = await c.download_media(
                                        p, file=os.path.join(
                                            photo_dest_dir,
                                            f"{ent.id}_{entry['id']}"))
                                    if saved:
                                        entry["path"] = os.path.basename(saved)
                                except Exception as e:
                                    log.debug(f"photo download failed: {e}")
                            photos_out.append(entry)
                    except Exception as e:
                        log.debug(f"photo history lookup partial: {e}")

                return {
                    "user_id": ent.id,
                    "username": getattr(ent, "username", None),
                    "first_name": getattr(ent, "first_name", None),
                    "last_name":  getattr(ent, "last_name", None),
                    "phone": getattr(ent, "phone", None),
                    "bio": bio,
                    "verified":   bool(getattr(ent, "verified", False)),
                    "scam":       bool(getattr(ent, "scam", False)),
                    "fake":       bool(getattr(ent, "fake", False)),
                    "bot":        bool(getattr(ent, "bot", False)),
                    "premium":    bool(getattr(ent, "premium", False)),
                    "restricted": bool(getattr(ent, "restricted", False)),
                    "common_chats_count": common_chats,
                    "lang_code": getattr(ent, "lang_code", None),
                    "has_photo": bool(getattr(ent, "photo", None)),
                    "photos": photos_out,
                }
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            return {"error": str(e)}

    # ── Member enumeration (groups / megagroups) ────────────────────────
    def list_members(self, channel_id, limit=200, query=None, username=None):
        """List participants of a group or megagroup. Broadcast channels
        forbid this server-side — we return {error: ...} instead of
        swallowing silently.

        Entity is resolved via @username when available (more reliable)
        and falls back to the numeric channel_id.

        Returns (at most `limit`) users with: user_id, username, first_name,
        last_name, phone (if visible), bot, verified, scam, premium, status
        (online/offline/recently), joined_date if available.

        `query` narrows to usernames / names containing the substring."""
        self._record_call(channel_id)
        entity = self._entity_ref(channel_id, username)
        async def _go():
            from telethon.tl.types import Channel
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                try:
                    ent = await c.get_entity(entity)
                except Exception as e:
                    return {"error": f"resolve failed: {e}"}
                # Broadcast channels disallow participant listing.
                if isinstance(ent, Channel) and getattr(ent, "broadcast", False) \
                        and not getattr(ent, "megagroup", False):
                    return {"error":
                            "member enumeration not allowed on broadcast channels"}
                out = []
                kwargs = {"entity": ent, "limit": int(limit),
                          "aggressive": False}
                if query:
                    kwargs["search"] = str(query)
                async for u in c.iter_participants(**kwargs):
                    if u is None: continue
                    status = None
                    st = getattr(u, "status", None)
                    if st is not None:
                        status = type(st).__name__.replace("UserStatus", "").lower()
                    out.append({
                        "user_id":    getattr(u, "id", None),
                        "username":   getattr(u, "username", None),
                        "first_name": getattr(u, "first_name", None),
                        "last_name":  getattr(u, "last_name", None),
                        "phone":      getattr(u, "phone", None),
                        "bot":        bool(getattr(u, "bot", False)),
                        "verified":   bool(getattr(u, "verified", False)),
                        "scam":       bool(getattr(u, "scam", False)),
                        "premium":    bool(getattr(u, "premium", False)),
                        "status":     status,
                    })
                return {"members": out, "count": len(out)}
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            log.warning(f"TG list_members failed: {e}")
            return {"error": str(e)}

    # ── On-demand media download ─────────────────────────────────────────
    def download_message_media(self, channel_id, msg_id, dest_dir,
                                max_bytes=50 * 1024 * 1024, username=None):
        """Download the media attached to a single message. On-demand only:
        the operator clicks a button in the UI. Automated bulk download is
        deliberately not enabled — malware in CTI-channel attachments is
        common, and unbounded download of a rigged file is a spam/abuse
        footgun. Returns {path, bytes, type} on success, {error: ...} on
        failure. `path` is RELATIVE to dest_dir so the UI can serve it
        from /loot/tg-media/.
        """
        entity = self._entity_ref(channel_id, username)
        async def _go():
            from telethon.errors import RPCError
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                # Fetch the single message by id; iter_messages(ids=[...]) is
                # cheaper than a full history scan.
                msgs = await c.get_messages(entity, ids=int(msg_id))
                msg = msgs if msgs and not isinstance(msgs, list) else (
                    msgs[0] if msgs else None)
                if not msg:
                    return {"error": "message not found"}
                if not getattr(msg, "media", None):
                    return {"error": "no media on this message"}
                # Size gate — skip oversized media; we refuse to become a
                # bulk file host.
                size = None
                try:
                    doc = getattr(msg, "document", None) or \
                          getattr(getattr(msg, "media", None), "document", None)
                    if doc is not None:
                        size = getattr(doc, "size", None)
                except Exception: pass
                if size and size > max_bytes:
                    return {"error": f"media too large ({size} bytes)"}
                os.makedirs(dest_dir, exist_ok=True)
                # Telethon picks a sensible default filename based on
                # document attributes; prefixed with the msg_id so files
                # from the same channel sort chronologically.
                saved = await msg.download_media(
                    file=os.path.join(dest_dir, f"{msg_id}_"))
                if not saved: return {"error": "download returned no path"}
                rel = os.path.basename(saved)
                try: bytes_ = os.path.getsize(saved)
                except OSError: bytes_ = None
                return {"path": rel, "bytes": bytes_,
                        "type": self._media_type(msg)}
            except RPCError as e:
                return {"error": f"rpc:{e!s}"}
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            log.warning(f"TG media download failed: {e}")
            return {"error": str(e)}

    # ── Live channel search (OSINT) ────────────────────────────────────────
    def search_in_channel(self, channel_id, query, limit=50, min_date_iso=None,
                           username=None):
        """Run a native Telegram message search inside a specific channel.
        Much more powerful than DB LIKE because it can surface messages
        we've never scraped. Best-effort: returns [] on any error so the
        UI layer can fall back to local results; `last_search_error`
        says why, and is None after a search that ran.

        `username` (optional): when set, resolved as @handle — more
        reliable than the numeric channel_id across session rebuilds.
        `min_date_iso` (optional) caps results to messages on/after that date.
        """
        self._record_call(channel_id)
        self.last_search_error = None
        entity = self._entity_ref(channel_id, username)
        async def _go():
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    self.last_search_error = "not authenticated (session expired)"
                    log.warning("[tg] search_in_channel: not authenticated")
                    return []
                kwargs = {"entity": entity, "search": query,
                          "limit": limit}
                # iter_messages walks newest -> oldest. Its offset_date means
                # "start at this date and go OLDER", which inverted the
                # "on/after min_date" filter. Stop once we pass the cutoff.
                min_date = None
                if min_date_iso:
                    try:
                        from datetime import datetime as _dt
                        min_date = _dt.fromisoformat(min_date_iso)
                        if min_date.tzinfo is None:
                            min_date = min_date.replace(tzinfo=timezone.utc)
                    except Exception:
                        min_date = None
                q_lower = (query or "").lower()
                out = []
                async for msg in c.iter_messages(**kwargs):
                    if msg is None: continue
                    if min_date and msg.date and msg.date < min_date:
                        break
                    text = msg.message or ""
                    if not text: continue
                    out.append({
                        # Telegram's server search is fuzzy (stemming,
                        # word-prefix). Flag hits that really contain the
                        # keyword so they can be told apart / ranked first.
                        "exact_match": q_lower in text.lower(),
                        "channel_id": channel_id,
                        "msg_id": msg.id,
                        "date_iso": msg.date.isoformat() if msg.date else None,
                        "text": text,
                        "views": getattr(msg, "views", None),
                    })
                return out
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            self.last_search_error = f"flood wait: {e.seconds}s"
            log.warning(f"TG search flood-wait {e.seconds}s on channel {channel_id}")
            return []
        except Exception as e:
            self.last_search_error = f"{type(e).__name__}: {e}"
            log.warning(f"TG search failed for {channel_id}: {e}")
            return []

    # ── Channel-mention extraction + successor-chain following ────────────
    # Regex catches @handles, t.me/handle, https://t.me/handle, and
    # telegram.me/ variants. Handles are 5-32 chars, start with a letter,
    # alnum+underscore. Rejects obvious false positives like emails.
    _MENTION_RE = re.compile(
        r"(?:^|[^\w@])"                              # not after @ or \w
        r"(?:https?://)?(?:t\.me|telegram\.me)/"
        r"(?:joinchat/)?"                            # ignore invite links
        r"(?P<name>[A-Za-z][A-Za-z0-9_]{4,31})"
        r"|"
        r"(?:^|[^\w])@(?P<handle>[A-Za-z][A-Za-z0-9_]{4,31})\b",
        re.I)

    # Phrases that boost the likelihood a mention is a successor channel
    # announcement (banned/moved). Case-insensitive.
    _SUCCESSOR_HINTS = re.compile(
        r"\b(new channel|backup(?: channel)?|we('?ve)? moved|move(?:d)? to|"
        r"our new|follow us(?: at)?|successor|replacement|mirror|"
        r"if banned|if this channel|old channel|new home|official(?: channel)?)\b",
        re.I)

    @classmethod
    def extract_channel_mentions(cls, text):
        """Return a set of Telegram channel handles mentioned in text.
        De-duplicated, normalized to lowercase (Telegram handles are case-
        insensitive). Strips invite links (joinchat/...) since those can't
        be resolved without joining."""
        if not text: return set()
        out = set()
        for m in cls._MENTION_RE.finditer(text):
            name = m.group("name") or m.group("handle")
            if not name: continue
            nl = name.lower()
            # Skip obvious non-channel names.
            if nl in ("joinchat", "addstickers", "share", "proxy"): continue
            out.add(nl)
        return out

    def find_successor_hints(self, channel_id, last_n=50):
        """Inspect a channel's recent messages + entity description for
        mentions that plausibly point at a successor channel. Returns a
        list of (handle, score, reason) sorted highest-score first.

        Scoring:
        - Mention in `about` description: +5 (strongest signal)
        - Mention near a successor-hint phrase in same message: +3
        - Mention alone in a message body: +1
        - Mention in one of the LAST messages (chronologically): +1 bonus"""
        async def _go():
            from telethon.tl.functions.channels import GetFullChannelRequest
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return []
                ent = await c.get_entity(channel_id)
                hints = {}  # handle → [score, reasons[]]

                def bump(handle, score, reason):
                    h = handle.lower()
                    if h not in hints:
                        hints[h] = [0, []]
                    hints[h][0] += score
                    hints[h][1].append(reason)

                # 1. about / description
                about = None
                try:
                    if isinstance(ent, Channel):
                        full = await c(GetFullChannelRequest(ent))
                        about = getattr(full.full_chat, "about", None)
                except Exception: pass
                if about:
                    for name in self.extract_channel_mentions(about):
                        bump(name, 5, "mentioned in channel description")

                # 2. iterate recent messages
                idx = 0
                async for msg in c.iter_messages(ent, limit=last_n):
                    idx += 1
                    if not msg or not msg.message: continue
                    text = msg.message
                    names = self.extract_channel_mentions(text)
                    if not names: continue
                    has_hint = bool(self._SUCCESSOR_HINTS.search(text))
                    recency_bonus = 1 if idx <= 10 else 0
                    for name in names:
                        if has_hint:
                            bump(name, 3 + recency_bonus,
                                 f"successor-hint phrase in msg #{msg.id}")
                        else:
                            bump(name, 1 + recency_bonus,
                                 f"plain mention in msg #{msg.id}")

                return sorted(
                    [{"handle": h, "score": s, "reasons": r}
                     for h, (s, r) in hints.items()],
                    key=lambda x: -x["score"])
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            log.warning(f"TG successor-hint flood-wait {e.seconds}s")
            return []
        except Exception as e:
            log.warning(f"TG successor-hint failed for {channel_id}: {e}")
            return []

    def channel_status(self, identifier):
        """Quickly classify a channel as alive / dead / unknown.
        'alive' — resolved, has recent activity
        'dead'  — resolve failed with banned/private/invalid-style error
        'stale' — resolved but no messages in the last 30 days
        'unknown' — couldn't be classified (network / auth)"""
        async def _go():
            from telethon.errors import (
                ChannelPrivateError, ChannelInvalidError, UsernameNotOccupiedError,
                UsernameInvalidError)
            from datetime import datetime as _dt, timezone as _tz
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"status": "unknown", "reason": "not authenticated"}
                try:
                    name = self._normalize_identifier(identifier)
                    ent = await c.get_entity(name)
                except (ChannelPrivateError, ChannelInvalidError) as e:
                    return {"status": "dead", "reason": f"private/invalid ({type(e).__name__})"}
                except (UsernameNotOccupiedError, UsernameInvalidError) as e:
                    return {"status": "dead", "reason": f"username gone ({type(e).__name__})"}
                except Exception as e:
                    return {"status": "unknown",
                            "reason": f"resolve error: {type(e).__name__}"}
                # Alive — check recency.
                last_date = None
                async for msg in c.iter_messages(ent, limit=1):
                    if msg and msg.date:
                        last_date = msg.date
                    break
                if not last_date:
                    return {"status": "stale", "reason": "no messages yet",
                            "channel_id": ent.id, "username": getattr(ent,"username",None)}
                now = _dt.now(_tz.utc)
                days = (now - last_date).total_seconds() / 86400
                if days > 30:
                    return {"status": "stale",
                            "reason": f"last message {int(days)}d ago",
                            "channel_id": ent.id, "username": getattr(ent,"username",None),
                            "last_date": last_date.isoformat()}
                return {"status": "alive", "reason": f"last message {int(days)}d ago",
                        "channel_id": ent.id, "username": getattr(ent,"username",None),
                        "last_date": last_date.isoformat()}
            finally:
                try: await c.disconnect()
                except Exception: pass
        try:
            return self._run_coro(_go)
        except Exception as e:
            return {"status": "unknown", "reason": f"{type(e).__name__}: {e}"}

    def follow_channel_chain(self, starting_identifier, max_hops=5):
        """Follow a (possibly-dead) channel to its current successor by
        scraping its about/last-messages for successor hints and hopping
        the highest-scored mention. Stops at the first alive channel, at
        max_hops, or when a hop fails to produce a new candidate.

        Returns a list of nodes, each:
            {handle, status, reason, hints_considered, score, chosen_reason}
        """
        chain = []
        seen = set()
        current = self._normalize_identifier(starting_identifier)
        for _ in range(max_hops):
            if not current or current in seen:
                break
            seen.add(current)

            status = self.channel_status(current)
            node = {"handle": current, **status,
                    "hints": [], "chose": None}

            if status.get("status") == "alive":
                node["chose"] = "stop — channel is alive"
                chain.append(node)
                break

            # Dead or stale: look for a successor mention.
            hints = []
            if status.get("status") in ("dead", "stale"):
                # For dead channels we can't read their messages directly;
                # find_successor_hints requires the entity. Skip when dead.
                # For stale: try the hint pipeline.
                ch_id = status.get("channel_id")
                if ch_id:
                    hints = self.find_successor_hints(ch_id)
            node["hints"] = hints[:10]

            # Pick the top mention (if any) as the next hop.
            if hints and hints[0]["score"] >= 3:
                next_handle = hints[0]["handle"]
                node["chose"] = f"→ @{next_handle} (score {hints[0]['score']})"
                chain.append(node)
                current = next_handle
            else:
                node["chose"] = "no successor found" if not hints \
                                else f"best hint too weak (score {hints[0]['score']})"
                chain.append(node)
                break
        return chain

    # ── Global directory search (channel discovery) ────────────────────────
    def search_directory(self, query, limit=30):
        """Query Telegram's global directory for channels/groups/users whose
        name or @handle matches `query`. Same API the official client uses
        when you type in its search bar. Returns a flat structure the UI
        can render as clickable "add channel" cards.

        Response:
            {channels: [{id, title, username, subscribers, kind,
                          verified, scam, fake, restricted}],
             users:    [{id, first_name, last_name, username,
                          bot, verified, scam}]}
        """
        q = (query or "").strip().lstrip("@")
        if not q or len(q) < 3:
            return {"error": "query must be at least 3 characters"}

        async def _go():
            from telethon.tl.functions.contacts import SearchRequest
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    return {"error": "not authenticated"}
                resp = await c(SearchRequest(q=q, limit=limit))
                channels, users = [], []
                for ent in (resp.chats or []):
                    # SearchRequest returns both Chat (legacy groups) and
                    # Channel (broadcast + megagroup). Both map to our
                    # "channel" concept for Add-purposes.
                    kind = DarkMTProto._classify_entity(ent)
                    if kind == "other":  # pragma: no cover
                        continue
                    channels.append({
                        "id": getattr(ent, "id", None),
                        "title": getattr(ent, "title", "") or "",
                        "username": getattr(ent, "username", None),
                        "subscribers": getattr(ent, "participants_count", None),
                        "kind": kind,
                        "verified":   bool(getattr(ent, "verified", False)),
                        "scam":       bool(getattr(ent, "scam", False)),
                        "fake":       bool(getattr(ent, "fake", False)),
                        "restricted": bool(getattr(ent, "restricted", False)),
                    })
                for u in (resp.users or []):
                    # Skip users without a handle — nothing to add.
                    if not getattr(u, "username", None):
                        continue
                    users.append({
                        "id": getattr(u, "id", None),
                        "username": u.username,
                        "first_name": getattr(u, "first_name", None),
                        "last_name":  getattr(u, "last_name", None),
                        "bot":       bool(getattr(u, "bot", False)),
                        "verified":  bool(getattr(u, "verified", False)),
                        "scam":      bool(getattr(u, "scam", False)),
                    })
                # Sort: verified first, then scam-flagged last, then
                # by subscriber count desc (missing last).
                channels.sort(key=lambda c: (
                    c["scam"] or c["fake"], not c["verified"],
                    -(c["subscribers"] or 0)))
                return {"channels": channels, "users": users}
            finally:
                try: await c.disconnect()
                except Exception: pass

        try:
            return self._run_coro(_go)
        except FloodWaitError as e:
            return {"error": f"flood_wait:{e.seconds}s"}
        except Exception as e:
            return {"error": str(e)}

    # ── Clever global channel search ──────────────────────────────────────
    # Small CTI-themed synonym dictionary. Keys are lowercased tokens;
    # values are additional search variants to try. Kept small and
    # hand-curated rather than pulled in as a library — these are the
    # categories that actually drive real CTI-channel discovery. Extend
    # via config.telegram.synonyms if the operator wants more.
    _SYNONYMS = {
        "ransom":      ["ransomware", "ransom gang", "ransom news"],
        "ransomware":  ["ransom", "ransom gang", "leaks", "leak site"],
        "leak":        ["leaks", "leaked", "dump", "breach", "breaches"],
        "leaks":       ["leak", "leaked", "dump", "breach"],
        "breach":      ["breached", "breaches", "leak", "dump"],
        "stealer":     ["stealer logs", "redline", "raccoon", "lumma", "vidar"],
        "logs":        ["stealer logs", "combo", "combolist"],
        "combo":       ["combolist", "combo list", "cracked", "accounts"],
        "carding":     ["cc", "cvv", "carders", "dumps", "fullz"],
        "cc":          ["carding", "cvv", "dumps"],
        "cvv":         ["cc", "carding", "fullz"],
        "iab":         ["initial access broker", "access broker", "rdp access"],
        "rdp":         ["rdp access", "rdp sales", "iab"],
        "exploit":     ["exploits", "0day", "zero day", "cve"],
        "0day":        ["zero day", "exploit", "exploits"],
        "malware":     ["stealer", "rat", "botnet", "loader"],
        "botnet":      ["c2", "c&c", "loader", "malware"],
        "phish":       ["phishing", "scampage", "letter", "smtp"],
        "phishing":    ["phish", "scampage", "letter"],
        "osint":       ["intel", "recon", "investigations"],
        "cti":         ["threat intel", "osint", "intel"],
    }

    # Common suffixes that tend to appear in CTI / leak-channel names.
    # Applied to short queries (1–2 words) to surface named communities
    # like "LockBit News", "Akira Leaks", etc.
    _TOPIC_SUFFIXES = [
        "news", "leaks", "chat", "official", "group",
        "intel", "logs", "shop", "market", "ru", "en"]

    @classmethod
    def expand_query(cls, query, max_variants=8):
        """Generate search-variant strings from a raw query. Idea:
        Telegram's `contacts.SearchRequest` is a prefix+substring match on
        name + username, so a single query misses channels whose names use
        a synonym, a common suffix, or a spacing variant. Expanding the
        query surfaces channels the operator would otherwise never see.

        Returns an ordered list; the original query is always first so
        rank-tie-break favors the exact intent. De-duped, lowercased,
        short-circuit at `max_variants` to stay inside the rate-limit
        budget."""
        q = (query or "").strip()
        if not q: return []
        tokens = q.lower().split()
        variants = [q.lower()]

        def _add(v):
            vn = v.strip().lower()
            if vn and vn not in variants and len(vn) >= 3:
                variants.append(vn)

        # Spacing variants — "ransom ware" vs "ransomware" both show up.
        if " " in q:
            _add(q.replace(" ", ""))
            _add(q.replace(" ", "_"))
        elif "_" in q:
            _add(q.replace("_", " "))

        # Handle stripping — "@lockbit" and "lockbit" return different hits.
        if q.startswith("@"):
            _add(q[1:])

        # Synonym expansion — per token.
        for tok in tokens:
            for syn in cls._SYNONYMS.get(tok, []):
                _add(syn)

        # Topic-suffix expansion — only for short (1–2 word) queries.
        if len(tokens) <= 2:
            for suf in cls._TOPIC_SUFFIXES:
                _add(f"{q} {suf}")

        return variants[:max_variants]

    def smart_discover(self, query, limit=30, max_variants=6,
                       tracked_channels=None, mine_forwards=True,
                       per_variant_limit=20):
        """Clever global-channel search. Runs multiple strategies and
        aggregates + ranks the results:

          1. **Query expansion** — synonyms + spacing + topic suffixes.
             One SearchRequest per variant (budget-gated).
          2. **Forwards-from-tracked** — for each channel we already
             monitor, scan recent messages for forward-from-channel
             references + @mentions matching the query. Channels
             forwarded-from by channels we trust get a discovery boost.
          3. **Aggregation** — dedupe by channel_id. Channels matching
             multiple variants get a multi-hit boost. Forward signals
             add a trust boost.
          4. **Ranking** — popularity (subscribers) × trust × variant
             breadth × verified × scam-penalty.

        Args:
          query            — free-text search
          limit            — max channels returned
          max_variants     — cap on expanded query variants
          tracked_channels — list of {channel_id, username} dicts; the
                             caller (web.py) pulls these from the DB
          mine_forwards    — if True, scan tracked channels for matches
          per_variant_limit — SearchRequest limit per variant

        Returns:
          {channels: [...enriched with score, variant_hits, signals],
           users:    [...],
           variants: [...list of expanded queries actually used]}
        """
        q = (query or "").strip().lstrip("@")
        if not q or len(q) < 3:
            return {"error": "query must be at least 3 characters"}

        variants = self.expand_query(q, max_variants=max_variants)
        agg_channels = {}  # id → enriched record
        agg_users = {}

        def _merge_channel(row, source_variant, signal):
            cid = row.get("id")
            if not cid: return
            rec = agg_channels.get(cid)
            if rec is None:
                rec = dict(row)
                rec["variant_hits"] = set()
                rec["signals"]      = set()
                agg_channels[cid] = rec
            if source_variant:
                rec["variant_hits"].add(source_variant)
            if signal:
                rec["signals"].add(signal)

        # ── Strategy 1: query-variant SearchRequests ──────────────────
        for v in variants:
            # Budget is managed by caller via set_mode(); each variant
            # costs one MTProto call. Bail cleanly when exhausted.
            if hasattr(self, "_budget") and self._budget > 0:
                if not self._spend(1):
                    log.info(f"[smart_discover] budget exhausted after variants={list(agg_channels)[:3]}...")
                    break
            r = self.search_directory(v, limit=per_variant_limit)
            if r.get("error"):
                log.debug(f"[smart_discover] variant '{v}' error: {r['error']}")
                continue
            for row in r.get("channels", []):
                _merge_channel(row, v, "directory")
            for u in r.get("users", []):
                uid = u.get("id")
                if uid and uid not in agg_users:
                    agg_users[uid] = u

        # ── Strategy 2: forwards / mentions from tracked channels ─────
        if mine_forwards and tracked_channels:
            ql = q.lower()
            # Sort tracked channels by pressure ASC so we prefer cooler
            # channels first — spreads load across the fleet instead of
            # hammering whichever N happen to be at the top of the list.
            sorted_tracked = sorted(
                tracked_channels,
                key=lambda tc: self.channel_pressure(tc.get("channel_id")))
            for tc in sorted_tracked[:10]:          # cap to stay cheap
                tc_id = tc.get("channel_id")
                tc_user = tc.get("username") or ""
                if not tc_id: continue
                if self.channel_pressure(tc_id) >= self.pressure_skip_threshold:
                    log.info(f"[smart_discover] skipping hot channel "
                             f"@{tc_user} (pressure={self.channel_pressure(tc_id)})")
                    continue
                if hasattr(self, "_budget") and self._budget > 0:
                    if not self._spend(1):
                        break
                hits = self.search_in_channel(tc_id, q, limit=25,
                                               username=tc_user)
                for h in hits:
                    text = h.get("text") or ""
                    if ql not in text.lower():
                        # search_in_channel returns the Telegram API's best
                        # match; not always substring — require it for the
                        # mention-mining loop to reduce FP.
                        continue
                    for handle in self.extract_channel_mentions(text):
                        if handle == tc_user.lower(): continue
                        # Cheap resolve — use cache heavily.
                        if hasattr(self, "_budget") and self._budget > 0:
                            if not self._spend(1): break
                        info = self.cached_resolve(handle)
                        if info.get("error"): continue
                        row = {
                            "id":          info.get("channel_id"),
                            "title":       info.get("title", ""),
                            "username":    info.get("username"),
                            "subscribers": info.get("subscribers"),
                            "kind":        info.get("kind", "channel"),
                            "verified":    bool(info.get("verified", False)),
                            "scam":        bool(info.get("scam", False)),
                            "fake":        bool(info.get("fake", False)),
                            "restricted":  bool(info.get("restricted", False)),
                        }
                        _merge_channel(row, q.lower(), f"forward_from:@{tc_user}")

        # ── Ranking ───────────────────────────────────────────────────
        import math
        def _score(rec):
            subs = rec.get("subscribers") or 0
            popularity = math.log10(subs + 10) * 100
            vh = len(rec["variant_hits"])
            multi_variant_boost = 1.0 + 0.4 * max(0, vh - 1)
            forward_signal = any(
                s.startswith("forward_from:") for s in rec["signals"])
            forward_boost = 1.35 if forward_signal else 1.0
            verified_boost = 1.5 if rec.get("verified") else 1.0
            scam_penalty = 0.15 if (rec.get("scam") or rec.get("fake")) else 1.0
            return (popularity * multi_variant_boost * forward_boost
                    * verified_boost * scam_penalty)

        for rec in agg_channels.values():
            rec["score"] = round(_score(rec), 1)
            rec["variant_hits"] = sorted(rec["variant_hits"])
            rec["signals"]      = sorted(rec["signals"])

        # Telegram-flagged scam/fake channels always rank below every
        # unflagged one: subscriber counts are cheap to inflate, so the
        # score penalty alone could leave a big fake near the top.
        channels = sorted(agg_channels.values(),
                          key=lambda r: (bool(r.get("scam") or r.get("fake")),
                                         -r["score"]))[:limit]
        users = list(agg_users.values())[:limit]

        return {
            "channels": channels,
            "users":    users,
            "variants": variants,
            "budget_remaining": self._budget if hasattr(self, "_budget") else None,
        }


# Backward-compat alias. The engine was renamed DarkMTProto when its scope
# grew beyond "scraper"; existing imports (web.py, external scripts) keep
# working without change. New code should use DarkMTProto directly.
TelegramScraper = DarkMTProto


# ─── Real-time live listener ─────────────────────────────────────────────────

class TelegramLiveListener:
    """Runs a persistent Telethon client in a daemon thread, subscribing
    to new-message events on a configurable set of tracked channels.
    Each incoming message is converted into the same dict shape as
    DarkMTProto.fetch_new_messages so the caller's message-handling
    pipeline works unchanged.

    Enable via config.telegram.live_enabled. Off by default — it keeps a
    long-lived MTProto session running, which is a different fingerprint
    than the poll-and-disconnect pattern we use elsewhere. Operators who
    want instant alerts on new posts turn it on; operators optimizing for
    lowest-possible footprint leave it off.

    Thread-safety: the listener callback runs in the listener's asyncio
    loop. The caller's callback MUST be quick and thread-safe (ideally
    it enqueues and returns; the heavy scan work happens elsewhere)."""

    def __init__(self, scraper: 'DarkMTProto', on_message,
                 channel_ids=None):
        """
        Args:
            scraper       — shared TelegramScraper (for client construction)
            on_message(channel_id, username, msg_dict) — sync callback
                           invoked for each new message on a tracked channel
            channel_ids   — iterable of numeric channel ids to watch; can
                           be updated live via set_channels()
        """
        self.scraper = scraper
        self.on_message = on_message
        self._channel_ids = set(channel_ids or [])
        self._thread = None
        self._loop = None
        self._client = None
        self._stop = threading.Event()

    def set_channels(self, channel_ids):
        """Update the watched-channel set. Safe to call from any thread;
        the filter is consulted per-event so changes take effect
        immediately without reconnecting."""
        self._channel_ids = set(channel_ids or [])

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="TgLiveListener", daemon=True)
        self._thread.start()
        log.info(f"[tg-live] listener starting (watching {len(self._channel_ids)} channels)")

    def stop(self, timeout=5):
        self._stop.set()
        if self._loop:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception: pass
        if self._thread:
            self._thread.join(timeout=timeout)

    def _run(self):
        import asyncio
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._main())
        except Exception as e:
            log.error(f"[tg-live] listener crashed: {e}")
        finally:
            try: self._loop.close()
            except Exception: pass
            self._loop = None

    async def _main(self):
        from telethon import events
        while not self._stop.is_set():
            try:
                self._client = self.scraper._build_client()
                await self._client.connect()
                if not await self._client.is_user_authorized():
                    log.warning("[tg-live] not authenticated — sleeping 60s")
                    await self._sleep(60)
                    continue

                @self._client.on(events.NewMessage)
                async def _handler(event):
                    await self._on_event(event)

                log.info("[tg-live] listener connected + subscribed")
                # run_until_disconnected blocks forever. We exit when the
                # stop event fires or the connection drops.
                disconnect_task = asyncio.ensure_future(
                    self._client.run_until_disconnected())
                while not self._stop.is_set():
                    if disconnect_task.done():
                        break
                    await asyncio.sleep(1.0)
                if not disconnect_task.done():
                    await self._client.disconnect()
            except Exception as e:
                log.error(f"[tg-live] connect loop error: {e}")
                await self._sleep(30)
            finally:
                try:
                    if self._client: await self._client.disconnect()
                except Exception: pass
                self._client = None

    async def _on_event(self, event):
        """NewMessage handler: filter to the watched channels, convert the
        message to the fetch_new_messages dict and hand it to on_message.
        Keeps media-only posts (no caption), like the polling path."""
        try:
            # event.chat_id is the "marked" id (-100<id> for channels);
            # abs() of that is 100<id>, which never matched the raw ids we
            # store. resolve_id() strips the marker and returns the raw
            # positive id.
            cid = event.chat_id
            cid_norm = (tg_resolve_id(int(cid))[0]
                        if cid is not None else None)
            if cid_norm and cid_norm not in {abs(int(c))
                                             for c in self._channel_ids}:
                return
            msg = event.message
            text = msg.message or ""
            has_media = bool(getattr(msg, "media", None))
            # Skip only messages with neither text nor media (service
            # messages); an uncaptioned photo is a post like any other.
            if not text and not has_media:
                return
            sender = await event.get_sender()
            fwd_user, fwd_msg = DarkMTProto._fwd_info(msg)
            reply_to = getattr(msg.reply_to, "reply_to_msg_id", None) \
                       if getattr(msg, "reply_to", None) else None
            msg_dict = {
                "msg_id": msg.id,
                "date_iso": msg.date.isoformat() if msg.date else None,
                "sender_id": getattr(sender, "id", None) if sender else None,
                "sender_username": getattr(sender, "username", None) if sender else None,
                "sender_name": (getattr(sender, "first_name", None)
                                or getattr(sender, "title", None)
                                if sender else None),
                "text": text,
                "views": getattr(msg, "views", None),
                "forwards": getattr(msg, "forwards", None),
                "reactions_total": DarkMTProto._reactions_total(msg),
                "reactions_detail": DarkMTProto._reactions_detail(msg),
                "has_media": has_media,
                "media_type": DarkMTProto._media_type(msg),
                "fwd_from_username": fwd_user,
                "fwd_from_msg_id": fwd_msg,
                "reply_to_msg_id": reply_to,
            }
            username = (getattr(event.chat, "username", None)
                        if event.chat else None)
            # Dispatch synchronously into caller-land. Caller is
            # responsible for thread safety + not blocking here for long
            # (use a queue if heavy work).
            self.on_message(cid_norm, username, msg_dict)
        except Exception as e:
            log.warning(f"[tg-live] handler error: {e}")

    async def _sleep(self, s):
        """Interruptable sleep — wakes on stop event."""
        import asyncio
        for _ in range(int(s)):
            if self._stop.is_set(): return
            await asyncio.sleep(1)
