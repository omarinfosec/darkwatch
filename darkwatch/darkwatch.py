#!/usr/bin/env python3
"""
DarkWatch — Dark Web OSINT Crawler & Keyword Monitor
Custom-built for CTI teams to monitor .onion sites for organizational mentions.
Hardened edition with anti-detection and security controls.
"""

__version__ = "0.1.0"

import os
import sys
import json
import time
import sqlite3
import hashlib
import logging
import argparse
import re
import yara
import threading
import random
from queue import Queue
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

import requests
from bs4 import BeautifulSoup

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

# ─── Configuration ───────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "proxy": {
        "host": "127.0.0.1",
        "port": 9050,
        "type": "socks5h"
    },
    "crawler": {
        "max_depth": 2,
        "max_threads": 5,
        "timeout": 60,
        "retries": 3,
        "retry_delay": 10,
        "max_pages_per_site": 100,
        "rescan_days": 7,
        "scan_pdfs": False,
        "screenshot_mode": "tor_render",
        "newnym_between_sites": True,
        "domain_fail_breaker": 3,
        "tor_control_host": "tor",
        "tor_control_port": 9051,
        "tor_control_password": "",
        # Auto-rescan cadence (hours). 0 = disabled. When >0, the
        # monitor scheduler fires rescan_pages(all) when that interval
        # has elapsed since the last rescan — backfills new findings
        # when the operator adds keywords or refreshes threat intel.
        "auto_rescan_hours": 0,
        # Max depth of the screenshot worker queue. Full → new captures
        # are dropped (counted in darkwatch_screenshot_dropped_total).
        "screenshot_queue": 64,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0"
        ]
    },
    "stealth": {
        "min_delay": 2,
        "max_delay": 8,
        "randomize_header_order": True,
        "referer_spoof": True,
        "accept_language_variants": [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.5",
            "en;q=0.8,en-US;q=0.6",
            "en-US,en;q=0.9,fr;q=0.3"
        ]
    },
    "security": {
        "max_response_size_mb": 10,
        "allowed_content_types": [
            "text/html",
            "application/xhtml+xml",
            "text/plain"
        ],
        "strip_scripts": True,
        "strip_iframes": True,
        "strip_objects": True,
        "strip_tracking": True,
        "block_binary_downloads": True,
        "sanitize_saved_html": True
    },
    "yara": {
        "keywords_file": "yara/keywords.yar",
        "categories_file": "yara/categories.yar"
    },
    "alerts": {
        "telegram_enabled": False,
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "slack_enabled": False,
        "slack_webhook_url": "",
        "discord_enabled": False,
        "discord_webhook_url": "",
        "generic_webhook_enabled": False,
        "generic_webhook_url": "",
        "min_alert_score": 80
    },
    "database": {
        "path": "data/darkwatch.db"
    },
    "telegram": {
        "api_id": "",
        "api_hash": "",
        "session_path": "data/telegram.session",
        "proxy_host": "tunnel2",
        "proxy_port": 1080,
        "proxy_type": "socks5",
        "use_tor": False,
        "scrape_limit_per_tick": 100,
        "scrape_delay_s": 3,
        # Rate-limit knobs (Safe mode defaults). Thorough-mode overrides
        # live alongside and are picked up when route_tg_search_deep is
        # called with ?mode=thorough.
        "rate_per_s": 0.5,
        "burst": 3,
        "jitter": 0.40,
        "max_deep_budget": 25,
        "entity_ttl_s": 600,
        "thorough_rate_per_s": 1.0,
        "thorough_burst": 5,
        "thorough_jitter": 0.25,
        "thorough_max_deep_budget": 60
    },
    "output": {
        "loot_dir": "/loot",
        "save_pages": True,
        "save_screenshots": True,
        # Selective screenshot threshold: only pages with findings at or
        # above this severity get rendered. "low" = always (legacy);
        # "medium"/"high"/"critical" = progressively more selective.
        "screenshot_min_severity": "low",
        "reports_dir": "/loot/reports",
        "thumbnails_dir": "/loot/thumbnails"
    },
    "threat_intel": {
        # When empty, threat_intel.DEFAULT_FEEDS is used (URLhaus .onion
        # filter + Feodo C2). Override here to add org-specific feeds or
        # disable defaults. `timeout` is per-feed HTTP timeout in seconds.
        "feeds": None,
        "timeout": 30
    }
}


class _JSONLogFormatter(logging.Formatter):
    """Optional JSON log formatter. Toggled via env LOG_FORMAT=json.
    Each record emits a one-line JSON dict, which is what ELK / Loki /
    CloudWatch Insights expect. Free-form message remains the `msg`
    field so existing log lines don't need touching."""
    def format(self, record):
        d = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
             "level": record.levelname,
             "logger": record.name,
             "msg": record.getMessage()}
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, default=str)


def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    use_json = (os.environ.get("LOG_FORMAT", "").lower() == "json")
    if use_json:
        handler = logging.StreamHandler()
        handler.setFormatter(_JSONLogFormatter())
        logging.basicConfig(level=level, handlers=[handler], force=True)
    else:
        fmt = "%(asctime)s %(levelname)-5s %(name)-12s %(message)s"
        logging.basicConfig(level=level, format=fmt,
                            datefmt="%Y-%m-%d %H:%M:%S")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


log = logging.getLogger("darkwatch")


# ─── Database ────────────────────────────────────────────────────────────────

class Database:
    def __init__(self, db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        # Enforce FK constraints so declared REFERENCES actually prevent
        # orphan rows. Must be set per-connection in SQLite.
        self.conn.execute("PRAGMA foreign_keys = ON")
        # WAL lets the web's read queries run alongside the crawler's
        # writes without blocking each other — noticeably snappier UI
        # during active scans.
        try:
            self.conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.OperationalError:
            pass
        self.lock = threading.Lock()
        self._init_tables()

    def _init_tables(self):
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    source TEXT DEFAULT 'manual',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scan TIMESTAMP,
                    status INTEGER DEFAULT 0,
                    scan_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS pages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url_id INTEGER,
                    page_url TEXT NOT NULL,
                    title TEXT,
                    content_hash TEXT,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (url_id) REFERENCES urls(id)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url_id INTEGER,
                    page_url TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    rule_type TEXT DEFAULT 'keyword',
                    score INTEGER DEFAULT 0,
                    matched_strings TEXT,
                    snippet TEXT,
                    severity TEXT DEFAULT 'medium',
                    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged INTEGER DEFAULT 0,
                    FOREIGN KEY (url_id) REFERENCES urls(id)
                );
                CREATE TABLE IF NOT EXISTS scan_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    urls_scanned INTEGER DEFAULT 0,
                    pages_scanned INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    errors INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url_id INTEGER,
                    page_url TEXT NOT NULL,
                    action TEXT,
                    method TEXT,
                    inputs_json TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (url_id) REFERENCES urls(id)
                );
                CREATE TABLE IF NOT EXISTS user_keywords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    keyword TEXT UNIQUE NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    category TEXT DEFAULT 'user',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                -- One row per Telegram message. Holds rich metadata that
                -- doesn't fit the generic `pages` table: sender, reactions,
                -- media presence, forward-from, reply-to. `pages` still
                -- stores the raw message text (for dedup + YARA).
                CREATE TABLE IF NOT EXISTS tg_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    page_id INTEGER NOT NULL,
                    url_id INTEGER NOT NULL,
                    msg_id INTEGER NOT NULL,
                    date_iso TEXT,
                    sender_id INTEGER,
                    sender_username TEXT,
                    sender_name TEXT,
                    text TEXT,                -- raw message body (UI display)
                    views INTEGER,
                    forwards INTEGER,
                    reactions_total INTEGER,
                    has_media INTEGER DEFAULT 0,
                    media_type TEXT,
                    fwd_from_username TEXT,
                    fwd_from_msg_id INTEGER,
                    reply_to_msg_id INTEGER,
                    FOREIGN KEY (page_id) REFERENCES pages(id),
                    FOREIGN KEY (url_id) REFERENCES urls(id)
                );
                CREATE INDEX IF NOT EXISTS idx_tg_messages_url
                    ON tg_messages(url_id, msg_id DESC);
                CREATE TABLE IF NOT EXISTS monitor_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url_id INTEGER NOT NULL,
                    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status INTEGER DEFAULT 0,
                    pages INTEGER DEFAULT 0,
                    findings INTEGER DEFAULT 0,
                    page_id INTEGER,            -- latest page row for this check (FK to pages)
                    note TEXT,
                    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE,
                    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_monitor_events_url
                    ON monitor_events(url_id, checked_at DESC);
            """)
        # Migrations on urls table: add monitoring + Telegram columns idempotently.
        for col, coltype in [
            ("monitored", "INTEGER DEFAULT 0"),
            ("monitor_interval_min", "INTEGER DEFAULT 60"),
            ("next_check_at", "TIMESTAMP"),
            # Telegram-source extensions — only populated when source='telegram'.
            ("tg_channel_id", "INTEGER"),     # numeric Telegram channel id
            ("tg_last_msg_id", "INTEGER"),    # highest msg id already scraped
            ("tg_subscribers", "INTEGER"),    # cached for UI
            ("tg_username", "TEXT"),          # canonical @handle
            ("tg_about", "TEXT"),             # channel description
            ("tg_verified", "INTEGER DEFAULT 0"),  # telegram-verified
            ("tg_scam", "INTEGER DEFAULT 0"),      # telegram-flagged scam
            ("tg_kind", "TEXT"),              # 'channel' | 'group' | 'megagroup'
            # Enriched channel metadata (populated by get_channel_details).
            ("tg_created", "TEXT"),           # ISO-date channel was created
            ("tg_admins_count", "INTEGER"),   # admin headcount
            ("tg_online_count", "INTEGER"),   # currently-online members
            ("tg_linked_chat_id", "INTEGER"), # discussion-group link
            ("tg_migrated_from", "INTEGER"),  # legacy-group id if migrated
            ("tg_slowmode_seconds", "INTEGER"),
            ("tg_pinned_msg_id", "INTEGER"),
            ("tg_participants_hidden", "INTEGER DEFAULT 0"),
            ("tg_antispam", "INTEGER DEFAULT 0"),
            ("tg_ttl_period", "INTEGER"),     # auto-delete ttl, seconds
            ("tg_restricted_reason", "TEXT"), # why Telegram restricts it
            # Creator / owner info — only populated if we can enumerate
            # admins (public channels where participants aren't hidden).
            ("tg_creator_id", "INTEGER"),
            ("tg_creator_username", "TEXT"),
            ("tg_creator_name", "TEXT"),
            ("tg_creator_phone", "TEXT"),
            ("tg_creator_bot", "INTEGER DEFAULT 0"),
            ("tg_creator_premium", "INTEGER DEFAULT 0"),
            ("tg_details_fetched_at", "TIMESTAMP"),
            # Public / private marker. Public = has a @username handle
            # anyone can resolve. Private = joined via invite link; can
            # only be accessed by members. Populated at resolve time.
            ("tg_is_private", "INTEGER DEFAULT 0"),
            # Membership: 1 = operator's account has joined, 0 = not
            # joined, NULL = unknown. Needed because some channels
            # require membership for iter_messages to return anything
            # at all.
            ("tg_is_member", "INTEGER"),
            # Path under /loot/tg-media/channels/ to the downloaded
            # profile photo (channel avatar). Served via
            # /loot/tg-media/<relpath>. Null when no photo or download
            # skipped.
            ("tg_photo_path", "TEXT"),
            # Channel's display TITLE (e.g. "BreachForums Announcements")
            # — distinct from @handle. Previously we only kept a
            # derived title from pages, which was always the synthesized
            # message title. Now authoritative from Telegram.
            ("tg_title", "TEXT"),
        ]:
            try:
                self.conn.execute(f"ALTER TABLE urls ADD COLUMN {col} {coltype}")
            except sqlite3.OperationalError:
                pass
        # Migrations: add columns for data extraction and screenshots.
        # `text_snapshot` stores the stripped page text so rescan_pages()
        # can re-run YARA without re-fetching the target. `primary_severity`
        # caches the max severity seen on the page so selective screenshots
        # and UI filters don't have to join findings.
        for col, coltype in [("extracted_data", "TEXT"),
                              ("screenshot_path", "TEXT"),
                              ("thumbnail_path", "TEXT"),
                              ("page_type", "TEXT DEFAULT 'other'"),
                              ("text_snapshot", "TEXT"),
                              ("primary_severity", "TEXT"),
                              ("max_score", "INTEGER DEFAULT 0")]:
            try:
                self.conn.execute(f"ALTER TABLE pages ADD COLUMN {col} {coltype}")
            except sqlite3.OperationalError:
                pass
        # findings enrichments: dedup key, occurrence count, last-seen
        # timestamp, and a false-positive score [0..100] (higher = more
        # likely noise). ioc_hash is a sha256 of normalized matched_strings.
        for col, coltype in [
                ("ioc_hash", "TEXT"),
                ("occurrence_count", "INTEGER DEFAULT 1"),
                ("last_seen_at", "TIMESTAMP"),
                ("fp_score", "INTEGER DEFAULT 0")]:
            try:
                self.conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {coltype}")
            except sqlite3.OperationalError:
                pass
        # Unique index enables INSERT OR IGNORE dedup semantics — a rerun
        # of the same rule on the same page with the same IOCs no longer
        # stores a duplicate row; add_finding() bumps occurrence_count
        # instead. `COALESCE(ioc_hash,'')` keeps rows predating the
        # migration uniqued on rule_name alone.
        try:
            self.conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup "
                "ON findings(url_id, page_url, rule_name, "
                "             COALESCE(ioc_hash, ''))")
        except sqlite3.OperationalError as e:
            log.debug(f"findings dedup index skipped: {e}")
        # urls: track last fetch-error category for adaptive backoff.
        for col, coltype in [
                ("last_error_category", "TEXT"),
                ("last_error_at", "TIMESTAMP"),
                ("consecutive_errors", "INTEGER DEFAULT 0")]:
            try:
                self.conn.execute(f"ALTER TABLE urls ADD COLUMN {col} {coltype}")
            except sqlite3.OperationalError:
                pass
        # ops table: lightweight key-value for scheduler bookkeeping
        # (e.g. last global rescan timestamp). Avoids adding a whole
        # settings table for one-off ops.
        try:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS ops_state ("
                "  key TEXT PRIMARY KEY, value TEXT, "
                "  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        except sqlite3.OperationalError:
            pass
        # Migrations on tg_messages: richer metadata added after v2.3 ship.
        for col, coltype in [
            # JSON string: [{emoji, count}, ...] — per-emoji breakdown.
            ("reactions_detail", "TEXT"),
            # Topic thread id (forum channels). Null for non-forum channels.
            ("topic_id", "INTEGER"),
            # Topic title (forum channels). Null for non-forum.
            ("topic_title", "TEXT"),
            # Relative path under /loot/tg-media if media was downloaded.
            ("media_path", "TEXT"),
            # Bytes downloaded; null if not downloaded / skipped.
            ("media_bytes", "INTEGER"),
        ]:
            try:
                self.conn.execute(f"ALTER TABLE tg_messages ADD COLUMN {col} {coltype}")
            except sqlite3.OperationalError:
                pass

        # One-time data migration: canonical TG URLs switched from
        # the opaque `tg://<handle>[/<msg_id>]` scheme to `https://t.me/...`.
        # Benefits: clickable in any browser, Playwright-screenshottable,
        # shareable links in findings. Idempotent — only affects rows
        # that still carry the old prefix.
        with self.conn:
            self.conn.execute(
                "UPDATE urls SET url = 'https://t.me/' || substr(url, 6) "
                "WHERE url LIKE 'tg://%' AND source = 'telegram'")
            self.conn.execute(
                "UPDATE pages SET page_url = 'https://t.me/' || substr(page_url, 6) "
                "WHERE page_url LIKE 'tg://%'")
            self.conn.execute(
                "UPDATE findings SET page_url = 'https://t.me/' || substr(page_url, 6) "
                "WHERE page_url LIKE 'tg://%'")

    def add_url(self, url, source="manual"):
        with self.lock:
            try:
                self.conn.execute("INSERT OR IGNORE INTO urls (url, source) VALUES (?, ?)", (url, source))
                self.conn.commit()
            except sqlite3.Error as e:
                log.error(f"DB error adding URL: {e}")

    def get_urls_to_scan(self, rescan_days=7):
        cutoff = (datetime.now() - timedelta(days=rescan_days)).isoformat()
        with self.lock:
            cur = self.conn.execute("SELECT id, url FROM urls WHERE last_scan IS NULL OR last_scan < ? ORDER BY last_scan ASC NULLS FIRST", (cutoff,))
            return cur.fetchall()

    def update_scan(self, url_id, status):
        with self.lock:
            self.conn.execute("UPDATE urls SET last_scan = ?, status = ?, scan_count = scan_count + 1 WHERE id = ?", (datetime.now().isoformat(), status, url_id))
            self.conn.commit()

    def increment_fail(self, url_id):
        with self.lock:
            self.conn.execute("UPDATE urls SET fail_count = fail_count + 1 WHERE id = ?", (url_id,))
            self.conn.commit()

    def add_page(self, url_id, page_url, title, content_hash,
                 extracted_data=None, screenshot_path=None,
                 thumbnail_path=None, page_type="other",
                 text_snapshot=None):
        """Insert a page row. `text_snapshot` (stripped plain text) lets
        `rescan_pages()` re-run YARA rules offline without re-fetching the
        target — critical when the operator adds new keywords after a
        crawl and wants to backfill findings on historical pages."""
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO pages (url_id, page_url, title, content_hash, "
                "extracted_data, screenshot_path, thumbnail_path, page_type, "
                "text_snapshot) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (url_id, page_url, title, content_hash,
                 json.dumps(extracted_data) if extracted_data else None,
                 screenshot_path, thumbnail_path, page_type,
                 (text_snapshot or "")[:200_000] if text_snapshot else None)
            )
            self.conn.commit()
            return cur.lastrowid

    def update_page_screenshot(self, page_id, screenshot_path, thumbnail_path):
        """Patch a page row after deferred screenshot capture. Used by the
        screenshot worker thread so scan_page() doesn't block on Playwright."""
        with self.lock:
            self.conn.execute(
                "UPDATE pages SET screenshot_path = ?, thumbnail_path = ? "
                "WHERE id = ?", (screenshot_path, thumbnail_path, page_id))
            self.conn.commit()

    def update_page_severity(self, page_id, severity, max_score):
        """Cache the most serious finding on a page so filters/thumbnails
        don't need a join."""
        with self.lock:
            self.conn.execute(
                "UPDATE pages SET primary_severity = ?, max_score = ? "
                "WHERE id = ?", (severity, int(max_score or 0), page_id))
            self.conn.commit()

    def iter_pages_with_text(self, url_id=None):
        """Yield rows suitable for rescan: (page_id, url_id, page_url,
        text_snapshot). Skips rows without a stored snapshot."""
        with self.lock:
            if url_id is not None:
                cur = self.conn.execute(
                    "SELECT id, url_id, page_url, text_snapshot "
                    "FROM pages WHERE url_id = ? AND text_snapshot IS NOT NULL "
                    "  AND text_snapshot != ''", (url_id,))
            else:
                cur = self.conn.execute(
                    "SELECT id, url_id, page_url, text_snapshot "
                    "FROM pages WHERE text_snapshot IS NOT NULL "
                    "  AND text_snapshot != ''")
            return cur.fetchall()

    def purge_findings_for_page(self, url_id, page_url):
        """Drop findings on a given page ahead of a rescan, so that fresh
        rule output replaces — not accumulates on top of — stale hits.
        Returns the number of rows removed."""
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM findings WHERE url_id = ? AND page_url = ?",
                (url_id, page_url))
            self.conn.commit()
            return cur.rowcount

    def record_url_error(self, url_id, category):
        """Tag a URL with its most recent error category for adaptive
        backoff. `category` is one of: timeout, connect, http_4xx, http_5xx,
        redirect, tor_down, unknown."""
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET last_error_category = ?, "
                "  last_error_at = CURRENT_TIMESTAMP, "
                "  consecutive_errors = consecutive_errors + 1 "
                "WHERE id = ?", (category, url_id))
            self.conn.commit()

    def clear_url_errors(self, url_id):
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET consecutive_errors = 0, "
                "  last_error_category = NULL WHERE id = ?", (url_id,))
            self.conn.commit()

    def error_category_counts(self):
        with self.lock:
            cur = self.conn.execute(
                "SELECT COALESCE(last_error_category, 'none') AS cat, "
                "       COUNT(*) AS n FROM urls "
                "GROUP BY cat")
            return {row[0]: row[1] for row in cur.fetchall()}

    def ops_get(self, key, default=None):
        with self.lock:
            row = self.conn.execute(
                "SELECT value FROM ops_state WHERE key = ?", (key,)).fetchone()
            return row[0] if row else default

    def ops_set(self, key, value):
        with self.lock:
            self.conn.execute(
                "INSERT INTO ops_state (key, value, updated_at) "
                "VALUES (?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(key) DO UPDATE SET "
                "  value = excluded.value, updated_at = CURRENT_TIMESTAMP",
                (key, value))
            self.conn.commit()

    def add_form(self, url_id, page_url, action, method, inputs):
        with self.lock:
            try:
                self.conn.execute(
                    "INSERT INTO forms (url_id, page_url, action, method, inputs_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (url_id, page_url, action, method, json.dumps(inputs))
                )
                self.conn.commit()
            except sqlite3.Error as e:
                log.debug(f"DB error adding form: {e}")

    def get_url_rows(self, limit=500, source=None, offset=0):
        """Return tracked urls ordered by last_scan desc. `offset` + `limit`
        paginate when there are too many rows to render at once. If
        `source` is given, only that source."""
        with self.lock:
            where = ""
            params = []
            if source:
                where = "WHERE u.source = ? "
                params.append(source)
            params.extend([limit, max(0, int(offset or 0))])
            cur = self.conn.execute(
                "SELECT u.id, u.url, u.status, u.scan_count, u.fail_count, "
                "  u.last_scan, u.source, "
                "  u.monitored, u.monitor_interval_min, u.next_check_at, "
                "  u.tg_channel_id, u.tg_last_msg_id, "
                "  u.tg_subscribers, u.tg_username, "
                "  u.tg_about, u.tg_verified, u.tg_scam, u.tg_kind, "
                "  u.tg_is_private, u.tg_is_member, u.tg_photo_path, "
                "  u.tg_created, u.tg_creator_username, u.tg_creator_name, "
                "  u.tg_title, "
                "  (SELECT title FROM pages p WHERE p.url_id = u.id "
                "     AND title IS NOT NULL AND title != '' "
                "     ORDER BY scanned_at ASC LIMIT 1) AS title, "
                "  (SELECT id FROM pages p WHERE p.url_id = u.id "
                "     AND thumbnail_path IS NOT NULL "
                "     ORDER BY scanned_at DESC LIMIT 1) AS latest_page_id, "
                "  (SELECT page_type FROM pages p WHERE p.url_id = u.id "
                "     AND page_type IS NOT NULL AND page_type != 'other' "
                "     ORDER BY scanned_at DESC LIMIT 1) AS page_type, "
                # Latest-message timestamp for activity scoring. Uses the
                # real message date (msg.date_iso), not scrape time — so
                # "active" means "the channel is posting", not "we polled
                # it recently".
                "  (SELECT MAX(m.date_iso) FROM tg_messages m "
                "     WHERE m.url_id = u.id) AS tg_last_msg_date, "
                "  (SELECT COUNT(*) FROM tg_messages m "
                "     WHERE m.url_id = u.id) AS tg_msg_count "
                "FROM urls u " + where +
                "ORDER BY u.last_scan DESC NULLS LAST LIMIT ? OFFSET ?",
                params
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count_url_rows(self, source=None):
        """Total row count matching the optional source filter. Used by
        the UI to render 'N of TOTAL' captions next to paginated tables."""
        with self.lock:
            if source:
                cur = self.conn.execute(
                    "SELECT COUNT(*) FROM urls WHERE source = ?", (source,))
            else:
                cur = self.conn.execute("SELECT COUNT(*) FROM urls")
            return int(cur.fetchone()[0])

    def get_page_screenshot(self, page_id):
        with self.lock:
            cur = self.conn.execute(
                "SELECT screenshot_path, thumbnail_path, page_url "
                "FROM pages WHERE id = ?",
                (page_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {"screenshot_path": row[0], "thumbnail_path": row[1], "page_url": row[2]}

    def add_finding(self, url_id, page_url, rule_name, rule_type, score,
                     matched_strings, snippet, severity,
                     ioc_hash=None, fp_score=0):
        """Insert a finding or bump occurrence_count if a row with the same
        (url_id, page_url, rule_name, ioc_hash) already exists. Dedup keeps
        the UI readable when the same IOC keeps surfacing across rescans
        of the same page. Returns True if this was a fresh row."""
        now = datetime.now().isoformat()
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO findings "
                "(url_id, page_url, rule_name, rule_type, score, "
                " matched_strings, snippet, severity, ioc_hash, "
                " occurrence_count, last_seen_at, fp_score) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (url_id, page_url, rule_name, rule_type, score,
                 matched_strings, snippet, severity,
                 ioc_hash or "", now, int(fp_score or 0)))
            fresh = cur.rowcount > 0
            if not fresh:
                # Same IOC on same page hit again — bump counter, refresh
                # last-seen, and take the higher score (rule metadata can
                # change between scans).
                self.conn.execute(
                    "UPDATE findings SET occurrence_count = occurrence_count + 1, "
                    "  last_seen_at = ?, score = MAX(score, ?), "
                    "  fp_score = ? "
                    "WHERE url_id = ? AND page_url = ? AND rule_name = ? "
                    "  AND COALESCE(ioc_hash,'') = ?",
                    (now, int(score or 0), int(fp_score or 0),
                     url_id, page_url, rule_name, ioc_hash or ""))
            self.conn.commit()
            return fresh

    def delete_finding(self, finding_id):
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM findings WHERE id = ?", (finding_id,))
            self.conn.commit()
            return cur.rowcount

    def delete_findings(self, severity=None, min_score=None):
        with self.lock:
            clauses, params = [], []
            if severity and severity != "all":
                clauses.append("severity = ?")
                params.append(severity)
            if min_score is not None:
                clauses.append("score >= ?")
                params.append(min_score)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            cur = self.conn.execute(f"DELETE FROM findings{where}", params)
            self.conn.commit()
            return cur.rowcount

    def page_seen(self, content_hash):
        with self.lock:
            cur = self.conn.execute("SELECT id FROM pages WHERE content_hash = ?", (content_hash,))
            return cur.fetchone() is not None

    def get_findings(self, min_score=0, limit=100, before_id=None,
                      severity=None, max_fp_score=None):
        """Paginated descending by id. `before_id` is a simple cursor —
        pass the last id of the previous page to fetch older rows.
        `max_fp_score` filters out likely false positives — callers can
        pass 40 to hide anything scored >=40 by compute_fp_score()."""
        where = ["f.score >= ?"]
        params = [min_score]
        if before_id is not None:
            where.append("f.id < ?")
            params.append(before_id)
        if severity and severity != "all":
            where.append("f.severity = ?")
            params.append(severity)
        if max_fp_score is not None:
            where.append("COALESCE(f.fp_score, 0) <= ?")
            params.append(int(max_fp_score))
        params.append(limit)
        sql = (
            "SELECT f.*, u.url as base_url, u.source as source, "
            "p.id as page_id, p.title as page_title, "
            "p.screenshot_path, p.thumbnail_path, "
            "p.extracted_data, p.page_type "
            "FROM findings f "
            "JOIN urls u ON f.url_id = u.id "
            "LEFT JOIN pages p ON p.url_id = f.url_id AND p.page_url = f.page_url "
            "WHERE " + " AND ".join(where) + " "
            "GROUP BY f.id "
            "ORDER BY f.id DESC LIMIT ?")
        with self.lock:
            cur = self.conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_stats(self):
        with self.lock:
            stats = {}
            stats["total_urls"] = self.conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
            stats["scanned_urls"] = self.conn.execute("SELECT COUNT(*) FROM urls WHERE last_scan IS NOT NULL").fetchone()[0]
            stats["monitored_urls"] = self.conn.execute("SELECT COUNT(*) FROM urls WHERE monitored = 1").fetchone()[0]
            stats["total_pages"] = self.conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
            stats["total_findings"] = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            stats["critical_findings"] = self.conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'critical'").fetchone()[0]
            return stats

    # ── Telegram-channel helpers ───────────────────────────────────────────
    def upsert_tg_channel(self, username, channel_id, title=None,
                           subscribers=None, about=None, verified=None,
                           scam=None, kind=None, is_private=None):
        """Insert (or update) a urls row for a Telegram channel/group. Keyed
        by url = 'https://t.me/<username>' so re-adds are idempotent and
        the URL is browser-openable (enables screenshots + clickable
        links in findings). All metadata fields use COALESCE so we don't
        overwrite known values with None when we only have partial info.
        Returns the row id."""
        canonical_url = f"https://t.me/{username}"
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO urls (url, source) VALUES (?, 'telegram')",
                (canonical_url,))
            self.conn.execute(
                "UPDATE urls SET source = 'telegram', "
                "  tg_channel_id = ?, tg_username = ?, "
                "  tg_title       = COALESCE(?, tg_title), "
                "  tg_subscribers = COALESCE(?, tg_subscribers), "
                "  tg_about       = COALESCE(?, tg_about), "
                "  tg_verified    = COALESCE(?, tg_verified), "
                "  tg_scam        = COALESCE(?, tg_scam), "
                "  tg_kind        = COALESCE(?, tg_kind), "
                "  tg_is_private  = COALESCE(?, tg_is_private) "
                "WHERE url = ?",
                (channel_id, username, title, subscribers, about,
                 1 if verified else (0 if verified is False else None),
                 1 if scam else (0 if scam is False else None),
                 kind,
                 1 if is_private else (0 if is_private is False else None),
                 canonical_url))
            row = self.conn.execute(
                "SELECT id FROM urls WHERE url = ?", (canonical_url,)
            ).fetchone()
            self.conn.commit()
            return row[0] if row else None

    def update_tg_channel_details(self, url_id, details):
        """Persist enriched channel metadata (creation date, admin count,
        creator identity, etc.) from DarkMTProto.get_channel_details().
        Uses COALESCE semantics — partial results don't nuke existing data."""
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET "
                "  tg_created             = COALESCE(?, tg_created), "
                "  tg_admins_count        = COALESCE(?, tg_admins_count), "
                "  tg_online_count        = COALESCE(?, tg_online_count), "
                "  tg_linked_chat_id      = COALESCE(?, tg_linked_chat_id), "
                "  tg_migrated_from       = COALESCE(?, tg_migrated_from), "
                "  tg_slowmode_seconds    = COALESCE(?, tg_slowmode_seconds), "
                "  tg_pinned_msg_id       = COALESCE(?, tg_pinned_msg_id), "
                "  tg_participants_hidden = COALESCE(?, tg_participants_hidden), "
                "  tg_antispam            = COALESCE(?, tg_antispam), "
                "  tg_ttl_period          = COALESCE(?, tg_ttl_period), "
                "  tg_restricted_reason   = COALESCE(?, tg_restricted_reason), "
                "  tg_creator_id          = COALESCE(?, tg_creator_id), "
                "  tg_creator_username    = COALESCE(?, tg_creator_username), "
                "  tg_creator_name        = COALESCE(?, tg_creator_name), "
                "  tg_creator_phone       = COALESCE(?, tg_creator_phone), "
                "  tg_creator_bot         = COALESCE(?, tg_creator_bot), "
                "  tg_creator_premium     = COALESCE(?, tg_creator_premium), "
                "  tg_is_private          = COALESCE(?, tg_is_private), "
                "  tg_about               = COALESCE(?, tg_about), "
                "  tg_subscribers         = COALESCE(?, tg_subscribers), "
                "  tg_title               = COALESCE(?, tg_title), "
                "  tg_photo_path          = COALESCE(?, tg_photo_path), "
                "  tg_details_fetched_at  = CURRENT_TIMESTAMP "
                "WHERE id = ?",
                (details.get("created"),
                 details.get("admins_count"),
                 details.get("online_count"),
                 details.get("linked_chat_id"),
                 details.get("migrated_from"),
                 details.get("slowmode_seconds"),
                 details.get("pinned_msg_id"),
                 1 if details.get("participants_hidden") else (
                     0 if details.get("participants_hidden") is False else None),
                 1 if details.get("antispam") else (
                     0 if details.get("antispam") is False else None),
                 details.get("ttl_period"),
                 details.get("restricted_reason"),
                 (details.get("creator") or {}).get("user_id"),
                 (details.get("creator") or {}).get("username"),
                 (details.get("creator") or {}).get("name"),
                 (details.get("creator") or {}).get("phone"),
                 1 if (details.get("creator") or {}).get("bot") else 0,
                 1 if (details.get("creator") or {}).get("premium") else 0,
                 1 if details.get("is_private") else (
                     0 if details.get("is_private") is False else None),
                 details.get("about"),
                 details.get("subscribers"),
                 details.get("title"),
                 details.get("photo_path"),
                 url_id))
            self.conn.commit()

    def add_tg_message(self, url_id, page_id, msg):
        """Persist the rich metadata for a single message. `msg` is the
        dict returned by DarkMTProto.fetch_new_messages()."""
        with self.lock:
            detail = msg.get("reactions_detail")
            self.conn.execute(
                "INSERT INTO tg_messages (page_id, url_id, msg_id, date_iso, "
                "  sender_id, sender_username, sender_name, text, "
                "  views, forwards, reactions_total, reactions_detail, "
                "  has_media, media_type, media_path, media_bytes, "
                "  fwd_from_username, fwd_from_msg_id, reply_to_msg_id, "
                "  topic_id, topic_title) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (page_id, url_id, msg["msg_id"], msg.get("date_iso"),
                 msg.get("sender_id"), msg.get("sender_username"),
                 msg.get("sender_name"), msg.get("text"),
                 msg.get("views"), msg.get("forwards"),
                 msg.get("reactions_total"),
                 json.dumps(detail) if detail else None,
                 1 if msg.get("has_media") else 0,
                 msg.get("media_type"),
                 msg.get("media_path"), msg.get("media_bytes"),
                 msg.get("fwd_from_username"), msg.get("fwd_from_msg_id"),
                 msg.get("reply_to_msg_id"),
                 msg.get("topic_id"), msg.get("topic_title")))
            self.conn.commit()

    def search_tg_messages_local(self, query, limit=100, min_date_iso=None,
                                   url_ids=None):
        """Case-insensitive substring search across all already-scraped TG
        messages. O(log N) via the sqlite_ftx-style LIKE plus the
        `idx_tg_messages_url` index when url_ids is narrow. Returns rows
        with channel context + finding counts."""
        where = ["m.text IS NOT NULL", "LOWER(m.text) LIKE LOWER(?)"]
        params = ["%" + query + "%"]
        if min_date_iso:
            where.append("m.date_iso >= ?")
            params.append(min_date_iso)
        if url_ids:
            marks = ",".join("?" for _ in url_ids)
            where.append(f"m.url_id IN ({marks})")
            params.extend(url_ids)
        params.append(limit)
        sql = (
            "SELECT m.id, m.page_id, m.url_id, m.msg_id, m.date_iso, "
            "  m.sender_username, m.sender_name, m.text, "
            "  m.views, m.forwards, m.reactions_total, m.reactions_detail, "
            "  m.has_media, m.media_type, m.media_path, m.media_bytes, "
            "  m.fwd_from_username, m.reply_to_msg_id, "
            "  m.topic_id, m.topic_title, "
            "  u.tg_username AS channel_username, "
            "  (SELECT title FROM pages p WHERE p.id = m.page_id) AS page_title, "
            "  (SELECT COUNT(*) FROM findings f WHERE f.url_id = m.url_id "
            "     AND f.page_url = (SELECT page_url FROM pages "
            "                        WHERE id = m.page_id)) AS finding_count "
            "FROM tg_messages m "
            "JOIN urls u ON u.id = m.url_id "
            "WHERE " + " AND ".join(where) +
            " ORDER BY m.msg_id DESC LIMIT ?"
        )
        with self.lock:
            cur = self.conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def list_tg_messages(self, url_id, limit=50):
        """Return recent messages for a channel. Joins findings so the UI
        can show which messages matched rules without a per-row query.
        Ordered newest-first by msg_id."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT m.id, m.page_id, m.msg_id, m.date_iso, "
                "  m.sender_username, m.sender_name, "
                "  m.text, m.views, m.forwards, m.reactions_total, m.reactions_detail, "
                "  m.has_media, m.media_type, m.media_path, m.media_bytes, "
                "  m.fwd_from_username, m.fwd_from_msg_id, m.reply_to_msg_id, "
                "  m.topic_id, m.topic_title, "
                "  p.page_url, "
                "  (SELECT COUNT(*) FROM findings f "
                "     WHERE f.url_id = m.url_id AND f.page_url = p.page_url) "
                "    AS finding_count, "
                "  (SELECT GROUP_CONCAT(f.matched_strings, ', ') "
                "     FROM findings f "
                "     WHERE f.url_id = m.url_id AND f.page_url = p.page_url) "
                "    AS finding_matches "
                "FROM tg_messages m "
                "JOIN pages p ON p.id = m.page_id "
                "WHERE m.url_id = ? "
                "ORDER BY m.msg_id DESC LIMIT ?", (url_id, limit))
            cols = [d[0] for d in cur.description]
            out = []
            for row in cur.fetchall():
                d = dict(zip(cols, row))
                if d.get("reactions_detail"):
                    try: d["reactions_detail"] = json.loads(d["reactions_detail"])
                    except (ValueError, TypeError): d["reactions_detail"] = None
                out.append(d)
            return out

    def set_tg_media(self, msg_row_id, rel_path, bytes_):
        """Record that the media for a stored tg_messages row has been
        downloaded to /loot/tg-media/. rel_path is basename-only; the UI
        prepends the channel dir when serving."""
        with self.lock:
            self.conn.execute(
                "UPDATE tg_messages SET media_path = ?, media_bytes = ? "
                "WHERE id = ?", (rel_path, bytes_, msg_row_id))
            self.conn.commit()

    def get_tg_message(self, msg_row_id):
        """Fetch a stored tg_messages row joined with the channel's
        tg_channel_id / tg_username. Used by the media download endpoint."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT m.id, m.url_id, m.msg_id, m.media_type, "
                "  m.media_path, u.tg_channel_id, u.tg_username "
                "FROM tg_messages m "
                "JOIN urls u ON u.id = m.url_id "
                "WHERE m.id = ?", (msg_row_id,))
            row = cur.fetchone()
            if not row: return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))

    # Regexes for link extraction — matched against tg_messages.text.
    _URL_RE = re.compile(
        r"\bhttps?://[^\s<>\"'()]+",      # plain URLs
        re.IGNORECASE)
    _TME_RE = re.compile(
        r"\b(?:https?://)?(?:t\.me|telegram\.me)/"
        r"(?:joinchat/|\+)?(?P<tok>[A-Za-z0-9_]+)"
        r"(?:/(?P<msg>\d+))?",
        re.IGNORECASE)
    _MENTION_RE = re.compile(
        r"(?:^|[^\w@])@(?P<h>[A-Za-z][A-Za-z0-9_]{4,31})\b")

    def extract_channel_links(self, url_id):
        """Aggregate links from every stored message of a channel. Returns
        three de-duplicated, sorted-by-frequency lists:

          forwards       — channels this one forwards FROM (via fwd_from_username
                           column, the authoritative signal)
          telegram       — t.me URLs + @mentions found in message text, minus
                           the channel itself
          external       — plain http/https URLs to non-Telegram hosts

        The result is what the UI's "Links" box renders. Heavy list =
        high pivot value — a channel that forwards from 40 others is
        a CTI aggregator you want to follow."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT u.tg_username, m.text, m.fwd_from_username "
                "FROM tg_messages m JOIN urls u ON u.id = m.url_id "
                "WHERE m.url_id = ?", (url_id,))
            rows = cur.fetchall()

        own_handle = None
        forwards = {}      # handle -> count
        telegram = {}      # (handle, msg_id_or_None) -> count
        external = {}      # host -> [url samples, count]

        for own, text, fwd in rows:
            own_handle = own_handle or (own or "").lower()
            if fwd:
                h = str(fwd).lstrip("@").lower()
                if h and h != own_handle:
                    forwards[h] = forwards.get(h, 0) + 1
            if not text:
                continue
            for m in self._TME_RE.finditer(text):
                tok = (m.group("tok") or "").lower()
                msg_id = m.group("msg")
                if not tok or tok in ("joinchat", "addstickers",
                                       "share", "proxy", "s"):
                    continue
                if tok == own_handle:
                    continue
                key = (tok, msg_id)
                telegram[key] = telegram.get(key, 0) + 1
            # External URLs — exclude t.me / telegram.me which are
            # captured above as telegram links.
            for m in self._URL_RE.finditer(text):
                url = m.group(0).rstrip(".,);]")
                low = url.lower()
                if "t.me/" in low or "telegram.me/" in low \
                        or low.startswith(("https://t.me", "https://telegram.me")):
                    continue
                # Extract host for grouping.
                try:
                    host = url.split("//", 1)[1].split("/", 1)[0].lower()
                except Exception:
                    host = url
                host = host.split("@")[-1]
                entry = external.setdefault(host, {"count": 0, "samples": []})
                entry["count"] += 1
                if len(entry["samples"]) < 3 and url not in entry["samples"]:
                    entry["samples"].append(url)
            for m in self._MENTION_RE.finditer(text):
                h = (m.group("h") or "").lower()
                if not h or h == own_handle: continue
                key = (h, None)
                telegram[key] = telegram.get(key, 0) + 1

        fwd_list = sorted(
            ({"handle": h, "count": c, "url": f"https://t.me/{h}"}
             for h, c in forwards.items()),
            key=lambda r: -r["count"])
        tg_list = sorted(
            ({"handle": h, "msg_id": int(msg) if msg else None,
              "count": c,
              "url": f"https://t.me/{h}" + (f"/{msg}" if msg else "")}
             for (h, msg), c in telegram.items()),
            key=lambda r: -r["count"])
        ext_list = sorted(
            ({"host": host, "count": v["count"], "samples": v["samples"]}
             for host, v in external.items()),
            key=lambda r: -r["count"])
        return {"forwards": fwd_list, "telegram": tg_list, "external": ext_list,
                "scanned_messages": len(rows)}

    def set_tg_membership(self, url_id, is_member):
        """Flip the is_member flag. 1 after a successful join, 0 after
        leave. Caller must supply the bool — we don't infer."""
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET tg_is_member = ? WHERE id = ?",
                (1 if is_member else 0, url_id))
            self.conn.commit()

    def update_tg_last_msg_id(self, url_id, last_msg_id):
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET tg_last_msg_id = ? WHERE id = ?",
                (last_msg_id, url_id))
            self.conn.commit()

    def get_tg_channel(self, url_id):
        """Return the TG-specific fields for a url row, or None if not TG."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT id, url, source, tg_channel_id, tg_last_msg_id, "
                "       tg_subscribers, tg_username, tg_about, "
                "       tg_verified, tg_scam, tg_kind, tg_is_private, "
                "       tg_created, tg_admins_count, tg_online_count, "
                "       tg_linked_chat_id, tg_migrated_from, "
                "       tg_slowmode_seconds, tg_pinned_msg_id, "
                "       tg_participants_hidden, tg_antispam, "
                "       tg_ttl_period, tg_restricted_reason, "
                "       tg_creator_id, tg_creator_username, "
                "       tg_creator_name, tg_creator_phone, "
                "       tg_creator_bot, tg_creator_premium, "
                "       tg_details_fetched_at, tg_is_member, tg_photo_path "
                "FROM urls WHERE id = ? AND source = 'telegram'", (url_id,))
            row = cur.fetchone()
            if not row: return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))

    # ── Monitoring ─────────────────────────────────────────────────────────
    def set_monitor(self, url_id, enabled, interval_min=60, next_check_at=None):
        """Toggle monitoring on a URL. If enabling, schedule the first
        check `next_check_at` (caller decides — usually now() so the
        scheduler picks it up on the next tick)."""
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET monitored = ?, monitor_interval_min = ?, "
                "next_check_at = ? WHERE id = ?",
                (1 if enabled else 0, int(interval_min),
                 next_check_at, url_id))
            self.conn.commit()

    def get_monitored_due(self, now_iso):
        """Return all monitored URLs whose next_check_at is in the past."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT id, url, monitor_interval_min "
                "FROM urls WHERE monitored = 1 "
                "AND (next_check_at IS NULL OR next_check_at <= ?)",
                (now_iso,))
            return [{"id": r[0], "url": r[1], "interval_min": r[2]}
                    for r in cur.fetchall()]

    def schedule_next_check(self, url_id, next_check_at):
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET next_check_at = ? WHERE id = ?",
                (next_check_at, url_id))
            self.conn.commit()

    def stagger_due_monitors(self, now):
        """Rewrite next_check_at for any already-due monitored URLs so they
        don't all fire in the first scheduler tick after a restart. Each
        due row is rescheduled to a random point within its own interval.
        Returns count of rows rescheduled."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT id, monitor_interval_min FROM urls "
                "WHERE monitored = 1 AND (next_check_at IS NULL "
                "                          OR next_check_at <= ?)",
                (now.isoformat(),))
            rows = cur.fetchall()
            count = 0
            for url_id, interval_min in rows:
                interval_s = int(interval_min or 60) * 60
                delay = random.uniform(0, interval_s)
                when = (now + timedelta(seconds=delay)).isoformat()
                self.conn.execute(
                    "UPDATE urls SET next_check_at = ? WHERE id = ?",
                    (when, url_id))
                count += 1
            if count:
                self.conn.commit()
            return count

    def url_exists(self, url_id):
        """Used by API endpoints to 404 early on unknown url_id."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM urls WHERE id = ?", (url_id,))
            return cur.fetchone() is not None

    def add_monitor_event(self, url_id, status, pages, findings,
                           page_id=None, note=None):
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO monitor_events "
                "(url_id, status, pages, findings, page_id, note) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (url_id, status, pages, findings, page_id, note))
            self.conn.commit()
            return cur.lastrowid

    def get_url_timeline(self, url_id, limit=50):
        with self.lock:
            cur = self.conn.execute(
                "SELECT e.id, e.checked_at, e.status, e.pages, e.findings, "
                "  e.note, e.page_id, p.thumbnail_path "
                "FROM monitor_events e "
                "LEFT JOIN pages p ON p.id = e.page_id "
                "WHERE e.url_id = ? "
                "ORDER BY e.checked_at DESC LIMIT ?",
                (url_id, limit))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def delete_url(self, url_id):
        """Delete a URL and cascade through every child table.

        Order matters under `PRAGMA foreign_keys = ON`: tables whose
        rows reference others must be purged first. tg_messages has
        FKs to BOTH pages and urls, so it has to go before pages.
        Missing this was the root cause of silent-fail deletes."""
        with self.lock:
            # Child-first order. `monitor_events` has ON DELETE CASCADE
            # on url_id but we include it explicitly for clarity +
            # consistency across pre-CASCADE schema versions.
            for tbl in ("tg_messages", "monitor_events", "findings",
                        "forms", "pages", "urls"):
                where = "WHERE id = ?" if tbl == "urls" else "WHERE url_id = ?"
                try:
                    self.conn.execute(f"DELETE FROM {tbl} {where}", (url_id,))
                except sqlite3.OperationalError as e:
                    # Table may not exist on older DBs — tolerate and continue.
                    log.debug(f"delete_url: skipping {tbl}: {e}")
            self.conn.commit()

    # ── User keyword management ───────────────────────────────────────────
    def add_keyword(self, keyword, severity="medium", category="user"):
        with self.lock:
            try:
                cur = self.conn.execute(
                    "INSERT INTO user_keywords (keyword, severity, category) "
                    "VALUES (?, ?, ?)",
                    (keyword, severity, category))
                self.conn.commit()
                return cur.lastrowid
            except sqlite3.IntegrityError:
                return None   # duplicate

    def delete_keyword(self, kid):
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM user_keywords WHERE id = ?", (kid,))
            self.conn.commit()
            return cur.rowcount

    def list_keywords(self):
        with self.lock:
            cur = self.conn.execute(
                "SELECT id, keyword, severity, category, added_at "
                "FROM user_keywords ORDER BY added_at DESC")
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def log_scan(self, started, finished, urls, pages, findings, errors):
        with self.lock:
            self.conn.execute("INSERT INTO scan_log (started_at, finished_at, urls_scanned, pages_scanned, findings_count, errors) VALUES (?, ?, ?, ?, ?, ?)", (started, finished, urls, pages, findings, errors))
            self.conn.commit()


# ─── YARA Scanner ────────────────────────────────────────────────────────────

class YaraScanner:
    # Severity → YARA score used when generating user rules.
    SEVERITY_SCORES = {
        "critical": 100,
        "high":     70,
        "medium":   40,
        "low":      15,
    }

    def __init__(self, keywords_file, categories_file, user_file=None,
                 private_dir=None):
        self.keyword_rules = None
        self.category_rules = None
        self.user_rules = None
        self.private_rules = None
        self.keywords_file = keywords_file
        self.categories_file = categories_file
        # user_file is where dynamic, operator-managed keywords get written.
        # MUST be on a writable mount — the curated yara/ dir is :ro.
        # If None, regenerate_user_rules() no-ops with a warning.
        self.user_file = user_file
        # private_dir is an optional read-only directory of operator-specific
        # *.yar files mounted in from outside the repo (compose mounts
        # ${DATA_ROOT}/yara-private:/app/yara-private:ro). Lets operators ship
        # sensitive rules without committing them. Missing or empty dir is a
        # no-op — never an error.
        self.private_dir = private_dir
        self._compile_all()

    def _compile_one(self, path):
        if not (path and os.path.exists(path)):
            return None
        try:
            return yara.compile(filepath=path)
        except yara.Error as e:
            log.error(f"Failed to compile YARA {path}: {e}")
            return None

    def _private_rule_filepaths(self, exclude_fname=None):
        """Map namespace -> path for every *.yar in private_dir."""
        paths = {}
        if not (self.private_dir and os.path.isdir(self.private_dir)):
            return paths
        for fname in sorted(os.listdir(self.private_dir)):
            if exclude_fname and fname == exclude_fname:
                continue
            if not fname.endswith((".yar", ".yara")):
                continue
            full = os.path.join(self.private_dir, fname)
            if not os.path.isfile(full):
                continue
            ns = re.sub(r"[^A-Za-z0-9_]", "_", os.path.splitext(fname)[0])
            paths[ns] = full
        return paths

    def _compile_private_dir(self):
        """Compile every *.yar in self.private_dir into one yara.Rules object,
        using filename-derived namespaces to avoid rule-name collisions across
        files. Returns None if the dir is unset, missing, or empty."""
        paths = self._private_rule_filepaths()
        if not paths:
            return None
        try:
            return yara.compile(filepaths=paths)
        except yara.Error as e:
            log.error(f"Failed to compile YARA private rules in "
                      f"{self.private_dir}: {e}")
            return None

    def _compile_all(self):
        self.keyword_rules = self._compile_one(self.keywords_file)
        self.category_rules = self._compile_one(self.categories_file)
        self.user_rules = self._compile_one(self.user_file)
        self.private_rules = self._compile_private_dir()
        for label, r, f in [("keyword", self.keyword_rules, self.keywords_file),
                            ("category", self.category_rules, self.categories_file),
                            ("user", self.user_rules, self.user_file),
                            ("private", self.private_rules, self.private_dir)]:
            if r:
                log.info(f"Loaded {label} rules from {f}")

    @staticmethod
    def _yara_escape(s):
        # Escape backslashes, quotes, and control chars — YARA string
        # literals use C-like escape rules. Belt-and-suspenders with the
        # API-level validator in web.py route_keywords_add().
        return (s.replace("\\", "\\\\")
                 .replace('"', '\\"')
                 .replace("\n", "\\n")
                 .replace("\r", "\\r")
                 .replace("\t", "\\t"))

    def regenerate_user_rules(self, keywords):
        """Write `user_file` from a list of {keyword, severity} dicts and
        recompile. Groups keywords into one rule per severity so scoring
        flows through the existing pipeline unchanged."""
        if not self.user_file:
            log.warning("regenerate_user_rules: no user_file configured; skipping")
            return False
        buckets = {}   # severity -> [keyword, ...]
        for k in keywords:
            kw = (k.get("keyword") or "").strip()
            sev = k.get("severity") or "medium"
            if not kw or sev not in self.SEVERITY_SCORES:
                continue
            buckets.setdefault(sev, []).append(kw)

        lines = [
            "/* Auto-generated by DarkWatch — DO NOT EDIT. "
            "Managed via the Keywords tab in the UI. */",
            "",
        ]
        for sev, kws in buckets.items():
            if not kws:
                continue
            score = self.SEVERITY_SCORES[sev]
            lines.append(f"rule user_{sev}")
            lines.append("{")
            lines.append("    meta:")
            lines.append('        author = "user"')
            lines.append(f'        description = "User-defined {sev} keywords"')
            lines.append(f"        score = {score}")
            lines.append("")
            lines.append("    strings:")
            for i, kw in enumerate(kws):
                lines.append(f'        $k{i} = "{self._yara_escape(kw)}" '
                             f'wide ascii nocase')
            lines.append("")
            lines.append("    condition:")
            lines.append("        any of them")
            lines.append("}")
            lines.append("")

        os.makedirs(os.path.dirname(self.user_file) or ".", exist_ok=True)
        if len(lines) <= 2:
            # No keywords — remove the file so no user rule fires.
            try: os.remove(self.user_file)
            except FileNotFoundError: pass
            self.user_rules = None
            log.info("User rules cleared (no keywords)")
            return True
        # Explicit UTF-8 — keywords may contain non-ASCII characters. Some
        # container images default to LANG=C / ASCII and would mojibake.
        with open(self.user_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self.user_rules = self._compile_one(self.user_file)
        log.info(f"User rules regenerated: {sum(len(v) for v in buckets.values())} "
                 f"keyword(s), {len(buckets)} severity bucket(s)")
        return True

    @staticmethod
    def parse_rules_file(path):
        """Lightweight YARA parser — extracts rule name, meta (score,
        description, author), and the raw string literals defined in
        `strings:`. Enough for a UI rules-browser view; does NOT try to
        re-implement yara-python or validate conditions."""
        if not path or not os.path.exists(path):
            return []
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            return []

        rules = []
        # Match: rule <name> [: tag ...] { ... }
        rule_pat = re.compile(
            r'rule\s+(\w+)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', re.M | re.S)
        for m in rule_pat.finditer(text):
            name = m.group(1)
            body = m.group(2)
            # meta section
            meta = {}
            meta_m = re.search(r'meta\s*:(.*?)(?:strings\s*:|condition\s*:)',
                               body, re.S)
            if meta_m:
                for kv in re.finditer(
                        r'(\w+)\s*=\s*(?:"([^"]*)"|(\d+)|([^\n]+))',
                        meta_m.group(1)):
                    k = kv.group(1)
                    v = kv.group(2) if kv.group(2) is not None else \
                        kv.group(3) if kv.group(3) is not None else \
                        (kv.group(4) or "").strip()
                    meta[k] = v
            # strings section — extract quoted literals
            strings = []
            strings_m = re.search(r'strings\s*:(.*?)condition\s*:', body, re.S)
            if strings_m:
                for sm in re.finditer(
                        r'\$(\w+)\s*=\s*"([^"]+)"', strings_m.group(1)):
                    strings.append({"name": sm.group(1), "value": sm.group(2)})
            rules.append({
                "name": name,
                "description": meta.get("description", ""),
                "author": meta.get("author", ""),
                "score": int(meta.get("score", 0) or 0),
                "strings": strings,
                "file": os.path.basename(path),
                "deletable": os.path.basename(path) == "user.yar",
                "custom": False,
                "custom_file": "",
            })
        return rules

    def list_rules(self):
        """Combined rule list from curated, user-generated, and custom files."""
        rules = (self.parse_rules_file(self.keywords_file)
                 + self.parse_rules_file(self.categories_file)
                 + self.parse_rules_file(self.user_file))
        if self.private_dir and os.path.isdir(self.private_dir):
            for fname in sorted(os.listdir(self.private_dir)):
                if not fname.endswith((".yar", ".yara")):
                    continue
                path = os.path.join(self.private_dir, fname)
                if not os.path.isfile(path):
                    continue
                for rule in self.parse_rules_file(path):
                    rule["deletable"] = True
                    rule["custom"] = True
                    rule["custom_file"] = fname
                    rules.append(rule)
        return rules

    @staticmethod
    def _safe_custom_filename(stem):
        """Return a basename like 'my_rule.yar' or raise ValueError."""
        stem = (stem or "").strip()
        if not stem:
            raise ValueError("filename is required")
        base = os.path.splitext(stem)[0] if stem.lower().endswith(
            (".yar", ".yara")) else stem
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", base):
            raise ValueError(
                "filename must be 1–64 chars: letters, digits, _ or -")
        return f"{base}.yar"

    @staticmethod
    def extract_rule_names_from_text(text):
        """Return YARA rule identifiers declared in source text."""
        rule_pat = re.compile(
            r'rule\s+(\w+)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', re.M | re.S)
        return [m.group(1) for m in rule_pat.finditer(text or "")]

    def reload_private_rules(self):
        """Recompile operator drop-in rules after add/delete."""
        self.private_rules = self._compile_private_dir()
        return self.private_rules is not None

    def validate_custom_rule_compile(self, content, filename):
        """Compile-test new rule together with existing private rule files."""
        text = (content or "").strip()
        fname = self._safe_custom_filename(filename)
        paths = self._private_rule_filepaths()
        ns = re.sub(r"[^A-Za-z0-9_]", "_", os.path.splitext(fname)[0])
        if ns in paths:
            raise ValueError(
                f"a rule file named {fname!r} already exists — "
                "choose another filename or delete the existing rule")
        sources = {}
        for pns, path in paths.items():
            try:
                with open(path, encoding="utf-8") as f:
                    sources[pns] = f.read()
            except OSError as e:
                raise ValueError(f"cannot read existing rule {path!r}: {e}") from e
        sources[ns] = text
        try:
            yara.compile(sources=sources)
        except yara.Error as e:
            raise ValueError(f"YARA compile error: {e}") from e

    def save_custom_rule(self, content, filename):
        """Write a custom .yar file after compile validation."""
        if not self.private_dir:
            raise ValueError("custom rules directory is not configured")
        text = (content or "").strip()
        if not text:
            raise ValueError("rule content is required")
        if len(text) > 64 * 1024:
            raise ValueError("rule content is too large (>64 KiB)")
        new_names = self.extract_rule_names_from_text(text)
        if not new_names:
            raise ValueError("content must contain at least one YARA rule")
        seen_in_file = set()
        dupes_in_file = []
        for n in new_names:
            if n in seen_in_file:
                dupes_in_file.append(n)
            seen_in_file.add(n)
        if dupes_in_file:
            joined = ", ".join(sorted(set(dupes_in_file)))
            raise ValueError(f"duplicate rule name(s) in file: {joined}")
        fname = self._safe_custom_filename(filename)
        path = os.path.join(self.private_dir, fname)
        if os.path.isfile(path):
            raise ValueError(
                f"a rule file named {fname!r} already exists — "
                "choose another filename or delete the existing rule")
        existing = {r["name"] for r in self.list_rules()}
        dupes = sorted({n for n in new_names if n in existing})
        if dupes:
            joined = ", ".join(dupes)
            raise ValueError(
                f"rule name(s) already in use: {joined}")
        self.validate_custom_rule_compile(text, fname)
        os.makedirs(self.private_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.rstrip() + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self.reload_private_rules()
        return fname

    def delete_custom_files(self, filenames):
        """Remove custom rule files by basename."""
        if not self.private_dir:
            return 0
        removed = 0
        for raw in filenames or []:
            try:
                fname = self._safe_custom_filename(raw)
            except ValueError:
                continue
            path = os.path.join(self.private_dir, fname)
            if os.path.isfile(path):
                os.remove(path)
                removed += 1
        if removed:
            self.reload_private_rules()
        return removed

    def resolve_rule_deletions(self, rule_names):
        """Split rule names into keyword-backed (user.yar) vs custom file deletes."""
        by_name = {r["name"]: r for r in self.list_rules()}
        user_names = []
        custom_files = set()
        for name in rule_names or []:
            rule = by_name.get(name)
            if not rule or not rule.get("deletable"):
                continue
            if rule.get("custom_file"):
                custom_files.add(rule["custom_file"])
            elif rule.get("file") == "user.yar":
                user_names.append(name)
        return user_names, sorted(custom_files)

    def delete_rules(self, rule_names, db):
        """Delete selected deletable rules (keywords and/or custom files)."""
        user_names, custom_files = self.resolve_rule_deletions(rule_names)
        removed_kw = self.delete_user_rules(user_names, db) if user_names else 0
        removed_files = self.delete_custom_files(custom_files) if custom_files else 0
        return {"removed_keywords": removed_kw, "removed_custom_files": removed_files}

    def delete_user_rules(self, rule_names, db):
        """Remove keywords backing named user_* rules and recompile user.yar."""
        names = {n.strip() for n in (rule_names or []) if n and str(n).strip()}
        if not names or not self.user_file:
            return 0
        user_rules = self.parse_rules_file(self.user_file)
        keywords_to_remove = set()
        for rule in user_rules:
            if rule["name"] in names:
                for s in rule.get("strings") or []:
                    val = (s.get("value") or "").strip()
                    if val:
                        keywords_to_remove.add(val.lower())
        if not keywords_to_remove:
            return 0
        removed = 0
        for kw in db.list_keywords():
            if (kw.get("keyword") or "").strip().lower() in keywords_to_remove:
                if db.delete_keyword(kw["id"]):
                    removed += 1
        self.regenerate_user_rules(db.list_keywords())
        return removed

    @staticmethod
    def _decode_match(data):
        if isinstance(data, bytes):
            try: return data.decode("utf-8", "replace")
            except Exception: return str(data)
        return str(data) if data is not None else ""

    @classmethod
    def _extract_match_strings(cls, m, limit=5):
        """Return up to `limit` actual matched substrings from a yara match.

        Handles both yara-python <4.3 (tuples) and >=4.3 (StringMatch objects
        with .instances). Empty/blank matches are filtered out. Overlapping
        regex matches (same hit, different start offsets — e.g. `admin@x:y`,
        `dmin@x:y`, `min@x:y`) are deduped by dropping any string that is a
        suffix of a longer already-kept one.
        """
        raw = []
        for s in m.strings:
            if hasattr(s, "instances"):
                for inst in s.instances:
                    txt = cls._decode_match(getattr(inst, "matched_data", b""))
                    txt = txt.strip()
                    if txt: raw.append(txt[:200])
            elif isinstance(s, tuple) and len(s) >= 3:
                txt = cls._decode_match(s[2]).strip()
                if txt: raw.append(txt[:200])
            else:
                # Fallback — preserve the identifier rather than silently drop.
                raw.append(str(s))

        unique = []
        for t in sorted(set(raw), key=len, reverse=True):
            if not any(u.endswith(t) and u != t for u in unique):
                unique.append(t)
            if len(unique) >= limit: break
        return unique

    def scan(self, text):
        results = {"keywords": [], "categories": []}
        for rules in (self.keyword_rules, self.user_rules,
                       self.private_rules,
                       getattr(self, "intel_rules", None)):
            if not rules: continue
            for m in rules.match(data=text):
                score = m.meta.get("score", 0)
                matched = self._extract_match_strings(m)
                results["keywords"].append({
                    "rule": m.rule, "score": score,
                    "matched_strings": matched, "meta": dict(m.meta)})
        if self.category_rules:
            for m in self.category_rules.match(data=text):
                score = m.meta.get("score", 0)
                results["categories"].append({
                    "rule": m.rule, "score": score, "meta": dict(m.meta)})
        return results

    def scan_parallel(self, text, html):
        """Run text and HTML YARA passes concurrently via a shared 2-worker
        pool (kept on the scanner so we don't pay thread-creation cost per
        page). yara-python releases the GIL during rules.match(), so real
        parallelism is available on multi-core hosts.

        Returns (text_hits, html_hits).
        """
        pool = getattr(self, "_scan_pool", None)
        if pool is None:
            pool = ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="yara")
            self._scan_pool = pool
        ft = pool.submit(self.scan, text)
        fh = pool.submit(self.scan, html)
        return ft.result(), fh.result()

    def load_intel_rules(self, path):
        """Slot an externally-sourced YARA file (threat-intel feed output)
        into the scan pipeline. Compiled rules are stored in `intel_rules`
        and consulted alongside keyword + user rules. Call with path=None
        (or a missing file) to unload."""
        if not path or not os.path.exists(path):
            self.intel_rules = None
            return False
        try:
            self.intel_rules = yara.compile(filepath=path)
            log.info(f"Loaded threat-intel rules from {path}")
            return True
        except yara.Error as e:
            log.error(f"Failed to compile intel rules {path}: {e}")
            self.intel_rules = None
            return False


# ─── Alerting ────────────────────────────────────────────────────────────────

class Alerter:
    def __init__(self, config):
        self.config = config

    def send(self, finding):
        score = finding.get("score", 0)
        if score < self.config.get("min_alert_score", 80):
            return
        msg = self._format(finding)
        if self.config.get("telegram_enabled"):
            self._telegram(msg)
        if self.config.get("slack_enabled"):
            self._slack(msg)
        if self.config.get("discord_enabled"):
            self._discord(msg, finding)
        if self.config.get("generic_webhook_enabled"):
            self._generic(msg, finding)

    def _format(self, f):
        return (f"DarkWatch Alert\n"
            f"Rule: {f.get('rule_name')}\n"
            f"Score: {f.get('score')}\n"
            f"Severity: {f.get('severity', 'unknown').upper()}\n"
            f"URL: {f.get('page_url')}\n"
            f"Matched: {f.get('matched_strings')}\n"
            f"Snippet: {f.get('snippet', '')[:200]}\n"
            f"Time: {datetime.now().isoformat()}")

    def _telegram(self, msg):
        token = self.config.get("telegram_bot_token")
        chat_id = self.config.get("telegram_chat_id")
        if not token or not chat_id:
            return
        try:
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={"chat_id": chat_id, "text": msg}, timeout=10)
            log.info("Telegram alert sent")
        except Exception as e:
            log.error(f"Telegram alert failed: {e}")

    def _slack(self, msg):
        webhook = self.config.get("slack_webhook_url")
        if not webhook:
            return
        try:
            requests.post(webhook, json={"text": msg}, timeout=10)
            log.info("Slack alert sent")
        except Exception as e:
            log.error(f"Slack alert failed: {e}")

    def _discord(self, msg, finding):
        """Discord accepts `{content, embeds}` on incoming-webhook endpoints.
        A small embed makes alerts much more readable than raw text."""
        webhook = self.config.get("discord_webhook_url")
        if not webhook:
            return
        severity = (finding.get("severity") or "medium").lower()
        color = {"critical": 0xff4d4d, "high": 0xff8c00,
                 "medium": 0xffcc00, "low": 0x1e90ff}.get(severity, 0x888888)
        payload = {
            "content": f"**DarkWatch alert** — {severity.upper()}",
            "embeds": [{
                "title": finding.get("rule_name") or "match",
                "description": (finding.get("snippet") or "")[:1500],
                "color": color,
                "fields": [
                    {"name": "Score",   "value": str(finding.get("score")),
                     "inline": True},
                    {"name": "Matched", "value": str(finding.get("matched_strings") or "-")[:200],
                     "inline": True},
                    {"name": "Source",  "value": finding.get("page_url") or "-",
                     "inline": False},
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }]
        }
        try:
            requests.post(webhook, json=payload, timeout=10)
            log.info("Discord alert sent")
        except Exception as e:
            log.error(f"Discord alert failed: {e}")

    def _generic(self, msg, finding):
        """POST the full finding dict to any custom endpoint. Operator
        controls their own receiver; we just guarantee a predictable JSON
        shape."""
        webhook = self.config.get("generic_webhook_url")
        if not webhook:
            return
        payload = {
            "tool": "darkwatch",
            "ts": datetime.now(timezone.utc).isoformat(),
            "severity": finding.get("severity"),
            "score": finding.get("score"),
            "rule_name": finding.get("rule_name"),
            "matched_strings": finding.get("matched_strings"),
            "snippet": finding.get("snippet"),
            "page_url": finding.get("page_url"),
            "summary_text": msg,
        }
        try:
            requests.post(webhook, json=payload, timeout=10)
            log.info("Generic webhook alert sent")
        except Exception as e:
            log.error(f"Generic webhook alert failed: {e}")


# ─── HTML Sanitizer ──────────────────────────────────────────────────────────

class HTMLSanitizer:
    TRACKING_PATTERNS = [
        r'url\(["\x27]?https?://[^)]+["\x27]?\)',
        r'@import\s+["\x27]https?://',
    ]

    @staticmethod
    def sanitize(html, config):
        soup = BeautifulSoup(html, "lxml")

        # strip script/noscript
        if config.get("strip_scripts", True):
            for tag in soup.find_all(["script", "noscript"]):
                tag.decompose()

        # strip iframes/frames
        if config.get("strip_iframes", True):
            for tag in soup.find_all(["iframe", "frame", "frameset"]):
                tag.decompose()

        # strip objects/embeds
        if config.get("strip_objects", True):
            for tag in soup.find_all(["object", "embed", "applet"]):
                tag.decompose()

        # strip forms
        for tag in soup.find_all(["form", "input", "button", "textarea", "select"]):
            tag.decompose()

        # strip tracking and event handlers
        if config.get("strip_tracking", True):
            for tag in soup.find_all(True):
                for attr in list(tag.attrs.keys()):
                    if attr.lower().startswith("on"):
                        del tag[attr]
                    if attr in ("src", "href", "action"):
                        val = str(tag.get(attr, ""))
                        if val.strip().lower().startswith("javascript:"):
                            del tag[attr]
                        if val.strip().lower().startswith("data:") and "script" in val.lower():
                            del tag[attr]

            # remove tracking pixels
            for img in soup.find_all("img"):
                width = img.get("width", "")
                height = img.get("height", "")
                if str(width) in ("0", "1") or str(height) in ("0", "1"):
                    img.decompose()
                    continue
                src = img.get("src", "")
                if src.startswith("http"):
                    img["src"] = "[EXTERNAL_IMAGE_REMOVED]"
                    img["data-original-src"] = src

            # strip meta refresh
            for meta in soup.find_all("meta"):
                if meta.get("http-equiv", "").lower() == "refresh":
                    meta.decompose()

            # strip external CSS tracking
            for style in soup.find_all("style"):
                text = style.string or ""
                for pattern in HTMLSanitizer.TRACKING_PATTERNS:
                    text = re.sub(pattern, "/* REMOVED */", text, flags=re.I)
                style.string = text

            # strip non-stylesheet link tags
            for link in soup.find_all("link"):
                rel = " ".join(link.get("rel", []))
                if "stylesheet" not in rel.lower():
                    link.decompose()

        # Operator fingerprint removed: no timestamped comment injected.
        # Saved pages must not reveal when/which operator touched them.
        return str(soup)


# ─── Data Extractor ──────────────────────────────────────────────────────────

class DataExtractor:
    """Safely extracts structured IOCs and data from page text.

    All extraction uses pre-compiled regex — no code execution,
    no eval, input length capped to prevent ReDoS.
    """

    PATTERNS = {
        'emails': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b'),
        'btc_addresses': re.compile(
            r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Za-km-z0-9]{25,62})\b'
        ),
        'eth_addresses': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
        'xmr_addresses': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
        'ipv4_addresses': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        'onion_urls': re.compile(r'(?:https?://)?[a-z2-7]{16,56}\.onion(?:/[^\s"\'<>]*)?'),
        'phone_numbers': re.compile(
            r'\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b'
        ),
        'pgp_blocks': re.compile(
            r'-----BEGIN PGP[A-Z\s]*BLOCK-----[\s\S]{32,8192}?-----END PGP[A-Z\s]*BLOCK-----'
        ),
    }

    IGNORE_IPS = {'0.0.0.0', '127.0.0.1', '255.255.255.255', '192.168.0.1', '10.0.0.1'}

    @staticmethod
    def extract(text, max_per_type=50):
        """Extract IOCs from text. Input capped at 500k chars."""
        results = {}
        text = text[:500_000]
        for name, pattern in DataExtractor.PATTERNS.items():
            try:
                matches = list(set(pattern.findall(text)))[:max_per_type]
                if name == 'ipv4_addresses':
                    matches = [m for m in matches if m not in DataExtractor.IGNORE_IPS]
                if matches:
                    results[name] = matches
            except Exception:
                continue
        return results

    @staticmethod
    def harvest_html_context(html, max_per_type=50):
        """Pull IOC candidates from HTML attributes, <meta> tags, and comments
        that get stripped before plaintext IOC extraction.

        Returns a blob of text suitable for feeding back into extract().
        """
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return ""
        fragments = []
        # <meta> content attrs (description, keywords, etc.)
        for meta in soup.find_all("meta"):
            for attr in ("content", "name", "property"):
                val = meta.get(attr)
                if val:
                    fragments.append(str(val))
        # attribute values that commonly hide IOCs
        attr_whitelist = ("title", "alt", "href", "src", "data-wallet",
                          "data-address", "data-email", "data-btc",
                          "data-onion", "aria-label")
        for tag in soup.find_all(True):
            for attr in attr_whitelist:
                val = tag.get(attr)
                if val:
                    fragments.append(str(val))
        # HTML comments (often contain debug info, forgotten emails, etc.)
        from bs4 import Comment
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            fragments.append(str(comment))
        # <pre> blocks (PGP keys, configs)
        for pre in soup.find_all(["pre", "code"]):
            fragments.append(pre.get_text())
        return "\n".join(fragments)[:500_000]


# ─── Screenshot Engine ───────────────────────────────────────────────────────

class ScreenshotEngine:
    """Captures page screenshots by rendering fetched HTML offline.

    Safety:
    - JavaScript execution DISABLED
    - ALL network requests BLOCKED (route → abort)
    - Renders already-fetched HTML via set_content (no navigation)
    - Graceful fallback if Playwright is not installed

    Async migration note (Phase 5b of the roadmap):
    This class uses playwright.sync_api. sync_api is thread-bound — the
    browser + context + page must all be used from the thread that
    created them. That's why _crawl_lock serializes scans; it's why we
    can't parallelize screenshotting within a scan. To lift that, the
    migration path is:

      1. Replace sync_playwright with playwright.async_api.
      2. Run the browser on a dedicated asyncio loop (see
         PersistentTelethonLoop for the pattern).
      3. Submit page.goto / page.screenshot coroutines from worker
         threads via run_coroutine_threadsafe, unlocking parallelism.

    Not done here — current serialized path is correct and fast enough
    for single-operator scans. Enable via config.crawler.async_playwright
    = true once implemented.
    """

    # Stealth launch args — reduce the headless-browser fingerprint footprint.
    # Firefox prefs defeat WebRTC + canvas/WebGL fingerprinting, which can
    # leak LAN/public IPs even when network is route-aborted.
    FIREFOX_PREFS = {
        "media.peerconnection.enabled": False,   # disable WebRTC
        "webgl.disabled": True,                   # disable WebGL fingerprint surface
        "privacy.resistFingerprinting": True,
        "javascript.enabled": False,             # hard-disable JS at the engine level
        # Force DNS resolution through the SOCKS proxy (Tor). Without this,
        # Firefox does local DNS even with a SOCKS proxy configured — that's
        # a hard-fail leak for onion targets and reveals the operator's
        # interest to whatever DNS resolver is in use.
        "network.proxy.socks_remote_dns": True,
    }
    FIREFOX_ARGS = ["--disable-blink-features=AutomationControlled"]

    def __init__(self, output_dir, thumbnails_dir=None, proxy_url=None,
                 mode="tor_render"):
        self.output_dir = os.path.abspath(output_dir)
        self.thumbnails_dir = os.path.abspath(thumbnails_dir) if thumbnails_dir \
            else os.path.abspath(os.path.join(output_dir, "..", "thumbnails"))
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.thumbnails_dir, exist_ok=True)
        self._playwright = None
        self._browser = None
        # proxy_url: e.g. "socks5://tor:9050" — routes ALL browser traffic
        #   through Tor, so same-origin asset loads stay on the .onion.
        # mode:
        #   "tor_render" — browser does page.goto() via Tor proxy. JS off,
        #                  cross-origin requests blocked. Produces realistic
        #                  screenshots with CSS + same-origin images.
        #   "offline"    — legacy mode: set_content on already-fetched HTML,
        #                  all network aborted. Ugliest but no second hit.
        self.proxy_url = proxy_url
        self.mode = mode if mode in ("tor_render", "offline") else "tor_render"

    def _ensure_browser(self):
        if not PLAYWRIGHT_AVAILABLE:
            return False
        if self._browser is None:
            try:
                self._playwright = sync_playwright().start()
                launch_kwargs = {
                    "headless": True,
                    "args": self.FIREFOX_ARGS,
                    "firefox_user_prefs": self.FIREFOX_PREFS,
                }
                if self.mode == "tor_render" and self.proxy_url:
                    # Playwright/Firefox accepts socks5:// (NOT socks5h://) —
                    # the trailing 'h' is a Python-requests-only extension.
                    # Strip it; DNS-through-SOCKS is enforced via the
                    # network.proxy.socks_remote_dns pref instead.
                    pw_proxy = self.proxy_url.replace("socks5h://", "socks5://", 1)
                    launch_kwargs["proxy"] = {"server": pw_proxy}
                self._browser = self._playwright.firefox.launch(**launch_kwargs)
                log.info(f"Screenshot engine ready (mode={self.mode}, "
                         f"proxy={launch_kwargs.get('proxy', {}).get('server', 'none')})")
            except Exception as e:
                log.warning(f"Screenshot engine unavailable: {e}")
                return False
        return True

    def _safe_paths(self, url, ts):
        """Build PNG + JPEG paths, guarded against traversal."""
        safe_name = re.sub(r'[^\w]', '_', url)[:80].strip("_") or "page"
        filename = f"{safe_name}_{ts}.png"
        full_path = os.path.abspath(os.path.join(self.output_dir, filename))
        thumb_path = os.path.abspath(
            os.path.join(self.thumbnails_dir, f"{safe_name}_{ts}.jpg"))
        if not full_path.startswith(self.output_dir + os.sep):
            raise ValueError(f"screenshot path escapes output dir: {full_path}")
        if not thumb_path.startswith(self.thumbnails_dir + os.sep):
            raise ValueError(f"thumbnail path escapes thumb dir: {thumb_path}")
        return full_path, thumb_path

    def _render(self, html_content, url, output_path):
        """Render a page and screenshot it. The security posture depends on mode:

        tor_render: navigate to `url` through the browser-level Tor proxy.
                    JS hard-disabled. Any cross-origin request (tracker,
                    CDN, analytics) is aborted at the route handler level
                    so it never leaves the browser process.
        offline:    load the already-fetched HTML via set_content and abort
                    every network request. Ugly but bulletproof.
        """
        context = None
        try:
            context = self._browser.new_context(
                viewport={'width': 1280, 'height': 800},
                java_script_enabled=False,
                # Don't carry cookies across pages — each capture is isolated.
                storage_state=None,
                ignore_https_errors=True,
            )
            page = context.new_page()

            if self.mode == "offline":
                page.route("**/*", lambda route: route.abort())
                page.set_content(html_content, wait_until="domcontentloaded",
                                 timeout=15000)
            else:
                page_host = urlparse(url).netloc

                def guard(route):
                    """Allow only same-origin requests; abort everything else.
                    Stops trackers, CDN calls, and third-party beacons from
                    touching the network — even though we're already behind
                    Tor, we don't want the operator's crawl to ping unrelated
                    domains and give the target site a correlatable pattern.
                    """
                    try:
                        req_host = urlparse(route.request.url).netloc
                        rtype = route.request.resource_type
                        # Block scripts outright as belt-and-suspenders with
                        # javascript.enabled=false (covers service workers,
                        # worklets, etc.).
                        if rtype in ("script", "websocket", "media"):
                            return route.abort()
                        if req_host == page_host:
                            return route.continue_()
                        return route.abort()
                    except Exception:
                        try: route.abort()
                        except Exception: pass

                page.route("**/*", guard)
                page.goto(url, wait_until="domcontentloaded", timeout=20000)

            page.screenshot(path=output_path, full_page=False, timeout=10000)
            return True
        finally:
            if context:
                try: context.close()
                except Exception: pass

    def capture(self, html_content, url, timestamp=None):
        """Render HTML offline, screenshot + thumbnail. Returns
        (screenshot_path, thumbnail_path) or (None, None).
        Hard-capped at 30s total to prevent crawl-wide Playwright hangs.
        """
        if not self._ensure_browser():
            return None, None

        ts = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            full_path, thumb_path = self._safe_paths(url, ts)
        except ValueError as e:
            log.warning(f"  Screenshot path rejected: {e}")
            return None, None

        # NOTE: Playwright sync API is thread-bound to whichever thread
        # first called .start(), so we cannot offload this to a worker
        # thread. Playwright's own timeouts bound the hang risk per page.
        try:
            self._render(html_content, url, full_path)
        except Exception as e:
            log.warning(f"  Screenshot failed: {e}")
            return None, None

        log.debug(f"  Screenshot saved: {os.path.basename(full_path)}")

        # Thumbnail generation (best-effort; missing Pillow does not fail)
        tpath = None
        if PILLOW_AVAILABLE:
            try:
                img = Image.open(full_path)
                img.thumbnail((240, 160))
                img.convert("RGB").save(thumb_path, "JPEG", quality=75)
                tpath = thumb_path
            except Exception as e:
                log.debug(f"  Thumbnail failed: {e}")
        return full_path, tpath


class ScreenshotWorker:
    """A dedicated single-threaded worker that owns the Playwright
    browser lifecycle and services a queue of capture requests.

    Why: sync_playwright is thread-bound. Rather than serializing the
    whole crawler on a _crawl_lock, we give screenshots their own
    thread — the fetch+scan loop enqueues work and immediately moves
    on. The worker patches the page row when the screenshot finishes
    (via Database.update_page_screenshot).

    The queue has a small upper bound; if we fill it up (e.g., during
    a big crawl), new requests are dropped with a log warning. This
    prefers forward crawl progress over 100% screenshot coverage —
    the operator still has the HTML and findings.
    """

    def __init__(self, engine, db, max_queue=64):
        self.engine = engine
        self.db = db
        self._queue = Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._thread = None
        self.dropped = 0
        self.processed = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="ScreenshotWorker", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        # Poison pill — ensures _queue.get() returns promptly.
        try: self._queue.put_nowait(None)
        except Exception: pass

    def enqueue(self, page_id, html, page_url):
        """Non-blocking submit. Returns True on queued, False if full."""
        try:
            self._queue.put_nowait((page_id, html, page_url))
            return True
        except Exception:
            self.dropped += 1
            return False

    def qsize(self):
        return self._queue.qsize()

    def _run(self):
        log.info("Screenshot worker started")
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except Exception:
                continue
            if item is None:
                break
            page_id, html, page_url = item
            try:
                spath, tpath = self.engine.capture(html, page_url)
                if spath:
                    self.db.update_page_screenshot(page_id, spath, tpath)
                self.processed += 1
            except Exception as e:
                log.warning(f"Screenshot worker error: {e}")
        log.info("Screenshot worker stopped")

    def close(self):
        """Clean up browser resources."""
        try:
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass


# ─── Stealth Engine ──────────────────────────────────────────────────────────

class StealthEngine:
    TOR_BROWSER_PROFILES = [
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        },
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-GB,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
        },
    ]

    def __init__(self, config):
        self.user_agents = config.get("crawler", {}).get("user_agents", [])
        self.stealth_cfg = config.get("stealth", {})
        self.min_delay = self.stealth_cfg.get("min_delay", 2)
        self.max_delay = self.stealth_cfg.get("max_delay", 8)
        self.lang_variants = self.stealth_cfg.get("accept_language_variants", ["en-US,en;q=0.5"])

    def get_headers(self, referer=None):
        ua = random.choice(self.user_agents)
        profile = random.choice(self.TOR_BROWSER_PROFILES).copy()
        profile["User-Agent"] = ua
        profile["Accept-Language"] = random.choice(self.lang_variants)
        if referer and self.stealth_cfg.get("referer_spoof", True):
            profile["Referer"] = referer
        if self.stealth_cfg.get("randomize_header_order", True):
            items = list(profile.items())
            random.shuffle(items)
            profile = dict(items)
        return profile

    def delay(self):
        wait = random.uniform(self.min_delay, self.max_delay)
        log.debug(f"  Stealth delay: {wait:.1f}s")
        time.sleep(wait)

    def jitter_timeout(self, base_timeout):
        # Clamp so we never exceed the caller's stated timeout budget.
        # Previously (-5, +10) could turn 60s into 70s, breaking upstream callers.
        return max(5, base_timeout + random.uniform(-5, 5))


# ─── Response Validator ──────────────────────────────────────────────────────

class ResponseValidator:
    BINARY_SIGNATURES = [
        b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'PK\x03\x04',
        b'%PDF', b'\x7fELF', b'MZ', b'\x1f\x8b', b'Rar!',
    ]

    def __init__(self, config):
        self.config = config.get("security", {})
        self.max_size = self.config.get("max_response_size_mb", 10) * 1024 * 1024
        self.allowed_types = list(self.config.get(
            "allowed_content_types",
            ["text/html", "application/xhtml+xml", "text/plain"]))
        # Opt-in: allow PDFs through when the crawler is configured to scan them.
        if config.get("crawler", {}).get("scan_pdfs", False):
            self.allowed_types.append("application/pdf")

    def validate(self, response):
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_size:
            return False, f"Response too large: {content_length} bytes"
        if len(response.content) > self.max_size:
            return False, f"Response body too large: {len(response.content)} bytes"

        content_type = response.headers.get("Content-Type", "").lower()
        type_ok = any(allowed in content_type for allowed in self.allowed_types)

        if not content_type:
            if response.content[:100].strip().lower().startswith((b'<', b'<!', b'<?')):
                type_ok = True

        if not type_ok and self.config.get("block_binary_downloads", True):
            header = response.content[:8]
            for sig in self.BINARY_SIGNATURES:
                if header.startswith(sig):
                    return False, f"Binary file detected (blocked): {content_type}"
            try:
                response.content[:500].decode('utf-8')
                type_ok = True
            except UnicodeDecodeError:
                return False, f"Non-text content blocked: {content_type}"

        return True, "ok"


# ─── Telegram scraper ────────────────────────────────────────────────────────

try:
    from telethon import TelegramClient
    from telethon.errors import (
        SessionPasswordNeededError, PhoneCodeInvalidError,
        FloodWaitError, AuthKeyUnregisteredError,
    )
    from telethon.tl.types import Channel, Chat
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

    @classmethod
    def reset(cls):
        """Force a re-selection on next `current()`. Useful for tests;
        production flow should let it persist for the container's life."""
        cls._chosen = None


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
        self.use_tor = bool(tg.get("use_tor"))
        self.scrape_delay_s = int(tg.get("scrape_delay_s") or 3)
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

    async def _with_client(self, fn, *, require_auth=True, on_auth_fail=None):
        """Run `fn(client)` with a connected, authenticated client and
        guaranteed disconnect. Centralizes the connect / auth-check /
        try/finally boilerplate that's in ~15 methods. `on_auth_fail`
        is the value returned when auth is required but missing.

        Coroutines that want a different shape can still call
        _build_client() directly — this helper is opt-in."""
        c = self._build_client()
        await c.connect()
        try:
            if require_auth and not await c.is_user_authorized():
                log.warning("[darkmtproto] not authenticated — "
                            "session expired or never completed")
                return on_auth_fail
            return await fn(c)
        finally:
            try: await c.disconnect()
            except Exception: pass

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
            p = self.config.get("proxy", {})
            return ("socks5", p.get("host", "tor"), int(p.get("port", 9050)))
        if self.proxy_host:
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
        return TelegramClient(**kwargs)

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
                "authenticated": self._check_authorized() if sess_exists else False,
                "proxy": self._proxy_tuple(),
                "use_tor": self.use_tor}

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
                # Tighten permissions on the session file — it IS a
                # credential.
                for p in (self.session_path,
                          self.session_path + ".session"):
                    if os.path.exists(p):
                        try: os.chmod(p, 0o600)
                        except Exception: pass
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
                    for p in (self.session_path,
                              self.session_path + ".session"):
                        if os.path.exists(p):
                            try: os.chmod(p, 0o600)
                            except Exception: pass
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
                ChannelParticipantsAdmins, ChannelParticipantCreator,
                ChatAdminRights)
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
        """Return up to `limit` messages newer than `since_msg_id`. Each
        entry is a rich dict suitable for storage in tg_messages:

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
        Best-effort: returns [] on any Telethon error so the monitor loop
        never crashes. Writes a warning to the log on auth failure or
        resolution errors so the operator can see WHY it returned empty.

        Forum-channel aware: if the channel's entity has .forum=True,
        fetches the topic list once and labels each message with its
        topic_id / topic_title so the UI can group by thread."""
        limit = limit or self.scrape_limit
        self._record_call(channel_id)
        self.last_fetch_error = None
        # Prefer the @handle when we have it — resolve-by-username is far
        # more reliable than resolve-by-numeric-id across session resets.
        entity = self._entity_ref(channel_id, username)

        async def _go():
            # GetForumTopicsRequest moved between Telethon versions:
            #   * ≤1.32 or so: telethon.tl.functions.channels
            #   * ≥1.33 (current 1.43): telethon.tl.functions.messages
            # Both paths tried; if neither works we degrade gracefully
            # and just don't label messages with their forum topic.
            GetForumTopicsRequest = None
            try:
                from telethon.tl.functions.messages \
                    import GetForumTopicsRequest
            except ImportError:
                try:
                    from telethon.tl.functions.channels \
                        import GetForumTopicsRequest
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
                if GetForumTopicsRequest is not None:
                    try:
                        ent = await c.get_entity(entity)
                        if bool(getattr(ent, "forum", False)):
                            resp = await c(GetForumTopicsRequest(
                                channel=ent, offset_date=None, offset_id=0,
                                offset_topic=0, limit=100))
                            for t in getattr(resp, "topics", []) or []:
                                topic_map[getattr(t, "id", None)] = \
                                    getattr(t, "title", None)
                    except Exception as e:
                        log.debug(f"forum topic fetch skipped for {entity}: {e}")

                kwargs = {"entity": entity, "limit": limit}
                if since_msg_id:
                    kwargs["min_id"] = int(since_msg_id)
                if before_msg_id:
                    # max_id is exclusive — returns messages with id < max_id.
                    # Used by multi-batch historical scrapes to walk backward
                    # through history.
                    kwargs["max_id"] = int(before_msg_id)
                out = []
                async for msg in c.iter_messages(**kwargs):
                    if msg is None: continue
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
            from telethon.tl.types import Channel, Chat
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
        UI layer can fall back to local results.

        `username` (optional): when set, resolved as @handle — more
        reliable than the numeric channel_id across session rebuilds.
        `min_date_iso` (optional) caps results to messages on/after that date.
        """
        self._record_call(channel_id)
        entity = self._entity_ref(channel_id, username)
        async def _go():
            c = self._build_client()
            await c.connect()
            try:
                if not await c.is_user_authorized():
                    log.warning("[tg] search_in_channel: not authenticated")
                    return []
                kwargs = {"entity": entity, "search": query,
                          "limit": limit}
                if min_date_iso:
                    try:
                        from datetime import datetime as _dt
                        kwargs["offset_date"] = _dt.fromisoformat(min_date_iso)
                    except Exception:
                        pass
                out = []
                async for msg in c.iter_messages(**kwargs):
                    if msg is None: continue
                    text = msg.message or ""
                    if not text: continue
                    out.append({
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
            log.warning(f"TG search flood-wait {e.seconds}s on channel {channel_id}")
            return []
        except Exception as e:
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
                    not c["verified"], c["scam"],
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

        channels = sorted(agg_channels.values(),
                          key=lambda r: -r["score"])[:limit]
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


# ─── Persistent Telethon loop (infra for future migration) ───────────────────

class PersistentTelethonLoop:
    """A dedicated thread owning one asyncio event loop. Callers submit
    coroutines via submit(); the loop runs them and the calling thread
    blocks on the returned Future.

    Benefits over per-call asyncio.run(): no connect/disconnect churn (a
    persistent client lives on this loop), better fingerprint (normal
    clients stay connected), unlocks QR login + live events on the same
    client. Currently UNUSED in the hot path — each scraper method still
    runs its own asyncio.run — this class is infrastructure for a future
    migration. Enabled via config.telegram.persistent_client=true, then
    consumers should route through run_on_persistent() instead of
    _run_coro.

    Not yet enabled because the migration touches every scraper method
    and requires careful thread-safety review (shared client state +
    re-entrancy). Ship as opt-in once the migration is complete."""

    def __init__(self):
        self._loop = None
        self._thread = None
        self._ready = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive(): return
        self._thread = threading.Thread(
            target=self._run, name="TelethonPersistent", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)

    def _run(self):
        import asyncio
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try: self._loop.run_forever()
        finally:
            try: self._loop.close()
            except Exception: pass
            self._loop = None

    def stop(self, timeout=5):
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=timeout)

    def submit(self, coro):
        """Run `coro` on the persistent loop, block until it returns."""
        import asyncio
        if not self._loop or not self._loop.is_running():
            raise RuntimeError("persistent loop not running — call start()")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result()


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
                    try:
                        cid = getattr(event.chat_id, "channel_id", None) \
                              or event.chat_id
                        # Telethon normalizes to negative IDs for channels;
                        # use abs when comparing against our positive ids.
                        cid_norm = abs(int(cid)) if cid is not None else None
                        if cid_norm and cid_norm not in {abs(int(c))
                                                         for c in self._channel_ids}:
                            return
                        msg = event.message
                        text = msg.message or ""
                        if not text: return
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
                            "has_media": bool(getattr(msg, "media", None)),
                            "media_type": DarkMTProto._media_type(msg),
                            "fwd_from_username": fwd_user,
                            "fwd_from_msg_id": fwd_msg,
                            "reply_to_msg_id": reply_to,
                        }
                        username = (getattr(event.chat, "username", None)
                                    if event.chat else None)
                        # Dispatch synchronously into caller-land. Caller
                        # is responsible for thread safety + not blocking
                        # here for long (use a queue if heavy work).
                        self.on_message(cid_norm, username, msg_dict)
                    except Exception as e:
                        log.warning(f"[tg-live] handler error: {e}")

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

    async def _sleep(self, s):
        """Interruptable sleep — wakes on stop event."""
        import asyncio
        for _ in range(int(s)):
            if self._stop.is_set(): return
            await asyncio.sleep(1)


# ─── Scan-quality helpers ────────────────────────────────────────────────────

def _ioc_hash(matched_strings):
    """Stable hash of the YARA-matched substrings so the same IOC set on
    the same page/rule collapses under the findings unique index.
    Normalization: lowercase + sort + dedup — minor presentation
    differences between runs don't spawn duplicates."""
    if not matched_strings:
        return ""
    if isinstance(matched_strings, str):
        parts = [p.strip() for p in matched_strings.split(",")]
    else:
        parts = [str(p).strip() for p in matched_strings]
    norm = "|".join(sorted({p.lower() for p in parts if p}))
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()[:32]


# Generic freemail / no-reply patterns treated as weak matches. Hits that
# only comprise these are almost always noise on leak-site index pages
# (footer contact addresses, example code, etc.).
_FP_GENERIC_EMAIL = re.compile(
    r"^(?:no-?reply|info|admin|support|contact|webmaster|test|example|"
    r"root|hello|hi|sales)@", re.I)


def compute_fp_score(matched_strings, snippet, page_type, extracted=None,
                      context="text"):
    """Return a false-positive score in [0..100]; higher = more likely noise.

    This is intentionally a simple, explainable heuristic rather than a
    trained model — operators can reason about why a finding got flagged.
    Signals:
      - +25 on login/register pages (routine auth UI mentions "password")
      - +20 when matches are only generic freemail addresses
      - +15 when the single matched string is < 4 chars (substring noise)
      - +10 when the hit came from HTML attrs/meta (context='html') —
              less reliable than body-text hits
      - -15 when the page also extracted ≥3 distinct IOC types (cred
              dumps, wallet addresses, onions) — real leak content tends
              to cluster IOCs
      - -10 when the snippet contains strong leak verbs (leaked, dumped,
              stolen, combo)
    """
    score = 0
    pt = (page_type or "").lower()
    if pt in ("login", "register", "login_register"):
        score += 25
    if context == "html":
        score += 10
    parts = []
    if matched_strings:
        parts = [p.strip() for p in (
            matched_strings if isinstance(matched_strings, list)
            else matched_strings.split(","))]
    parts = [p for p in parts if p]
    if parts and all(_FP_GENERIC_EMAIL.match(p) for p in parts):
        score += 20
    if parts and len(parts) == 1 and len(parts[0]) < 4:
        score += 15
    if extracted and sum(1 for v in extracted.values() if v) >= 3:
        score -= 15
    if snippet and re.search(
            r"\b(leaked|stolen|dumped|combo|breach|ransom)\b", snippet, re.I):
        score -= 10
    return max(0, min(100, score))


_V3_ONION_LABEL = re.compile(r"^[a-z2-7]{56}$")
_V2_ONION_LABEL = re.compile(r"^[a-z2-7]{16}$")


def onion_url_error(url):
    """Return a human-readable error if `url` is an unreachable .onion target.

    Modern Tor dropped v2 hidden services; only 56-char v3 hostnames work.
    Names like ``thehiddenwiki.onion`` are not valid v3 addresses and will
    fail at the SOCKS layer with a misleading "tor_down" error.
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return "malformed URL"
    if not host.endswith(".onion"):
        return None
    label = host[:-6]
    if _V3_ONION_LABEL.match(label):
        return None
    if _V2_ONION_LABEL.match(label):
        return ("v2 .onion deprecated — Tor requires a v3 address "
                "(56-character hostname)")
    return (f"invalid .onion hostname ({host}) — must be 56 lowercase "
            f"base32 characters before .onion")


def classify_fetch_error(exc):
    """Return a short category string for an exception raised by requests.
    Used for adaptive backoff + metrics — finer-grained than a single
    'error' counter. Callers pass the exception, a requests.Response,
    or None (HTTP-level non-2xx handled elsewhere)."""
    if exc is None:
        return "unknown"
    name = type(exc).__name__
    if "Timeout" in name:
        return "timeout"
    if "ConnectionError" in name:
        # ConnectionError wraps Tor-down, DNS-fail, refused, reset.
        msg = str(exc).lower()
        if "socks" in msg or "tor" in msg or "proxy" in msg:
            return "tor_down"
        return "connect"
    if "TooManyRedirects" in name:
        return "redirect"
    if "SSL" in name:
        return "ssl"
    return "unknown"


# ─── Crawler ─────────────────────────────────────────────────────────────────

class DarkWebCrawler:
    def __init__(self, config):
        self.config = config
        proxy_cfg = config["proxy"]
        proxy_url = f"{proxy_cfg['type']}://{proxy_cfg['host']}:{proxy_cfg['port']}"
        self.proxies = {"http": proxy_url, "https": proxy_url}

        self.timeout = config["crawler"]["timeout"]
        self.retries = config["crawler"]["retries"]
        self.retry_delay = config["crawler"]["retry_delay"]
        self.max_depth = config["crawler"]["max_depth"]
        self.max_pages = config["crawler"]["max_pages_per_site"]

        db_path = config["database"]["path"]
        self.db = Database(db_path)
        # user.yar lives next to the SQLite DB, on the writable data mount.
        # The curated yara/ dir stays read-only.
        user_yar_path = os.path.join(
            os.path.dirname(os.path.abspath(db_path)) or ".", "user.yar")
        # Operator-private rules dir is fixed at /app/yara-private so it
        # matches the compose mount. Config can override for tests.
        private_dir = config["yara"].get("private_dir", "/app/yara-private")
        self.scanner = YaraScanner(
            config["yara"]["keywords_file"],
            config["yara"]["categories_file"],
            user_file=user_yar_path,
            private_dir=private_dir,
        )
        self.alerter = Alerter(config["alerts"])
        self.stealth = StealthEngine(config)
        self.validator = ResponseValidator(config)
        self.sanitizer = HTMLSanitizer()
        self.data_extractor = DataExtractor()
        self.loot_dir = config["output"]["loot_dir"]
        self.thumbnails_dir = config["output"].get(
            "thumbnails_dir", os.path.join(self.loot_dir, "thumbnails"))
        self.screenshot_engine = ScreenshotEngine(
            os.path.join(self.loot_dir, "screenshots"),
            thumbnails_dir=self.thumbnails_dir,
            proxy_url=proxy_url,
            mode=config["crawler"].get("screenshot_mode", "tor_render"),
        )
        # Dedicated worker so scan_page() doesn't block on Playwright.
        # sync_playwright is thread-bound, so this worker's _ensure_browser()
        # fires on its own thread and owns the Firefox instance.
        self.screenshot_worker = ScreenshotWorker(
            self.screenshot_engine, self.db,
            max_queue=int(config["crawler"].get("screenshot_queue", 64)))
        self.screenshot_worker.start()
        self.security_cfg = config.get("security", {})

        self.save_pages = config["output"]["save_pages"]
        self.save_screenshots = config["output"].get("save_screenshots", True)
        # Only screenshot pages where the highest-scoring finding clears
        # this severity bar. "low"=always, "medium"/"high"/"critical"=more
        # selective. Selective screenshots dominate the cost on big crawls.
        self.screenshot_min_severity = (
            config["output"].get("screenshot_min_severity", "low")).lower()
        self.reports_dir = config["output"]["reports_dir"]

        # Threat-intel feed file: compiled into YaraScanner.intel_rules
        # when present. Refreshed by ThreatIntelFeed.refresh() — see
        # threat_intel module.
        intel_path = os.path.join(
            os.path.dirname(os.path.abspath(db_path)) or ".",
            "threat_intel.yar")
        self.intel_rules_path = intel_path
        self.scanner.load_intel_rules(intel_path)

        # Auto-rescan cadence (hours). 0 disables. Consulted by the
        # monitor scheduler in web.py — see _maybe_auto_rescan().
        self.auto_rescan_hours = int(
            config["crawler"].get("auto_rescan_hours", 0) or 0)

        # Crawler behavior toggles
        cc = config["crawler"]
        self.scan_pdfs = cc.get("scan_pdfs", False)
        self.newnym_between_sites = cc.get("newnym_between_sites", True)
        self.domain_fail_breaker = cc.get("domain_fail_breaker", 3)
        self.tor_control_host = cc.get("tor_control_host", "tor")
        self.tor_control_port = cc.get("tor_control_port", 9051)
        self.tor_control_password = cc.get("tor_control_password", "")

        os.makedirs(self.loot_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(os.path.join(self.loot_dir, "pages"), exist_ok=True)
        os.makedirs(os.path.join(self.loot_dir, "screenshots"), exist_ok=True)
        os.makedirs(self.thumbnails_dir, exist_ok=True)

    def rotate_tor_circuit(self):
        """Request a new Tor circuit via the ControlPort (NEWNYM).
        Silently no-ops if stem or ControlPort is unavailable — scans must
        not fail when operator hasn't enabled the ControlPort.
        """
        if not self.newnym_between_sites or not STEM_AVAILABLE:
            return False
        try:
            with Controller.from_port(
                address=self.tor_control_host,
                port=self.tor_control_port,
            ) as ctrl:
                if self.tor_control_password:
                    ctrl.authenticate(password=self.tor_control_password)
                else:
                    ctrl.authenticate()
                ctrl.signal(Signal.NEWNYM)
            log.info("Tor circuit rotated (NEWNYM)")
            return True
        except Exception as e:
            log.debug(f"NEWNYM skipped: ControlPort unavailable ({e})")
            return False

    def _get_session(self):
        session = requests.Session()
        session.proxies = self.proxies
        session.max_redirects = 3
        return session

    @staticmethod
    def _pdf_to_text(pdf_bytes):
        """Shell out to `pdftotext` (poppler) to extract plain text.
        Returns "" when pdftotext is missing or the file is unreadable —
        the crawler continues as if the page were empty."""
        import subprocess
        try:
            proc = subprocess.run(
                ["pdftotext", "-q", "-enc", "UTF-8", "-", "-"],
                input=pdf_bytes,
                capture_output=True,
                timeout=20,
            )
            if proc.returncode != 0:
                return ""
            return proc.stdout.decode("utf-8", errors="replace")[:500_000]
        except FileNotFoundError:
            log.debug("pdftotext not installed; skipping PDF")
            return ""
        except Exception as e:
            log.debug(f"pdftotext failed: {e}")
            return ""

    def fetch(self, url, session=None, referer=None):
        """Adaptive fetch with categorized errors.

        Returns (response_or_None, error_category_or_None). Callers that
        only care about the payload can still use `resp, _ = fetch(...)`.
        error_category is one of: timeout, connect, tor_down, http_4xx,
        http_5xx, redirect, ssl, rejected, size, None.
        """
        if session is None:
            session = self._get_session()

        onion_err = onion_url_error(url)
        if onion_err:
            log.warning(f"  Invalid .onion URL: {url} — {onion_err}")
            return None, "invalid_onion"

        last_category = "unknown"

        for attempt in range(1, self.retries + 1):
            try:
                headers = self.stealth.get_headers(referer=referer)
                timeout = self.stealth.jitter_timeout(self.timeout)

                resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)

                # check size before downloading
                content_length = resp.headers.get("Content-Length")
                max_size = self.security_cfg.get("max_response_size_mb", 10) * 1024 * 1024
                if content_length and int(content_length) > max_size:
                    log.warning(f"  Response too large ({content_length} bytes), skipping")
                    resp.close()
                    return None, "size"

                # stream with size limit
                chunks = []
                total = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    total += len(chunk)
                    if total > max_size:
                        log.warning(f"  Response exceeded size limit, aborting")
                        resp.close()
                        return None, "size"
                    chunks.append(chunk)

                resp._content = b"".join(chunks)
                resp.encoding = resp.apparent_encoding or "utf-8"

                if resp.status_code == 200:
                    ok, reason = self.validator.validate(resp)
                    if not ok:
                        log.warning(f"  Response rejected: {reason}")
                        return None, "rejected"
                    return resp, None

                # HTTP error. 4xx rarely improves on retry, abort fast;
                # 5xx might (server was transiently overloaded).
                last_category = "http_4xx" if 400 <= resp.status_code < 500 \
                                else "http_5xx"
                log.warning(f"  HTTP {resp.status_code} ({last_category}) "
                            f"attempt {attempt}/{self.retries}: {url}")
                if last_category == "http_4xx":
                    return None, last_category

            except requests.exceptions.ReadTimeout as e:
                last_category = "timeout"
                log.warning(f"  Timeout attempt {attempt}/{self.retries}: {url}")
            except requests.exceptions.ConnectionError as e:
                last_category = classify_fetch_error(e)
                log.warning(f"  Connection ({last_category}) attempt "
                            f"{attempt}/{self.retries}: {url}")
            except requests.exceptions.TooManyRedirects:
                log.warning(f"  Too many redirects: {url}")
                return None, "redirect"
            except requests.exceptions.SSLError as e:
                log.warning(f"  SSL error: {e}")
                return None, "ssl"
            except requests.exceptions.RequestException as e:
                last_category = classify_fetch_error(e)
                log.warning(f"  Request error ({last_category}) attempt "
                            f"{attempt}/{self.retries}: {e}")

            if attempt < self.retries:
                # Adaptive backoff: timeouts get longer waits (Tor slow
                # circuit); tor_down short-circuits into a long sleep so
                # we don't burn all retries against a downed proxy.
                mult = {"timeout": 3, "tor_down": 6, "connect": 2,
                        "http_5xx": 2}.get(last_category, 1)
                raw = self.retry_delay * mult * (2 ** (attempt - 1)) \
                      + random.uniform(0, 5)
                delay = min(raw, self.retry_delay * 60)
                log.debug(f"  Retrying in {delay:.1f}s (attempt {attempt}/{self.retries})")
                time.sleep(delay)

        log.warning(f"  fetch() giving up after {self.retries} retries "
                    f"(last={last_category}): {url}")
        return None, last_category

    def extract_text(self, html):
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript", "iframe", "object"]):
            tag.decompose()
        return " ".join(soup.stripped_strings)

    def extract_title(self, html):
        soup = BeautifulSoup(html, "lxml")
        title = soup.find("title")
        if title:
            return title.get_text(strip=True)[:200]
        return None

    def extract_links(self, html, base_url):
        soup = BeautifulSoup(html, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if ".onion" in parsed.netloc:
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean.endswith("/"):
                    clean = clean[:-1]
                links.add(clean)
        return links

    def extract_forms(self, html, base_url):
        """Inventory <form> elements for later review. No auto-submission."""
        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return forms
        for form in soup.find_all("form"):
            action = form.get("action", "") or base_url
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "tag": inp.name,
                    "name": inp.get("name"),
                    "type": inp.get("type"),
                })
            forms.append({
                "action": urljoin(base_url, action),
                "method": method,
                "inputs": inputs,
            })
        return forms

    # Signals that distinguish a register form from a login form.
    _REGISTER_HINTS = re.compile(
        r"\b(sign\s*up|register|registration|create\s+(an?\s+)?account|"
        r"new\s+user|join\s+now|confirm\s+password|repeat\s+password|"
        r"password\s*(confirmation|confirm))\b", re.I)

    @classmethod
    def classify_page(cls, html, title=""):
        """Label a page based on its form structure so findings on routine
        login/register pages can be visually distinguished from findings on
        actual leak / dump content. Returns one of:
          'login' | 'register' | 'login_register' | 'other'

        A form counts as an "auth form" if it has a password input AND
        either an email input or an input named user/email/login/account.
        Register vs. login is decided by text cues in the form (or the
        page title) — sign up, create account, confirm password, etc.
        """
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return "other"
        has_login = has_register = False
        for form in soup.find_all("form"):
            if not form.find("input", {"type": "password"}):
                continue
            # Look for a username / email identity field.
            has_ident = bool(form.find("input", {"type": "email"})) or \
                        bool(form.find("input", attrs={
                            "name": re.compile(
                                r"(email|user(name)?|login|account)",
                                re.I)}))
            if not has_ident:
                continue
            form_text = form.get_text(" ", strip=True)
            combined = (form_text + " " + (title or ""))
            # Count password inputs: 2+ almost always means a register
            # form ("password" + "confirm password").
            pw_count = len(form.find_all("input", {"type": "password"}))
            looks_register = (pw_count >= 2 or
                              bool(cls._REGISTER_HINTS.search(combined)))
            if looks_register:
                has_register = True
            else:
                has_login = True
        if has_login and has_register: return "login_register"
        if has_register:               return "register"
        if has_login:                  return "login"
        return "other"

    def extract_snippet(self, text, keyword, context=150, fallback_html=None):
        """Return ~300 chars of context centered on the first `keyword` hit.
        If the keyword isn't in the stripped text (common when the YARA rule
        matched in html-context — an attribute, <meta>, or comment),
        optionally search `fallback_html` and strip tags only inside the
        snippet window so the operator still sees meaningful surroundings.
        """
        if not keyword:
            return text[:300]
        idx = text.lower().find(keyword.lower())
        if idx != -1:
            start = max(0, idx - context)
            end = min(len(text), idx + len(keyword) + context)
            return f"...{text[start:end]}..."
        if fallback_html:
            hidx = fallback_html.lower().find(keyword.lower())
            if hidx != -1:
                start = max(0, hidx - context)
                end = min(len(fallback_html), hidx + len(keyword) + context)
                window = fallback_html[start:end]
                # Try a cleaner tag-stripped view first. If stripping removes
                # the keyword (match was inside an attribute / tag), fall back
                # to the raw HTML so the operator still sees the context and
                # the highlighter has something to mark.
                stripped = re.sub(r"<[^>]+>", " ", window)
                stripped = re.sub(r"\s+", " ", stripped).strip()
                if keyword.lower() in stripped.lower():
                    return f"…[html] {stripped}…"
                compact = re.sub(r"\s+", " ", window).strip()
                return f"…[html-raw] {compact[:320]}…"
        return text[:300]

    def score_to_severity(self, score):
        if score >= 100: return "critical"
        elif score >= 60: return "high"
        elif score >= 30: return "medium"
        return "low"

    def save_page(self, url, html):
        if not self.save_pages:
            return
        if self.security_cfg.get("sanitize_saved_html", True):
            html = self.sanitizer.sanitize(html, self.security_cfg)
        safe_name = re.sub(r'[^\w]', '_', url)[:100]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.loot_dir, "pages", f"{safe_name}_{ts}.html")
        try:
            with open(path, "w", errors="replace") as f:
                f.write(html)
        except Exception as e:
            log.error(f"Failed to save page: {e}")

    def _yara_match_text(self, url_id, page_url, text):
        """Run YARA rules against a piece of plain text and write findings.
        Runs text + lower-cased text in parallel, then de-dupes by rule
        name — keywords.yar isn't always `nocase` but auto-generated user
        rules are, so an all-caps leak message needs both views.
        Returns the number of findings written."""
        raw_hits, lower_hits = self.scanner.scan_parallel(text, text.lower())
        seen_rules = set()
        finding_count = 0
        for hits in (raw_hits, lower_hits):
            for kw in hits.get("keywords", []):
                if kw["rule"] in seen_rules:
                    continue
                seen_rules.add(kw["rule"])
                score = kw["score"]
                severity = self.score_to_severity(score)
                matched_list = kw["matched_strings"][:5]
                matched = ", ".join(matched_list)
                snippet = ""
                if matched_list:
                    snippet = self.extract_snippet(text, matched_list[0])
                ioc_h = _ioc_hash(matched_list)
                fp = compute_fp_score(matched_list, snippet, None)
                self.db.add_finding(
                    url_id, page_url, kw["rule"], "keyword:text",
                    score, matched, snippet, severity,
                    ioc_hash=ioc_h, fp_score=fp)
                finding_count += 1
                if severity in ("critical", "high"):
                    log.warning(f"  ALERT {severity.upper()} | {kw['rule']} "
                                f"(score:{score} fp:{fp}) | {page_url}")
                    if fp < 60:
                        self.alerter.send({
                            "rule_name": kw["rule"], "score": score,
                            "severity": severity, "page_url": page_url,
                            "matched_strings": matched, "snippet": snippet,
                            "fp_score": fp})
                else:
                    log.info(f"  MATCH {severity} | {kw['rule']} "
                             f"(score:{score} fp:{fp}) | {page_url}")
        # Categories: log-only (design choice — categories classify, not alert).
        cats = set()
        for hits in (raw_hits, lower_hits):
            for c in hits.get("categories", []):
                cats.add(c["rule"])
        if cats:
            log.info(f"  Categories: {', '.join(sorted(cats))}")
        return finding_count

    def scan_tg_message(self, url_id, channel_username, msg):
        """Route a single Telegram message through the same pipeline as a
        web page: dedup by content-hash, YARA scan, IOC extract, findings
        write. Also persists rich message metadata (sender, views,
        reactions, fwd/reply, media flag) in tg_messages so the UI can
        render a proper channel timeline.

        `msg` is the dict returned by DarkMTProto.fetch_new_messages().
        Returns the number of findings produced.
        """
        text = msg.get("text") or ""
        has_media = bool(msg.get("has_media"))
        media_type = msg.get("media_type") or "media"
        # Media-only messages (photos/documents with no caption) used to
        # be dropped here — that made image-heavy channels look empty.
        # Now we persist them with a synthetic text marker so the UI
        # shows + downloads them. YARA still runs on the real text (if
        # any); rules won't spuriously match the "[photo]" marker.
        if not text and not has_media:
            return 0
        synthetic_text = text or f"[{media_type}]"
        page_url = f"https://t.me/{channel_username}/{msg['msg_id']}"
        date_iso = msg.get("date_iso") or ""
        title = f"[{channel_username}] {date_iso}".strip()
        # Dedup key: real text when present (so two channels reposting
        # the same leak collapse), otherwise msg_id-based to keep every
        # media-only post unique (same "[photo]" marker would otherwise
        # collide across the entire channel).
        hash_basis = text if text else f"{page_url}|media"
        content_hash = hashlib.sha256(hash_basis.encode("utf-8")).hexdigest()

        if self.db.page_seen(content_hash):
            return 0

        extracted = self.data_extractor.extract(text) if text else {}

        # No screenshot for text messages; no form inventory; no html ctx.
        self.db.add_page(
            url_id, page_url, title, content_hash,
            extracted_data=extracted,
            screenshot_path=None, thumbnail_path=None,
            page_type="telegram_message")

        # Look up the page row we just inserted so we can link it from
        # tg_messages. SQLite doesn't have RETURNING on older versions;
        # simplest path is a follow-up SELECT by content_hash.
        row = self.db.conn.execute(
            "SELECT id FROM pages WHERE content_hash = ? "
            "ORDER BY id DESC LIMIT 1", (content_hash,)).fetchone()
        page_id = row[0] if row else None
        if page_id is not None:
            try:
                # Persist the synthetic text for media-only messages so the
                # UI's message list shows SOMETHING ("[photo]") instead of
                # an empty row.
                msg_persist = dict(msg)
                if not msg_persist.get("text"):
                    msg_persist["text"] = synthetic_text
                self.db.add_tg_message(url_id, page_id, msg_persist)
            except Exception as e:
                log.debug(f"add_tg_message failed: {e}")

        # YARA only meaningful on real text. For media-only messages
        # (where text is the synthetic marker) we skip scanning to avoid
        # a burst of false "[photo]"-substring matches.
        finding_count = self._yara_match_text(url_id, page_url, text) if text else 0
        if extracted:
            for ioc_type, iocs in extracted.items():
                log.info(f"  Extracted {ioc_type}: {len(iocs)} item(s)")
        return finding_count

    def rescan_tg_channel(self, url_id):
        """Re-run YARA rules against every stored message for a channel.
        Use when the operator has added new user keywords AFTER historical
        scraping — the old messages are already in `pages` (page_seen
        dedup would skip them on a re-scrape) so fresh rule evaluation
        needs this dedicated path.

        Returns {scanned, findings}."""
        rows = self.db.conn.execute(
            "SELECT m.url_id, m.msg_id, m.text, u.tg_username "
            "FROM tg_messages m JOIN urls u ON u.id = m.url_id "
            "WHERE m.url_id = ? AND m.text IS NOT NULL AND m.text != ''",
            (url_id,)).fetchall()
        scanned = 0
        found = 0
        for r in rows:
            url_id_, msg_id, text, username = r
            page_url = f"https://t.me/{username}/{msg_id}"
            # Purge any prior findings on this page_url so rescan is idempotent.
            self.db.conn.execute(
                "DELETE FROM findings WHERE url_id = ? AND page_url = ?",
                (url_id_, page_url))
            found += self._yara_match_text(url_id_, page_url, text)
            scanned += 1
        self.db.conn.commit()
        return {"scanned": scanned, "findings": found}

    # Severity ordering used for the selective-screenshot threshold.
    _SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def _severity_meets(self, severity, threshold):
        return (self._SEVERITY_RANK.get(severity, 0)
                >= self._SEVERITY_RANK.get(threshold, 0))

    def scan_page(self, url_id, page_url, html):
        text = self.extract_text(html)
        title = self.extract_title(html)
        content_hash = hashlib.sha256(text.encode()).hexdigest()

        # Dedup BEFORE any YARA or IOC work — scanning duplicates wastes CPU.
        if self.db.page_seen(content_hash):
            log.debug(f"  Skipping duplicate content: {page_url}")
            return 0

        # IOC extraction: clean text + HTML context (attrs, meta, comments, <pre>).
        # Keys from both passes are merged; dedup via set().
        extracted = self.data_extractor.extract(text)
        html_context = self.data_extractor.harvest_html_context(html)
        if html_context:
            ctx_iocs = self.data_extractor.extract(html_context)
            for k, v in ctx_iocs.items():
                merged = set(extracted.get(k, [])) | set(v)
                extracted[k] = list(merged)[:50]

        # Classify so the UI can distinguish a login/register page from
        # actual leak content; also helps operators triage noisy rules.
        page_type = self.classify_page(html, title)
        if page_type != "other":
            log.info(f"  Page type: {page_type}")

        # Insert the page row up front WITHOUT screenshot paths — the
        # screenshot worker (if enabled) patches them later. text_snapshot
        # is persisted so the rescan endpoint can re-run rules offline.
        page_id = self.db.add_page(
            url_id, page_url, title, content_hash,
            extracted_data=extracted,
            screenshot_path=None,
            thumbnail_path=None,
            page_type=page_type,
            text_snapshot=text)

        # Inventory form endpoints (no auto-submission).
        for form in self.extract_forms(html, page_url):
            self.db.add_form(url_id, page_url, form["action"],
                              form["method"], form["inputs"])

        # Parallel dual-mode YARA: text + html passes in concurrent threads.
        # _merge_yara_hits prefers the higher-score hit when a rule fires
        # in both contexts.
        text_hits, html_hits = self.scanner.scan_parallel(text.lower(), html)
        results = self._merge_yara_hits(text_hits, html_hits)

        finding_count = 0
        max_severity = "low"
        max_score = 0

        for kw in results["keywords"]:
            score = kw["score"]
            severity = self.score_to_severity(score)
            matched_list = kw["matched_strings"][:5]
            matched = ", ".join(matched_list)
            ctx = kw.get("context", "text")

            # `matched_strings` are the literal substrings that matched
            # (email@example.com, "combo list", etc.), so the snippet helper
            # can locate and center context around the actual hit.
            snippet = ""
            if matched_list:
                snippet = self.extract_snippet(
                    text, matched_list[0], fallback_html=html)

            ioc_h = _ioc_hash(matched_list)
            fp = compute_fp_score(matched_list, snippet, page_type,
                                    extracted=extracted, context=ctx)

            rule_type = f"keyword:{ctx}"
            self.db.add_finding(url_id, page_url, kw["rule"], rule_type,
                                score, matched, snippet, severity,
                                ioc_hash=ioc_h, fp_score=fp)

            finding = {"rule_name": kw["rule"], "score": score,
                        "severity": severity, "page_url": page_url,
                        "matched_strings": matched, "snippet": snippet,
                        "fp_score": fp}

            # Alerts: suppress when FP score is >= 60 (strong noise signal).
            if severity in ("critical", "high"):
                log.warning(f"  ALERT {severity.upper()} | {kw['rule']} "
                            f"(score:{score} fp:{fp}) | {page_url}")
                if fp < 60:
                    self.alerter.send(finding)
                else:
                    log.info(f"  Alert suppressed (fp:{fp})")
            else:
                log.info(f"  MATCH {severity} | {kw['rule']} "
                         f"(score:{score} fp:{fp}) | {page_url}")

            if self._SEVERITY_RANK.get(severity, 0) > \
                    self._SEVERITY_RANK.get(max_severity, 0):
                max_severity = severity
            if score > max_score:
                max_score = score
            finding_count += 1

        # Cache the worst finding severity on the page for UI + selective
        # screenshotting.
        if finding_count:
            self.db.update_page_severity(page_id, max_severity, max_score)

        # Screenshot now — but only when the findings justify the cost.
        # On a 100-page crawl, selective screenshotting cuts Playwright
        # time by 80%+. Enqueue to the worker; scan_page returns fast.
        if self.save_screenshots and self._severity_meets(
                max_severity, self.screenshot_min_severity):
            worker = getattr(self, "screenshot_worker", None)
            if worker is not None:
                if not worker.enqueue(page_id, html, page_url):
                    log.debug("  Screenshot queue full — skipping")
            else:
                spath, tpath = self.screenshot_engine.capture(html, page_url)
                if spath:
                    self.db.update_page_screenshot(page_id, spath, tpath)

        if title:
            log.info(f"  Title: {title}")
        if results["categories"]:
            cats = [c["rule"] for c in results["categories"]]
            log.info(f"  Categories: {', '.join(cats)}")
        if extracted:
            for ioc_type, iocs in extracted.items():
                log.info(f"  Extracted {ioc_type}: {len(iocs)} item(s)")

        return finding_count

    # ── Bulk rescan ──────────────────────────────────────────────────────
    def rescan_pages(self, url_id=None):
        """Re-run YARA across every stored page's `text_snapshot` for a
        given URL (or all URLs). Purges prior findings on the page first
        so results are a clean replacement, not an accumulation. Useful
        after the operator adds new keywords / threat-intel rules.

        Returns {scanned, findings, skipped}.
        """
        rows = self.db.iter_pages_with_text(url_id=url_id)
        scanned = 0
        findings_total = 0
        skipped = 0
        for page_id, uid, page_url, text in rows:
            if not text:
                skipped += 1
                continue
            self.db.purge_findings_for_page(uid, page_url)
            text_hits, html_hits = self.scanner.scan_parallel(text.lower(), text)
            merged = self._merge_yara_hits(text_hits, html_hits)
            page_max_sev = "low"
            page_max_score = 0
            page_findings = 0
            for kw in merged["keywords"]:
                score = kw["score"]
                severity = self.score_to_severity(score)
                matched_list = kw["matched_strings"][:5]
                matched = ", ".join(matched_list)
                snippet = ""
                if matched_list:
                    snippet = self.extract_snippet(text, matched_list[0])
                ioc_h = _ioc_hash(matched_list)
                fp = compute_fp_score(matched_list, snippet, None,
                                        context=kw.get("context", "text"))
                self.db.add_finding(
                    uid, page_url, kw["rule"],
                    f"keyword:{kw.get('context','text')}",
                    score, matched, snippet, severity,
                    ioc_hash=ioc_h, fp_score=fp)
                page_findings += 1
                if self._SEVERITY_RANK.get(severity, 0) > \
                        self._SEVERITY_RANK.get(page_max_sev, 0):
                    page_max_sev = severity
                if score > page_max_score:
                    page_max_score = score
            if page_findings:
                self.db.update_page_severity(page_id, page_max_sev, page_max_score)
            scanned += 1
            findings_total += page_findings
        if url_id is None:
            self.db.ops_set("last_rescan_at", datetime.utcnow().isoformat())
        log.info(f"rescan_pages: scanned={scanned} findings={findings_total} "
                 f"skipped={skipped}")
        return {"scanned": scanned, "findings": findings_total, "skipped": skipped}

    @staticmethod
    def _merge_yara_hits(text_hits, html_hits):
        """Merge text-mode and html-mode scans, preferring the higher-score
        hit when the same rule fires in both. Annotates each kept hit with
        the context ('text' or 'html') so findings are auditable."""
        by_rule = {}
        for h in text_hits.get("keywords", []):
            key = h["rule"]
            by_rule[key] = {**h, "context": "text"}
        for h in html_hits.get("keywords", []):
            key = h["rule"]
            if key not in by_rule or h["score"] > by_rule[key]["score"]:
                by_rule[key] = {**h, "context": "html"}
        cats = {c["rule"]: c for c in text_hits.get("categories", [])}
        for c in html_hits.get("categories", []):
            cats.setdefault(c["rule"], c)
        return {"keywords": list(by_rule.values()), "categories": list(cats.values())}

    def crawl_site(self, url_id, base_url, stop_event=None, max_depth=None):
        session = self._get_session()
        # Opsec: clear any cookies carried over from a prior crawl_site call
        # on the same crawler instance — prevents cross-target correlation.
        session.cookies.clear()

        visited = set()
        to_visit = [(base_url, 0, None)]
        total_findings = 0
        pages_scanned = 0
        consecutive_fails = 0
        effective_depth = max_depth if max_depth is not None else self.max_depth
        base_domain = urlparse(base_url).netloc

        while to_visit and pages_scanned < self.max_pages:
            if stop_event and stop_event.is_set():
                log.info("Scan stopped by user")
                break

            current_url, depth, referer = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            if pages_scanned > 0:
                self.stealth.delay()

            # Opsec: only send a Referer if the previous URL shared the same
            # host. Cross-host referrers on onion traversal leak topology of
            # the operator's crawl path.
            send_referer = None
            if referer:
                try:
                    ref_host = urlparse(referer).netloc
                    tgt_host = urlparse(current_url).netloc
                    if ref_host and ref_host == tgt_host:
                        send_referer = referer
                except Exception:
                    pass

            log.info(f"[depth:{depth}] Fetching: {current_url}")
            resp, err_category = self.fetch(
                current_url, session, referer=send_referer)

            if resp is None:
                log.warning(f"  FAIL ({err_category}) after {self.retries} retries")
                consecutive_fails += 1
                # Persist error category so the UI + adaptive scheduler can
                # see why a URL is flaky (Tor vs. 4xx vs. timeout).
                try: self.db.record_url_error(url_id, err_category or "unknown")
                except Exception: pass
                # Per-domain circuit breaker: after N consecutive failures,
                # drop remaining queued links from this host and stop.
                if consecutive_fails >= self.domain_fail_breaker:
                    log.warning(
                        f"  Circuit breaker tripped after {consecutive_fails} "
                        f"consecutive failures on {base_domain}; aborting site.")
                    break
                continue

            consecutive_fails = 0
            try: self.db.clear_url_errors(url_id)
            except Exception: pass
            content_type = resp.headers.get("Content-Type", "").lower()

            # Opt-in PDF handling: convert to text, wrap in minimal HTML so
            # the rest of the pipeline (YARA, IOC, save, screenshot) works
            # uniformly. Off by default; requires `pdftotext` binary.
            if self.scan_pdfs and "application/pdf" in content_type:
                pdf_text = self._pdf_to_text(resp.content)
                if not pdf_text:
                    log.debug(f"  PDF text extraction yielded nothing: {current_url}")
                    continue
                html = f"<html><head><title>{current_url}</title></head>" \
                       f"<body><pre>{pdf_text}</pre></body></html>"
            else:
                html = resp.text

            pages_scanned += 1

            self.save_page(current_url, html)
            findings = self.scan_page(url_id, current_url, html)
            total_findings += findings

            if depth < effective_depth:
                links = self.extract_links(html, current_url)
                for link in links:
                    link_domain = urlparse(link).netloc
                    if link_domain == base_domain and link not in visited:
                        to_visit.append((link, depth + 1, current_url))

        return pages_scanned, total_findings

    def crawl_url(self, url, stop_event=None, max_depth=None):
        if not url.startswith("http"):
            url = f"http://{url}"
        self.db.add_url(url, source="manual")
        rows = self.db.conn.execute("SELECT id, url FROM urls WHERE url = ?", (url,)).fetchall()
        if not rows:
            log.error("Failed to add URL to database")
            return
        url_id, db_url = rows[0]
        log.info(f"Crawling: {db_url}")
        pages, findings = self.crawl_site(url_id, db_url, stop_event=stop_event, max_depth=max_depth)
        self.db.update_scan(url_id, 200 if pages > 0 else 404)
        log.info(f"Done: {pages} pages scanned, {findings} findings")
        return pages, findings

    def crawl_all(self, stop_event=None):
        rescan_days = self.config["crawler"]["rescan_days"]
        urls = self.db.get_urls_to_scan(rescan_days)
        if not urls:
            log.info("No URLs due for scanning.")
            return

        log.info(f"Found {len(urls)} URLs to scan")
        started = datetime.now().isoformat()
        total_pages = 0
        total_findings = 0
        total_errors = 0

        for idx, (url_id, url) in enumerate(urls):
            if stop_event and stop_event.is_set():
                log.info("Scan stopped by user")
                break

            # Rotate Tor circuit between sites (best-effort; silent no-op
            # if ControlPort unreachable). Skip for the very first site
            # since we haven't used the current circuit yet.
            if idx > 0:
                self.rotate_tor_circuit()

            try:
                if not url.startswith("http"):
                    url = f"http://{url}"
                log.info(f"\n{'='*60}")
                log.info(f"Scanning: {url}")
                log.info(f"{'='*60}")

                pages, findings = self.crawl_site(url_id, url, stop_event=stop_event)
                self.db.update_scan(url_id, 200 if pages > 0 else 404)
                total_pages += pages
                total_findings += findings

                if pages == 0:
                    self.db.increment_fail(url_id)

                if stop_event and stop_event.is_set():
                    break
                time.sleep(random.uniform(5, 15))

            except Exception as e:
                log.error(f"Error crawling {url}: {e}")
                self.db.increment_fail(url_id)
                total_errors += 1

        finished = datetime.now().isoformat()
        self.db.log_scan(started, finished, len(urls), total_pages, total_findings, total_errors)

        log.info(f"\n{'='*60}")
        log.info(f"Scan complete")
        log.info(f"URLs: {len(urls)} | Pages: {total_pages} | Findings: {total_findings} | Errors: {total_errors}")
        log.info(f"{'='*60}")

    def add_urls_from_file(self, filepath):
        count = 0
        with open(filepath) as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith("#"):
                    if not url.startswith("http"):
                        url = f"http://{url}"
                    self.db.add_url(url, source="file")
                    count += 1
        log.info(f"Imported {count} URLs from {filepath}")

    def search_findings(self, keyword=None, min_score=0, limit=50):
        findings = self.db.get_findings(min_score=min_score, limit=limit)
        if keyword:
            findings = [f for f in findings if keyword.lower() in json.dumps(f).lower()]
        return findings

    def generate_report(self, min_score=0):
        findings = self.db.get_findings(min_score=min_score, limit=1000)
        stats = self.db.get_stats()
        report = {"generated_at": datetime.now().isoformat(), "statistics": stats, "findings": findings}

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.reports_dir, f"report_{ts}.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        summary_path = os.path.join(self.reports_dir, f"summary_{ts}.txt")
        with open(summary_path, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("  DARKWATCH SCAN REPORT\n")
            f.write(f"  Generated: {report['generated_at']}\n")
            f.write("=" * 60 + "\n\n")
            f.write("STATISTICS\n" + "-" * 40 + "\n")
            for k, v in stats.items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")

            for sev in ["critical", "high", "medium", "low"]:
                sev_findings = [x for x in findings if x.get("severity") == sev]
                if sev_findings:
                    f.write(f"\n{sev.upper()} FINDINGS ({len(sev_findings)})\n" + "-" * 40 + "\n")
                    for finding in sev_findings:
                        f.write(f"  Rule: {finding['rule_name']}\n")
                        f.write(f"  Score: {finding['score']}\n")
                        f.write(f"  URL: {finding['page_url']}\n")
                        f.write(f"  Matched: {finding['matched_strings']}\n")
                        if finding.get("snippet"):
                            f.write(f"  Snippet: {finding['snippet'][:200]}\n")
                        f.write(f"  Found: {finding['found_at']}\n\n")

        log.info(f"Report saved: {report_path}")
        log.info(f"Summary saved: {summary_path}")
        return report_path, summary_path


# ─── CLI ─────────────────────────────────────────────────────────────────────

# Match strings of the form "${VAR_NAME}" — used by load_config() to
# substitute environment variables into config values so secrets stay
# out of the committed config.json. Whole-string match only; we don't do
# inline substitution like "prefix-${VAR}-suffix" because none of our
# config fields need that and partial matches make leak-detection harder.
_ENV_PLACEHOLDER_RE = re.compile(r'^\$\{([A-Z_][A-Z0-9_]*)\}$')


def _substitute_env(value):
    """Recursively replace ${VAR} placeholders in a config tree with the
    matching env var. Missing vars resolve to '' and emit a warning so
    misconfiguration shows up in logs instead of silently failing later
    (e.g. int('${TELEGRAM_API_ID}') deep in the Telegram client)."""
    if isinstance(value, str):
        m = _ENV_PLACEHOLDER_RE.match(value)
        if m:
            var = m.group(1)
            if var in os.environ:
                return os.environ[var]
            log.warning(f"config references ${{{var}}} but env var is unset; using ''")
            return ""
        return value
    if isinstance(value, dict):
        return {k: _substitute_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_env(v) for v in value]
    return value


def load_config(config_path):
    config = DEFAULT_CONFIG.copy()
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            user_config = json.load(f)
        # Resolve ${VAR} placeholders against the environment BEFORE
        # merging, so DEFAULT_CONFIG fallbacks aren't shadowed by
        # unsubstituted literal strings.
        user_config = _substitute_env(user_config)
        for key in user_config:
            if isinstance(user_config[key], dict) and key in config:
                config[key].update(user_config[key])
            else:
                config[key] = user_config[key]
    return config


def main():
    parser = argparse.ArgumentParser(
        description="DarkWatch - Dark Web OSINT Crawler & Monitor (Hardened)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python darkwatch.py --url http://target.onion
  python darkwatch.py --url http://target.onion --depth 3
  python darkwatch.py --import-urls urls.txt
  python darkwatch.py --crawl-all
  python darkwatch.py --findings --keyword "example" --min-score 80
  python darkwatch.py --report
  python darkwatch.py --stats
        """)

    parser.add_argument("--config", "-c", default="config.json")
    parser.add_argument("--url", "-u", help="Crawl a single .onion URL")
    parser.add_argument("--depth", "-d", type=int, help="Override crawl depth")
    parser.add_argument("--crawl-all", action="store_true")
    parser.add_argument("--import-urls", dest="import_file")
    parser.add_argument("--findings", action="store_true")
    parser.add_argument("--keyword", "-k")
    parser.add_argument("--min-score", type=int, default=0)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--test-tor", action="store_true")

    args = parser.parse_args()
    setup_logging(args.debug)
    config = load_config(args.config)

    if args.depth:
        config["crawler"]["max_depth"] = args.depth

    crawler = DarkWebCrawler(config)

    if args.test_tor:
        log.info("Testing Tor connectivity...")
        resp, err = crawler.fetch("https://check.torproject.org/api/ip")
        if resp:
            log.info(f"Tor working: {resp.json()}")
        else:
            log.error(f"Tor connection failed! ({err})")
        return

    if args.import_file:
        crawler.add_urls_from_file(args.import_file)
    if args.url:
        crawler.crawl_url(args.url)
    if args.crawl_all:
        crawler.crawl_all()

    if args.findings:
        findings = crawler.search_findings(keyword=args.keyword, min_score=args.min_score)
        if findings:
            for f in findings:
                sev = f.get("severity", "?").upper()
                print(f"[{sev}] {f['rule_name']} (score:{f['score']}) | {f['page_url']}")
                if f.get("snippet"):
                    print(f"  > {f['snippet'][:150]}")
                print()
        else:
            print("No findings match your criteria.")

    if args.report:
        crawler.generate_report(min_score=args.min_score)
    if args.stats:
        stats = crawler.db.get_stats()
        print("\n" + "=" * 40)
        print("  DARKWATCH STATISTICS")
        print("=" * 40)
        for k, v in stats.items():
            print(f"  {k}: {v}")
        print("=" * 40)

    if not any([args.url, args.crawl_all, args.import_file, args.findings, args.report, args.stats, args.test_tor]):
        parser.print_help()


if __name__ == "__main__":
    main()
