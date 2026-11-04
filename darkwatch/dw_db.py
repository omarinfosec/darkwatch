"""
DarkWatch database: the SQLite store (schema, migrations, findings,
Telegram tables, monitor state, retention).

Split out of darkwatch.py, which re-exports `Database` and `utcnow`, so
`from darkwatch import Database` keeps working.
"""

import os
import re
import json
import random
import sqlite3
import logging
import threading
from datetime import datetime, timedelta, timezone

# Same logger as darkwatch.py, so the log lines keep their name.
log = logging.getLogger("darkwatch")


def utcnow():
    """Current UTC time as a naive datetime, like the deprecated
    datetime.utcnow() (Python 3.12+): stored timestamps are naive UTC ISO
    strings, compared as strings or against naive datetimes."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
                -- Lookup indexes for page_seen() (every scanned page and
                -- Telegram message), the per-URL title/thumbnail subqueries
                -- of /api/urls and the findings -> pages join. Without them
                -- each is a full scan of `pages`. None is UNIQUE, so an
                -- older release rolled back onto this database still
                -- inserts its rows as before.
                CREATE INDEX IF NOT EXISTS idx_pages_content_hash
                    ON pages(content_hash);
                CREATE INDEX IF NOT EXISTS idx_pages_url_scanned
                    ON pages(url_id, scanned_at);
                CREATE INDEX IF NOT EXISTS idx_pages_url_page
                    ON pages(url_id, page_url);
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

    def update_page_severity(self, page_id, severity, max_score,
                             raise_only=False):
        """Cache the most serious finding on a page so filters/thumbnails
        don't need a join. `raise_only=True` (rescans, which never remove
        findings) keeps a higher cached severity or score."""
        with self.lock:
            if raise_only:
                rank = ("CASE {} WHEN 'critical' THEN 3 WHEN 'high' THEN 2 "
                        "WHEN 'medium' THEN 1 WHEN 'low' THEN 0 ELSE -1 END")
                self.conn.execute(
                    "UPDATE pages SET primary_severity = CASE WHEN "
                    + rank.format("?") + " > "
                    + rank.format("primary_severity")
                    + " THEN ? ELSE primary_severity END, "
                    "max_score = MAX(COALESCE(max_score, 0), ?) "
                    "WHERE id = ?",
                    (severity, severity, int(max_score or 0), page_id))
            else:
                self.conn.execute(
                    "UPDATE pages SET primary_severity = ?, max_score = ? "
                    "WHERE id = ?", (severity, int(max_score or 0), page_id))
            self.conn.commit()

    def iter_pages_with_text(self, url_id=None, batch=200):
        """Yield rows suitable for rescan: (page_id, url_id, page_url,
        text_snapshot). Skips rows without a stored snapshot.

        Reads `batch` rows per lock acquisition, in id order, so a rescan
        of a large database neither holds every snapshot in memory nor
        keeps the lock (and with it the dashboard and the crawler) for
        the whole read."""
        where = "text_snapshot IS NOT NULL AND text_snapshot != '' AND id > ?"
        params = []
        if url_id is not None:
            where += " AND url_id = ?"
            params.append(url_id)
        last_id = 0
        while True:
            with self.lock:
                rows = self.conn.execute(
                    "SELECT id, url_id, page_url, text_snapshot FROM pages "
                    "WHERE " + where + " ORDER BY id LIMIT ?",
                    [last_id] + params + [batch]).fetchall()
            yield from rows
            if len(rows) < batch:
                return
            last_id = rows[-1][0]

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
                     ioc_hash=None, fp_score=0, bump=True):
        """Insert a finding or bump occurrence_count if a row with the same
        (url_id, page_url, rule_name, ioc_hash) already exists. Dedup keeps
        the UI readable when the same IOC keeps surfacing across scans
        of the same page. `bump=False` leaves occurrence_count and
        last_seen_at of an existing row untouched (an offline rescan
        re-reads stored text, it does not see the IOC again) and only
        raises its score/severity. Returns True if this was a fresh row."""
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
            if not fresh and bump:
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
            elif not fresh:
                # Rescan: apply a raised rule score (and its severity) so
                # the row agrees with the page's cached severity. SET
                # right-hand sides all read the old score.
                self.conn.execute(
                    "UPDATE findings SET severity = CASE WHEN ? > score "
                    "  THEN ? ELSE severity END, score = MAX(score, ?) "
                    "WHERE url_id = ? AND page_url = ? AND rule_name = ? "
                    "  AND COALESCE(ioc_hash,'') = ?",
                    (int(score or 0), severity, int(score or 0),
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

    def rules_found_for_content(self, content_hash):
        """Names of the rules with a finding on any page whose content hash
        is `content_hash`: the rules an earlier copy of a Telegram repost
        already matched (and alerted for)."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT DISTINCT f.rule_name FROM pages p "
                "JOIN findings f ON f.url_id = p.url_id "
                "  AND f.page_url = p.page_url "
                "WHERE p.content_hash = ?", (content_hash,))
            return {r[0] for r in cur.fetchall()}

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

    def tg_message_seen(self, url_id, msg_id):
        """True if this channel's message is already stored. Telegram
        message ids are per channel, so (url_id, msg_id) names one message
        whichever path fetched it (poll, live listener, scrape)."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM tg_messages WHERE url_id = ? AND msg_id = ? "
                "LIMIT 1", (url_id, int(msg_id)))
            return cur.fetchone() is not None

    def search_tg_messages_local(self, query, limit=100, min_date_iso=None,
                                   url_ids=None):
        """Case-insensitive substring search across all already-scraped TG
        messages. O(log N) via the sqlite_ftx-style LIKE plus the
        `idx_tg_messages_url` index when url_ids is narrow. Returns rows
        with channel context + finding counts."""
        # Escape LIKE metacharacters so % and _ in a keyword match literally
        # (e.g. "user_name" must not match "userXname").
        escaped = (query.replace("\\", "\\\\")
                        .replace("%", "\\%").replace("_", "\\_"))
        where = ["m.text IS NOT NULL", "LOWER(m.text) LIKE LOWER(?) ESCAPE '\\'"]
        params = ["%" + escaped + "%"]
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
        """Raise the channel's high-water mark (the highest message id
        read, service messages included). Never lowers it, so a historical
        scrape or a late batch cannot move the polling cursor back."""
        with self.lock:
            self.conn.execute(
                "UPDATE urls SET tg_last_msg_id = "
                "  MAX(COALESCE(tg_last_msg_id, 0), ?) WHERE id = ?",
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

    def get_monitored_due(self, now_iso, source=None, exclude_source=None):
        """Return monitored URLs whose next_check_at is in the past.
        `source` keeps only rows of that source; `exclude_source` drops
        them (the .onion scheduler passes exclude_source="telegram", the
        Telegram one source="telegram")."""
        sql = ("SELECT id, url, monitor_interval_min "
               "FROM urls WHERE monitored = 1 "
               "AND (next_check_at IS NULL OR next_check_at <= ?)")
        params = [now_iso]
        if source is not None:
            sql += " AND source = ?"
            params.append(source)
        if exclude_source is not None:
            sql += " AND COALESCE(source, '') != ?"
            params.append(exclude_source)
        with self.lock:
            cur = self.conn.execute(sql, params)
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

    # Small lookups for callers outside this class (web.py, crawl_url), so
    # none of them reads self.conn without the lock.
    def get_url_id(self, url):
        """id of the urls row for `url`, or None."""
        with self.lock:
            row = self.conn.execute(
                "SELECT id FROM urls WHERE url = ?", (url,)).fetchone()
            return row[0] if row else None

    def get_url_source(self, url_id):
        """source of a urls row ('telegram', 'manual', ...), or None if
        there is no such row."""
        with self.lock:
            row = self.conn.execute(
                "SELECT source FROM urls WHERE id = ?", (url_id,)).fetchone()
            return row[0] if row else None

    def latest_page_id(self, url_id):
        """id of the most recently scanned page of a url, or None."""
        with self.lock:
            row = self.conn.execute(
                "SELECT id FROM pages WHERE url_id = ? "
                "ORDER BY scanned_at DESC LIMIT 1", (url_id,)).fetchone()
            return row[0] if row else None

    def get_url_by_tg_channel_id(self, channel_id):
        """(url_id, tg_username) of the row tracking a Telegram channel id,
        or None."""
        with self.lock:
            row = self.conn.execute(
                "SELECT id, tg_username FROM urls "
                "WHERE tg_channel_id = ? LIMIT 1", (channel_id,)).fetchone()
            return (row[0], row[1]) if row else None

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
        Missing this was the root cause of silent-fail deletes.

        Returns the files the deleted rows pointed to, for
        DarkWebCrawler.delete_url to remove: {"screenshots": [...],
        "thumbnails": [...]} (paths as stored) and {"tg_media": [...],
        "avatars": [...]} (relative to loot/tg-media)."""
        files = {"screenshots": [], "thumbnails": [], "tg_media": [],
                 "avatars": []}
        with self.lock:
            for key, sql in (
                    ("screenshots", "SELECT screenshot_path FROM pages "
                                    "WHERE url_id = ? AND screenshot_path IS NOT NULL"),
                    ("thumbnails", "SELECT thumbnail_path FROM pages "
                                   "WHERE url_id = ? AND thumbnail_path IS NOT NULL"),
                    ("tg_media", "SELECT media_path FROM tg_messages "
                                 "WHERE url_id = ? AND media_path IS NOT NULL"),
                    # An avatar another tracked row still shows is kept.
                    ("avatars", "SELECT tg_photo_path FROM urls u WHERE id = ? "
                                "  AND tg_photo_path IS NOT NULL AND NOT EXISTS ("
                                "    SELECT 1 FROM urls o WHERE o.id != u.id "
                                "      AND o.tg_photo_path = u.tg_photo_path)")):
                try:
                    files[key] = sorted({r[0] for r in self.conn.execute(
                        sql, (url_id,)) if r[0]})
                except sqlite3.OperationalError as e:
                    log.debug(f"delete_url: no {key} lookup: {e}")
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
        return files

    # ── Retention (darkwatch.py --retention, run by ops/retention.sh) ─────
    # Each step works in chunks, one lock acquisition and one commit per
    # chunk, so the dashboard and crawler (another process, same database)
    # never wait long for the write lock.
    _RETENTION_CHUNK = 500

    @staticmethod
    def _retention_cutoff(days):
        """`days` ago in the format of CURRENT_TIMESTAMP columns."""
        return (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    def prune_monitor_events(self, days, dry_run=False):
        """Delete monitor_events rows older than `days`. Returns the count
        (that would be) deleted."""
        cutoff = self._retention_cutoff(days)
        if dry_run:
            with self.lock:
                return self.conn.execute(
                    "SELECT COUNT(*) FROM monitor_events WHERE checked_at < ?",
                    (cutoff,)).fetchone()[0]
        total = 0
        while True:
            with self.lock:
                cur = self.conn.execute(
                    "DELETE FROM monitor_events WHERE id IN ("
                    "  SELECT id FROM monitor_events WHERE checked_at < ? "
                    "  LIMIT ?)", (cutoff, self._RETENTION_CHUNK))
                self.conn.commit()
            total += cur.rowcount
            if cur.rowcount < self._RETENTION_CHUNK:
                return total

    def prune_text_snapshots(self, days, dry_run=False):
        """Set text_snapshot to NULL on pages scanned more than `days` ago,
        except the newest snapshot of each (url_id, page_url), which a
        rescan still needs. Page rows (title, IOCs, findings links) stay.
        Returns the count (that would be) cleared."""
        cutoff = self._retention_cutoff(days)
        with self.lock:
            ids = [r[0] for r in self.conn.execute(
                "SELECT p.id FROM pages p "
                "WHERE p.text_snapshot IS NOT NULL AND p.text_snapshot != '' "
                "  AND p.scanned_at < ? "
                "  AND p.id != (SELECT p2.id FROM pages p2 "
                "    WHERE p2.url_id = p.url_id AND p2.page_url = p.page_url "
                "      AND p2.text_snapshot IS NOT NULL "
                "      AND p2.text_snapshot != '' "
                "    ORDER BY p2.scanned_at DESC, p2.id DESC LIMIT 1)",
                (cutoff,))]
        if dry_run:
            return len(ids)
        total = 0
        for i in range(0, len(ids), self._RETENTION_CHUNK):
            chunk = ids[i:i + self._RETENTION_CHUNK]
            with self.lock:
                cur = self.conn.execute(
                    "UPDATE pages SET text_snapshot = NULL WHERE id IN ("
                    + ",".join("?" * len(chunk)) + ") "
                    "AND text_snapshot IS NOT NULL", chunk)
                self.conn.commit()
            total += cur.rowcount
        return total

    def clear_missing_file_paths(self, tg_media_dir, dry_run=False):
        """Set pages.screenshot_path / thumbnail_path and
        tg_messages.media_path to NULL where the file no longer exists
        (pruned by ops/retention.sh, or removed by hand), so the dashboard
        stops linking to it. A path whose directory is missing as a whole
        (loot not mounted) is left alone. Returns {column: count}."""
        def page_file(p):
            return p, os.path.dirname(p)

        def media_file(p):
            return os.path.join(tg_media_dir, p), tg_media_dir

        counts = {}
        for table, col, resolve in (("pages", "screenshot_path", page_file),
                                    ("pages", "thumbnail_path", page_file),
                                    ("tg_messages", "media_path", media_file)):
            counts[col] = 0
            last_id = 0
            while True:
                with self.lock:
                    rows = self.conn.execute(
                        f"SELECT id, {col} FROM {table} WHERE id > ? "
                        f"  AND {col} IS NOT NULL AND {col} != '' "
                        "ORDER BY id LIMIT ?",
                        (last_id, self._RETENTION_CHUNK)).fetchall()
                if not rows:
                    break
                last_id = rows[-1][0]
                missing = []
                for rid, p in rows:
                    path, root = resolve(p)
                    if os.path.isdir(root) and not os.path.isfile(path):
                        missing.append((rid, p))
                if missing and not dry_run:
                    with self.lock:
                        # Only if the path is unchanged since it was read.
                        self.conn.executemany(
                            f"UPDATE {table} SET {col} = NULL "
                            f"WHERE id = ? AND {col} = ?", missing)
                        self.conn.commit()
                counts[col] += len(missing)
        return counts

    def wal_checkpoint(self):
        """PRAGMA wal_checkpoint(TRUNCATE): copy the WAL into the database
        and truncate it. Returns (busy, wal_pages, checkpointed_pages);
        busy=1 means a reader (the dashboard) kept it from finishing."""
        with self.lock:
            return tuple(self.conn.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)").fetchone())

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
