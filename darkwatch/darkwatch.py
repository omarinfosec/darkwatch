#!/usr/bin/env python3
"""
DarkWatch — Dark Web OSINT Crawler & Keyword Monitor
Custom-built for CTI teams to monitor .onion sites for organizational mentions.
Hardened edition with anti-detection and security controls.

The database lives in dw_db.py and the Telegram engine in dw_telegram.py;
their names are re-exported here (see the imports below).
"""

__version__ = "0.3.1"

import os
import sys
import copy
import json
import html as html_lib
import socket
import time
import hashlib
import logging
import argparse
import re
import yara
import threading
import random
from queue import Queue
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

import requests
from bs4 import BeautifulSoup, Doctype

# Database and the Telegram engine moved to their own modules. Their names
# stay importable from here (`from darkwatch import Database`,
# `darkwatch.DarkMTProto`) for web.py, the tests and scripts.
from dw_db import Database, utcnow
from dw_telegram import (
    TELETHON_AVAILABLE, DARKMTPROTO_VERSION, RateLimiter, EntityCache,
    CallPressure, ClientProfile, DarkMTProto, TelegramScraper,
    TelegramLiveListener,
)

# Names above that darkwatch.py itself does not use: listed so pyflakes
# counts them as used.
_REEXPORTS = (TELETHON_AVAILABLE, DARKMTPROTO_VERSION, RateLimiter,
              EntityCache, CallPressure, ClientProfile, DarkMTProto,
              TelegramScraper, TelegramLiveListener)

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
        "timeout": 60,
        "retries": 3,
        "retry_delay": 10,
        "max_pages_per_site": 100,
        "rescan_days": 7,
        "scan_pdfs": False,
        "screenshot_mode": "tor_render",
        "newnym_between_sites": True,
        "domain_fail_breaker": 3,
        "tor_control_host": "tunnel1",
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
    },
    # Database retention, applied by `darkwatch.py --retention` (run
    # nightly by ops/retention.sh, which prunes the loot/ files first).
    # A days value of 0 turns that step off. Page and finding rows are
    # never deleted.
    "retention": {
        "monitor_events_days": 180,
        # Older snapshots are set to NULL; the newest one of each page is
        # kept so a rescan still covers every page.
        "text_snapshot_days": 365,
        # NULL screenshot/thumbnail/media paths whose file is gone.
        "clear_missing_files": True,
        "wal_checkpoint": True
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
            return yara.compile(filepath=path, includes=False)
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
            return yara.compile(filepaths=paths, includes=False)
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
            yara.compile(sources=sources, includes=False)
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
            self.intel_rules = yara.compile(filepath=path, includes=False)
            log.info(f"Loaded threat-intel rules from {path}")
            return True
        except yara.Error as e:
            log.error(f"Failed to compile intel rules {path}: {e}")
            self.intel_rules = None
            return False


# ─── Alerting ────────────────────────────────────────────────────────────────

def alert_proxy_routes(config):
    """Ordered egress routes for alert webhooks.

    Alerts carry the .onion URL and the matched text, so they must not leave
    from the host's own IP. Try the Telegram tunnel (a VPN exit, which Slack /
    Discord / Telegram accept), then Tor. A direct connection is used only if
    the operator opts in with alerts.allow_direct = true."""
    from urllib.parse import quote
    routes = []
    tg = config.get("telegram", {}) or {}
    if tg.get("proxy_host"):
        auth = ""
        if tg.get("proxy_user") and tg.get("proxy_password"):
            auth = (f"{quote(str(tg['proxy_user']), safe='')}:"
                    f"{quote(str(tg['proxy_password']), safe='')}@")
        url = f"socks5h://{auth}{tg['proxy_host']}:{int(tg.get('proxy_port') or 1080)}"
        routes.append(("telegram tunnel", {"http": url, "https": url}))
    p = config.get("proxy", {}) or {}
    if p.get("host"):
        url = f"{p.get('type', 'socks5h')}://{p['host']}:{int(p.get('port', 9050))}"
        routes.append(("tor", {"http": url, "https": url}))
    if (config.get("alerts", {}) or {}).get("allow_direct"):
        routes.append(("direct", None))
    return routes


class Alerter:
    def __init__(self, config, routes=None):
        self.config = config
        self.routes = routes if routes is not None else []

    # Any URL in a message: keep scheme://host, drop credentials, path, query.
    _URL_IN_ERR = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)"   # scheme
                             r"(?:[^/\s'\"@]*@)?"              # user:pass@
                             r"([^/\s'\"?#]*)"                 # host[:port]
                             r"([^\s'\"]*)")                   # path?query

    @staticmethod
    def _scrub(err, url):
        """Error text with the alert URL's secret parts removed. The bot
        token sits in the Telegram URL path and webhook tokens in the path or
        query, and requests/urllib3 quote the URL or its path in their
        messages ("Max retries exceeded with url: /bot<token>/sendMessage",
        "Invalid URL '...'"), which then went to the logs and the dashboard."""
        text = str(err)
        parts = set()
        try:
            u = urlparse(url)
            parts.update({url, requests.utils.requote_uri(url), u.path,
                          u.query, u.fragment, u.path + "?" + u.query})
        except Exception:
            parts.add(url)
        try:
            # urllib3 quotes the prepared, percent-encoded path, which differs
            # when the token or webhook has spaces, newlines or non-ASCII.
            pu = urlparse(requests.Request("POST", url).prepare().url)
            parts.update({pu.path, pu.query, pu.path + "?" + pu.query})
        except Exception:
            pass
        for p in sorted((p for p in parts if p and len(p) > 1), key=len, reverse=True):
            text = text.replace(p, "[redacted]")
        text = re.sub(r"(with url: )\S+", r"\1[redacted]", text)
        return Alerter._URL_IN_ERR.sub(
            lambda m: m[1] + m[2] + ("/[redacted]" if m[3] else ""), text)

    def _post(self, url, payload):
        """POST through the first route that connects. Only connection-level
        failures fall through to the next route, so an alert that reached
        the receiver is never sent twice. Raised errors never carry the URL
        (it holds the token)."""
        if not self.routes:
            raise RuntimeError("no tunnel available for alerts "
                               "(set alerts.allow_direct to send directly)")
        last = None
        for name, proxies in self.routes:
            try:
                return requests.post(url, json=payload, proxies=proxies, timeout=20)
            except (requests.exceptions.ProxyError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ConnectTimeout) as e:
                last = f"{type(e).__name__}: {self._scrub(e, url)}"
                log.debug(f"alert route '{name}' unavailable: {last}")
            except Exception as e:
                # InvalidURL, MissingSchema, ReadTimeout...: another route
                # would not help (or could send twice). `from None`: the
                # original exception and its message stay out of tracebacks.
                raise RuntimeError(f"alert failed: {type(e).__name__}: "
                                   f"{self._scrub(e, url)}") from None
        raise RuntimeError(f"all alert routes failed: {last}")

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
            self._post(f"https://api.telegram.org/bot{token}/sendMessage",
                       {"chat_id": chat_id, "text": msg})
            log.info("Telegram alert sent")
        except Exception as e:
            log.error(f"Telegram alert failed: {e}")

    def _slack(self, msg):
        webhook = self.config.get("slack_webhook_url")
        if not webhook:
            return
        try:
            self._post(webhook, {"text": msg})
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
            self._post(webhook, payload)
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
            self._post(webhook, payload)
            log.info("Generic webhook alert sent")
        except Exception as e:
            log.error(f"Generic webhook alert failed: {e}")


# ─── HTML Sanitizer ──────────────────────────────────────────────────────────

class HTMLSanitizer:
    # Saved pages are opened in an analyst's browser. The policy is the
    # backstop for everything the tag and attribute rules below miss: no
    # script, frame, fetch, form or remote load, only inline styles and
    # data: images, media and fonts.
    CSP = ("default-src 'none'; img-src data:; media-src data:; "
           "font-src data:; style-src 'unsafe-inline'; base-uri 'none'; "
           "form-action 'none'")

    TRACKING_PATTERNS = [
        r'url\(\s*["\x27]?\s*(?:https?:)?//[^)]+["\x27]?\s*\)',
        r'@import\s+["\x27](?:https?:)?//',
    ]

    # Attributes a browser reads as a URL.
    URL_ATTRS = {"src", "href", "action", "formaction", "srcset", "poster",
                 "background", "data", "xlink:href", "cite", "longdesc",
                 "lowsrc", "dynsrc", "ping", "manifest", "codebase", "icon"}

    # (tag, attribute) pairs that load a resource as soon as the page is
    # shown. A remote value moves to data-original-<attribute>.
    REMOTE_LOADS = {"video": ("src", "poster"), "audio": ("src",),
                    "source": ("src", "srcset"), "track": ("src",),
                    "image": ("href", "xlink:href"), "link": ("href",),
                    "img": ("srcset",)}

    # A scheme ("http:x" is remote from a file:// page too) or a
    # protocol-relative "//", after _norm_url.
    _REMOTE = re.compile(r"^(?:[a-z][a-z0-9+.\-]*:|//)")

    @staticmethod
    def _norm_url(val):
        """The URL as a browser reads its scheme: without control
        characters or whitespace (so "java\\tscript:" is javascript:), with
        "\\" read as "/", lower-cased."""
        return re.sub(r"[\x00-\x20\x7f\s]+", "", str(val)).replace(
            "\\", "/").lower()

    @staticmethod
    def _is_remote(norm):
        return (bool(HTMLSanitizer._REMOTE.match(norm))
                and not norm.startswith("data:"))

    @staticmethod
    def _srcset_is_remote(norm):
        # Candidates are comma-separated, but data: URLs contain commas
        # too, so any "//" or non-data scheme counts.
        return "//" in norm or bool(
            re.search(r"(?:^|,)(?!data:)[a-z][a-z0-9+.\-]*:", norm))

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

        # <base> would point every relative URL at a remote host.
        for tag in soup.find_all("base"):
            tag.decompose()

        # strip tracking and event handlers
        if config.get("strip_tracking", True):
            for tag in soup.find_all(True):
                for attr in list(tag.attrs.keys()):
                    if attr.lower().startswith("on"):
                        del tag[attr]
                        continue
                    if attr.lower() in HTMLSanitizer.URL_ATTRS:
                        val = HTMLSanitizer._norm_url(tag.get(attr, ""))
                        if (val.startswith(("javascript:", "vbscript:"))
                                or (val.startswith("data:")
                                    and not val.startswith("data:image/"))):
                            del tag[attr]
                    elif attr.lower() == "style":
                        text = str(tag[attr])
                        for pattern in HTMLSanitizer.TRACKING_PATTERNS:
                            text = re.sub(pattern, "/* REMOVED */", text, flags=re.I)
                        tag[attr] = text

            # remove tracking pixels
            for img in soup.find_all("img"):
                width = img.get("width", "")
                height = img.get("height", "")
                if str(width) in ("0", "1") or str(height) in ("0", "1"):
                    img.decompose()
                    continue
                src = img.get("src", "")
                if HTMLSanitizer._is_remote(HTMLSanitizer._norm_url(src)):
                    img["src"] = "[EXTERNAL_IMAGE_REMOVED]"
                    img["data-original-src"] = src

            # media, SVG images and stylesheets that load on view
            for tag in soup.find_all(list(HTMLSanitizer.REMOTE_LOADS)):
                for attr in HTMLSanitizer.REMOTE_LOADS[tag.name]:
                    if not tag.has_attr(attr):
                        continue
                    norm = HTMLSanitizer._norm_url(tag[attr])
                    if (HTMLSanitizer._srcset_is_remote(norm)
                            if attr == "srcset"
                            else HTMLSanitizer._is_remote(norm)):
                        tag["data-original-" + attr.replace(":", "-")] = tag[attr]
                        del tag[attr]

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

        # The policy goes last, as the first child of <head>, so that no
        # element the page carries comes before it.
        html_tag = soup.find("html")
        if html_tag is None:
            html_tag = soup.new_tag("html")
            for node in list(soup.contents):
                if not isinstance(node, Doctype):
                    html_tag.append(node.extract())
            soup.append(html_tag)
        head = html_tag.find("head", recursive=False)
        if head is None:
            head = soup.new_tag("head")
            html_tag.insert(0, head)
        head.insert(0, soup.new_tag(
            "meta", attrs={"http-equiv": "Content-Security-Policy",
                           "content": HTMLSanitizer.CSP}))

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
    """Captures a screenshot and thumbnail of a crawled page.

    Two modes (config.crawler.screenshot_mode; any other value means
    "tor_render"):
    - "tor_render" (the default): the browser loads the page itself through
      the Tor SOCKS proxy (proxy_url), so CSS and same-origin images show.
      Only same-origin requests go out; scripts, websockets, media and every
      cross-origin request are aborted. A page that fails to load (most
      often a redirect, which FIREFOX_PREFS disables) falls back to
      offline rendering. Without a proxy_url it renders offline.
    - "offline": renders the HTML the crawler already fetched via
      set_content, with every network request aborted, so the site is not
      hit a second time. The browser's proxy is DEAD_PROXY, so anything
      that slips past the route handler fails instead of going out.

    In both modes JavaScript is disabled, each capture gets a fresh browser
    context, and a missing Playwright makes capture() return (None, None).

    sync_playwright is thread-bound: one ScreenshotWorker thread owns the
    engine and runs every capture.
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
        # Send localhost/127.0.0.1 through the proxy too (Firefox exempts it
        # by default), so a page can't point the browser at the dashboard
        # or anything else listening inside this container.
        "network.proxy.allow_hijacking_localhost": True,
        # Speculative connections are not seen by Playwright's route handler:
        # no DNS prefetch, link prefetch, preconnect, predictor or pings.
        "network.dns.disablePrefetch": True,
        "network.dns.disablePrefetchFromHTTPS": True,
        "network.prefetch-next": False,
        "network.predictor.enabled": False,
        "network.http.speculative-parallel-limit": 0,
        "browser.send_pings": False,
        "media.navigator.enabled": False,
        # Playwright's route handler only sees the first URL of a redirect
        # chain, so a same-origin image answering 302 -> tracker.example
        # would be fetched without passing the same-origin guard. Follow no
        # redirects at all; a page that redirects is rendered offline from
        # the HTML the crawler already fetched (see _render).
        "network.http.redirection-limit": 0,
    }

    # Unroutable proxy for "offline" mode: anything that slips past the
    # route handler (speculative connections, etc.) fails instead of going
    # out directly from the host.
    DEAD_PROXY = "socks5://127.0.0.1:9"
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
                else:
                    # offline mode, or tor_render without a proxy: never let
                    # the browser reach the network directly.
                    launch_kwargs["proxy"] = {"server": self.DEAD_PROXY}
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

            def render_offline():
                page.route("**/*", lambda route: route.abort())
                page.set_content(html_content, wait_until="domcontentloaded",
                                 timeout=15000)

            if self.mode == "offline" or not self.proxy_url:
                render_offline()
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
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)
                except Exception as e:
                    # Most often the page redirects (redirects are disabled,
                    # see FIREFOX_PREFS). Render the HTML we already fetched,
                    # with every network request aborted, instead of failing.
                    log.debug(f"  tor_render failed ({e}); rendering offline")
                    page.unroute("**/*")
                    render_offline()

            page.screenshot(path=output_path, full_page=False, timeout=10000)
            return True
        finally:
            if context:
                try: context.close()
                except Exception: pass

    def capture(self, html_content, url, timestamp=None):
        """Render the page (see the class docstring for the modes),
        screenshot + thumbnail. Returns (screenshot_path, thumbnail_path)
        or (None, None).
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
        try:
            declared = int(content_length or 0)
        except ValueError:
            # Malformed header (e.g. "5, 5"): ignore it; the real body size
            # is checked just below. Raising here aborted the whole site crawl.
            declared = 0
        if declared > self.max_size:
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
        self.alerter = Alerter(config["alerts"], routes=alert_proxy_routes(config))
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
        self.tor_control_host = cc.get("tor_control_host", "tunnel1")
        self.tor_control_port = cc.get("tor_control_port", 9051)
        self.tor_control_password = cc.get("tor_control_password", "")

        os.makedirs(self.loot_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(os.path.join(self.loot_dir, "pages"), exist_ok=True)
        os.makedirs(os.path.join(self.loot_dir, "screenshots"), exist_ok=True)
        os.makedirs(self.thumbnails_dir, exist_ok=True)

    def delete_url(self, url_id):
        """Delete a URL's rows (Database.delete_url), then, best effort, the
        files they pointed to: screenshots, thumbnails, downloaded Telegram
        media and the channel avatar. Only files inside their own loot
        directory are removed; a failure is logged and skipped. Saved HTML
        copies (loot/pages) are not tracked per URL; ops/retention.sh ages
        them out. Returns the number of files removed."""
        files = self.db.delete_url(url_id) or {}
        tg_media = os.path.join(self.loot_dir, "tg-media")
        targets = [(p, os.path.join(self.loot_dir, "screenshots"))
                   for p in files.get("screenshots", [])]
        targets += [(p, self.thumbnails_dir) for p in files.get("thumbnails", [])]
        targets += [(os.path.join(tg_media, p), tg_media)
                    for p in files.get("tg_media", []) + files.get("avatars", [])]
        removed = 0
        for path, base in targets:
            full = os.path.realpath(path)
            if not full.startswith(os.path.realpath(base) + os.sep):
                log.warning(f"delete_url: not removing {path}: outside {base}")
                continue
            try:
                os.remove(full)
                removed += 1
            except FileNotFoundError:
                pass
            except OSError as e:
                log.warning(f"delete_url: could not remove {path}: {e}")
        if removed:
            log.info(f"delete_url: removed {removed} file(s) of URL {url_id}")
        return removed

    def rotate_tor_circuit(self):
        """Request a new Tor circuit via the ControlPort (NEWNYM).
        Silently no-ops if stem or ControlPort is unavailable — scans must
        not fail when operator hasn't enabled the ControlPort.
        """
        if not self.newnym_between_sites or not STEM_AVAILABLE:
            return False
        try:
            # stem's from_port only accepts an IP literal ("Invalid IP
            # address: tunnel1"), so resolve the container name first.
            # This is Docker's internal DNS for a sidecar, not a target lookup.
            addr = socket.gethostbyname(self.tor_control_host)
            with Controller.from_port(
                address=addr,
                port=int(self.tor_control_port),
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
                try:
                    declared = int(content_length or 0)
                except ValueError:
                    declared = 0  # malformed header; streamed cap below still applies
                if declared > max_size:
                    log.warning(f"  Response too large ({content_length} bytes), skipping")
                    resp.close()
                    return None, "size"

                # stream with size AND total-time limits. requests' timeout
                # applies per read, so a server dripping one byte just under
                # it could otherwise hold this crawl thread indefinitely.
                chunks = []
                total = 0
                deadline = time.monotonic() + max(120, 3 * self.timeout)
                for chunk in resp.iter_content(chunk_size=8192):
                    if time.monotonic() > deadline:
                        resp.close()
                        raise requests.exceptions.ReadTimeout(
                            "download exceeded total time limit")
                    total += len(chunk)
                    if total > max_size:
                        log.warning("  Response exceeded size limit, aborting")
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

            except requests.exceptions.ReadTimeout:
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
            try:
                full = urljoin(base_url, href)
                parsed = urlparse(full)
            except ValueError:          # e.g. "http://[::1": skip, don't abort
                continue
            # The host itself must be an onion: "<x>.onion.evil.com" and
            # "<x>.onion@evil.com" (userinfo) only contain the string.
            if (parsed.scheme in ("http", "https")
                    and (parsed.hostname or "").endswith(".onion")):
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

    def _yara_match_text(self, url_id, page_url, text, suppress_rules=(),
                         bump=True):
        """Run YARA rules against a piece of plain text and write findings.
        Runs text + lower-cased text in parallel, then de-dupes by rule
        name — keywords.yar isn't always `nocase` but auto-generated user
        rules are, so an all-caps leak message needs both views.
        Findings of rules in `suppress_rules` are recorded without alerting
        (rules an earlier copy of a reposted text matched, which alerted
        then). `bump=False` is
        the rescan mode of add_finding: a match that is already recorded
        is neither counted nor alerted again.
        Returns the number of findings written (new ones when bump=False)."""
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
                fresh = self.db.add_finding(
                    url_id, page_url, kw["rule"], "keyword:text",
                    score, matched, snippet, severity,
                    ioc_hash=ioc_h, fp_score=fp, bump=bump)
                if not bump and not fresh:
                    continue
                finding_count += 1
                if severity in ("critical", "high"):
                    log.warning(f"  ALERT {severity.upper()} | {kw['rule']} "
                                f"(score:{score} fp:{fp}) | {page_url}")
                    if kw["rule"] in suppress_rules:
                        log.info("  Alert suppressed (repost of text that "
                                 "already matched this rule)")
                    elif fp < 60:
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
        web page: YARA scan, IOC extract, findings write. A message already
        stored for this channel is skipped; one whose text was seen before
        (a repost) is stored and scanned, alerting only for rules the
        earlier copies did not match. Also
        persists rich message metadata (sender, views, reactions,
        fwd/reply, media flag) in tg_messages so the UI can render a
        proper channel timeline.

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
        # A message is stored once per channel: polling, the live listener
        # and a historical scrape can all fetch the same one.
        if self.db.tg_message_seen(url_id, msg["msg_id"]):
            return 0
        # Content hash: real text when present, so a repost of the same
        # text (another channel, or the same channel again) is recognised;
        # otherwise msg_id-based, since every media-only post would share
        # the same "[photo]" marker.
        hash_basis = text if text else f"{page_url}|media"
        content_hash = hashlib.sha256(hash_basis.encode("utf-8")).hexdigest()
        # A repost is still stored and scanned, so this channel gets its
        # own message row and findings. Only an alert an earlier copy
        # already raised is not repeated: a rule added since then (that
        # matched no earlier copy) still alerts on the repost.
        earlier_rules = (self.db.rules_found_for_content(content_hash)
                         if text else set())

        extracted = self.data_extractor.extract(text) if text else {}

        # No screenshot for text messages; no form inventory; no html ctx.
        page_id = self.db.add_page(
            url_id, page_url, title, content_hash,
            extracted_data=extracted,
            screenshot_path=None, thumbnail_path=None,
            page_type="telegram_message")
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
        finding_count = (self._yara_match_text(url_id, page_url, text,
                                               suppress_rules=earlier_rules)
                         if text else 0)
        if extracted:
            for ioc_type, iocs in extracted.items():
                log.info(f"  Extracted {ioc_type}: {len(iocs)} item(s)")
        return finding_count

    def rescan_tg_channel(self, url_id):
        """Re-run YARA rules against every stored message for a channel.
        Use when the operator has added new user keywords AFTER historical
        scraping — the old messages are already stored (a re-scrape skips
        them) so fresh rule evaluation needs this dedicated path.

        Like rescan_pages it only adds findings: rows it matches again keep
        their occurrence_count and last_seen_at, and findings of rules
        that no longer match or were deleted stay. Only new rows alert.

        Returns {scanned, findings}; `findings` counts new rows."""
        with self.db.lock:
            rows = self.db.conn.execute(
                "SELECT m.url_id, m.msg_id, m.text, u.tg_username "
                "FROM tg_messages m JOIN urls u ON u.id = m.url_id "
                "WHERE m.url_id = ? AND m.text IS NOT NULL AND m.text != ''",
                (url_id,)).fetchall()
        targets = [(url_id_, f"https://t.me/{username}/{msg_id}", text)
                   for url_id_, msg_id, text, username in rows]
        # _yara_match_text takes db.lock itself (non-reentrant), so it runs
        # after the lock is released.
        found = 0
        for url_id_, page_url, text in targets:
            found += self._yara_match_text(url_id_, page_url, text,
                                           bump=False)
        return {"scanned": len(targets), "findings": found}

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
        # Saved copy (loot/pages) only for content not stored before: an
        # unchanged page on every monitor check used to add a file each time.
        self.save_page(page_url, html)

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
        given URL (or all URLs). Useful after the operator adds new
        keywords / threat-intel rules.

        A rescan only adds findings; it never deletes or rewrites them.
        The snapshot holds the stripped text of one version of the page,
        so findings from older versions or from the HTML-only pass (attrs,
        comments, <meta>) can't be re-derived from it. Findings of rules
        that were deleted since stay too. Existing rows the rescan matches
        again keep their occurrence_count and last_seen_at; a raised rule
        score raises their score and severity.

        Returns {scanned, findings, skipped}; `findings` counts new rows.
        """
        rows = self.db.iter_pages_with_text(url_id=url_id)
        scanned = 0
        findings_total = 0
        skipped = 0
        for page_id, uid, page_url, text in rows:
            if not text:
                skipped += 1
                continue
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
                if self.db.add_finding(
                        uid, page_url, kw["rule"],
                        f"keyword:{kw.get('context','text')}",
                        score, matched, snippet, severity,
                        ioc_hash=ioc_h, fp_score=fp, bump=False):
                    page_findings += 1
                if self._SEVERITY_RANK.get(severity, 0) > \
                        self._SEVERITY_RANK.get(page_max_sev, 0):
                    page_max_sev = severity
                if score > page_max_score:
                    page_max_score = score
            if merged["keywords"]:
                self.db.update_page_severity(page_id, page_max_sev,
                                             page_max_score, raise_only=True)
            scanned += 1
            findings_total += page_findings
        if url_id is None:
            self.db.ops_set("last_rescan_at", utcnow().isoformat())
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
                # Escape: PDF text is attacker-controlled and this wrapper is
                # parsed for links/forms and rendered for the screenshot.
                html = f"<html><head><title>{html_lib.escape(current_url)}</title></head>" \
                       f"<body><pre>{html_lib.escape(pdf_text)}</pre></body></html>"
            else:
                html = resp.text

            pages_scanned += 1

            # scan_page saves the HTML copy itself, for new content only.
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
        url_id = self.db.get_url_id(url)
        if url_id is None:
            log.error("Failed to add URL to database")
            return
        log.info(f"Crawling: {url}")
        pages, findings = self.crawl_site(url_id, url, stop_event=stop_event, max_depth=max_depth)
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
        log.info("Scan complete")
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

    REPORT_MAX_FINDINGS = 1000

    def generate_report(self, min_score=0):
        # One row past the cap tells whether older findings were left out.
        cap = self.REPORT_MAX_FINDINGS
        findings = self.db.get_findings(min_score=min_score, limit=cap + 1)
        truncated = len(findings) > cap
        findings = findings[:cap]
        stats = self.db.get_stats()
        report = {"generated_at": datetime.now().isoformat(), "statistics": stats,
                  "findings_included": len(findings), "truncated": truncated,
                  "findings": findings}

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
            if truncated:
                f.write(f"NOTE: report truncated: only the newest {cap} findings are "
                        "included below. Use Export CSV for more.\n\n")

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


# Operator overrides merged over config.json, so local settings live outside
# the git checkout (deploy.sh refuses a dirty tree). Compose mounts
# $DARKWEBAPP_DATA_ROOT/config.d read-only at /app/config.local.d. An empty
# DARKWATCH_CONFIG_LOCAL turns the override off.
DEFAULT_CONFIG_LOCAL = "/app/config.local.d/config.local.json"


def _deep_merge(base, override):
    """Merge `override` into `base` in place: nested dicts merge key by
    key, so keys the override doesn't name keep their value; anything else
    (lists included) is replaced. Returns `base`."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _read_config_file(path, missing_ok=False):
    """Parse one config file and resolve its ${VAR} placeholders. A file
    that exists but can't be read or isn't a JSON object is an error, not
    something to skip: running on half the operator's settings is worse
    than not starting. With `missing_ok`, a file that doesn't exist gives
    None."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        if missing_ok:
            return None
        raise ValueError(f"cannot read config file {path}: {e}") from e
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"config file {path} is not valid JSON: {e}") from e
    except OSError as e:
        raise ValueError(f"cannot read config file {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"config file {path} must hold a JSON object, "
                         f"not {type(data).__name__}")
    # Resolve ${VAR} placeholders against the environment BEFORE merging,
    # so DEFAULT_CONFIG fallbacks aren't shadowed by unsubstituted literal
    # strings.
    return _substitute_env(data)


def load_config(config_path, local_path=None):
    """DEFAULT_CONFIG, then `config_path` (config.json), then the local
    override file (`local_path`, else $DARKWATCH_CONFIG_LOCAL, else
    DEFAULT_CONFIG_LOCAL), each merged recursively over the one before.
    Missing files are skipped; invalid ones raise ValueError."""
    config = copy.deepcopy(DEFAULT_CONFIG)
    if config_path and os.path.exists(config_path):
        _deep_merge(config, _read_config_file(config_path))
    if local_path is None:
        local_path = os.environ.get("DARKWATCH_CONFIG_LOCAL", DEFAULT_CONFIG_LOCAL)
    # Opened rather than checked with os.path.exists, which also says False
    # for a file darkwatch may not look up (EACCES), and that must fail.
    local = _read_config_file(local_path, missing_ok=True) if local_path else None
    if local is not None:
        _deep_merge(config, local)
        log.info(f"config: applied local overrides from {local_path}")
    return config


def run_retention(db, loot_dir, retention_cfg=None, dry_run=False):
    """Apply the database retention steps (see DEFAULT_CONFIG["retention"])
    and log what each one did. `dry_run` only counts. Returns the counts.
    Deletes and NULLs cannot be undone: the backup taken before v0.4.0 is
    the only way back."""
    rc = dict(DEFAULT_CONFIG["retention"])
    rc.update(retention_cfg or {})
    # A dashboard write can hold the lock for a moment; wait for it.
    db.conn.execute("PRAGMA busy_timeout = 30000")
    def did(done, would):
        return would if dry_run else done
    tag = "retention (dry run)" if dry_run else "retention"
    out = {}
    days = int(rc.get("monitor_events_days") or 0)
    if days > 0:
        out["monitor_events"] = db.prune_monitor_events(days, dry_run=dry_run)
        log.info(f"{tag}: monitor_events: {out['monitor_events']} row(s) "
                 f"older than {days} days {did('deleted', 'to delete')}")
    else:
        log.info(f"{tag}: monitor_events: step off")
    days = int(rc.get("text_snapshot_days") or 0)
    if days > 0:
        out["text_snapshots"] = db.prune_text_snapshots(days, dry_run=dry_run)
        log.info(f"{tag}: pages.text_snapshot: {out['text_snapshots']} "
                 f"snapshot(s) older than {days} days and not the newest "
                 f"of their page {did('set to NULL', 'to set to NULL')}")
    else:
        log.info(f"{tag}: pages.text_snapshot: step off")
    if rc.get("clear_missing_files", True):
        missing = db.clear_missing_file_paths(
            os.path.join(loot_dir, "tg-media"), dry_run=dry_run)
        out.update(missing)
        log.info(f"{tag}: paths whose file is gone "
                 f"{did('set to NULL', 'to set to NULL')}: "
                 + ", ".join(f"{k}={v}" for k, v in missing.items()))
    else:
        log.info(f"{tag}: missing file paths: step off")
    if rc.get("wal_checkpoint", True) and not dry_run:
        # A pending TRUNCATE checkpoint blocks new writers while it waits for
        # readers: wait briefly (writers use a 5 s timeout) and leave a busy
        # checkpoint to the next nightly run.
        db.conn.execute("PRAGMA busy_timeout = 1000")
        busy, wal, done = db.wal_checkpoint()
        out["wal_checkpoint"] = {"busy": busy, "wal_pages": wal,
                                 "checkpointed": done}
        log.info(f"{tag}: wal_checkpoint(TRUNCATE): busy={busy} "
                 f"wal_pages={wal} checkpointed={done}")
    return out


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
  python darkwatch.py --retention --dry-run
        """)

    # Same config file as the dashboard (web.py) when run in its container.
    parser.add_argument("--config", "-c",
                        default=os.environ.get("DARKWATCH_CONFIG", "config.json"))
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
    parser.add_argument("--retention", action="store_true",
                        help="Apply database retention (config 'retention'); "
                             "ops/retention.sh runs it nightly")
    parser.add_argument("--dry-run", action="store_true",
                        help="With --retention: only count, change nothing")
    parser.add_argument("--monitor-events-days", type=int, metavar="DAYS",
                        help="With --retention: override "
                             "retention.monitor_events_days (0 = off)")
    parser.add_argument("--text-snapshot-days", type=int, metavar="DAYS",
                        help="With --retention: override "
                             "retention.text_snapshot_days (0 = off)")

    args = parser.parse_args()
    if not args.retention and (args.dry_run or args.monitor_events_days is not None
                               or args.text_snapshot_days is not None):
        parser.error("--dry-run and the --*-days options need --retention")
    setup_logging(args.debug)
    try:
        config = load_config(args.config)
    except ValueError as e:
        sys.exit(f"darkwatch: {e}")

    if args.retention:
        # Database and loot dir only: no crawler, so no screenshot worker,
        # YARA compile or Tor session in this one-off process.
        rcfg = dict(config.get("retention") or {})
        for key in ("monitor_events_days", "text_snapshot_days"):
            if getattr(args, key) is not None:
                rcfg[key] = getattr(args, key)
        run_retention(Database(config["database"]["path"]),
                      config["output"]["loot_dir"], rcfg, dry_run=args.dry_run)
        return

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
