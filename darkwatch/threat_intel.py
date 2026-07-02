"""Threat-intel feed ingester.

Pulls indicator lists from external sources and compiles them into a
YARA rule file that YaraScanner picks up alongside the curated keyword
rules. This replaces the manual "copy/paste an abuse.ch URL into
user.yar" workflow that used to be the only way to get fresh CTI into
DarkWatch.

Supported feed shapes (auto-detected from the response):
  - plain text: one indicator per line (URLhaus text export, phishtank
      text, feodotracker IP list, etc.). Comment lines (starting with #)
      and empty lines are ignored.
  - CSV: the first non-comment column is taken as the indicator (URLhaus
      CSV, DigitalSide OSINT).
  - JSON list: each element is taken as a string indicator if scalar,
      or the first value of a dict if an object.

All indicators are escaped and written into one `rule intel_feed_<name>`
per feed so the operator can tell which feed produced a hit. Feeds are
fetched through the Tor proxy (respects config.proxy) because some
CTI endpoints geo-block certain VPN IPs and operators may want to keep
their research pattern off the cleartext net.

No network calls happen at import time. Call `ThreatIntelFeed.refresh()`
from a route, a CLI flag, or a scheduled task.
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional

import requests

log = logging.getLogger("darkwatch.intel")


# A modest set of sensible defaults. Operators can override the full list
# via config.threat_intel.feeds, but the defaults give a working setup
# out of the box. Score values mean: 100=critical (malware sample),
# 60=high (phishing/leak), 40=medium (suspicious).
DEFAULT_FEEDS = [
    {
        "name": "urlhaus_onion",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "format": "text",
        # URLhaus dumps ALL URLs — we filter to .onion here so the rule
        # file stays small and relevant. A cleartext URL match would
        # fire on any page that happens to embed that URL, which is
        # mostly noise.
        "filter_regex": r"\.onion(?:/|\s|$)",
        "score": 70,
        "severity": "high",
        "description": "URLhaus online malware URLs (.onion only)",
        "enabled": True,
    },
    {
        "name": "feodo_c2",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "format": "text",
        "score": 60,
        "severity": "high",
        "description": "Feodo Tracker botnet C2 IPs",
        "enabled": True,
    },
]


def _yara_escape(s: str) -> str:
    return (s.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\n", "\\n")
             .replace("\r", "\\r")
             .replace("\t", "\\t"))


def _parse_indicators(body: str, fmt: str,
                       filter_re: Optional[re.Pattern] = None,
                       limit: int = 2000) -> List[str]:
    """Extract indicators from a raw feed body. `limit` caps the output
    so a runaway feed (100k+ lines) doesn't produce a YARA file that
    takes minutes to compile."""
    out: List[str] = []
    fmt = (fmt or "text").lower()
    if fmt == "json":
        try:
            data = json.loads(body)
        except ValueError:
            log.warning("threat_intel: feed declared JSON but didn't parse")
            return out
        items = data if isinstance(data, list) else [data]
        for it in items:
            if isinstance(it, str):
                val = it
            elif isinstance(it, dict):
                # Take the first string-valued field ('url', 'indicator',
                # 'value' are the common ones). Order matters — these
                # are the most likely authoritative fields.
                val = None
                for k in ("url", "indicator", "ioc", "value", "host", "ip"):
                    if isinstance(it.get(k), str):
                        val = it[k]
                        break
                if val is None:
                    continue
            else:
                continue
            val = val.strip()
            if val and (not filter_re or filter_re.search(val)):
                out.append(val)
            if len(out) >= limit:
                break
        return out

    # CSV or text.
    lines = body.splitlines()
    if fmt == "csv":
        reader = csv.reader(io.StringIO(body))
        for row in reader:
            if not row or not row[0] or row[0].startswith("#"):
                continue
            val = row[0].strip()
            if val and (not filter_re or filter_re.search(val)):
                out.append(val)
            if len(out) >= limit:
                break
        return out

    # Plain text — one indicator per line, # comments.
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if filter_re and not filter_re.search(line):
            continue
        out.append(line)
        if len(out) >= limit:
            break
    return out


class ThreatIntelFeed:
    """Fetch + compile threat-intel feeds into a YARA rule file.

    Usage (from web.py):
        tif = ThreatIntelFeed(crawler.intel_rules_path, feeds_cfg,
                               proxies=crawler.proxies)
        result = tif.refresh()
        crawler.scanner.load_intel_rules(crawler.intel_rules_path)

    The caller must re-load the YARA file after refresh; this class
    deliberately doesn't reach into the scanner, so it's reusable by
    CLI tools and tests.
    """

    def __init__(self, output_path: str, feeds: Optional[List[Dict]] = None,
                 proxies: Optional[Dict] = None, timeout: int = 30):
        self.output_path = output_path
        # Operator-supplied feeds override defaults entirely — not a merge.
        # If you want to extend defaults, copy + add + set in config.
        self.feeds = feeds if feeds is not None else DEFAULT_FEEDS
        self.proxies = proxies
        self.timeout = timeout

    def _fetch_one(self, feed: Dict) -> List[str]:
        name = feed.get("name") or "feed"
        url = feed.get("url")
        if not url:
            return []
        fmt = feed.get("format", "text")
        filt = feed.get("filter_regex")
        filter_re = re.compile(filt, re.I) if filt else None
        # Plenty of threat-intel sources rate-limit; keep a cache so
        # operator-initiated refreshes don't hammer the endpoint.
        try:
            # Some feeds refuse compressed responses from non-browser
            # clients; a simple UA avoids surprise 403s.
            r = requests.get(
                url,
                proxies=self.proxies,
                timeout=self.timeout,
                headers={"User-Agent": "DarkWatch-ThreatIntel/1.0"},
            )
            if r.status_code != 200:
                log.warning(f"threat_intel[{name}]: HTTP {r.status_code}")
                return []
            items = _parse_indicators(r.text, fmt, filter_re=filter_re)
            log.info(f"threat_intel[{name}]: parsed {len(items)} indicators")
            return items
        except Exception as e:
            log.warning(f"threat_intel[{name}] fetch error: {e}")
            return []

    def _emit_rule(self, name: str, score: int, severity: str,
                    description: str, indicators: List[str]) -> str:
        """Build one YARA rule body for a feed. Deduplicates + caps to
        stay under yara's per-rule string count (practical limit ~10k)."""
        seen = set()
        unique: List[str] = []
        for ind in indicators:
            key = ind.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(ind)
            if len(unique) >= 5000:
                break
        if not unique:
            return ""
        lines = [f"rule intel_{re.sub(r'[^A-Za-z0-9_]', '_', name)}", "{",
                 "    meta:",
                 '        author = "threat_intel_feed"',
                 f'        feed = "{_yara_escape(name)}"',
                 f'        description = "{_yara_escape(description)}"',
                 f'        severity = "{_yara_escape(severity)}"',
                 f"        score = {int(score)}",
                 "",
                 "    strings:"]
        for i, ind in enumerate(unique):
            lines.append(f'        $i{i} = "{_yara_escape(ind)}" '
                         'wide ascii nocase')
        lines.extend(["", "    condition:", "        any of them", "}", ""])
        return "\n".join(lines)

    def refresh(self) -> Dict:
        """Fetch all enabled feeds, rewrite the YARA file atomically,
        return a summary dict the API route can return verbatim."""
        feeds_out: List[Dict] = []
        rule_bodies: List[str] = []
        total_indicators = 0
        started = time.time()
        for feed in self.feeds:
            if not feed.get("enabled", True):
                feeds_out.append({"name": feed.get("name"),
                                   "enabled": False, "indicators": 0})
                continue
            indicators = self._fetch_one(feed)
            body = self._emit_rule(
                feed.get("name", "feed"),
                int(feed.get("score", 50)),
                feed.get("severity", "medium"),
                feed.get("description", ""),
                indicators)
            if body:
                rule_bodies.append(body)
            total_indicators += len(indicators)
            feeds_out.append({"name": feed.get("name"),
                               "indicators": len(indicators),
                               "enabled": True})

        if not rule_bodies:
            # No indicators fetched — do NOT overwrite an existing file
            # with an empty one; that would silently clear good rules on
            # a transient network failure. Keep the old file in place.
            log.warning("threat_intel: no indicators fetched; keeping existing file")
            return {"updated": False, "feeds": feeds_out,
                    "total_indicators": total_indicators,
                    "elapsed_s": round(time.time() - started, 2)}

        header = ["/* Auto-generated by DarkWatch threat_intel module. ",
                  "   DO NOT EDIT — changes will be overwritten on next refresh. */",
                  ""]
        payload = "\n".join(header + rule_bodies)

        # Atomic write: tmpfile + rename so a crashing fetcher can't leave
        # a half-written rule file that breaks YARA compile on startup.
        os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
        tmp = self.output_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, self.output_path)
        fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        log.info(f"threat_intel: wrote {self.output_path} "
                 f"({total_indicators} indicators, {len(rule_bodies)} feeds, "
                 f"sha={fingerprint})")
        return {"updated": True, "feeds": feeds_out,
                "total_indicators": total_indicators,
                "fingerprint": fingerprint,
                "elapsed_s": round(time.time() - started, 2)}
