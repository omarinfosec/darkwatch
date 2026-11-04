"""Findings integrity and database performance: the `pages` lookup indexes
are used by the hot queries, and an offline rescan only adds findings.
Run: pytest darkwatch/tests/
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _plans(db, call):
    """Run `call()` and return the EXPLAIN QUERY PLAN detail lines of every
    SELECT it sent, one list per statement (parameters already bound)."""
    sent = []
    db.conn.set_trace_callback(sent.append)
    try:
        call()
    finally:
        db.conn.set_trace_callback(None)
    plans = []
    for sql in sent:
        if not sql.lstrip().upper().startswith("SELECT"):
            continue
        rows = db.conn.execute("EXPLAIN QUERY PLAN " + sql).fetchall()
        plans.append([r[3] for r in rows])
    assert plans, "no SELECT was traced"
    return plans


def _seed(db):
    db.add_url("http://leaks.onion")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    page_id = db.add_page(url_id, "http://leaks.onion/a", "t", "h1")
    db.add_finding(url_id, "http://leaks.onion/a", "r", "keyword:text",
                   50, "m", "s", "medium")
    db.conn.execute(
        "INSERT INTO tg_messages (page_id, url_id, msg_id, text) "
        "VALUES (?, ?, 1, 'hello')", (page_id, url_id))
    db.conn.commit()
    return url_id


def test_pages_indexes_are_not_unique(tmp_path):
    """A rolled-back release must still be able to insert duplicate rows."""
    from darkwatch import Database

    db = Database(str(tmp_path / "dw.db"))
    idx = {r[1]: r[2] for r in db.conn.execute("PRAGMA index_list(pages)")}
    for name in ("idx_pages_content_hash", "idx_pages_url_scanned",
                 "idx_pages_url_page"):
        assert idx.get(name) == 0, (name, idx)


def test_page_seen_uses_content_hash_index(tmp_path):
    from darkwatch import Database

    db = Database(str(tmp_path / "dw.db"))
    _seed(db)
    (plan,) = _plans(db, lambda: db.page_seen("h1"))
    assert plan == [
        "SEARCH pages USING COVERING INDEX idx_pages_content_hash "
        "(content_hash=?)"], plan


def test_url_rows_subqueries_use_url_scanned_index(tmp_path):
    """/api/urls: the title / latest page / page_type subqueries run once
    per URL; each must be an index search, not a scan of `pages`."""
    from darkwatch import Database

    db = Database(str(tmp_path / "dw.db"))
    _seed(db)
    (plan,) = _plans(db, lambda: db.get_url_rows())
    pages_lines = [l for l in plan if l.split()[1:2] in (["p"], ["pages"])]
    assert len(pages_lines) == 3, plan
    for line in pages_lines:
        assert line.startswith("SEARCH p USING ") and \
            "INDEX idx_pages_url_scanned (url_id=?)" in line, plan


def test_findings_joins_use_indexes(tmp_path):
    from darkwatch import Database

    db = Database(str(tmp_path / "dw.db"))
    _seed(db)
    (plan,) = _plans(db, lambda: db.get_findings())
    assert any(l.startswith("SEARCH p USING ")
               and "idx_pages_url_page (url_id=? AND page_url=?)" in l
               for l in plan), plan
    assert not any(l.startswith("SCAN p") for l in plan), plan

    # Telegram search: per-message finding count is answered from the
    # findings dedup index alone.
    (plan,) = _plans(db, lambda: db.search_tg_messages_local("hello"))
    assert ("SEARCH f USING COVERING INDEX idx_findings_dedup "
            "(url_id=? AND page_url=?)") in plan, plan


LEAK_RULE = """
rule leak_email
{
    meta:
        score = 70
    strings:
        $a = "alice@corp.example" nocase
    condition:
        $a
}
"""

MOVED_RULE = """
rule page_moved
{
    meta:
        score = 40
    strings:
        $a = "this page has moved" nocase
    condition:
        $a
}
"""


def _rescan_crawler(db, scanner):
    from darkwatch import DarkWebCrawler

    # rescan_pages only needs the database and the scanner; skip __init__
    # (Tor session, Playwright, alerting).
    crawler = DarkWebCrawler.__new__(DarkWebCrawler)
    crawler.db = db
    crawler.scanner = scanner
    return crawler


def test_rescan_keeps_findings_and_only_counts_new_rows(tmp_path):
    """Two snapshots of one page: v1 leaked an address, v2 no longer does.
    The rescan must keep v1's finding and the HTML-only finding (neither
    can be re-derived from v2's text), leave occurrence_count and
    last_seen_at alone, and report only rows it actually added."""
    pytest.importorskip("yara")
    from darkwatch import Database, YaraScanner, _ioc_hash

    curated = tmp_path / "keywords.yar"
    curated.write_text(LEAK_RULE)
    priv = tmp_path / "priv"
    priv.mkdir()
    db = Database(str(tmp_path / "dw.db"))
    db.add_url("http://leaks.onion")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    page_url = "http://leaks.onion/dump"
    v1 = db.add_page(url_id, page_url, "dump", "hash-v1",
                     text_snapshot="full dump: alice@corp.example:hunter2")
    v2 = db.add_page(url_id, page_url, "dump", "hash-v2",
                     text_snapshot="this page has moved")
    # What scan_page stored for v1: the text hit (same ioc_hash a rescan
    # computes) and a hit only the raw-HTML pass could see.
    db.add_finding(url_id, page_url, "leak_email", "keyword:text", 70,
                   "alice@corp.example", "...", "high",
                   ioc_hash=_ioc_hash(["alice@corp.example"]))
    db.add_finding(url_id, page_url, "html_comment", "keyword:html", 100,
                   "<!-- admin panel -->", "...", "critical",
                   ioc_hash=_ioc_hash(["<!-- admin panel -->"]))
    db.update_page_severity(v1, "critical", 100)
    db.conn.execute("UPDATE findings SET last_seen_at = '2026-01-01T00:00:00'")
    db.conn.commit()

    def rows():
        return db.conn.execute(
            "SELECT rule_name, occurrence_count, last_seen_at FROM findings "
            "ORDER BY rule_name").fetchall()

    before = rows()
    assert [r[0] for r in before] == ["html_comment", "leak_email"]

    scanner = YaraScanner(str(curated), str(curated), user_file=None,
                          private_dir=str(priv))
    out = _rescan_crawler(db, scanner).rescan_pages()
    assert out == {"scanned": 2, "findings": 0, "skipped": 0}
    assert rows() == before
    # The re-matched lower-severity hit does not lower the cached severity.
    assert db.conn.execute(
        "SELECT primary_severity, max_score FROM pages WHERE id = ?",
        (v1,)).fetchone() == ("critical", 100)

    # A rule added after the crawl that matches v2 adds exactly one row.
    (priv / "moved.yar").write_text(MOVED_RULE)
    scanner = YaraScanner(str(curated), str(curated), user_file=None,
                          private_dir=str(priv))
    crawler = _rescan_crawler(db, scanner)
    out = crawler.rescan_pages(url_id=url_id)
    assert out == {"scanned": 2, "findings": 1, "skipped": 0}
    after = rows()
    assert [r[0] for r in after] == ["html_comment", "leak_email", "page_moved"]
    assert after[:2] == before
    assert db.conn.execute(
        "SELECT primary_severity, max_score FROM pages WHERE id = ?",
        (v2,)).fetchone() == ("medium", 40)

    # Running it again adds nothing.
    assert crawler.rescan_pages(url_id=url_id)["findings"] == 0
    assert rows() == after


def test_rescan_applies_raised_rule_score(tmp_path):
    """A rule whose score was raised since the crawl: the re-matched row
    takes the new score and severity (matching the page's cached
    severity) but keeps occurrence_count and last_seen_at."""
    pytest.importorskip("yara")
    from darkwatch import Database, YaraScanner, _ioc_hash

    curated = tmp_path / "keywords.yar"
    curated.write_text(LEAK_RULE.replace("score = 70", "score = 90"))
    priv = tmp_path / "priv"
    priv.mkdir()
    db = Database(str(tmp_path / "dw.db"))
    db.add_url("http://leaks.onion")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    page_url = "http://leaks.onion/dump"
    page_id = db.add_page(url_id, page_url, "dump", "hash-v1",
                          text_snapshot="dump: alice@corp.example")
    db.add_finding(url_id, page_url, "leak_email", "keyword:text", 40,
                   "alice@corp.example", "...", "medium",
                   ioc_hash=_ioc_hash(["alice@corp.example"]))
    db.update_page_severity(page_id, "medium", 40)
    db.conn.execute("UPDATE findings SET last_seen_at = '2026-01-01T00:00:00'")
    db.conn.commit()

    scanner = YaraScanner(str(curated), str(curated), user_file=None,
                          private_dir=str(priv))
    out = _rescan_crawler(db, scanner).rescan_pages()
    assert out == {"scanned": 1, "findings": 0, "skipped": 0}
    assert db.conn.execute(
        "SELECT score, severity, occurrence_count, last_seen_at "
        "FROM findings").fetchall() == [
            (90, "high", 1, "2026-01-01T00:00:00")]
    assert db.conn.execute(
        "SELECT primary_severity, max_score FROM pages WHERE id = ?",
        (page_id,)).fetchone() == ("high", 90)


def test_add_finding_bump_false_never_lowers_score(tmp_path):
    from darkwatch import Database

    db = Database(str(tmp_path / "dw.db"))
    db.add_url("http://leaks.onion")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    page_url = "http://leaks.onion/a"
    db.add_finding(url_id, page_url, "r", "keyword:text", 90, "m", "s",
                   "high", ioc_hash="x")
    assert db.add_finding(url_id, page_url, "r", "keyword:text", 40, "m",
                          "s", "medium", ioc_hash="x", bump=False) is False
    assert db.conn.execute(
        "SELECT score, severity FROM findings").fetchone() == (90, "high")


def test_add_finding_bump_false_leaves_existing_row(tmp_path):
    from darkwatch import Database

    db = Database(str(tmp_path / "dw.db"))
    db.add_url("http://leaks.onion")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    args = (url_id, "http://leaks.onion/a", "r", "keyword:text", 50,
            "m", "s", "medium")
    assert db.add_finding(*args, ioc_hash="x") is True
    assert db.add_finding(*args, ioc_hash="x", bump=False) is False
    assert db.conn.execute(
        "SELECT occurrence_count FROM findings").fetchone()[0] == 1
    assert db.add_finding(*args, ioc_hash="x") is False
    assert db.conn.execute(
        "SELECT occurrence_count FROM findings").fetchone()[0] == 2


def test_scan_tg_message_links_the_inserted_page(tmp_path):
    """tg_messages.page_id is the row id add_page returned, even when
    another thread inserts a page with the same content hash right after
    (a re-select by hash would pick up that later row)."""
    from types import SimpleNamespace
    from darkwatch import Database, DarkWebCrawler

    db = Database(str(tmp_path / "dw.db"))
    db.add_url("https://t.me/leaks", source="telegram")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    real_add_page = db.add_page
    returned = []

    def add_page_then_race(uid, page_url, title, content_hash, **kw):
        pid = real_add_page(uid, page_url, title, content_hash, **kw)
        returned.append(pid)
        real_add_page(uid, "https://t.me/other/9", "other", content_hash)
        return pid

    db.add_page = add_page_then_race
    crawler = DarkWebCrawler.__new__(DarkWebCrawler)
    crawler.db = db
    crawler.data_extractor = SimpleNamespace(extract=lambda text: {})
    crawler._yara_match_text = lambda *a: 0
    msg = {"msg_id": 7, "text": "", "has_media": True, "media_type": "photo",
           "date_iso": "2026-11-01T00:00:00"}
    assert crawler.scan_tg_message(url_id, "leaks", msg) == 0
    page_id, mid = db.conn.execute(
        "SELECT page_id, msg_id FROM tg_messages").fetchone()
    assert mid == 7
    assert page_id == returned[0]
    assert db.conn.execute(
        "SELECT page_url FROM pages WHERE id = ?",
        (page_id,)).fetchone()[0] == "https://t.me/leaks/7"


# ── Lookups go through Database, under its lock ─────────────────────────────

def _unlocked_statements(db, call):
    """Run `call()` and return every SQL statement it sent while db.lock
    was free. The tests are single-threaded, so a held lock is the
    caller's own."""
    bad = []
    db.conn.set_trace_callback(
        lambda sql: None if db.lock.locked() else bad.append(sql))
    try:
        call()
    finally:
        db.conn.set_trace_callback(None)
    return bad


def test_url_lookup_helpers(tmp_path):
    from darkwatch import Database

    db = Database(str(tmp_path / "dw.db"))
    db.add_url("http://a.onion")
    url_id = db.get_url_id("http://a.onion")
    assert url_id is not None and db.get_url_id("http://b.onion") is None
    assert db.get_url_source(url_id) == "manual"
    assert db.get_url_source(url_id + 99) is None
    assert db.latest_page_id(url_id) is None
    db.conn.execute(
        "INSERT INTO pages (url_id, page_url, scanned_at) VALUES "
        "(?, 'http://a.onion/old', '2026-01-01'), "
        "(?, 'http://a.onion/new', '2026-02-01')", (url_id, url_id))
    newest = db.conn.execute(
        "SELECT id FROM pages WHERE page_url = 'http://a.onion/new'").fetchone()[0]
    assert db.latest_page_id(url_id) == newest
    tg_id = db.upsert_tg_channel("chan", 4242, title="chan")
    assert db.get_url_by_tg_channel_id(4242) == (tg_id, "chan")
    assert db.get_url_by_tg_channel_id(4243) is None
    # add_url still returns nothing (INSERT OR IGNORE has no reliable id).
    assert db.add_url("http://a.onion") is None

    assert _unlocked_statements(db, lambda: (
        db.get_url_id("http://a.onion"), db.get_url_source(url_id),
        db.latest_page_id(url_id), db.get_url_by_tg_channel_id(4242))) == []


def test_web_and_crawl_url_lookups_hold_the_db_lock(web, tmp_path, monkeypatch):
    """The scan thread, the monitor and the live consumer share one
    sqlite connection with every other thread, so they must not query it
    without the lock."""
    import queue
    import threading

    from darkwatch import Database, DarkWebCrawler

    db = Database(str(tmp_path / "dw.db"))
    crawler = DarkWebCrawler.__new__(DarkWebCrawler)
    crawler.db = db

    def crawl_site(url_id, url, **kw):
        db.add_page(url_id, url + "/p", "t", "h-" + url)
        return 1, 0
    crawler.crawl_site = crawl_site
    monkeypatch.setattr(web, "_crawler", crawler)
    monkeypatch.setattr(web, "_stop_event", threading.Event())

    assert _unlocked_statements(db, lambda: web._run_scan(["http://scan.onion"], 0)) == []
    assert _unlocked_statements(db, lambda: crawler.crawl_url("http://cli.onion")) == []
    url_id = db.get_url_id("http://scan.onion")
    assert url_id is not None
    assert _unlocked_statements(db, lambda: web._monitor_one(url_id, "http://scan.onion")) == []
    assert db.conn.execute(
        "SELECT page_id FROM monitor_events WHERE url_id = ?", (url_id,)
    ).fetchone()[0] == db.latest_page_id(url_id)

    tg_id = db.upsert_tg_channel("live", 777, title="live")
    monkeypatch.setattr(web, "_monitor_tg_channel", lambda _id: (0, 0, None))
    assert _unlocked_statements(db, lambda: web._monitor_one(tg_id, "tg://live")) == []

    stop, q, scanned = threading.Event(), queue.Queue(), []

    def scan_tg_message(*a):
        scanned.append(a[:2])
        stop.set()
    crawler.scan_tg_message = scan_tg_message
    monkeypatch.setattr(web, "_tg_live_stop", stop)
    monkeypatch.setattr(web, "_tg_live_queue", q)
    q.put({"channel_id": 777, "username": "live", "msg": {"msg_id": 1}})
    assert _unlocked_statements(db, web._tg_live_consumer) == []
    assert scanned == [(tg_id, "live")]
