"""Telegram ingest completeness: the polling cursor walks forward without
gaps, the live listener keeps media-only posts and does not move the
cursor, each channel stores its own copy of a repost (alerting once), and
a per-channel rescan only adds findings."""

import asyncio
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from darkwatch import (Database, DarkMTProto, DarkWebCrawler,  # noqa: E402
                       TelegramLiveListener)


class _Scanner:
    """YaraScanner stand-in: every rule in `rules` matches any text that
    contains "leak". Counts calls and checks db.lock is free (the scan
    path takes it itself; it is not reentrant)."""
    def __init__(self, db, rules=("leak_rule",), score=80):
        self.db = db
        self.rules = list(rules)
        self.score = score
        self.calls = 0

    def scan_parallel(self, text, lower):
        assert self.db.lock.acquire(timeout=1), "db.lock held during YARA"
        self.db.lock.release()
        self.calls += 1
        hits = {"keywords": [], "categories": []}
        if "leak" in text.lower():
            hits["keywords"] = [{"rule": r, "score": self.score,
                                 "matched_strings": ["leak"]}
                                for r in self.rules]
        return hits, hits


def _crawler(tmp_path):
    db = Database(str(tmp_path / "dw.db"))
    crawler = DarkWebCrawler.__new__(DarkWebCrawler)
    crawler.db = db
    crawler.data_extractor = SimpleNamespace(extract=lambda text: {})
    crawler.scanner = _Scanner(db)
    crawler.alerts = []
    crawler.alerter = SimpleNamespace(send=crawler.alerts.append)
    return crawler


def _channel(db, name, channel_id=None, mark=None):
    url_id = db.upsert_tg_channel(name, channel_id or abs(hash(name)) % 10**9,
                                  title=name)
    if mark is not None:
        db.update_tg_last_msg_id(url_id, mark)
    return url_id


def _count(db, sql, *params):
    return db.conn.execute(sql, params).fetchone()[0]


def _msg(msg_id, text="", **kw):
    return {"msg_id": msg_id, "text": text,
            "date_iso": "2026-11-01T00:00:00", **kw}


# ── Polling cursor ──────────────────────────────────────────────────────────

class _FakeTg:
    """DarkMTProto.fetch_new_messages over a channel holding `ids`: with
    since_msg_id the oldest `limit` above it ascending (min_id + reverse),
    without it the newest `limit` descending, below before_msg_id if set.
    Ids in `service` are service messages (joins, pins): they use up the
    limit but are not returned, as in the real fetch."""
    def __init__(self, ids, limit=100, service=()):
        self.service = set(service)
        self.ids = sorted(set(ids) | self.service)
        self.scrape_limit = limit
        self.calls = []
        self.last_fetch_error = None
        self.last_fetch_count = self.last_fetch_max_id = 0

    def fetch_new_messages(self, channel_id, since_msg_id=None, limit=None,
                           username=None, before_msg_id=None):
        self.calls.append(since_msg_id)
        if since_msg_id:
            read = [i for i in self.ids if i > since_msg_id][:limit]
        else:
            read = [i for i in self.ids[::-1]
                    if not before_msg_id or i < before_msg_id][:limit]
        self.last_fetch_count = len(read)
        self.last_fetch_max_id = max(read, default=0)
        return [_msg(i, f"post {i}") for i in read if i not in self.service]


@pytest.fixture
def poll(web, tmp_path, monkeypatch):
    crawler = _crawler(tmp_path)
    monkeypatch.setattr(web, "_crawler", crawler)
    monkeypatch.setattr(web, "_monitor_stop", threading.Event())
    monkeypatch.setattr(web.random, "uniform", lambda a, b: 0)

    def run(url_id, tg):
        monkeypatch.setattr(web, "_tg", tg)
        return web._monitor_tg_channel(url_id)
    return crawler, run


def _stored_ids(db, url_id):
    return [r[0] for r in db.conn.execute(
        "SELECT msg_id FROM tg_messages WHERE url_id = ? ORDER BY msg_id",
        (url_id,))]


def test_poll_catches_up_in_batches_without_gaps(poll):
    crawler, run = poll
    url_id = _channel(crawler.db, "busy", mark=1000)
    tg = _FakeTg(range(1, 1251), limit=100)
    assert run(url_id, tg) == (250, 0)
    assert _stored_ids(crawler.db, url_id) == list(range(1001, 1251))
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 1250
    # Each batch resumes from the previous batch's highest id.
    assert tg.calls == [1000, 1100, 1200]


def test_poll_saves_the_mark_after_each_batch(poll):
    crawler, run = poll
    url_id = _channel(crawler.db, "flaky", mark=1000)
    real_scan = crawler.scan_tg_message

    def fail_in_third_batch(url_id_, username, m):
        if m["msg_id"] == 1205:
            raise RuntimeError("database is locked")
        return real_scan(url_id_, username, m)
    crawler.scan_tg_message = fail_in_third_batch
    with pytest.raises(RuntimeError):
        run(url_id, _FakeTg(range(1, 1251), limit=100))
    # The two finished batches are kept; the third is fetched again.
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 1200


def test_poll_stops_at_the_batch_cap_and_warns(poll, web, caplog):
    crawler, run = poll
    url_id = _channel(crawler.db, "flood", mark=1000)
    tg = _FakeTg(range(1001, 1701), limit=100)
    with caplog.at_level(logging.WARNING):
        assert run(url_id, tg)[0] == 100 * web.TG_CATCHUP_BATCHES
    assert len(tg.calls) == web.TG_CATCHUP_BATCHES
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 1500
    assert any("catch-up stopped" in r.getMessage() for r in caplog.records)
    # The next check carries on where this one stopped.
    run(url_id, tg)
    assert _stored_ids(crawler.db, url_id) == list(range(1001, 1701))


def test_first_poll_without_a_mark_fetches_one_newest_batch(poll):
    crawler, run = poll
    url_id = _channel(crawler.db, "fresh")
    tg = _FakeTg(range(1, 251), limit=100)
    assert run(url_id, tg)[0] == 100
    assert tg.calls == [None]
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 250


def test_poll_moves_past_a_run_of_service_messages(poll):
    crawler, run = poll
    url_id = _channel(crawler.db, "joins", mark=100)
    # A join wave: 101..200 fill a whole batch and are all filtered out.
    tg = _FakeTg([201, 202], limit=100, service=range(101, 201))
    assert run(url_id, tg) == (2, 0)
    assert _stored_ids(crawler.db, url_id) == [201, 202]
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 202
    assert tg.calls == [100, 200]
    # The next check starts past them instead of reading them again.
    tg.ids.append(203)
    run(url_id, tg)
    assert tg.calls[-1] == 202
    assert _stored_ids(crawler.db, url_id) == [201, 202, 203]


def test_service_messages_do_not_end_the_catch_up(poll):
    crawler, run = poll
    url_id = _channel(crawler.db, "mixed", mark=1000)
    # One pin in the first batch: 99 posts come back, but the batch was
    # full, so the check carries on.
    tg = _FakeTg(range(1001, 1251), limit=100, service=[1050])
    assert run(url_id, tg)[0] == 249
    assert tg.calls == [1000, 1100, 1200]
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 1250


def test_poll_without_read_counts_falls_back_to_the_messages(poll):
    # A fetcher without last_fetch_count / last_fetch_max_id (an older
    # engine or a stub) still works off the returned messages.
    crawler, run = poll
    url_id = _channel(crawler.db, "plain", mark=10)
    tg = _FakeTg(range(1, 31), limit=100)
    tg.fetch_new_messages = lambda *a, **kw: [_msg(i, "x") for i in (11, 12)]
    del tg.last_fetch_count, tg.last_fetch_max_id
    assert run(url_id, tg) == (2, 0)
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 12


def test_mark_never_moves_back(tmp_path):
    db = Database(str(tmp_path / "dw.db"))
    url_id = _channel(db, "c", mark=500)
    db.update_tg_last_msg_id(url_id, 200)
    assert db.get_tg_channel(url_id)["tg_last_msg_id"] == 500
    db.update_tg_last_msg_id(url_id, 600)
    assert db.get_tg_channel(url_id)["tg_last_msg_id"] == 600


class _TlMsg:
    def __init__(self, mid, text="", media=None):
        self.id = mid
        self.date = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.message = text
        self.media = media
        self.sender = None
        self.reply_to = None
        self.fwd_from = None
        self.views = 0


class _KwargsClient:
    """Records the iter_messages kwargs; yields nothing."""
    def __init__(self):
        self.kwargs = None
    async def connect(self): pass
    async def disconnect(self): pass
    async def is_user_authorized(self): return True
    async def get_entity(self, ref):
        return SimpleNamespace(forum=False)
    def iter_messages(self, **kwargs):
        self.kwargs = kwargs
        async def gen():
            return
            yield
        return gen()


def _engine():
    return DarkMTProto({"telegram": {
        "api_id": "1", "api_hash": "x", "proxy_host": "tunnel2",
        "rate_per_s": 1000, "burst": 1000, "jitter": 0}})


def test_fetch_passes_reverse_only_with_since(monkeypatch):
    pytest.importorskip("telethon")
    eng = _engine()
    fake = _KwargsClient()
    monkeypatch.setattr(eng, "_build_client", lambda: fake)
    eng.fetch_new_messages(123, since_msg_id=40, limit=100, username="@c")
    assert fake.kwargs["min_id"] == 40 and fake.kwargs["reverse"] is True
    # Without a cursor, reverse would start at the channel's first post.
    eng.fetch_new_messages(123, limit=100, username="@c")
    assert "reverse" not in fake.kwargs and "min_id" not in fake.kwargs
    eng.fetch_new_messages(123, limit=100, username="@c", before_msg_id=90)
    assert "reverse" not in fake.kwargs and fake.kwargs["max_id"] == 90


class _ListClient(_KwargsClient):
    """Yields `msgs`, then raises `fail` if set."""
    def __init__(self, msgs, fail=None):
        super().__init__()
        self.msgs, self.fail = msgs, fail
    def iter_messages(self, **kwargs):
        self.kwargs = kwargs
        msgs, fail = self.msgs, self.fail
        async def gen():
            for m in msgs:
                yield m
            if fail:
                raise fail
        return gen()


def test_fetch_reports_how_far_it_read(monkeypatch):
    pytest.importorskip("telethon")
    eng = _engine()
    # 41-42 are service messages (no text, no media): not returned, but
    # they were read and count toward the limit.
    fake = _ListClient([_TlMsg(41), _TlMsg(42), _TlMsg(43, "post")])
    monkeypatch.setattr(eng, "_build_client", lambda: fake)
    out = eng.fetch_new_messages(123, since_msg_id=40, limit=3, username="@c")
    assert [m["msg_id"] for m in out] == [43]
    assert (eng.last_fetch_count, eng.last_fetch_max_id) == (3, 43)
    # A failed fetch stored nothing, so it reports nothing read.
    fake.fail = RuntimeError("connection lost")
    assert eng.fetch_new_messages(123, since_msg_id=40, username="@c") == []
    assert (eng.last_fetch_count, eng.last_fetch_max_id) == (0, 0)


# ── Manual scrape ───────────────────────────────────────────────────────────

@pytest.fixture
def scrape(web, tmp_path, monkeypatch):
    crawler = _crawler(tmp_path)
    monkeypatch.setattr(web, "_crawler", crawler)

    def run(url_id, tg, limit):
        tg.configured = lambda: True
        tg.status = lambda: {"authenticated": True}
        monkeypatch.setattr(web, "_tg", tg)
        r = web.app.test_client().post(
            f"/api/telegram/channels/{url_id}/scrape",
            base_url="http://127.0.0.1:8080", json={"limit": limit})
        assert r.status_code == 200, r.get_json()
        return r.get_json()
    return crawler, run


def test_scrape_that_reaches_the_mark_raises_it(scrape):
    crawler, run = scrape
    url_id = _channel(crawler.db, "near", mark=150)
    assert run(url_id, _FakeTg(range(1, 201)), 100)["fetched"] == 100
    # 101..200 covers everything above 150: nothing left for polling.
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 200


def test_scrape_without_a_mark_sets_it(scrape):
    crawler, run = scrape
    url_id = _channel(crawler.db, "new")
    run(url_id, _FakeTg(range(1, 201)), 100)
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 200


def test_scrape_that_misses_the_mark_leaves_it_for_polling(
        scrape, web, monkeypatch):
    crawler, run = scrape
    url_id = _channel(crawler.db, "far", mark=50)
    tg = _FakeTg(range(1, 201))
    assert run(url_id, tg, 100)["fetched"] == 100
    # The scrape got 101..200; 51..100 were never fetched, so the mark
    # stays and the next poll walks the gap.
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 50
    monkeypatch.setattr(web, "_monitor_stop", threading.Event())
    monkeypatch.setattr(web.random, "uniform", lambda a, b: 0)
    # It fetches 51..200 again; the scraped half is not stored twice.
    assert web._monitor_tg_channel(url_id) == (150, 0)
    assert _count(crawler.db, "SELECT COUNT(*) FROM tg_messages") == 150
    assert _stored_ids(crawler.db, url_id) == list(range(51, 201))
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 200


# ── Live listener ───────────────────────────────────────────────────────────

class MessageMediaPhoto:
    pass


def _event(msg, chat_id=-1000000000123):
    async def get_sender():
        return None
    return SimpleNamespace(chat_id=chat_id, message=msg, chat=None,
                           get_sender=get_sender)


def test_live_listener_keeps_media_only_messages():
    pytest.importorskip("telethon")
    got = []
    listener = TelegramLiveListener(
        None, on_message=lambda *a: got.append(a), channel_ids=[123])
    asyncio.run(listener._on_event(_event(_TlMsg(5, "", MessageMediaPhoto()))))
    asyncio.run(listener._on_event(_event(_TlMsg(6, "", None))))   # service msg
    assert [(cid, m["msg_id"], m["has_media"], m["media_type"])
            for cid, _, m in got] == [(123, 5, True, "photo")]


def test_live_consumer_does_not_move_the_mark(web, tmp_path, monkeypatch):
    import queue
    crawler = _crawler(tmp_path)
    url_id = _channel(crawler.db, "live", channel_id=777, mark=5)
    stop = threading.Event()
    q = queue.Queue()
    monkeypatch.setattr(web, "_crawler", crawler)
    monkeypatch.setattr(web, "_tg_live_stop", stop)
    monkeypatch.setattr(web, "_tg_live_queue", q)
    real_scan = crawler.scan_tg_message

    def scan_then_stop(*a):
        try:
            return real_scan(*a)
        finally:
            stop.set()
    crawler.scan_tg_message = scan_then_stop
    q.put({"channel_id": 777, "username": "live", "msg": _msg(9, "hello")})
    web._tg_live_consumer()
    assert _stored_ids(crawler.db, url_id) == [9]
    # Messages 6-8 may have been missed by the listener; the next poll
    # must still fetch them.
    assert crawler.db.get_tg_channel(url_id)["tg_last_msg_id"] == 5


# ── Reposts and duplicates ──────────────────────────────────────────────────

def test_repost_in_two_channels_stores_both_and_alerts_once(tmp_path):
    crawler = _crawler(tmp_path)
    db = crawler.db
    a, b = _channel(db, "chan_a"), _channel(db, "chan_b")
    assert crawler.scan_tg_message(a, "chan_a", _msg(1, "big leak")) == 1
    assert crawler.scan_tg_message(b, "chan_b", _msg(4, "big leak")) == 1
    assert _count(db, "SELECT COUNT(*) FROM tg_messages") == 2
    assert _count(db, "SELECT COUNT(*) FROM pages") == 2
    assert crawler.scanner.calls == 2
    assert sorted(r[0] for r in db.conn.execute(
        "SELECT page_url FROM findings")) == \
        ["https://t.me/chan_a/1", "https://t.me/chan_b/4"]
    assert [x["page_url"] for x in crawler.alerts] == ["https://t.me/chan_a/1"]


def test_repeated_text_in_one_channel_is_stored(tmp_path):
    crawler = _crawler(tmp_path)
    url_id = _channel(crawler.db, "chat")
    crawler.scan_tg_message(url_id, "chat", _msg(1, "ok"))
    crawler.scan_tg_message(url_id, "chat", _msg(2, "ok"))
    assert _stored_ids(crawler.db, url_id) == [1, 2]


def test_same_message_twice_adds_nothing(tmp_path):
    crawler = _crawler(tmp_path)
    db = crawler.db
    url_id = _channel(db, "chan")
    assert crawler.scan_tg_message(url_id, "chan", _msg(3, "big leak")) == 1
    before = [_count(db, f"SELECT COUNT(*) FROM {t}")
              for t in ("pages", "tg_messages", "findings")]
    assert crawler.scan_tg_message(url_id, "chan", _msg(3, "big leak")) == 0
    assert [_count(db, f"SELECT COUNT(*) FROM {t}")
            for t in ("pages", "tg_messages", "findings")] == before
    assert _count(db, "SELECT occurrence_count FROM findings") == 1
    assert crawler.scanner.calls == 1
    assert len(crawler.alerts) == 1


def test_tg_message_seen_uses_the_channel_index(tmp_path):
    db = Database(str(tmp_path / "dw.db"))
    sent = []
    db.conn.set_trace_callback(sent.append)
    try:
        db.tg_message_seen(1, 2)
    finally:
        db.conn.set_trace_callback(None)
    (sql,) = [s for s in sent if s.lstrip().upper().startswith("SELECT")]
    plan = " ".join(r[3] for r in db.conn.execute("EXPLAIN QUERY PLAN " + sql))
    assert "idx_tg_messages_url" in plan, plan


# ── Per-channel rescan ──────────────────────────────────────────────────────

def test_channel_rescan_only_adds_findings(tmp_path):
    crawler = _crawler(tmp_path)
    db = crawler.db
    url_id = _channel(db, "chan")
    crawler.scanner.rules = ["gone_rule", "kept_rule"]
    crawler.scan_tg_message(url_id, "chan", _msg(1, "big leak"))
    db.conn.execute("UPDATE findings SET occurrence_count = 3")
    db.conn.commit()
    alerts_before = len(crawler.alerts)

    # gone_rule was deleted, new_rule was added.
    crawler.scanner.rules = ["kept_rule", "new_rule"]
    assert crawler.rescan_tg_channel(url_id) == {"scanned": 1, "findings": 1}
    rows = dict(db.conn.execute(
        "SELECT rule_name, occurrence_count FROM findings"))
    assert rows == {"gone_rule": 3, "kept_rule": 3, "new_rule": 1}
    # Only the new row alerts.
    assert [a["rule_name"] for a in crawler.alerts[alerts_before:]] == \
        ["new_rule"]
    # Repeating it adds and alerts nothing.
    assert crawler.rescan_tg_channel(url_id) == {"scanned": 1, "findings": 0}
    assert dict(db.conn.execute(
        "SELECT rule_name, occurrence_count FROM findings")) == rows
    assert [a["rule_name"] for a in crawler.alerts[alerts_before:]] == \
        ["new_rule"]
