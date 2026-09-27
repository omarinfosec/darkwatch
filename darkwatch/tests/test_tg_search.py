"""Telegram keyword-search correctness: date filter, exact-match flag,
LIKE escaping, scam/fake ranking and the no-direct-connection guard."""

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytest.importorskip("telethon")

from darkwatch import Database, DarkMTProto  # noqa: E402


def _engine(**tg):
    base = {"api_id": "1", "api_hash": "x", "proxy_host": "tunnel2",
            "rate_per_s": 1000, "burst": 1000, "jitter": 0}
    base.update(tg)
    return DarkMTProto({"telegram": base})


class _Msg:
    def __init__(self, mid, day, text):
        self.id = mid
        self.date = datetime(2026, 1, day, tzinfo=timezone.utc)
        self.message = text
        self.views = 0


class _FakeClient:
    """Mimics TelegramClient.iter_messages: newest -> oldest, and records
    the kwargs it was called with."""
    def __init__(self, msgs):
        self.msgs = msgs
        self.kwargs = None
    async def connect(self): pass
    async def disconnect(self): pass
    async def is_user_authorized(self): return True
    def iter_messages(self, **kwargs):
        self.kwargs = kwargs
        msgs = self.msgs
        async def gen():
            for m in msgs:
                yield m
        return gen()


def test_search_in_channel_since_keeps_newer_and_flags_exact(monkeypatch):
    eng = _engine()
    fake = _FakeClient([
        _Msg(5, 20, "fresh LockBit leak"),     # after cutoff, exact
        _Msg(4, 15, "lockbits news"),          # after cutoff, exact (substring)
        _Msg(3, 12, "ransomware gang"),        # after cutoff, fuzzy only
        _Msg(2, 5, "old lockbit post"),        # before cutoff -> excluded
        _Msg(1, 1, "older lockbit post"),
    ])
    monkeypatch.setattr(eng, "_build_client", lambda: fake)
    out = eng.search_in_channel(123, "lockbit", min_date_iso="2026-01-10")
    assert [m["msg_id"] for m in out] == [5, 4, 3]
    assert [m["exact_match"] for m in out] == [True, True, False]
    # Must not pass offset_date (that walks OLDER than the date).
    assert "offset_date" not in fake.kwargs


def test_build_client_refuses_direct_connection():
    eng = _engine(proxy_host="")
    with pytest.raises(RuntimeError, match="refusing a direct connection"):
        eng._build_client()


def test_use_tor_defaults_to_tunnel1():
    eng = _engine(use_tor=True)
    assert eng._proxy_tuple()[1] == "tunnel1"


def test_local_search_escapes_like_wildcards(tmp_path):
    db = Database(str(tmp_path / "dw.db"))
    db.add_url("https://t.me/leaks", source="telegram")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    for i, text in enumerate(["user_name dumped", "userXname dumped",
                              "100% legit", "1000 rows"], start=1):
        db.add_page(url_id, f"https://t.me/leaks/{i}", "t", f"h{i}",
                    page_type="telegram_message")
        pid = db.conn.execute("SELECT id FROM pages WHERE content_hash = ?",
                              (f"h{i}",)).fetchone()[0]
        db.conn.execute("INSERT INTO tg_messages (page_id, url_id, msg_id, text) "
                        "VALUES (?, ?, ?, ?)", (pid, url_id, i, text))
    db.conn.commit()
    texts = lambda q: sorted(r["text"] for r in db.search_tg_messages_local(q))
    assert texts("user_name") == ["user_name dumped"]
    assert texts("100%") == ["100% legit"]
    assert texts("USER_NAME") == ["user_name dumped"]   # still case-insensitive


def test_smart_discover_ranks_scam_and_fake_last(monkeypatch):
    eng = _engine()
    rows = [
        {"id": 1, "title": "huge fake", "username": "a", "subscribers": 5_000_000_000,
         "verified": False, "scam": False, "fake": True},
        {"id": 2, "title": "huge scam", "username": "b", "subscribers": 5_000_000_000,
         "verified": False, "scam": True, "fake": False},
        {"id": 3, "title": "small real", "username": "c", "subscribers": 0,
         "verified": False, "scam": False, "fake": False},
    ]
    monkeypatch.setattr(eng, "search_directory",
                        lambda q, limit=20: {"channels": rows, "users": []})
    out = eng.smart_discover("lockbit", max_variants=1, mine_forwards=False)
    assert [c["id"] for c in out["channels"]][0] == 3
