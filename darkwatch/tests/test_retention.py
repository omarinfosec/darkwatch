"""Storage retention: the batched snapshot reader, `darkwatch.py
--retention` (monitor events, old text snapshots, paths of pruned files,
WAL checkpoint) and the file removal of a deleted URL.
Run: pytest darkwatch/tests/
"""

import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import darkwatch as dw  # noqa: E402

SITE = "http://" + "a" * 56 + ".onion"
BASE = "http://127.0.0.1:8080"


class _CountingLock:
    """threading.Lock that counts its acquisitions."""
    def __init__(self):
        self._lock = threading.Lock()
        self.count = 0

    def __enter__(self):
        self._lock.acquire()
        self.count += 1

    def __exit__(self, *exc):
        self._lock.release()

    def locked(self):
        return self._lock.locked()


def _url(db, url=SITE):
    db.add_url(url)
    return db.conn.execute("SELECT id FROM urls WHERE url = ?", (url,)).fetchone()[0]


def _page(db, url_id, page_url, days_ago, snapshot="text", title="Leak page",
          screenshot=None, thumbnail=None):
    pid = db.add_page(url_id, page_url, title, f"h-{page_url}-{days_ago}",
                      screenshot_path=screenshot, thumbnail_path=thumbnail,
                      text_snapshot=snapshot)
    db.conn.execute("UPDATE pages SET scanned_at = datetime('now', ?) "
                    "WHERE id = ?", (f"-{days_ago} days", pid))
    db.conn.commit()
    return pid


def _snapshots(db):
    return {r[0]: r[1] for r in db.conn.execute(
        "SELECT id, text_snapshot FROM pages")}


# ─── iter_pages_with_text ────────────────────────────────────────────────────

def test_iter_pages_with_text_reads_200_rows_per_lock(tmp_path):
    db = dw.Database(str(tmp_path / "dw.db"))
    a, b = _url(db), _url(db, SITE + "/other")
    ids = []
    for i in range(450):
        ids.append(_page(db, a if i % 3 else b, f"{SITE}/{i}", 1,
                         snapshot=f"t{i}"))
    _page(db, a, f"{SITE}/none", 1, snapshot=None)
    db.lock = _CountingLock()
    seen = []
    for row in db.iter_pages_with_text():
        # Not held while the caller works on a row (rescan writes findings).
        assert not db.lock.locked()
        seen.append(row[0])
    assert seen == ids
    assert db.lock.count == 3                     # 200 + 200 + 50
    only_b = [r[0] for r in db.iter_pages_with_text(url_id=b)]
    assert only_b == [pid for i, pid in enumerate(ids) if not i % 3]


# ─── --retention ─────────────────────────────────────────────────────────────

@pytest.fixture
def populated(tmp_path):
    """A database with old and new rows of every kind retention touches,
    and loot files of which some were pruned."""
    loot = tmp_path / "loot"
    shots, thumbs, media = loot / "screenshots", loot / "thumbnails", loot / "tg-media"
    for d in (shots, thumbs, media / "chan"):
        d.mkdir(parents=True)
    (shots / "kept.png").write_bytes(b"png")
    (thumbs / "kept.jpg").write_bytes(b"jpg")
    (media / "chan" / "kept.jpg").write_bytes(b"jpg")
    db = dw.Database(str(tmp_path / "dw.db"))
    u = _url(db)
    p = {
        # Page A: two old versions and a recent one.
        "a_old1": _page(db, u, f"{SITE}/a", 400),
        "a_old2": _page(db, u, f"{SITE}/a", 380),
        "a_new": _page(db, u, f"{SITE}/a", 10,
                       screenshot=str(shots / "kept.png"),
                       thumbnail=str(thumbs / "kept.jpg")),
        # Page B: only old versions; the newest keeps its snapshot.
        "b_old1": _page(db, u, f"{SITE}/b", 500,
                        screenshot=str(shots / "gone.png"),
                        thumbnail=str(thumbs / "gone.jpg")),
        "b_old2": _page(db, u, f"{SITE}/b", 390),
        # Page C: one old version whose screenshot dir is not there at all
        # (loot not mounted): its paths stay.
        "c_old": _page(db, u, f"{SITE}/c", 400,
                       screenshot=str(tmp_path / "unmounted" / "x.png")),
    }
    for days in (200, 181, 179, 1):
        eid = db.add_monitor_event(u, 200, 1, 0, page_id=p["a_new"])
        db.conn.execute("UPDATE monitor_events SET checked_at = "
                        "datetime('now', ?) WHERE id = ?", (f"-{days} days", eid))
    tg_page = _page(db, u, "https://t.me/chan/1", 1, snapshot=None)
    for msg_id, path in ((1, "chan/kept.jpg"), (2, "chan/gone.jpg"), (3, None)):
        db.add_tg_message(u, tg_page, {"msg_id": msg_id, "text": "m",
                                       "media_path": path})
    db.add_finding(u, f"{SITE}/b", "leak_rule", "keyword:text", 80,
                   "x", "snippet", "high")
    db.conn.commit()
    return db, str(loot), p


def test_retention_dry_run_counts_and_changes_nothing(populated):
    db, loot, _ = populated
    before = (_snapshots(db), db.conn.execute(
        "SELECT COUNT(*) FROM monitor_events").fetchone()[0],
        db.conn.execute("SELECT screenshot_path, thumbnail_path FROM pages "
                        "ORDER BY id").fetchall(),
        db.conn.execute("SELECT media_path FROM tg_messages").fetchall())
    out = dw.run_retention(db, loot, dry_run=True)
    assert out == {"monitor_events": 2, "text_snapshots": 3,
                   "screenshot_path": 1, "thumbnail_path": 1, "media_path": 1}
    after = (_snapshots(db), db.conn.execute(
        "SELECT COUNT(*) FROM monitor_events").fetchone()[0],
        db.conn.execute("SELECT screenshot_path, thumbnail_path FROM pages "
                        "ORDER BY id").fetchall(),
        db.conn.execute("SELECT media_path FROM tg_messages").fetchall())
    assert after == before


def test_retention_applies_each_step(populated):
    db, loot, p = populated
    pages = db.conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
    out = dw.run_retention(db, loot)
    assert out["monitor_events"] == 2 and out["text_snapshots"] == 3
    # Events older than 180 days are gone, newer ones stay.
    left = [r[0] for r in db.conn.execute(
        "SELECT CAST(julianday('now') - julianday(checked_at) AS INTEGER) "
        "FROM monitor_events ORDER BY checked_at")]
    assert left == [179, 1] or left == [178, 1]  # rounding at midnight
    # Old snapshots NULL except the newest of each page; no page row deleted.
    snaps = _snapshots(db)
    assert snaps[p["a_old1"]] is None and snaps[p["a_old2"]] is None
    assert snaps[p["a_new"]] == "text"
    assert snaps[p["b_old1"]] is None and snaps[p["b_old2"]] == "text"
    assert snaps[p["c_old"]] == "text"
    assert db.conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == pages
    assert db.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    # Paths of pruned files are NULL; existing files and unmounted dirs stay.
    paths = {r[0]: (r[1], r[2]) for r in db.conn.execute(
        "SELECT id, screenshot_path, thumbnail_path FROM pages")}
    assert paths[p["a_new"]][0].endswith("kept.png")
    assert paths[p["a_new"]][1].endswith("kept.jpg")
    assert paths[p["b_old1"]] == (None, None)
    assert paths[p["c_old"]][0].endswith("unmounted/x.png")
    media = [r[0] for r in db.conn.execute(
        "SELECT media_path FROM tg_messages ORDER BY msg_id")]
    assert media == ["chan/kept.jpg", None, None]
    assert out["wal_checkpoint"]["busy"] == 0
    # A second run has nothing left to do.
    again = dw.run_retention(db, loot)
    assert again["monitor_events"] == again["text_snapshots"] == 0
    assert again["screenshot_path"] == again["media_path"] == 0


def test_retention_steps_can_be_turned_off(populated):
    db, loot, _ = populated
    out = dw.run_retention(db, loot, {"monitor_events_days": 0,
                                      "text_snapshot_days": 0,
                                      "clear_missing_files": False,
                                      "wal_checkpoint": False})
    assert out == {}
    out = dw.run_retention(db, loot, {"monitor_events_days": 190,
                                      "text_snapshot_days": 450,
                                      "clear_missing_files": False})
    assert out["monitor_events"] == 1 and out["text_snapshots"] == 1


def test_retention_checkpoint_does_not_wait_long_for_a_reader(populated, tmp_path):
    """A pending TRUNCATE checkpoint blocks new writers (the crawler and the
    dashboard, 5 s timeout) while it waits for a reader: it gives up after
    about a second and reports busy, instead of the 30 s the row steps wait."""
    import sqlite3
    import time
    db, loot, _ = populated
    reader = sqlite3.connect(str(tmp_path / "dw.db"))
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM pages").fetchone()
        db.conn.execute("UPDATE pages SET title = 'x' WHERE id = 1")
        db.conn.commit()                    # WAL frames the reader can't see
        start = time.monotonic()
        out = dw.run_retention(db, loot, {"monitor_events_days": 0,
                                          "text_snapshot_days": 0,
                                          "clear_missing_files": False})
        assert time.monotonic() - start < 4
        assert out["wal_checkpoint"]["busy"] == 1
    finally:
        reader.close()


def test_retention_cli_uses_only_the_database(populated, tmp_path, monkeypatch):
    db, loot, _ = populated
    cfg = tmp_path / "config.json"
    cfg.write_text('{"database": {"path": "%s"}, "output": {"loot_dir": "%s"}}'
                   % (tmp_path / "dw.db", loot))

    def no_crawler(*a, **kw):
        raise AssertionError("--retention must not build the crawler")
    monkeypatch.setattr(dw, "DarkWebCrawler", no_crawler)
    monkeypatch.setenv("DARKWATCH_CONFIG", str(cfg))
    monkeypatch.setattr(sys, "argv", ["darkwatch.py", "--retention", "--dry-run"])
    dw.main()
    assert db.conn.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0] == 4
    monkeypatch.setattr(sys, "argv", ["darkwatch.py", "--retention",
                                      "--monitor-events-days", "190",
                                      "--text-snapshot-days", "0"])
    dw.main()
    assert db.conn.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0] == 3
    assert sum(v is None for v in _snapshots(db).values()) == 1  # the tg page
    monkeypatch.setattr(sys, "argv", ["darkwatch.py", "--dry-run"])
    with pytest.raises(SystemExit):
        dw.main()


def test_findings_resolve_after_retention_on_a_copy(populated, tmp_path,
                                                    web, monkeypatch):
    """On a copy of a populated database: /api/findings still resolves
    the page and its title after retention, and a thumbnail whose file was
    pruned is no longer offered instead of answering 404."""
    db, loot, _ = populated
    copy = dw.Database(str(tmp_path / "copy.db"))
    db.conn.backup(copy.conn)
    monkeypatch.setattr(web._crawler, "db", copy)
    monkeypatch.setattr(web._crawler, "loot_dir", loot)
    monkeypatch.setattr(web._crawler, "thumbnails_dir",
                        os.path.join(loot, "thumbnails"))
    client = web.app.test_client()

    def finding():
        r = client.get("/api/findings", base_url=BASE)
        assert r.status_code == 200
        (f,) = r.get_json()["findings"]
        return f

    before = finding()
    assert before["page_title"] == "Leak page" and before["page_id"]
    # Page B's newest version has no thumbnail; pin the join to the one
    # that had a (now pruned) file.
    copy.conn.execute("UPDATE pages SET thumbnail_path = ? WHERE page_url = ?",
                      (os.path.join(loot, "thumbnails", "gone.jpg"),
                       f"{SITE}/b"))
    copy.conn.commit()
    before = finding()
    assert client.get(before["thumbnail_url"], base_url=BASE).status_code == 404
    dw.run_retention(copy, loot)
    after = finding()
    assert after["page_title"] == "Leak page"
    assert after["page_id"] == before["page_id"]
    assert after["thumbnail_url"] is None and after["screenshot_url"] is None
    # The original database was not touched.
    assert db.conn.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0] == 4


# ─── delete_url removes the URL's files ──────────────────────────────────────

def test_delete_url_removes_its_files_best_effort(tmp_path):
    loot = tmp_path / "loot"
    shots, thumbs, media = loot / "screenshots", loot / "thumbs", loot / "tg-media"
    for d in (shots, thumbs, media / "chan", media / "channels"):
        d.mkdir(parents=True)
    files = {n: d / n for d, n in ((shots, "a.png"), (thumbs, "a.jpg"),
                                   (media / "chan", "1.jpg"),
                                   (media / "channels", "chan.jpg"),
                                   (media / "channels", "shared.jpg"),
                                   (tmp_path, "outside.png"))}
    for f in files.values():
        f.write_bytes(b"x")
    c = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    c.db = dw.Database(str(tmp_path / "dw.db"))
    c.loot_dir, c.thumbnails_dir = str(loot), str(thumbs)
    u, other, keep = (_url(c.db, SITE), _url(c.db, SITE + "/x"),
                      _url(c.db, "https://t.me/other"))
    _page(c.db, u, f"{SITE}/a", 1, screenshot=str(files["a.png"]),
          thumbnail=str(files["a.jpg"]))
    # A stored path outside its loot directory is never removed.
    _page(c.db, u, f"{SITE}/b", 1, screenshot=str(files["outside.png"]))
    # Already gone: skipped quietly.
    _page(c.db, u, f"{SITE}/c", 1, screenshot=str(shots / "missing.png"))
    tg = _page(c.db, u, "https://t.me/chan/1", 1, snapshot=None)
    c.db.add_tg_message(u, tg, {"msg_id": 1, "text": "m",
                                "media_path": "chan/1.jpg"})
    c.db.conn.execute("UPDATE urls SET tg_photo_path = 'channels/chan.jpg' "
                      "WHERE id = ?", (u,))
    # An avatar another tracked row still shows stays.
    c.db.conn.execute("UPDATE urls SET tg_photo_path = 'channels/shared.jpg' "
                      "WHERE id IN (?, ?)", (other, keep))
    c.db.conn.commit()
    assert c.delete_url(u) == 4
    for name in ("a.png", "a.jpg", "1.jpg", "chan.jpg"):
        assert not files[name].exists(), name
    assert files["outside.png"].exists() and files["shared.jpg"].exists()
    assert c.db.conn.execute(
        "SELECT COUNT(*) FROM pages WHERE url_id = ?", (u,)).fetchone()[0] == 0
    assert c.delete_url(other) == 0
    assert files["shared.jpg"].exists()


def test_delete_url_route_removes_files(web, tmp_path, monkeypatch):
    db = dw.Database(str(tmp_path / "dw.db"))
    shots = tmp_path / "loot" / "screenshots"
    shots.mkdir(parents=True)
    (shots / "s.png").write_bytes(b"x")
    u = _url(db)
    _page(db, u, f"{SITE}/a", 1, screenshot=str(shots / "s.png"))
    monkeypatch.setattr(web._crawler, "db", db)
    monkeypatch.setattr(web._crawler, "loot_dir", str(tmp_path / "loot"))
    monkeypatch.setattr(web, "_refresh_tg_live_channels", lambda: None)
    r = web.app.test_client().delete(f"/api/urls/{u}", base_url=BASE,
                                      headers={"Origin": BASE})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert not (shots / "s.png").exists()
    assert not db.url_exists(u)
