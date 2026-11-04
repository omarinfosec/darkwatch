"""Dashboard robustness: the live-log ring buffer behind /api/status,
integer max_hops, visible report/CSV truncation, and the quick health
check's Tunnel 1 probe (Tor's ControlPort, with a SOCKS fallback)."""

import collections
import json
import socket

import pytest

# The `web` fixture (the imported dashboard module) is in conftest.py.

BASE = "http://127.0.0.1:8080"


# ─── Live log ring buffer ────────────────────────────────────────────────────

@pytest.fixture
def logbuf(web, monkeypatch):
    """A fresh, small ring buffer so a test sees only its own lines."""
    monkeypatch.setattr(web, "_log_buf", collections.deque(maxlen=50))
    monkeypatch.setattr(web, "_LOG_SEQ_START", 1000)
    monkeypatch.setattr(web, "_log_seq", 1000)
    return web


def _status(web, since=None):
    q = "" if since is None else f"?since={since}"
    r = web.app.test_client().get("/api/status" + q, base_url=BASE)
    assert r.status_code == 200
    return r.get_json()


def _lines(body):
    return [line.split(" ", 2)[2] for line in body["new_logs"]]


def test_two_clients_both_get_every_log_line(logbuf):
    web = logbuf
    a = _status(web)["log_seq"]
    b = _status(web)["log_seq"]
    web.log.warning("ring line 1")
    web.log.warning("ring line 2")
    got_a = _status(web, a)
    got_b = _status(web, b)      # A's read must not have consumed them
    assert _lines(got_a) == _lines(got_b) == ["ring line 1", "ring line 2"]
    assert got_a["logs_gap"] is False and got_b["logs_gap"] is False
    assert got_a["log_seq"] == a + 2
    # Nothing new since the last seq.
    again = _status(web, got_a["log_seq"])
    assert again["new_logs"] == [] and again["logs_gap"] is False
    assert again["log_seq"] == got_a["log_seq"]


def test_status_without_cursor_returns_the_tail(logbuf, monkeypatch):
    web = logbuf
    monkeypatch.setattr(web, "LOG_TAIL_LINES", 3)
    first = _status(web)
    assert first["new_logs"] == [] and first["logs_gap"] is False
    for i in range(5):
        web.log.warning(f"tail {i}")
    body = _status(web)
    assert _lines(body) == ["tail 2", "tail 3", "tail 4"]
    assert body["logs_gap"] is True          # older lines exist
    # A cursor ahead of the buffer (from before a restart) gets the tail too.
    ahead = _status(web, body["log_seq"] + 100)
    assert _lines(ahead) == ["tail 2", "tail 3", "tail 4"]
    assert ahead["logs_gap"] is True


def test_buffer_overflow_sets_the_gap_flag(logbuf, monkeypatch):
    web = logbuf
    monkeypatch.setattr(web, "_log_buf", collections.deque(maxlen=4))
    web.log.warning("old")
    seq = _status(web)["log_seq"]
    for i in range(6):
        web.log.warning(f"new {i}")
    body = _status(web, seq)
    # Lines "new 0" and "new 1" fell out of the buffer before this read.
    assert _lines(body) == ["new 2", "new 3", "new 4", "new 5"]
    assert body["logs_gap"] is True
    # A cursor still inside the buffer has no gap.
    inside = _status(web, body["log_seq"] - 2)
    assert _lines(inside) == ["new 4", "new 5"] and inside["logs_gap"] is False


def test_status_rejects_a_bad_since(logbuf):
    r = logbuf.app.test_client().get("/api/status?since=abc", base_url=BASE)
    assert r.status_code == 400


# ─── max_hops ────────────────────────────────────────────────────────────────

class _ConfiguredTg:
    def configured(self):
        return True

    def follow_channel_chain(self, identifier, max_hops):
        return [{"handle": identifier, "max_hops": max_hops}]


def test_bad_max_hops_is_a_400(web, monkeypatch):
    monkeypatch.setattr(web, "_tg", _ConfiguredTg())
    c = web.app.test_client()
    r = c.get("/api/telegram/search/deep?q=x&max_hops=abc", base_url=BASE)
    assert r.status_code == 400
    r = c.get("/api/telegram/chain/durov?max_hops=2x", base_url=BASE)
    assert r.status_code == 400
    r = c.get("/api/telegram/chain/durov?max_hops=3", base_url=BASE)
    assert r.status_code == 200
    assert r.get_json()["chain"][0]["max_hops"] == 3


# ─── Report and CSV truncation ───────────────────────────────────────────────

def _add_findings(db, n, tag):
    db.add_url(f"http://{tag}.onion")
    url_id = db.conn.execute("SELECT id FROM urls WHERE url = ?",
                             (f"http://{tag}.onion",)).fetchone()[0]
    for i in range(n):
        db.add_finding(url_id, f"http://{tag}.onion/{i}", f"{tag}_rule_{i}",
                       "keyword:text", 50, f"match {i}", f"snippet {i}", "medium")
    return db.get_stats()["total_findings"]


def test_report_says_when_it_is_truncated(web, monkeypatch):
    crawler = web._crawler
    total = _add_findings(crawler.db, 3, "reporttrunc")
    monkeypatch.setattr(crawler, "REPORT_MAX_FINDINGS", total - 1)
    report_path, summary_path = crawler.generate_report()
    with open(report_path) as f:
        report = json.load(f)
    assert report["truncated"] is True
    assert report["findings_included"] == total - 1 == len(report["findings"])
    with open(summary_path) as f:
        assert f"only the newest {total - 1} findings" in f.read()

    monkeypatch.setattr(crawler, "REPORT_MAX_FINDINGS", total)
    report_path, summary_path = crawler.generate_report()
    with open(report_path) as f:
        report = json.load(f)
    assert report["truncated"] is False
    assert report["findings_included"] == total == len(report["findings"])
    with open(summary_path) as f:
        assert "truncated" not in f.read()


def _csv(web):
    import csv
    import io
    r = web.app.test_client().get("/api/findings.csv", base_url=BASE)
    assert r.status_code == 200
    return r, list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))


def test_findings_csv_pages_through_and_flags_truncation(web, monkeypatch):
    total = _add_findings(web._crawler.db, 5, "csvtrunc")
    monkeypatch.setattr(web, "FINDINGS_CSV_PAGE", 2)
    monkeypatch.setattr(web, "FINDINGS_CSV_MAX", total + 10)
    r, rows = _csv(web)
    assert len(rows) == total
    assert r.headers["X-Findings-Total"] == str(total)
    assert r.headers["X-Findings-Truncated"] == "false"
    assert sum(row["rule_name"].startswith("csvtrunc_rule_") for row in rows) == 5

    monkeypatch.setattr(web, "FINDINGS_CSV_MAX", total - 1)
    r, rows = _csv(web)
    assert r.headers["X-Findings-Truncated"] == "true"
    # The cut is in the header only: every row is a finding.
    assert len(rows) == total - 1
    assert all(row["rule_name"] and row["found_at"] for row in rows)


# ─── Quick health: Tunnel 1 via Tor's ControlPort ────────────────────────────

@pytest.fixture(autouse=True)
def no_circuit_cache(web, monkeypatch):
    """An empty ControlPort answer cache, and no reuse unless a test asks:
    most tests here change the stubbed answer between calls."""
    monkeypatch.setattr(web, "_tor_circuit_cache", {"ts": None, "value": None})
    monkeypatch.setattr(web, "TOR_CIRCUIT_TTL", 0)


def _socks(ok, calls=None):
    def probe():
        if calls is not None:
            calls.append(1)
        return {"ok": ok, "detail": "SOCKS stub"}
    return probe


def test_check_vpn_reads_tor_circuit_state(web, monkeypatch):
    calls = []
    monkeypatch.setattr(web, "_check_tor_alive", _socks(True, calls))
    monkeypatch.setattr(web, "_tor_circuit_established", lambda: True)
    r = web._check_vpn()
    assert r["ok"] is True and "circuit established" in r["detail"]
    monkeypatch.setattr(web, "_tor_circuit_established", lambda: False)
    r = web._check_vpn()
    assert r["ok"] is False and "circuit-established=0" in r["detail"]
    assert calls == []            # the ControlPort answered: no SOCKS probe


def test_check_vpn_falls_back_to_socks_when_controlport_fails(web, monkeypatch):
    def broken():
        raise OSError("connection refused")
    monkeypatch.setattr(web, "_tor_circuit_established", broken)
    calls = []
    monkeypatch.setattr(web, "_check_tor_alive", _socks(True, calls))
    r = web._check_vpn()
    assert r["ok"] is True and calls == [1]
    assert "Tor circuits not checked" in r["detail"]
    assert "connection refused" in r["detail"]
    monkeypatch.setattr(web, "_check_tor_alive", _socks(False))
    assert web._check_vpn()["ok"] is False
    # A SOCKS result passed in is reused, not probed again.
    calls.clear()
    monkeypatch.setattr(web, "_check_tor_alive", _socks(True, calls))
    r = web._check_vpn({"ok": False, "detail": "given"})
    assert r["ok"] is False and r["detail"].startswith("given") and calls == []


def test_quick_health_makes_one_socks_probe(web, monkeypatch):
    calls = []
    monkeypatch.setattr(web, "_check_tor_alive", _socks(True, calls))

    def broken():
        raise ValueError("ControlPort refused: 515 Authentication failed")
    monkeypatch.setattr(web, "_tor_circuit_established", broken)
    h = web._quick_health()
    assert calls == [1]
    assert h["tor"]["ok"] and h["vpn"]["ok"] and h["secure"] is True
    monkeypatch.setattr(web, "_tor_circuit_established", lambda: False)
    calls.clear()
    h = web._quick_health()
    assert calls == [1] and h["secure"] is False


def test_quick_health_reuses_the_controlport_answer(web, monkeypatch):
    # Tor logs every control connection: polls within TOR_CIRCUIT_TTL share
    # one query, the failure included; the full check (scan gate) asks again.
    monkeypatch.setattr(web, "TOR_CIRCUIT_TTL", 10)
    monkeypatch.setattr(web, "_check_tor_alive", _socks(True))
    queries = []

    def answer():
        queries.append(1)
        return True
    monkeypatch.setattr(web, "_tor_circuit_established", answer)
    assert web._quick_health()["secure"] is True
    assert web._quick_health()["secure"] is True
    assert queries == [1]
    web._check_vpn(max_age=0)
    assert queries == [1, 1]
    # Past the TTL the next poll asks again.
    monkeypatch.setitem(web._tor_circuit_cache, "ts",
                        web._tor_circuit_cache["ts"] - 11)
    web._quick_health()
    assert queries == [1, 1, 1]

    def broken():
        queries.append(1)
        raise OSError("connection refused")
    monkeypatch.setattr(web, "_tor_circuit_established", broken)
    web._check_vpn(max_age=0)
    r = web._quick_health()
    assert len(queries) == 4 and "Tor circuits not checked" in r["vpn"]["detail"]


def _answer(value):
    return lambda req: (b"250 OK\r\n"
                        b"250-status/circuit-established=" + value + b"\r\n"
                        b"250 OK\r\n250 closing connection\r\n")


@pytest.fixture
def controlport(web, monkeypatch, fake_controlport):
    def start(reply, password="pw"):
        srv = fake_controlport(reply)
        monkeypatch.setattr(web._crawler, "tor_control_host", "127.0.0.1")
        monkeypatch.setattr(web._crawler, "tor_control_port", srv.port)
        monkeypatch.setattr(web._crawler, "tor_control_password", password)
        return srv
    return start


def test_controlport_query_parses_tor_answers(web, controlport):
    srv = controlport(_answer(b"1"))
    assert web._tor_circuit_established() is True
    assert srv.requests[0] == (b'AUTHENTICATE "pw"\r\n'
                               b"GETINFO status/circuit-established\r\nQUIT\r\n")
    srv.reply = _answer(b"0")
    assert web._tor_circuit_established() is False


def test_controlport_query_escapes_the_password(web, controlport):
    srv = controlport(_answer(b"1"), password='a"b\\c')
    assert web._tor_circuit_established() is True
    assert srv.requests[0].startswith(b'AUTHENTICATE "a\\"b\\\\c"\r\n')


def test_controlport_query_raises_on_refusal_and_silence(web, controlport,
                                                         monkeypatch):
    controlport(lambda req: b"515 Authentication failed: Password did not match\r\n")
    with pytest.raises(ValueError, match="515"):
        web._tor_circuit_established()
    monkeypatch.setattr(web, "TOR_CONTROL_TIMEOUT", 0.3)
    controlport(lambda req: None)
    with pytest.raises(OSError):
        web._tor_circuit_established()


def test_check_vpn_end_to_end_falls_back_when_controlport_is_closed(
        web, monkeypatch):
    # Nothing listens on the ControlPort: the SOCKS probe decides.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    monkeypatch.setattr(web._crawler, "tor_control_host", "127.0.0.1")
    monkeypatch.setattr(web._crawler, "tor_control_port", port)
    monkeypatch.setattr(web, "_check_tor_alive", _socks(True))
    r = web._check_vpn()
    assert r["ok"] is True and "Tor circuits not checked" in r["detail"]


# ─── Tracked Telegram channel list limit ─────────────────────────────────────

@pytest.fixture
def tg_channels_db(web, monkeypatch, tmp_path):
    """A fresh database for web._crawler and a channel list limit of 2."""
    from darkwatch import Database
    db = Database(str(tmp_path / "dw.db"))
    monkeypatch.setattr(web._crawler, "db", db)
    monkeypatch.setattr(web, "TG_CHANNEL_LIST_LIMIT", 2)

    def add(n):
        for i in range(n):
            db.add_url(f"tg://chan{i}", source="telegram")
        db.add_url("http://example.onion", source="manual")
    return add


def test_tracked_tg_channels_warns_when_the_limit_skips_channels(
        web, tg_channels_db, caplog):
    tg_channels_db(3)
    with caplog.at_level("WARNING", logger="darkwatch.web"):
        rows = web._tracked_tg_channels("search all channels")
    assert len(rows) == 2
    msgs = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(msgs) == 1
    assert "search all channels: using 2 of 3 tracked Telegram channels" in msgs[0]
    assert "1 least recently scanned are skipped" in msgs[0]


def test_tracked_tg_channels_is_quiet_at_the_limit(web, tg_channels_db, caplog):
    tg_channels_db(2)
    with caplog.at_level("WARNING"):
        rows = web._tracked_tg_channels("live listener")
    assert len(rows) == 2
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


def test_live_listener_channel_list_uses_the_shared_limit(web, tg_channels_db,
                                                          monkeypatch, caplog):
    tg_channels_db(3)
    with web._crawler.db.lock:
        web._crawler.db.conn.execute(
            "UPDATE urls SET tg_channel_id = id WHERE source = 'telegram'")
        web._crawler.db.conn.commit()
    seen = []
    monkeypatch.setattr(web, "_tg_live",
                        type("L", (), {"set_channels": lambda self, ids: seen.append(ids)})())
    with caplog.at_level("WARNING"):
        web._refresh_tg_live_channels()
    assert len(seen[0]) == 2
    assert "live listener: using 2 of 3" in caplog.text
