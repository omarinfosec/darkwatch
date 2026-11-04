"""Dashboard request guard (DNS rebinding / cross-site), security headers,
CSV formula escaping, int-param validation, YARA include blocking, and
threat-intel refresh keeping a failed feed's previous rule."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# The `web` fixture (the imported dashboard module) is in conftest.py.


def test_web_fixture_does_not_leak_its_environment(web):
    # Set only around the import: later modules (setup/tests too) must
    # not inherit the throwaway config or bind address.
    assert os.environ.get("DARKWATCH_CONFIG") != web.CONFIG_PATH
    assert os.environ.get("DARKWATCH_BIND_IP") != "10.8.0.5"


def test_host_header_must_name_the_dashboard(web):
    c = web.app.test_client()
    assert c.get("/healthz", base_url="http://127.0.0.1:8080").status_code == 200
    assert c.get("/healthz", base_url="http://localhost:9000").status_code == 200
    assert c.get("/healthz", base_url="http://10.8.0.5:8080").status_code == 200
    # DNS rebinding: attacker domain resolved to 127.0.0.1.
    assert c.get("/api/findings", base_url="http://evil.example:8080").status_code == 403


def test_cross_site_writes_rejected(web):
    c = web.app.test_client()
    base = "http://127.0.0.1:8080"
    assert c.post("/api/stop", base_url=base,
                  headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/stop", base_url=base,
                  headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/api/stop", base_url=base,
                  headers={"Origin": "null"}).status_code == 403
    # Same-origin request from the dashboard's own page passes the guard.
    r = c.post("/api/stop", base_url=base, headers={"Origin": base,
                                                    "Sec-Fetch-Site": "same-origin"})
    assert r.status_code != 403


BASE = "http://127.0.0.1:8080"


def _site(site, mode=None, dest=None):
    h = {"Sec-Fetch-Site": site}
    if mode:
        h["Sec-Fetch-Mode"] = mode
    if dest:
        h["Sec-Fetch-Dest"] = dest
    return h


def test_cross_site_reads_rejected(web):
    c = web.app.test_client()
    # <img src="http://127.0.0.1:8080/api/telegram/user/x"> on another site
    # would fire a live Telegram lookup.
    r = c.get("/api/telegram/user/someone?download=1", base_url=BASE,
              headers=_site("cross-site", "no-cors", "image"))
    assert r.status_code == 403
    # A cross-site link straight to an API route or export.
    r = c.get("/api/findings", base_url=BASE,
              headers=_site("cross-site", "navigate", "document"))
    assert r.status_code == 403
    r = c.get("/api/telegram/channels/1/export.csv", base_url=BASE,
              headers=_site("cross-site", "navigate", "document"))
    assert r.status_code == 403
    # Framing the dashboard from another site.
    assert c.get("/", base_url=BASE, headers=_site(
        "cross-site", "navigate", "iframe")).status_code == 403
    # A fetch()/no-cors subresource load of "/" is not a navigation.
    assert c.get("/", base_url=BASE, headers=_site(
        "cross-site", "no-cors", "empty")).status_code == 403
    # Only GET is let through, not a cross-site form POST to "/".
    assert c.post("/", base_url=BASE, headers=_site(
        "cross-site", "navigate", "document")).status_code == 403


def test_cross_site_navigation_to_root_allowed(web):
    c = web.app.test_client()
    r = c.get("/", base_url=BASE, headers=_site("cross-site", "navigate", "document"))
    assert r.status_code == 200


@pytest.mark.parametrize("headers", [
    {},
    _site("same-origin", "cors", "empty"),
    _site("same-site", "no-cors", "image"),
    _site("none", "navigate", "document"),
    {"Origin": BASE, "Sec-Fetch-Site": "same-origin"},
    {"Origin": "http://localhost:8080"},
])
def test_same_origin_and_headerless_reads_allowed(web, headers):
    c = web.app.test_client()
    assert c.get("/", base_url=BASE, headers=headers).status_code == 200
    assert c.get("/api/findings", base_url=BASE, headers=headers).status_code == 200


def test_bad_origin_rejected_on_reads(web):
    c = web.app.test_client()
    assert c.get("/api/findings", base_url=BASE,
                 headers={"Origin": "null"}).status_code == 403
    assert c.get("/api/findings", base_url=BASE,
                 headers={"Origin": "https://evil.example"}).status_code == 403


def test_user_lookup_photo_limit_is_capped(web, monkeypatch):
    seen = []
    monkeypatch.setattr(web._tg, "configured", lambda: True)
    monkeypatch.setattr(web._tg, "lookup_user",
                        lambda handle, **kw: seen.append(kw["photo_history_limit"]) or {})
    c = web.app.test_client()
    for q, want in (("", 10), ("&photo_limit=0", 1), ("&photo_limit=-5", 1),
                    ("&photo_limit=7", 7), ("&photo_limit=100000", 50)):
        assert c.get(f"/api/telegram/user/someone?photos=1{q}",
                     base_url=BASE).status_code == 200
        assert seen.pop() == want
    assert c.get("/api/telegram/user/someone?photo_limit=x",
                 base_url=BASE).status_code == 400
    assert seen == []


def _assert_baseline_headers(r, csp="frame-ancestors 'none'"):
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Content-Security-Policy"] == csp
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "same-origin"


def test_security_headers(web, monkeypatch):
    c = web.app.test_client()
    r = c.get("/", base_url=BASE)
    _assert_baseline_headers(r)
    assert "no-store" not in r.headers.get("Cache-Control", "")
    for path in ("/api/findings", "/api/telegram/channels/1/export.bogus"):
        r = c.get(path, base_url=BASE)
        _assert_baseline_headers(r)
        assert r.headers["Cache-Control"] == "no-store"
    # Guard rejections carry them too.
    r = c.get("/api/findings", base_url=BASE, headers={"Origin": "null"})
    assert r.status_code == 403
    _assert_baseline_headers(r)
    assert r.headers["Cache-Control"] == "no-store"
    # send_file sets its own Cache-Control ("no-cache"); /api/* still ends
    # up no-store.
    thumb = os.path.join(web._crawler.thumbnails_dir, "t.png")
    os.makedirs(os.path.dirname(thumb), exist_ok=True)
    with open(thumb, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
    monkeypatch.setattr(web._crawler.db, "get_page_screenshot",
                        lambda pid: {"thumbnail_path": thumb})
    r = c.get("/api/thumbnail/1", base_url=BASE)
    assert r.status_code == 200
    _assert_baseline_headers(r)
    assert r.headers["Cache-Control"] == "no-store"


def test_tg_media_keeps_sandbox_csp(web):
    media = os.path.join(web._crawler.loot_dir, "tg-media", "chan", "p.png")
    os.makedirs(os.path.dirname(media), exist_ok=True)
    with open(media, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
    c = web.app.test_client()
    r = c.get("/loot/tg-media/chan/p.png", base_url=BASE)
    assert r.status_code == 200
    _assert_baseline_headers(r, csp="sandbox; default-src 'none'")


def _write(path, data=b"x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def test_tg_media_html_is_a_sandboxed_forced_download(web):
    _write(os.path.join(web._crawler.loot_dir, "tg-media", "chan", "x.html"),
           b"<script>fetch('/api/findings')</script>")
    r = web.app.test_client().get("/loot/tg-media/chan/x.html", base_url=BASE)
    assert r.status_code == 200
    assert r.headers["Content-Disposition"].startswith("attachment")
    assert r.mimetype == "application/octet-stream"
    _assert_baseline_headers(r, csp="sandbox; default-src 'none'")


def test_tg_media_png_is_inline(web):
    _write(os.path.join(web._crawler.loot_dir, "tg-media", "chan", "i.png"),
           b"\x89PNG\r\n\x1a\n")
    r = web.app.test_client().get("/loot/tg-media/chan/i.png", base_url=BASE)
    assert r.status_code == 200
    assert r.mimetype == "image/png"
    assert "attachment" not in r.headers.get("Content-Disposition", "")
    _assert_baseline_headers(r, csp="sandbox; default-src 'none'")


@pytest.mark.parametrize("path", [
    "/loot/tg-media/../outside.png",            # parent of tg-media
    "/loot/tg-media/..%2foutside.png",           # encoded separator
    "/loot/tg-media/%2e%2e/outside.png",         # encoded dots
    "/loot/tg-media/../tg-media-old/x.png",     # sibling sharing the prefix
])
def test_tg_media_traversal_is_404(web, path):
    loot = web._crawler.loot_dir
    os.makedirs(os.path.join(loot, "tg-media"), exist_ok=True)
    _write(os.path.join(loot, "outside.png"))
    _write(os.path.join(loot, "tg-media-old", "x.png"))
    r = web.app.test_client().get(path, base_url=BASE)
    assert r.status_code == 404


def test_tg_media_absolute_path_is_404(web):
    """An absolute relpath makes os.path.join drop the tg-media base. The
    router merges a leading "//" before the view runs, so call the view."""
    from werkzeug.exceptions import NotFound
    outside = os.path.join(web._crawler.loot_dir, "outside.png")
    _write(outside)
    with web.app.test_request_context("/loot/tg-media/x", base_url=BASE):
        with pytest.raises(NotFound):
            web.route_tg_media_serve(os.path.abspath(outside))


def _csv_rows(body):
    import csv
    import io
    return list(csv.DictReader(io.StringIO(body)))


def test_findings_csv_export_escapes_formulas(web):
    db = web._crawler.db
    db.add_url("http://csvtest.onion")
    url_id = db.conn.execute("SELECT id FROM urls WHERE url = ?",
                             ("http://csvtest.onion",)).fetchone()[0]
    db.add_finding(url_id, "http://csvtest.onion/p", "csv_rule", "keyword:text",
                   50, '=HYPERLINK("http://x")', "@SUM(A1)", "medium")
    r = web.app.test_client().get("/api/findings.csv", base_url=BASE)
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert r.headers["Content-Disposition"].startswith("attachment")
    (row,) = [x for x in _csv_rows(r.get_data(as_text=True))
              if x["rule_name"] == "csv_rule"]
    assert row["matched_strings"] == '\'=HYPERLINK("http://x")'
    assert row["snippet"] == "'@SUM(A1)"


def test_keywords_csv_export_escapes_formulas(web):
    web._crawler.db.add_keyword("=cmd|'/C calc'!A0", category="+csv")
    r = web.app.test_client().get("/api/keywords/export.csv", base_url=BASE)
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert r.headers["Content-Disposition"].startswith("attachment")
    (row,) = [x for x in _csv_rows(r.get_data(as_text=True))
              if x["category"] == "'+csv"]
    assert row["keyword"] == "'=cmd|'/C calc'!A0"


@pytest.fixture(scope="module")
def tg_channel(web):
    db = web._crawler.db
    url_id = db.upsert_tg_channel("csvchan", 4242, title="t")
    page_id = db.add_page(url_id, "https://t.me/csvchan/1", "t", "csvchan-1",
                          page_type="telegram_message")
    db.add_tg_message(url_id, page_id, {
        "msg_id": 1, "text": "=1+1", "sender_name": "-Mallory",
        "sender_username": "@m", "media_path": "+x.bin"})
    return url_id


def test_channel_csv_export_escapes_formulas(web, tg_channel):
    r = web.app.test_client().get(
        f"/api/telegram/channels/{tg_channel}/export.csv", base_url=BASE)
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert r.headers["Content-Disposition"].startswith("attachment")
    (row,) = _csv_rows(r.get_data(as_text=True))
    assert (row["text"], row["sender_name"], row["sender_username"]) == \
        ("'=1+1", "'-Mallory", "'@m")


def test_channel_zip_export_escapes_messages_csv(web, tg_channel):
    import io
    import zipfile
    r = web.app.test_client().get(
        f"/api/telegram/channels/{tg_channel}/export.zip", base_url=BASE)
    assert r.status_code == 200
    assert r.mimetype == "application/zip"
    with zipfile.ZipFile(io.BytesIO(r.data)) as z:
        (name,) = [n for n in z.namelist() if n.endswith("/messages.csv")]
        (row,) = _csv_rows(z.read(name).decode())
    assert (row["text"], row["sender_name"], row["media_path"]) == \
        ("'=1+1", "'-Mallory", "'+x.bin")


def test_bad_int_params_are_400_not_500(web):
    c = web.app.test_client()
    base = "http://127.0.0.1:8080"
    assert c.get("/api/findings?min_score=x", base_url=base).status_code == 400
    assert c.delete("/api/findings?min_score=x", base_url=base).status_code == 400
    r = c.post("/api/scan", base_url=base, json={"urls": "abc"})
    assert r.status_code == 400


def test_metrics_scrape(web):
    pytest.importorskip("prometheus_client")
    r = web.app.test_client().get("/metrics", base_url=BASE)
    assert r.status_code == 200
    # prometheus-client 0.26 advertises text format version 1.0.0
    # (0.20 sent 0.0.4); Prometheus accepts both.
    assert r.headers["Content-Type"] == \
        "text/plain; version=1.0.0; charset=utf-8"
    body = r.get_data(as_text=True)
    assert "# TYPE darkwatch_urls_total gauge" in body
    assert "darkwatch_scan_running 0.0" in body


def test_qr_login_svg_renders(web):
    pytest.importorskip("qrcode")
    svg = web._render_qr_svg("tg://login?token=AbC-123_x")
    assert svg is not None and "<svg" in svg and "<path" in svg


def test_csv_safe(web):
    assert web._csv_safe('=HYPERLINK("http://x")') == '\'=HYPERLINK("http://x")'
    assert web._csv_safe("+1") == "'+1"
    assert web._csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert web._csv_safe("normal text") == "normal text"
    assert web._csv_safe(-5) == -5          # numbers untouched


def test_custom_rule_include_is_rejected(tmp_path):
    pytest.importorskip("yara")
    from darkwatch import YaraScanner
    curated = tmp_path / "c.yar"
    curated.write_text('rule c { strings: $a = "zz" condition: $a }')
    priv = tmp_path / "priv"; priv.mkdir()
    scanner = YaraScanner(str(curated), str(curated), user_file=None, private_dir=str(priv))
    # A valid rule file elsewhere on disk: with includes enabled this would
    # be pulled in (arbitrary file read into the ruleset).
    other = tmp_path / "elsewhere.yar"
    other.write_text('rule stolen { condition: true }')
    with pytest.raises(ValueError):
        scanner.save_custom_rule(
            f'include "{other}"\nrule x {{ condition: true }}', "inc")


def test_threat_intel_keeps_failed_feeds_previous_rule(tmp_path, monkeypatch):
    from threat_intel import ThreatIntelFeed
    out = tmp_path / "intel.yar"
    feeds = [{"name": "a", "url": "http://a"}, {"name": "b", "url": "http://b"}]
    ti = ThreatIntelFeed(str(out), feeds=feeds)
    data = {"a": ["evil-a.example"], "b": ["evil-b.example"]}
    monkeypatch.setattr(ti, "_fetch_one", lambda f: data[f["name"]])
    assert ti.refresh()["updated"]
    data["b"] = []                                   # feed b times out
    res = ti.refresh()
    text = out.read_text()
    assert "rule intel_a" in text and "rule intel_b" in text
    assert "evil-b.example" in text
    assert [f.get("stale") for f in res["feeds"]] == [False, True]


def test_threat_intel_duplicate_idents_still_compile(tmp_path, monkeypatch):
    pytest.importorskip("yara")
    from threat_intel import ThreatIntelFeed
    out = tmp_path / "intel.yar"
    ti = ThreatIntelFeed(str(out), feeds=[{"name": "a-b", "url": "x"},
                                          {"name": "a_b", "url": "y"}])
    monkeypatch.setattr(ti, "_fetch_one", lambda f: ["ind-" + f["url"]])
    assert ti.refresh()["updated"]
    import yara
    yara.compile(filepath=str(out))


def _no_fetch_ip(*a, **kw):
    raise AssertionError("_fetch_ip must not run with the lockdown on")


def _fake_connect(outcomes, calls):
    """socket.create_connection stand-in: outcomes maps (host, port) to an
    exception to raise, or None for a completed handshake."""
    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def connect(addr, timeout=None, *a, **kw):
        calls.append((addr, timeout))
        exc = outcomes[addr]
        if exc is not None:
            raise exc
        return _Conn()
    return connect


@pytest.fixture
def lockdown_on(web, monkeypatch):
    monkeypatch.delenv("DARKWATCH_EGRESS_LOCKDOWN", raising=False)
    monkeypatch.setattr(web, "_fetch_ip", _no_fetch_ip)


def test_ip_leak_probes_are_ip_literals(web):
    import ipaddress
    assert len(web.LOCKDOWN_PROBES) == 2
    for host, port in web.LOCKDOWN_PROBES:
        ipaddress.ip_address(host)          # no DNS: literal only
        assert port == 443
    assert web.LOCKDOWN_PROBE_TIMEOUT == 2


def test_ip_leak_fails_when_direct_connect_succeeds(web, lockdown_on,
                                                    monkeypatch):
    """A real handshake to a local listener: the lockdown is missing."""
    import socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(4)
    try:
        port = srv.getsockname()[1]
        monkeypatch.setattr(web, "LOCKDOWN_PROBES",
                            (("127.0.0.1", port), ("127.0.0.1", port)))
        # Tor result is irrelevant: even with no exit IP it must run.
        r = web._check_ip_leak({"exit_ip": None})
    finally:
        srv.close()
    assert r["ok"] is False
    assert "sudo ./ops/egress-lockdown.sh" in r["detail"]


def test_ip_leak_fails_when_one_probe_connects(web, lockdown_on, monkeypatch):
    import socket
    (a, b), calls = web.LOCKDOWN_PROBES, []
    monkeypatch.setattr(socket, "create_connection", _fake_connect(
        {a: socket.timeout("timed out"), b: None}, calls))
    r = web._check_ip_leak({"exit_ip": "1.2.3.4"})
    assert r["ok"] is False and "egress-lockdown.sh" in r["detail"]
    assert sorted(c[0] for c in calls) == sorted([a, b])
    assert all(c[1] == 2 for c in calls)


@pytest.mark.parametrize("err", [
    "timeout", "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH", "EPERM"])
def test_ip_leak_passes_when_direct_egress_is_dropped(web, lockdown_on,
                                                      monkeypatch, err):
    import errno, socket
    exc = (socket.timeout("timed out") if err == "timeout"
           else OSError(getattr(errno, err), os.strerror(getattr(errno, err))))
    calls = []
    monkeypatch.setattr(socket, "create_connection", _fake_connect(
        {hp: exc for hp in web.LOCKDOWN_PROBES}, calls))
    for tor in ({"exit_ip": "1.2.3.4"}, {"exit_ip": None}, "Tor check failed"):
        r = web._check_ip_leak(tor)
        assert r["ok"] is True, r
    assert len(calls) == 6
    if err != "timeout":
        assert f"errno {getattr(errno, err)}" in r["detail"] and err in r["detail"]


def test_ip_leak_fails_closed_on_connection_refused(web, lockdown_on,
                                                    monkeypatch):
    """Decision 2: the lockdown DROPs, so a refusal means the SYN got out.
    Uses a real closed local port, so the kernel answers with RST."""
    import errno, socket
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                     # nothing listens now
    monkeypatch.setattr(web, "LOCKDOWN_PROBES",
                        (("127.0.0.1", port), ("127.0.0.1", port)))
    r = web._check_ip_leak({"exit_ip": "1.2.3.4"})
    assert r["ok"] is False
    assert "ECONNREFUSED" in r["detail"]
    assert f"errno {errno.ECONNREFUSED}" in r["detail"]


def test_ip_leak_fails_closed_on_unexpected_error(web, lockdown_on, monkeypatch):
    import errno, socket
    calls = []
    monkeypatch.setattr(socket, "create_connection", _fake_connect(
        {hp: OSError(errno.EADDRNOTAVAIL, "x") for hp in web.LOCKDOWN_PROBES},
        calls))
    r = web._check_ip_leak({"exit_ip": "1.2.3.4"})
    assert r["ok"] is False and "EADDRNOTAVAIL" in r["detail"]


def test_ip_leak_without_lockdown_keeps_ip_comparison(web, monkeypatch):
    """DARKWATCH_EGRESS_LOCKDOWN=0: the old (weak) exit-vs-direct check,
    with no direct TCP probes."""
    import socket
    monkeypatch.setenv("DARKWATCH_EGRESS_LOCKDOWN", "0")

    def no_connect(*a, **kw):
        raise AssertionError("no lockdown probe with DARKWATCH_EGRESS_LOCKDOWN=0")
    monkeypatch.setattr(socket, "create_connection", no_connect)
    direct = {"ip": None}
    monkeypatch.setattr(web, "_fetch_ip", lambda proxies=None, timeout=5:
                        (direct["ip"], "blocked") if direct["ip"] is None
                        else (direct["ip"], "svc"))
    tor = {"exit_ip": "1.2.3.4"}
    assert web._check_ip_leak(tor)["ok"] is False          # fetch failed
    direct["ip"] = "1.2.3.4"
    r = web._check_ip_leak(tor)
    assert r["ok"] is False and "LEAK" in r["detail"]
    direct["ip"] = "5.6.7.8"
    assert web._check_ip_leak(tor)["ok"] is True
    assert web._check_ip_leak("IsTor=True, exit 1.2.3.4")["ok"] is True
    assert web._check_ip_leak({"exit_ip": None})["ok"] is False


def test_scan_is_refused_when_direct_egress_is_open(web, lockdown_on, monkeypatch):
    """/api/scan returns 403 naming ip_leak when the lockdown is missing,
    even with every other required check green."""
    import socket
    ok = lambda *a, **kw: {"ok": True, "detail": "stub", "exit_ip": "1.2.3.4"}
    for name in ("_check_tor", "_check_vpn", "_check_dns",
                 "_check_playwright", "_check_tg_vpn"):
        monkeypatch.setattr(web, name, ok)
    monkeypatch.setitem(web._health_cache, "data", None)
    calls = []
    monkeypatch.setattr(socket, "create_connection", _fake_connect(
        {hp: None for hp in web.LOCKDOWN_PROBES}, calls))
    r = web.app.test_client().post("/api/scan", base_url="http://127.0.0.1:8080",
                                   json={"urls": [web.ONION_CANARY]})
    assert r.status_code == 403
    assert r.get_json()["error"] == "security gate failed: ip_leak"
    assert len(calls) == 2


def test_health_runs_lockdown_ip_leak_alongside_other_checks(web, lockdown_on,
                                                            monkeypatch):
    """With the lockdown on, ip_leak doesn't wait for the other checks:
    the Tor stub only returns once the ip_leak probe has started."""
    import threading
    leak_started, seen = threading.Event(), {}

    def tor():
        seen["concurrent"] = leak_started.wait(5)
        return {"ok": True, "detail": "stub", "exit_ip": "1.2.3.4"}

    def leak():
        leak_started.set()
        return {"ok": True, "detail": "stub leak"}
    ok = lambda *a, **kw: {"ok": True, "detail": "stub"}
    for name in ("_check_vpn", "_check_dns", "_check_playwright", "_check_tg_vpn"):
        monkeypatch.setattr(web, name, ok)
    monkeypatch.setattr(web, "_check_tor", tor)
    monkeypatch.setattr(web, "_check_ip_leak_lockdown", leak)
    r = web._run_health_checks()
    assert seen["concurrent"] is True
    assert r["ip_leak"] == {"ok": True, "detail": "stub leak"}
    assert r["secure"] is True


def test_health_without_lockdown_feeds_tor_result_to_ip_leak(web, monkeypatch):
    monkeypatch.setenv("DARKWATCH_EGRESS_LOCKDOWN", "0")
    tor_res, got = {"ok": True, "detail": "stub", "exit_ip": "1.2.3.4"}, []
    ok = lambda *a, **kw: {"ok": True, "detail": "stub"}
    for name in ("_check_vpn", "_check_dns", "_check_playwright", "_check_tg_vpn"):
        monkeypatch.setattr(web, name, ok)
    monkeypatch.setattr(web, "_check_tor", lambda: tor_res)
    monkeypatch.setattr(web, "_check_ip_leak",
                        lambda t: got.append(t) or {"ok": True, "detail": "cmp"})
    r = web._run_health_checks()
    assert got == [tor_res] and r["ip_leak"]["detail"] == "cmp"
