"""Dashboard request guard (DNS rebinding / cross-site), CSV formula
escaping, int-param validation, YARA include blocking, and threat-intel
refresh keeping a failed feed's previous rule."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    d = tmp_path_factory.mktemp("dw")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "config.json")) as f:
        cfg = json.load(f)
    cfg["output"].update(loot_dir=str(d / "loot"), reports_dir=str(d / "loot/reports"),
                         thumbnails_dir=str(d / "loot/thumbs"))
    cfg["database"]["path"] = str(d / "dw.db")
    (d / "config.json").write_text(json.dumps(cfg))
    os.environ["DARKWATCH_CONFIG"] = str(d / "config.json")
    os.environ["DARKWATCH_BIND_IP"] = "10.8.0.5"
    pytest.importorskip("flask")
    import web as web_mod
    return web_mod


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


def test_bad_int_params_are_400_not_500(web):
    c = web.app.test_client()
    base = "http://127.0.0.1:8080"
    assert c.get("/api/findings?min_score=x", base_url=base).status_code == 400
    assert c.delete("/api/findings?min_score=x", base_url=base).status_code == 400
    r = c.post("/api/scan", base_url=base, json={"urls": "abc"})
    assert r.status_code == 400


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
