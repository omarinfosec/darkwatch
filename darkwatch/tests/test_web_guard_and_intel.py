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
