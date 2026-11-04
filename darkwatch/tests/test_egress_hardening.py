"""Alerts never leave directly, Telegram proxy auth, crawler robustness
(malformed Content-Length, slow-drip downloads) and browser leak prefs."""

import os
import sys
import time

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import darkwatch as dw  # noqa: E402
import dw_tor  # noqa: E402

CFG = {
    "proxy": {"type": "socks5h", "host": "tunnel1", "port": 9050},
    "telegram": {"proxy_host": "tunnel2", "proxy_port": 1080,
                 "proxy_user": "darkwatch", "proxy_password": "p@ss"},
    "alerts": {},
}


def test_alert_routes_prefer_tunnel_then_tor_never_direct():
    routes = dw.alert_proxy_routes(CFG)
    assert [n for n, _ in routes] == ["telegram tunnel", "tor"]
    assert routes[0][1]["https"] == "socks5h://darkwatch:p%40ss@tunnel2:1080"
    assert routes[1][1]["https"] == "socks5h://tunnel1:9050"
    assert all(p is not None for _, p in routes)


def test_alert_direct_only_when_opted_in():
    cfg = dict(CFG, alerts={"allow_direct": True})
    assert dw.alert_proxy_routes(cfg)[-1] == ("direct", None)
    assert dw.alert_proxy_routes({"alerts": {}}) == []


def test_alerter_falls_back_on_connection_error_only(monkeypatch):
    calls = []
    def fake_post(url, json=None, proxies=None, timeout=None):
        calls.append(proxies)
        if len(calls) == 1:
            raise requests.exceptions.ProxyError("tunnel2 down")
        return "ok"
    monkeypatch.setattr(dw.requests, "post", fake_post)
    a = dw.Alerter({}, routes=dw.alert_proxy_routes(CFG))
    assert a._post("https://hooks.example/x", {"t": 1}) == "ok"
    assert calls[0]["https"].endswith("@tunnel2:1080")
    assert calls[1]["https"] == "socks5h://tunnel1:9050"


def test_alerter_without_routes_refuses(monkeypatch):
    monkeypatch.setattr(dw.requests, "post", lambda *a, **k: pytest.fail("sent directly"))
    with pytest.raises(RuntimeError, match="no tunnel"):
        dw.Alerter({}, routes=[])._post("https://hooks.example/x", {})


def test_telegram_proxy_tuple_carries_credentials():
    eng = dw.DarkMTProto({"telegram": dict(CFG["telegram"], api_id="1", api_hash="x")})
    assert eng._proxy_tuple() == ("socks5", "tunnel2", 1080, True, "darkwatch", "p@ss")


class _Resp:
    def __init__(self, headers, content=b"x", chunks=None):
        self.headers = headers; self.content = content; self._chunks = chunks or []
        self.status_code = 200; self.closed = False
    def iter_content(self, chunk_size=8192):
        yield from self._chunks
    def close(self): self.closed = True


def test_validator_tolerates_malformed_content_length():
    v = dw.ResponseValidator({"security": {"max_response_size_mb": 1}})
    ok, _ = v.validate(_Resp({"Content-Length": "5, 5", "Content-Type": "text/html"}))
    assert ok


def test_download_has_total_time_limit(monkeypatch):
    """A server dripping bytes just under the per-read timeout must not hold
    the crawl forever: the stream is cut at the total deadline."""
    crawler = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    crawler.timeout = 1
    crawler.retries = 1
    crawler.retry_delay = 0
    crawler.security_cfg = {"max_response_size_mb": 10}
    crawler.stealth = type("S", (), {"get_headers": lambda self, referer=None: {},
                                     "jitter_timeout": lambda self, t: t})()
    clock = iter(range(0, 10_000, 30))          # each read "takes" 30s
    monkeypatch.setattr(dw.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(dw.time, "sleep", lambda s: None)
    resp = _Resp({"Content-Type": "text/html"}, chunks=[b"a"] * 1000)
    session = type("Sess", (), {"get": lambda self, *a, **k: resp})()
    onion = "http://" + "a" * 56 + ".onion/"
    result, err = crawler.fetch(onion, session=session)
    assert result is None and err == "timeout"
    assert resp.closed


def test_browser_prefs_block_speculative_and_redirect_leaks():
    prefs = dw.ScreenshotEngine.FIREFOX_PREFS
    assert prefs["network.http.redirection-limit"] == 0
    assert prefs["network.dns.disablePrefetch"] is True
    assert prefs["network.prefetch-next"] is False
    assert prefs["network.http.speculative-parallel-limit"] == 0
    assert prefs["network.proxy.allow_hijacking_localhost"] is True
    assert dw.ScreenshotEngine.DEAD_PROXY.startswith("socks5://127.0.0.1:")


class _FakePlaywright:
    """Stands in for sync_playwright(): records firefox.launch() kwargs."""
    def __init__(self):
        self.launches = []
        self.firefox = self
    def __call__(self):
        return self
    def start(self):
        return self
    def launch(self, **kw):
        self.launches.append(kw)
        return object()


@pytest.fixture
def fake_pw(monkeypatch):
    pw = _FakePlaywright()
    monkeypatch.setattr(dw, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(dw, "sync_playwright", pw, raising=False)
    return pw


def test_browser_launch_uses_prefs_and_plain_socks5(fake_pw, tmp_path):
    eng = dw.ScreenshotEngine(str(tmp_path / "s"), proxy_url="socks5h://tunnel1:9050",
                              mode="tor_render")
    assert eng._ensure_browser() is True
    (kw,) = fake_pw.launches
    assert kw["firefox_user_prefs"] is dw.ScreenshotEngine.FIREFOX_PREFS
    assert kw["headless"] is True
    # Firefox rejects socks5h://; the h is dropped, remote DNS is a pref.
    assert kw["proxy"] == {"server": "socks5://tunnel1:9050"}


@pytest.mark.parametrize("mode,proxy_url", [
    ("offline", "socks5h://tunnel1:9050"),
    ("tor_render", None),
])
def test_browser_without_tor_proxy_uses_dead_proxy(fake_pw, tmp_path, mode, proxy_url):
    eng = dw.ScreenshotEngine(str(tmp_path / "s"), proxy_url=proxy_url, mode=mode)
    assert eng._ensure_browser() is True
    (kw,) = fake_pw.launches
    assert kw["proxy"] == {"server": dw.ScreenshotEngine.DEAD_PROXY}
    assert kw["firefox_user_prefs"] is dw.ScreenshotEngine.FIREFOX_PREFS


def test_newnym_connects_to_the_resolved_control_ip(monkeypatch):
    """The sidecar name is resolved first and the IP (not the name) dialled,
    as with stem, whose from_port() only took an IP literal."""
    seen = {}

    def connect(addr, timeout=None):
        seen["connect"] = addr
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(dw_tor.socket, "gethostbyname",
                        lambda name: seen.setdefault("resolved", name) and "172.31.250.2")
    monkeypatch.setattr(dw_tor.socket, "create_connection", connect)
    c = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    c.newnym_between_sites = True
    c.tor_control_host = "tunnel1"
    c.tor_control_port = "9051"
    c.tor_control_password = "ctl-pw"
    assert c.rotate_tor_circuit() is False
    assert seen == {"resolved": "tunnel1", "connect": ("172.31.250.2", 9051)}
