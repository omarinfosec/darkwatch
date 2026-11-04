"""Secrets stay out of alert error logs, and the Telegram session file (a
full login to the account) is kept at mode 0600."""

import logging
import os
import socket
import stat
import sys
from types import SimpleNamespace

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import darkwatch as dw  # noqa: E402

FINDING = {"score": 100, "rule_name": "r", "severity": "high",
           "page_url": "http://x.onion/", "matched_strings": "m", "snippet": "s"}


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def no_env_proxy(monkeypatch):
    for k in ("NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy",
              "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)


def _secret_free(caplog):
    for r in caplog.records:
        msg = r.getMessage()
        assert "SECRET" not in msg, msg       # also covers SECRETPATH


def test_failed_alerts_never_log_token_or_webhook_path(caplog, no_env_proxy):
    # Real requests through proxies that refuse, so the messages are the ones
    # urllib3 actually produces ("Max retries exceeded with url: /bot...").
    p = _closed_port()
    routes = [("telegram tunnel", {"https": f"http://darkwatch:pw@127.0.0.1:{p}"}),
              ("tor", {"https": f"socks5h://127.0.0.1:{p}"})]
    cfg = {"telegram_enabled": True, "telegram_bot_token": "123:SECRET",
           "telegram_chat_id": "1",
           "slack_enabled": True,
           "slack_webhook_url": "https://hooks.slack.com/services/T0/B0/SECRETPATH?t=SECRET"}
    caplog.set_level(logging.DEBUG)
    dw.Alerter(cfg, routes=routes).send(FINDING)
    _secret_free(caplog)
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 2
    assert all("ConnectionError" in m for m in errors), errors
    assert "Telegram alert failed" in errors[0] and "api.telegram.org" in errors[0]
    assert "ProxyError" in caplog.text      # first route, logged at debug


def test_invalid_url_is_scrubbed_and_not_retried(caplog, no_env_proxy, monkeypatch):
    calls = []
    real_post = requests.post
    def counting_post(*a, **k):
        calls.append(k.get("proxies"))
        return real_post(*a, **k)
    monkeypatch.setattr(dw.requests, "post", counting_post)
    routes = [("a", {"https": "socks5h://127.0.0.1:9"}), ("b", {"https": "socks5h://127.0.0.1:9"})]
    cfg = {"discord_enabled": True, "discord_webhook_url": "http://:80/SECRETPATH"}
    caplog.set_level(logging.DEBUG)
    dw.Alerter(cfg, routes=routes).send(FINDING)
    _secret_free(caplog)
    assert "InvalidURL" in caplog.text
    assert len(calls) == 1

    with pytest.raises(RuntimeError) as ei:
        dw.Alerter({}, routes=routes)._post("hooks.slack.com/SECRETPATH", {})
    assert "SECRET" not in str(ei.value) and "MissingSchema" in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


@pytest.mark.parametrize("url", [
    "https://api.telegram.org/bot123:SECRET TAIL/sendMessage",
    "https://api.telegram.org/bot123:SECRET\n/sendMessage",
    "https://h.example/\u00e9/SECRETPATH",
    "https://h.example/a<b>|c/SECRETPATH",
    "https://h.example/hook?a=b c&t=SECRET",
])
def test_percent_encoded_url_is_scrubbed(url, no_env_proxy):
    # urllib3 quotes the prepared (percent-encoded) path, which differs from
    # the configured URL when a token or webhook has spaces or non-ASCII.
    p = _closed_port()
    routes = [("a", {"https": f"http://127.0.0.1:{p}"})]
    with pytest.raises(RuntimeError) as ei:
        dw.Alerter({}, routes=routes)._post(url, {})
    assert "SECRET" not in str(ei.value), str(ei.value)
    assert "ProxyError" in str(ei.value)


def test_scrub_keeps_host_drops_credentials_path_query():
    out = dw.Alerter._scrub(
        "via socks5h://u:pw@tunnel2:1080 to https://h.example/a%20b/SECRET?q=SECRET",
        "https://other.example/x")
    assert out == "via socks5h://tunnel2:1080 to https://h.example/[redacted]"


# ── Telegram session file mode ───────────────────────────────────────────────

class _FakeClient:
    """Stands in for TelegramClient: creates the session file the way
    Telethon does (process umask, typically 0644) and rewrites it on login."""

    def __init__(self, session, **kwargs):
        self.path = session if session.endswith(".session") else session + ".session"
        if not os.path.exists(self.path):
            open(self.path, "w").close()
            os.chmod(self.path, 0o644)

    def _login_write(self):
        os.chmod(self.path, 0o644)

    async def connect(self): pass
    async def disconnect(self): pass
    async def sign_in(self, **kwargs): self._login_write()
    async def get_me(self): return SimpleNamespace(username="u", id=1, first_name="f")

    async def qr_login(self):
        client = self
        class _QR:
            url = "tg://login?token=x"
            expires = None
            async def wait(self): client._login_write()
        return _QR()


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.setattr(dw, "TelegramClient", _FakeClient, raising=False)
    eng = dw.DarkMTProto({"telegram": {
        "api_id": "1", "api_hash": "x", "session_path": str(tmp_path / "telegram"),
        "proxy_host": "tunnel2", "proxy_port": 1080}})
    return eng, tmp_path / "telegram.session"


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_build_client_fixes_existing_world_readable_session(engine):
    eng, sess = engine
    sess.touch()
    os.chmod(sess, 0o644)
    eng._build_client()
    assert _mode(sess) == 0o600


def test_code_login_leaves_session_0600(engine):
    eng, sess = engine
    assert eng.auth_confirm("+1", "12345", phone_code_hash="h")["ok"]
    assert _mode(sess) == 0o600


def test_qr_password_login_leaves_session_0600(engine):
    eng, sess = engine
    assert eng.auth_qr_password("tok", "pw")["ok"]
    assert _mode(sess) == 0o600


def test_qr_login_leaves_session_0600(engine):
    eng, sess = engine
    r = eng.auth_qr_start()
    eng._qr_sessions_dict()[r["token"]]["thread"].join(5)
    assert eng.auth_qr_status(r["token"])["authenticated"]
    assert _mode(sess) == 0o600
