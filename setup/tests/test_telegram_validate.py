"""Tests for live Telegram credential validation."""

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SETUP_AUTH_TOKEN", "test-token-fixture")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import telegram_validate as tv


def test_validate_telegram_credentials_timeout(monkeypatch):
    async def slow(*_a, **_k):
        await asyncio.sleep(5)
        return True, ""

    monkeypatch.setattr(tv, "_validate_async", slow)
    ok, err = tv.validate_telegram_credentials("123456", "a" * 32, timeout_s=0.1)
    assert ok is False
    assert "timed out" in err


def test_validate_telegram_credentials_api_id_invalid(monkeypatch):
    async def reject(*_a, **_k):
        return (
            False,
            "Telegram rejected these credentials — check api_id and api_hash "
            "at my.telegram.org/apps",
        )

    monkeypatch.setattr(tv, "_validate_async", reject)
    ok, err = tv.validate_telegram_credentials("123456", "a" * 32)
    assert ok is False
    assert "rejected" in err


PROXY = ("socks5", "tunnel2", 1080, True, "darkwatch", "s3cret")


@pytest.fixture
def fake_client(monkeypatch):
    """Replace telethon's TelegramClient. Set `fake.outcome` to what
    send_code_request() should do, or `fake.connect_error` to fail connect."""
    telethon = pytest.importorskip("telethon")

    class FakeClient:
        instances = []
        outcome = None
        connect_error = None

        def __init__(self, session, api_id, api_hash, proxy=None, **kw):
            self.args = (api_id, api_hash)
            self.proxy = proxy
            self.kw = kw
            self.disconnected = False
            FakeClient.instances.append(self)

        async def connect(self):
            if FakeClient.connect_error is not None:
                raise FakeClient.connect_error

        def is_connected(self):
            return True

        async def send_code_request(self, phone):
            assert phone == tv._PROBE_PHONE
            if FakeClient.outcome is not None:
                raise FakeClient.outcome

        async def disconnect(self):
            self.disconnected = True

    monkeypatch.setattr(telethon, "TelegramClient", FakeClient)
    return FakeClient


def _errors():
    from telethon import errors
    return errors


@pytest.mark.parametrize("outcome,want_ok,want_err", [
    (None, True, ""),                                       # code sent
    ("PhoneNumberInvalidError", True, ""),                  # creds accepted
    ("FloodWaitError", True, ""),                           # other RPC error
    ("ApiIdInvalidError", False, "rejected these credentials"),
])
def test_validate_outcomes_pass_the_proxy(fake_client, outcome, want_ok, want_err):
    if outcome is not None:
        cls = getattr(_errors(), outcome)
        fake_client.outcome = (cls(request=None, capture=5)
                               if outcome == "FloodWaitError" else cls(request=None))
    ok, err = tv.validate_telegram_credentials("123456", "A" * 32, proxy=PROXY)
    assert ok is want_ok
    if want_err:
        assert want_err in err
    else:
        assert err == ""
    (client,) = fake_client.instances
    assert client.proxy == PROXY
    assert client.args == (123456, "a" * 32)
    assert client.disconnected


def test_validate_unreachable_names_tunnel2_and_passes_the_proxy(fake_client):
    fake_client.connect_error = ConnectionError("SOCKS refused")
    ok, err = tv.validate_telegram_credentials("123456", "a" * 32, proxy=PROXY)
    assert ok is False
    assert "via Tunnel 2" in err and "SOCKS refused" in err
    (client,) = fake_client.instances
    assert client.proxy == PROXY
    assert client.disconnected


def test_validate_without_proxy_never_invents_one(fake_client):
    fake_client.connect_error = OSError("network unreachable")
    ok, err = tv.validate_telegram_credentials("123456", "a" * 32)
    assert ok is False
    assert "Configure Tunnel 2 first" in err
    (client,) = fake_client.instances
    assert client.proxy is None
