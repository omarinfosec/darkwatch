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
