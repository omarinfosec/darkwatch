"""Smoke tests for setup-ui validators. No FastAPI / docker dependencies."""

import os
import sys

import pytest

# Make main.py importable. Set required env so import doesn't SystemExit.
os.environ.setdefault("SETUP_AUTH_TOKEN", "test-token-fixture")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _import_main():
    # Import is deferred per-test so a missing fastapi doesn't kill collection.
    import importlib.util
    if importlib.util.find_spec("fastapi") is None:
        pytest.skip("fastapi not installed in this env")
    import main  # noqa: F401
    return main


def test_telegram_api_id_validator():
    main = _import_main()
    assert main._API_ID.match("123456789")
    assert main._API_ID.match("123456")           # 6 digits
    assert main._API_ID.match("123456789012")     # 12 digits
    assert not main._API_ID.match("12345")        # too short
    assert not main._API_ID.match("1234567890123")  # too long
    assert not main._API_ID.match("abcdefg")
    assert not main._API_ID.match("1234abc")


def test_telegram_api_hash_validator():
    main = _import_main()
    assert main._HEX32.match("deadbeefcafebabedeadbeefcafebabe")
    assert main._HEX32.match("0" * 32)
    assert main._HEX32.match("F" * 32)
    assert not main._HEX32.match("a" * 31)        # too short
    assert not main._HEX32.match("a" * 33)        # too long
    assert not main._HEX32.match("a" * 31 + "z")  # non-hex


def test_wg_config_validator_accepts_valid():
    main = _import_main()
    # Synthetic all-A WG private key — passes the 43-base64-char + "="
    # length/charset check the validator does. Zero entropy so it is
    # obviously fake to a human reader. gitleaks would otherwise flag
    # this string as a WireGuard private key; the .gitleaks.toml
    # `[allowlist]` block scopes the exemption to files matching
    # `.*/tests/test_validators\.py$`. If you move this file, update
    # the allowlist regex or the secret scan will start failing CI.
    valid = """[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address    = 10.2.0.2/32
DNS        = 10.2.0.1

[Peer]
PublicKey  = WGPubKeyExample0000000000000000000000000000=
AllowedIPs = 0.0.0.0/0
Endpoint   = vpn.example.com:51820
PersistentKeepalive = 25
"""
    assert main._validate_wg_config(valid) == []


def test_wg_config_validator_rejects_missing_sections():
    main = _import_main()
    no_interface = "PrivateKey = AAAA\n[Peer]\nPublicKey = BBBB\nEndpoint = h:1\n"
    errors = main._validate_wg_config(no_interface)
    assert any("Interface" in e for e in errors)


def test_wg_config_validator_rejects_short_privkey():
    main = _import_main()
    bad = """[Interface]
PrivateKey = short=
Address = 10.2.0.2/32

[Peer]
PublicKey  = WGPubKeyExample0000000000000000000000000000=
AllowedIPs = 0.0.0.0/0
Endpoint   = vpn.example.com:51820
"""
    errors = main._validate_wg_config(bad)
    assert any("PrivateKey" in e for e in errors)


def test_wg_config_validator_rejects_oversize():
    main = _import_main()
    huge = "x" * (33 * 1024)
    errors = main._validate_wg_config(huge)
    assert any("large" in e for e in errors)
