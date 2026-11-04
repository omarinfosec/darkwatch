"""Optional dashboard login (DARKWATCH_AUTH_TOKEN): off by default, Bearer
header or a signed session cookie when on, /healthz /login /static exempt."""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# The `web` fixture (the imported dashboard module) is in conftest.py.

BASE = "http://127.0.0.1:8080"
TOKEN = "a" * 64


@pytest.fixture
def auth(web, monkeypatch):
    """Login on, with TOKEN. web reads DARKWATCH_AUTH_TOKEN only at import,
    so set the module value it was read into."""
    monkeypatch.setattr(web, "_AUTH_TOKEN", TOKEN)
    return web


def _bearer(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def _set_cookie_headers(r):
    return [v for k, v in r.headers.items() if k.lower() == "set-cookie"]


def test_token_unset_leaves_the_dashboard_open(web):
    assert web._AUTH_TOKEN == ""
    c = web.app.test_client()
    assert c.get("/", base_url=BASE).status_code == 200
    assert c.get("/api/findings", base_url=BASE).status_code == 200
    assert c.get("/healthz", base_url=BASE).status_code == 200
    # Nothing to sign in to: /login goes back to the dashboard.
    for r in (c.get("/login", base_url=BASE),
              c.post("/login", base_url=BASE, data={"token": TOKEN})):
        assert r.status_code == 303
        assert r.headers["Location"].endswith("/")
        assert _set_cookie_headers(r) == []


def test_no_credentials_is_401(auth):
    c = auth.app.test_client()
    r = c.get("/api/findings", base_url=BASE)
    assert r.status_code == 401
    # The UI tells a login 401 from Telegram's own 401s by this header.
    assert r.headers["WWW-Authenticate"].startswith("Bearer")
    assert r.get_json() == {"error": "login required"}
    for path in ("/metrics", "/api/telegram/search/deep?q=x",
                 "/loot/tg-media/x.jpg", "/api/screenshot/1"):
        assert c.get(path, base_url=BASE).status_code == 401, path
    assert c.post("/api/stop", base_url=BASE).status_code == 401
    # A browser opening the dashboard is sent to the sign-in form.
    r = c.get("/", base_url=BASE)
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_bearer_token_is_accepted(auth):
    c = auth.app.test_client()
    assert c.get("/api/findings", base_url=BASE, headers=_bearer()).status_code == 200
    assert c.get("/", base_url=BASE, headers=_bearer()).status_code == 200
    assert c.get("/api/findings", base_url=BASE,
                 headers=_bearer("b" * 64)).status_code == 401
    assert c.get("/api/findings", base_url=BASE,
                 headers={"Authorization": f"Basic {TOKEN}"}).status_code == 401


def test_exempt_paths(auth):
    c = auth.app.test_client()
    assert c.get("/healthz", base_url=BASE).status_code == 200
    assert c.get("/login", base_url=BASE).status_code == 200
    assert c.get("/static/logo.svg", base_url=BASE).status_code == 200
    # The request guard still runs first.
    assert c.get("/healthz", base_url="http://evil.example").status_code == 403


def test_failed_login_sets_no_cookie(auth, caplog):
    c = auth.app.test_client()
    for value in ("wrong", TOKEN[:-1], ""):
        r = c.post("/login", base_url=BASE, data={"token": value})
        assert r.status_code == 401
        assert _set_cookie_headers(r) == []
        assert b"Invalid token" in r.data
    # Logged with the client IP, never the value submitted.
    assert "sign-in failed" in caplog.text
    assert TOKEN[:-1] not in caplog.text
    assert c.get("/api/findings", base_url=BASE).status_code == 401


def test_login_sets_a_working_cookie(auth):
    c = auth.app.test_client()
    r = c.post("/login", base_url=BASE, data={"token": f"  {TOKEN}\n"})
    assert r.status_code == 303 and r.headers["Location"].endswith("/")
    [cookie] = _set_cookie_headers(r)
    assert cookie.startswith(f"{auth.AUTH_COOKIE}=")
    assert TOKEN not in cookie
    attrs = cookie.lower()
    assert "httponly" in attrs
    assert "samesite=strict" in attrs
    assert f"max-age={7 * 24 * 3600}" in attrs
    assert "secure" not in attrs.replace("samesite", "")
    # The test client keeps the cookie, as a browser would.
    assert c.get("/api/findings", base_url=BASE).status_code == 200
    assert c.get("/", base_url=BASE).status_code == 200


def _client_with_cookie(web, value):
    c = web.app.test_client()
    c.set_cookie(web.AUTH_COOKIE, value, domain="127.0.0.1")
    return c


def test_expired_and_tampered_cookies_are_rejected(auth):
    now = time.time()
    good = auth._make_session(TOKEN, now=now - 60)
    assert _client_with_cookie(auth, good).get(
        "/api/findings", base_url=BASE).status_code == 200

    expired = auth._make_session(TOKEN, now=now - auth.AUTH_MAX_AGE - 5)
    future = auth._make_session(TOKEN, now=now + 3600)
    ts, mac = good.split(".")
    flipped = mac[:-1] + ("0" if mac[-1] != "0" else "1")
    for bad in (
        expired,
        future,
        f"{ts}.{flipped}",                       # MAC changed
        f"{int(ts) + 1}.{mac}",                  # issue time changed
        auth._make_session("b" * 64, now=now),   # signed with another token
        TOKEN,                                   # the raw token
        f"{ts}.", ".{mac}", "garbage",
    ):
        r = _client_with_cookie(auth, bad).get("/api/findings", base_url=BASE)
        assert r.status_code == 401, bad
    # The test client sends cookies UTF-8 encoded, so call the check directly
    # for timestamps that str.isdigit() accepts but int() rejects.
    for bad in ("\u00b2." + mac, "9" * 4400 + "." + mac, "\u0663." + mac):
        assert auth._valid_session(bad, TOKEN) is False


def test_changing_the_token_signs_sessions_out(auth, monkeypatch):
    c = _client_with_cookie(auth, auth._make_session(TOKEN))
    assert c.get("/api/findings", base_url=BASE).status_code == 200
    monkeypatch.setattr(auth, "_AUTH_TOKEN", "c" * 64)
    assert c.get("/api/findings", base_url=BASE).status_code == 401


def test_short_token_fails_closed(web, monkeypatch):
    short = "s" * 31
    monkeypatch.setattr(web, "_AUTH_TOKEN", short)
    c = web.app.test_client()
    assert c.get("/api/findings", base_url=BASE,
                 headers=_bearer(short)).status_code == 401
    r = c.post("/login", base_url=BASE, data={"token": short})
    assert r.status_code == 401 and _set_cookie_headers(r) == []
    c = _client_with_cookie(web, web._make_session(short))
    assert c.get("/api/findings", base_url=BASE).status_code == 401
    assert c.get("/healthz", base_url=BASE).status_code == 200


def test_telegram_401_is_not_a_login_401(auth, monkeypatch):
    # The UI redirects to /login only on a 401 with WWW-Authenticate; the
    # Telegram 2FA prompt answers 401 too and must not trigger it.
    monkeypatch.setattr(auth._tg, "auth_confirm",
                        lambda *a, **kw: {"ok": False, "error": "2fa_password_required"})
    r = auth.app.test_client().post(
        "/api/telegram/auth/confirm", base_url=BASE, headers=_bearer(),
        json={"phone": "+10000000000", "code": "12345"})
    assert r.status_code == 401
    assert "WWW-Authenticate" not in r.headers


def test_cross_site_link_reaches_the_login_form(auth):
    # Strict cookies are not sent on a navigation from another site, so a
    # link to "/" lands on /login; the guard must let that navigation in.
    nav = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
           "Sec-Fetch-Dest": "document"}
    c = auth.app.test_client()
    assert c.get("/", base_url=BASE, headers=nav).status_code == 302
    assert c.get("/login", base_url=BASE, headers=nav).status_code == 200
    assert c.post("/login", base_url=BASE, headers=nav,
                  data={"token": TOKEN}).status_code == 403
