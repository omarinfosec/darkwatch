"""Shared fixtures for the darkwatch test modules."""

import json
import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def web(tmp_path_factory):
    """The dashboard module, imported once against a throwaway config and
    database. Session-scoped: `web` reads its config and environment at
    import, so every test module must share the one import. The
    environment is set only around that import, so later test modules
    (setup/tests included) do not see DARKWATCH_CONFIG or
    DARKWATCH_BIND_IP."""
    d = tmp_path_factory.mktemp("dw")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "config.json")) as f:
        cfg = json.load(f)
    cfg["output"].update(loot_dir=str(d / "loot"), reports_dir=str(d / "loot/reports"),
                         thumbnails_dir=str(d / "loot/thumbs"))
    cfg["database"]["path"] = str(d / "dw.db")
    (d / "config.json").write_text(json.dumps(cfg))
    pytest.importorskip("flask")
    # Session-scoped, so the function-scoped monkeypatch fixture is not
    # available. web.py reads these variables only at import (CONFIG_PATH,
    # _ALLOWED_HOSTS, _AUTH_TOKEN), so the context restores them right
    # after it.
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("DARKWATCH_CONFIG", str(d / "config.json"))
        mp.setenv("DARKWATCH_BIND_IP", "10.8.0.5")
        # No local override file from the machine running the tests.
        mp.setenv("DARKWATCH_CONFIG_LOCAL", "")
        # Login off, as by default; test_dashboard_auth turns it on.
        mp.delenv("DARKWATCH_AUTH_TOKEN", raising=False)
        import web as web_mod
    # The import starts no monitor scheduler (test_web_startup checks
    # that), so no background tick uses the fakes tests swap in for
    # web._crawler and web._tg. Keep the schedulers' stop flag set so a
    # tick a test runs by hand stops at once unless the test gives it a
    # fresh Event.
    web_mod._monitor_stop.set()
    yield web_mod


class _FakeControlPort:
    """A one-connection-at-a-time Tor ControlPort on 127.0.0.1."""

    def __init__(self, reply):
        self.reply = reply            # callable(request bytes) -> bytes | None
        self.requests = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    while b"QUIT\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    pass
                self.requests.append(data)
                out = self.reply(data)
                if out is None:           # never answer
                    self.stop.wait(3)
                    continue
                conn.sendall(out)

    def close(self):
        self.stop.set()
        self.thread.join(5)
        self.sock.close()


@pytest.fixture
def fake_controlport():
    """Start a _FakeControlPort: fake_controlport(reply) -> server. `reply`
    maps the request bytes to the answer, or None to never answer."""
    servers = []

    def start(reply):
        srv = _FakeControlPort(reply)
        servers.append(srv)
        return srv
    yield start
    for srv in servers:
        srv.close()
