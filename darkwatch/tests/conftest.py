"""Shared fixtures for the darkwatch test modules."""

import json
import os
import sys

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
    # available. web.py reads both variables only at import (CONFIG_PATH,
    # _ALLOWED_HOSTS), so the context restores them right after it.
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("DARKWATCH_CONFIG", str(d / "config.json"))
        mp.setenv("DARKWATCH_BIND_IP", "10.8.0.5")
        import web as web_mod
    yield web_mod
