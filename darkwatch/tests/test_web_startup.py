"""Background services start only when web.py runs as the program
(`python web.py`, the image's CMD), never on `import web`.

Each case runs in a fresh interpreter: the shared `web` fixture has
already imported the module, and the threads under test are
process-wide.
Run: pytest darkwatch/tests/
"""

import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BACKGROUND = {"health-refresh", "MonitorScheduler", "TelegramMonitor"}

# Prints the names of the running threads as JSON: right after `import web`,
# or, for "main", at the moment web.py (run as __main__) calls app.run().
# Flask.run is stubbed so nothing listens; os._exit skips joining the daemon
# threads that did start.
_SCRIPT = r"""
import json, os, runpy, sys, threading
import flask

seen = []
flask.Flask.run = lambda self, *a, **kw: seen.append(
    (sorted(t.name for t in threading.enumerate()), kw.get("port")))
if sys.argv[1] == "import":
    import web
    seen.append((sorted(t.name for t in threading.enumerate()), None))
    seen.append(([web._monitor_thread, web._tg_monitor_thread,
                  web._health_refresh_thread].count(None), None))
else:
    runpy.run_path("web.py", run_name="__main__")
print(json.dumps(seen), flush=True)
os._exit(0)
"""


def _run(tmp_path, mode):
    pytest.importorskip("flask")
    with open(os.path.join(HERE, "config.json")) as f:
        cfg = json.load(f)
    loot = tmp_path / "loot"
    cfg["output"].update(loot_dir=str(loot), reports_dir=str(loot / "reports"),
                         thumbnails_dir=str(loot / "thumbs"))
    cfg["database"]["path"] = str(tmp_path / "dw.db")
    (tmp_path / "config.json").write_text(json.dumps(cfg))
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("DARKWATCH_")}
    env.update(DARKWATCH_CONFIG=str(tmp_path / "config.json"),
               DARKWATCH_CONFIG_LOCAL="", PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-c", _SCRIPT, mode], cwd=HERE, env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_import_starts_no_background_threads(tmp_path):
    (names, _), (unset, _) = _run(tmp_path, "import")
    assert not BACKGROUND & set(names), names
    assert "TgLiveConsumer" not in names
    assert unset == 3


def test_running_web_py_starts_them_before_serving(tmp_path):
    [(names, port)] = _run(tmp_path, "main")
    assert BACKGROUND <= set(names), names
    assert port == 8080
