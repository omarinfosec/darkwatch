"""
DarkWatch — Setup UI

Small FastAPI app that lets an operator paste:
  - Telegram api_id + api_hash
  - WireGuard config for Tunnel 1 (Tor research path)
  - WireGuard config for Tunnel 2 (Telegram research path)

…via a browser, and then writes them to /data/env and
/data/secrets/tunnelN/wg_confs/wg0.conf with correct perms, and restarts
the affected services via the docker socket.

Auth: bearer token from $SETUP_AUTH_TOKEN. First visit via ?token=... or the
login form sets an HttpOnly session cookie (7 days) so Settings ↗ from the
main dashboard opens without pasting the token each time.

Bring up:    docker compose --profile setup up -d setup
Bring down:  docker compose --profile setup stop setup
"""

import logging
import os
import re
import secrets
import stat
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

import docker
from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from telegram_validate import (
    TG_PROXY_HOST,
    TG_PROXY_PORT,
    validate_telegram_credentials_async,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("setup")

# Paths inside the setup container (mounted volumes).
DATA_ROOT = Path(os.environ.get("DARKWEBAPP_DATA_ROOT", "/data"))
REPO_ROOT = Path(os.environ.get("DARKWATCH_REPO_ROOT", "/repo"))
# Paths on the Docker *host* — compose bind mounts must use these when the
# setup container talks to the host daemon via /var/run/docker.sock. Using
# /repo/... from inside the container makes the daemon create bogus host dirs.
HOST_DATA_ROOT = Path(os.environ.get("DARKWATCH_HOST_DATA_ROOT", "/var/lib/darkwebapp"))
HOST_REPO_ROOT = Path(os.environ.get("DARKWATCH_HOST_REPO_ROOT", "/opt/darkwebapp"))
ENV_FILE = DATA_ROOT / "env"
SECRETS_ROOT = DATA_ROOT / "secrets"
TUNNEL1_CONF = SECRETS_ROOT / "tunnel1" / "wg_confs" / "wg0.conf"
TUNNEL2_CONF = SECRETS_ROOT / "tunnel2" / "wg_confs" / "wg0.conf"

# ── Auth ─────────────────────────────────────────────────────────────────────
_SETUP_CONTAINERS = ("darkwatch", "tunnel1", "tunnel2", "tor", "tg-socks", "setup")
SESSION_COOKIE = "dw_setup_session"
SESSION_MAX_AGE = 7 * 24 * 3600  # 7 days — re-paste token after expiry


def _read_env_var(key: str) -> str:
    """Read a single KEY=value from the mounted operator env file."""
    prefix = f"{key}="
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith(prefix):
                return line[len(prefix) :].strip()
    return os.environ.get(key, "").strip()


def _expected_token() -> str:
    """Live token from /data/env so rotation survives without recreating setup."""
    return _read_env_var("SETUP_AUTH_TOKEN")


if not _expected_token():
    log.error("SETUP_AUTH_TOKEN is not set. Refusing to start (would be unauthenticated).")
    log.error("Bootstrap should have generated one in /var/lib/darkwebapp/env.")
    log.error("If env is missing the value, run:")
    log.error("  echo 'SETUP_AUTH_TOKEN='\"$(openssl rand -hex 32)\" | sudo tee -a /var/lib/darkwebapp/env")
    raise SystemExit(2)


def _token_eq(provided: str, expected: str) -> bool:
    """Constant-time compare on bytes. compare_digest(str, str) raises
    TypeError on non-ASCII input, which surfaced as HTTP 500s."""
    return secrets.compare_digest(provided.encode(), expected.encode())


def _same_origin(request: Request) -> bool:
    """CSRF guard for cookie-authenticated writes. SameSite=Lax ignores the
    port, so the dashboard on :8080 (or anything else on this host) counts as
    same-site and would get the cookie attached. Require Origin (or Referer,
    for older clients) to name this exact host:port. The scheme is not
    compared so a TLS-terminating reverse proxy in front still works."""
    # Behind a reverse proxy Host is usually rewritten (nginx: $proxy_host),
    # so also accept X-Forwarded-Host. A cross-site page can't set that
    # header on a cookie-carrying request without a CORS preflight, which
    # this app never grants.
    hosts = {
        h.strip().lower()
        for h in (request.headers.get("host", ""),
                  *request.headers.get("x-forwarded-host", "").split(","))
        if h.strip()
    }
    source = request.headers.get("origin") or request.headers.get("referer") or ""
    if not hosts or not source:
        return False
    return urlsplit(source).netloc.lower() in hosts


def _set_session_cookie(response) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        _expected_token(),
        httponly=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
        path="/",
    )


def _is_authenticated(request: Request) -> bool:
    """Returns True iff a matching bearer token is presented.
    Accepts: HttpOnly session cookie, Authorization header, or ?token= on GET.
    """
    expected = _expected_token()
    if not expected:
        return False
    # Header form: Authorization: Bearer <token>. Not sent automatically by
    # browsers, so it needs no CSRF check.
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        provided = auth[7:].strip()
        if provided and _token_eq(provided, expected):
            return True
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if cookie and _token_eq(cookie, expected):
        if request.method in ("GET", "HEAD"):
            return True
        return _same_origin(request)
    # Query form (only valid for GET/HEAD; POSTs use cookie or header).
    if request.method in ("GET", "HEAD"):
        provided = request.query_params.get("token", "")
        if provided and _token_eq(provided, expected):
            return True
    return False


def _check_token(request: Request) -> None:
    """API-style enforcement: raise 401 unless authenticated. Used on the
    POST endpoints where a friendly HTML page wouldn't help — the caller
    is JS, not a browser navigation."""
    if not _is_authenticated(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing token",
        )


# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="DarkWatch Setup", docs_url=None, redoc_url=None)
_BASE = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=_BASE / "static"), name="static")
templates = Jinja2Templates(directory=_BASE / "templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not _is_authenticated(request):
        return templates.TemplateResponse(
            "no_token.html",
            {"request": request, "auth_error": None},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    if request.query_params.get("token"):
        # Trade the URL token for the HttpOnly cookie and drop it from the
        # address bar / history straight away.
        response = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(response)
        return response
    state = _current_state(include_values=True)
    response = templates.TemplateResponse(
        "index.html",
        {"request": request, "state": state, "token_present": True},
    )
    if not request.cookies.get(SESSION_COOKIE):
        _set_session_cookie(response)
    return response


@app.post("/auth", response_class=HTMLResponse)
async def auth_login(request: Request, token: str = Form(...)):
    provided = token.strip()
    if not provided or not _token_eq(provided, _expected_token()):
        return templates.TemplateResponse(
            "no_token.html",
            {"request": request, "auth_error": "Invalid token — check /var/lib/darkwebapp/env"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    response = RedirectResponse(url="/", status_code=303)
    _set_session_cookie(response)
    return response


# ── Validators ───────────────────────────────────────────────────────────────
_HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
_API_ID = re.compile(r"^\d{6,12}$")
# Required fragments in any sane WG client config
_WG_INTERFACE = re.compile(r"^\s*\[Interface\]\s*$", re.MULTILINE)
_WG_PEER = re.compile(r"^\s*\[Peer\]\s*$", re.MULTILINE)
_WG_PRIVKEY = re.compile(r"^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=\s*$", re.MULTILINE)
_WG_PUBKEY = re.compile(r"^\s*PublicKey\s*=\s*[A-Za-z0-9+/]{43}=\s*$", re.MULTILINE)
_WG_ENDPOINT = re.compile(r"^\s*Endpoint\s*=\s*\S+:\d+\s*$", re.MULTILINE)
# Plain client keys only. wg-quick runs PreUp/PostUp/PreDown/PostDown as root
# inside the tunnel container (NET_ADMIN + SYS_MODULE), so a pasted config
# must never be able to carry shell hooks.
_WG_ALLOWED_KEYS = {
    "privatekey", "address", "dns", "mtu", "listenport", "fwmark", "table",
    "publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive",
}


def _validate_wg_config(text: str) -> list[str]:
    """Return list of validation errors; empty list = ok."""
    errors = []
    if len(text) > 32 * 1024:
        errors.append("config is suspiciously large (>32 KiB)")
    if not _WG_INTERFACE.search(text):
        errors.append("missing [Interface] section")
    if not _WG_PEER.search(text):
        errors.append("missing [Peer] section")
    if not _WG_PRIVKEY.search(text):
        errors.append("missing or malformed PrivateKey (expected 44-char base64 in [Interface])")
    if not _WG_PUBKEY.search(text):
        errors.append("missing or malformed PublicKey (expected 44-char base64 in [Peer])")
    if not _WG_ENDPOINT.search(text):
        errors.append("missing Endpoint (expected host:port in [Peer])")
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", ";", "[")):
            continue
        key = s.split("=", 1)[0].strip()
        if key.lower() not in _WG_ALLOWED_KEYS:
            errors.append(f"disallowed key: {key} (hooks like PostUp are not accepted)")
    return errors


# ── Routes: telegram ─────────────────────────────────────────────────────────
@app.post("/api/telegram")
async def save_telegram(
    request: Request,
    api_id: str = Form(...),
    api_hash: str = Form(...),
):
    _check_token(request)
    api_id = api_id.strip()
    api_hash = api_hash.strip().lower()

    if not _API_ID.match(api_id):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "api_id must be 6–12 digits"},
        )
    if not _HEX32.match(api_hash):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "api_hash must be exactly 32 hex characters"},
        )

    proxy = None
    if TUNNEL2_CONF.is_file():
        proxy = ("socks5", TG_PROXY_HOST, TG_PROXY_PORT)
    ok, err = await validate_telegram_credentials_async(api_id, api_hash, proxy=proxy)
    if not ok:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": err},
        )

    _update_env({"TELEGRAM_API_ID": api_id, "TELEGRAM_API_HASH": api_hash})
    ok, detail = _recreate_darkwatch()
    if not ok:
        log.error("telegram creds saved but darkwatch recreate failed: %s", detail)
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": detail},
        )

    log.info("telegram credentials saved; recreated: %s", detail)
    return {"ok": True, "restarted": ["darkwatch"], "detail": detail}


# ── Routes: tunnel ───────────────────────────────────────────────────────────
@app.post("/api/tunnel/{n}")
async def save_tunnel(request: Request, n: int, conf: str = Form(...)):
    _check_token(request)
    if n not in (1, 2):
        raise HTTPException(status_code=400, detail="tunnel must be 1 or 2")

    errors = _validate_wg_config(conf)
    if errors:
        return JSONResponse(status_code=400, content={"ok": False, "errors": errors})

    target = TUNNEL1_CONF if n == 1 else TUNNEL2_CONF
    target.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically (tmpfile + rename) so a half-written file can't ever
    # be picked up by the next container restart.
    tmp = target.with_suffix(".tmp")
    _write_private(tmp, conf if conf.endswith("\n") else conf + "\n")
    os.replace(tmp, target)
    # Best-effort: own as root (we're root inside the container during the
    # entrypoint hand-off period). Falls back silently if not allowed.
    try:
        os.chown(target, 0, 0)
    except (PermissionError, OSError):
        pass

    # Recreate this tunnel + its sidecar. A plain `up -d` is a no-op when the
    # container already exists (only the mounted file changed), so an edited
    # WG config would otherwise never be applied.
    ok, detail = _compose_up_tunnel(n)
    if not ok:
        log.error("tunnel%d saved but compose up failed: %s", n, detail)
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": detail},
        )
    log.info("tunnel%d config saved (%d bytes); %s", n, len(conf), detail)
    return {"ok": True, "started": detail, "path": str(target)}


# ── Routes: status ───────────────────────────────────────────────────────────
@app.get("/api/state")
async def state(request: Request):
    _check_token(request)
    return _current_state()


# ── Helpers: env file munging ────────────────────────────────────────────────
def _write_private(path: Path, text: str) -> None:
    """Write `text` to `path`, created 0600 from the start (never briefly
    world-readable under the default umask)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)


_ENV_LOCK = threading.Lock()


def _update_env(updates: dict[str, str]) -> None:
    """Merge {VAR: VALUE} into ENV_FILE, preserving comments and order.
    If a var already exists, replace its value. Otherwise append.
    Atomic (tmp + rename) and serialized: a crash or concurrent save must not
    truncate the env file — it holds SETUP_AUTH_TOKEN and every secret."""
    with _ENV_LOCK:
        _update_env_locked(updates)


def _update_env_locked(updates: dict[str, str]) -> None:
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    seen = set()
    out = []
    for line in lines:
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=", line)
        if m and m.group(1) in updates:
            out.append(f"{m.group(1)}={updates[m.group(1)]}")
            seen.add(m.group(1))
        else:
            out.append(line)
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}")
    tmp = ENV_FILE.with_name(ENV_FILE.name + ".tmp")
    _write_private(tmp, "\n".join(out) + "\n")
    os.replace(tmp, ENV_FILE)


# ── Helpers: docker compose ──────────────────────────────────────────────────
def _compose_profiles() -> list[str]:
    profiles: list[str] = []
    if TUNNEL1_CONF.is_file():
        profiles.append("tor")
    if TUNNEL2_CONF.is_file():
        profiles.append("tg")
    return profiles


def _compose_run(
    services: list[str],
    *,
    force_recreate: bool = False,
    no_deps: bool = False,
) -> tuple[bool, str]:
    """Run docker compose up for `services`. Use force_recreate when env vars
    on disk changed — a plain container restart does NOT reload env_file."""
    # Existence checks use container mount paths (/repo, /data).
    local_compose = REPO_ROOT / "docker-compose.yml"
    if not local_compose.is_file():
        return False, (
            f"missing {local_compose} — is the repo mounted at {REPO_ROOT}? "
            f"(host path should be {HOST_REPO_ROOT})"
        )
    if not ENV_FILE.is_file():
        return False, (
            f"missing {ENV_FILE} — is operator state mounted at {DATA_ROOT}? "
            f"(host path should be {HOST_DATA_ROOT})"
        )

    profile_args: list[str] = []
    for profile in _compose_profiles():
        profile_args.extend(["--profile", profile])

    # Compose CLI reads --env-file and -f from the setup container filesystem.
    # --project-directory stays on the host so bind mounts resolve correctly.
    cmd = [
        "docker", "compose",
        "--project-directory", str(HOST_REPO_ROOT),
        "--env-file", str(ENV_FILE),
        "-f", str(local_compose),
        *profile_args,
        "up", "-d", "--remove-orphans",
    ]
    if force_recreate:
        cmd.append("--force-recreate")
    if no_deps:
        cmd.append("--no-deps")
    cmd.extend(services)

    # Setup's own DARKWEBAPP_DATA_ROOT=/data must not leak into compose variable
    # substitution — that would bind-mount bogus host paths like /data/darkwatch/...
    compose_env = os.environ.copy()
    compose_env["DARKWEBAPP_DATA_ROOT"] = str(HOST_DATA_ROOT)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=compose_env,
        )
    except subprocess.TimeoutExpired:
        return False, "docker compose up timed out after 5 minutes"
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "unknown error")[-800:]
        return False, f"docker compose up failed: {tail}"
    return True, ", ".join(services)


def _compose_up_tunnel(n: int) -> tuple[bool, str]:
    """Force-recreate tunnel N and its sidecar so a new WG config takes effect.
    Only the listed services are force-recreated; the other tunnel is untouched."""
    services = ["tunnel1", "tor"] if n == 1 else ["tunnel2", "tg-socks"]
    ok, detail = _compose_run(services, force_recreate=True)
    if not ok:
        return ok, detail
    # Make sure darkwatch is up too (no-op when it already is).
    ok, more = _compose_run(["darkwatch"], no_deps=True)
    return ok, f"{detail}, {more}" if ok else more


def _recreate_darkwatch() -> tuple[bool, str]:
    """Recreate darkwatch so env_file changes (e.g. Telegram creds) take effect."""
    return _compose_run(["darkwatch"], force_recreate=True, no_deps=True)


# ── Helpers: docker restart via socket (legacy) ──────────────────────────────
def _restart_services(names: list[str]) -> list[str]:
    """Restart named containers via the mounted docker socket. Returns the
    list of names that were actually restarted (silently skips ones that
    aren't running, e.g., tunnel1 if the user is configuring it for the
    very first time)."""
    try:
        client = docker.from_env()
    except Exception as e:
        log.error("docker client init failed: %s", e)
        return []
    out = []
    for name in names:
        try:
            ctr = client.containers.get(name)
            ctr.restart(timeout=10)
            out.append(name)
        except docker.errors.NotFound:
            log.info("skip restart: container '%s' not running", name)
        except Exception as e:
            log.warning("restart '%s' failed: %s", name, e)
    return out


# ── Helpers: current state for the UI ────────────────────────────────────────
def _current_state(include_values: bool = False) -> dict:
    """Snapshot what's already configured, for the UI to display.
    With include_values=True, returns the actual secret values for
    pre-filling form fields. With False (the default — used by /api/state),
    returns only booleans and sizes. The HTML render path passes True;
    the JSON API path stays opt-in conservative."""
    state = {
        "env_path": str(ENV_FILE),
        "tunnel1_conf_present": TUNNEL1_CONF.exists(),
        "tunnel2_conf_present": TUNNEL2_CONF.exists(),
        "tunnel1_size": TUNNEL1_CONF.stat().st_size if TUNNEL1_CONF.exists() else 0,
        "tunnel2_size": TUNNEL2_CONF.stat().st_size if TUNNEL2_CONF.exists() else 0,
        "telegram_api_id_set": False,
        "telegram_api_hash_set": False,
        # Pre-fill values — only populated when include_values=True.
        "telegram_api_id": "",
        "telegram_api_hash": "",
        "tunnel1_conf": "",
        "tunnel2_conf": "",
    }
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("TELEGRAM_API_ID="):
                v = line[len("TELEGRAM_API_ID="):].strip()
                state["telegram_api_id_set"] = bool(v)
                if include_values:
                    state["telegram_api_id"] = v
            elif line.startswith("TELEGRAM_API_HASH="):
                v = line[len("TELEGRAM_API_HASH="):].strip()
                state["telegram_api_hash_set"] = bool(v)
                if include_values:
                    state["telegram_api_hash"] = v
    if include_values:
        try:
            if TUNNEL1_CONF.exists():
                state["tunnel1_conf"] = TUNNEL1_CONF.read_text(encoding="utf-8")
            if TUNNEL2_CONF.exists():
                state["tunnel2_conf"] = TUNNEL2_CONF.read_text(encoding="utf-8")
        except Exception as e:
            log.warning("tunnel config read failed: %s", e)
    # Container running state
    try:
        client = docker.from_env()
        running = {c.name: c.status for c in client.containers.list(all=True)}
        state["containers"] = {
            name: running.get(name, "absent")
            for name in _SETUP_CONTAINERS
        }
    except Exception as e:
        log.warning("docker state lookup failed: %s", e)
        state["containers"] = {}
    return state
