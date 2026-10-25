"""Live Telegram api_id / api_hash validation via MTProto."""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("setup.telegram_validate")

# Match darkwatch's Telegram egress path when Tunnel 2 is configured.
TG_PROXY_HOST = "tunnel2"
TG_PROXY_PORT = 1080
TG_PROXY_USER = "darkwatch"
# Dummy phone — never receives SMS; Telegram validates api_id/api_hash before
# checking the number. PhoneNumberInvalidError means credentials were accepted.
_PROBE_PHONE = "+99900000000"


async def _validate_async(
    api_id: str,
    api_hash: str,
    *,
    proxy: tuple | None,
) -> tuple[bool, str]:
    try:
        from telethon import TelegramClient
        from telethon.errors import ApiIdInvalidError, PhoneNumberInvalidError, RPCError
        from telethon.sessions import StringSession
    except ImportError:
        return False, "telethon is not installed in the setup container"

    client = TelegramClient(
        StringSession(),
        int(api_id),
        api_hash.lower(),
        proxy=proxy,
    )
    try:
        await client.connect()
        if not client.is_connected():
            return False, "could not connect to Telegram"
        try:
            await client.send_code_request(_PROBE_PHONE)
            return True, ""
        except ApiIdInvalidError:
            return False, "api_id_invalid"
        except PhoneNumberInvalidError:
            return True, ""
        except RPCError as exc:
            # Creds were accepted; Telegram rejected the probe phone or rate-limited.
            log.info("telegram probe accepted creds (%s)", type(exc).__name__)
            return True, ""
    except (ConnectionError, OSError, TimeoutError) as exc:
        if proxy:
            return (
                False,
                "could not reach Telegram via Tunnel 2 "
                f"(tunnel2:{TG_PROXY_PORT}) — is the tg profile up? ({exc})",
            )
        return (
            False,
            "could not reach Telegram to verify credentials "
            f"({exc}). Configure Tunnel 2 first, or check outbound connectivity.",
        )
    except Exception as exc:
        log.warning("unexpected telegram credential check failure: %s", exc)
        return False, f"Telegram credential check failed: {exc}"
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def validate_telegram_credentials(
    api_id: str,
    api_hash: str,
    *,
    proxy: tuple | None = None,
    timeout_s: float = 20.0,
) -> tuple[bool, str]:
    """Sync wrapper for scripts/tests. Do not call from inside a running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        try:
            return asyncio.run(
                validate_telegram_credentials_async(
                    api_id, api_hash, proxy=proxy, timeout_s=timeout_s
                )
            )
        except asyncio.TimeoutError:
            return False, f"Telegram credential check timed out after {timeout_s:.0f}s"
        raise
    raise RuntimeError(
        "validate_telegram_credentials() cannot run inside an event loop; "
        "use validate_telegram_credentials_async()"
    )


async def validate_telegram_credentials_async(
    api_id: str,
    api_hash: str,
    *,
    proxy: tuple | None = None,
    timeout_s: float = 20.0,
) -> tuple[bool, str]:
    """Return (ok, error_message). error_message is empty when ok."""
    api_hash = api_hash.lower()
    try:
        ok, reason = await asyncio.wait_for(
            _validate_async(api_id, api_hash, proxy=proxy),
            timeout=timeout_s,
        )
        if ok:
            return True, ""
        if reason == "api_id_invalid":
            return (
                False,
                "Telegram rejected these credentials — api_id and api_hash must "
                "come from the same app at my.telegram.org/apps. Re-paste both "
                "values (do not reuse the old hash shown as dots).",
            )
        return False, reason
    except asyncio.TimeoutError:
        return False, f"Telegram credential check timed out after {timeout_s:.0f}s"
