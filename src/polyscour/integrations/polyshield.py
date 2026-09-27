r"""Optional, read-only integration with PolyShield.

PolyScour is a complete application without PolyShield. If PolyShield happens
to be installed and running, one dashboard tile gains real security posture
instead of being absent. That is the entire relationship in 0.1.

Three questions, and no more
----------------------------

    is_available()      PING
    security_posture()  STATUS, GET_INTEL_STATUS

Richer capabilities -- a path-level query, hash reputation, shared quarantine --
get added only when a concrete, committed feature needs them. None of them
exist on PolyShield's service today, and inventing one now would mean building
an IPC API before anything consumes it.

``security_posture()`` reads only fields ``STATUS`` and ``GET_INTEL_STATUS``
already return -- confirmed against PolyShield's own handlers
(``polyshield_service.py``, ``_build_status``/``_build_intel_status``), not
guessed. Notably, ``GET_INTEL_STATUS`` has never had an ``age_days`` field: its
real shape is a ``feeds`` mapping, each entry carrying PolyShield's own
freshness classification (``never`` / ``fresh`` / ``aging`` / ``stale`` /
``error`` / ``auth_required``) rather than a bare number of days. An earlier
version of this module read a field that PolyShield never sent, so
``intel_age_days`` was silently always ``None``; ``intel_feeds_enabled`` and
``intel_feeds_stale_or_error`` replace it, built from feed states PolyShield
already computed rather than PolyScour inventing its own age arithmetic.

localhost is not a trust boundary
---------------------------------

Any local process can bind a port. The shared secret PolyShield writes to its
state directory is what distinguishes its service from something else listening,
and this client **fails closed**: a response of an unexpected shape is treated as
"no PolyShield", never as a degraded yes. Nothing here can ask PolyShield to
*act* -- there is deliberately no code path from PolyScour to a scan, a
quarantine, or a change of security configuration. PolyShield being installed
must never silently grant PolyScour new authority.
"""
from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path

_HOST = "127.0.0.1"
_PORT = 52614
_CONNECT_TIMEOUT = 0.4      # a closed port on Windows can burn the full timeout
_CMD_TIMEOUT = 3.0


def _token_path() -> Path:
    r"""Where PolyShield's service writes its IPC secret.

    ``%ProgramData%\PolyShield\state\service_token.txt``, derived from the
    environment rather than hard-coded to ``C:\``: a machine booting from another
    volume would otherwise be looked up on the wrong disk.
    """
    base = os.environ.get("PROGRAMDATA", "").strip()
    if not base:
        drive = os.environ.get("SystemDrive", "").strip()
        if not drive:
            return Path("ProgramData/PolyShield/state/service_token.txt")
        base = str(Path(drive + "\\") / "ProgramData")
    return Path(base) / "PolyShield" / "state" / "service_token.txt"


def _read_token() -> str:
    """Read on every call rather than cached at import.

    PolyShield writes this file when its service first starts, so a client that
    cached its absence would keep failing forever afterwards.
    """
    try:
        return _token_path().read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _send(cmd: str, timeout: float = _CMD_TIMEOUT) -> dict | None:
    """One command, one response. None for every failure, without distinction.

    Deliberately undistinguished: "not installed", "not running", "refused us"
    and "answered nonsense" all mean the same thing to PolyScour, which is
    that the optional tile does not render. Reporting them differently would
    invite a caller to treat one of them as a partial yes.
    """
    token = _read_token()
    if not token:
        return None
    payload = json.dumps({"cmd": cmd, "token": token}).encode() + b"\n"
    try:
        with socket.create_connection((_HOST, _PORT), timeout=_CONNECT_TIMEOUT) as s:
            s.sendall(payload)
            s.settimeout(timeout)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                return None
            reply = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    # Fail closed on shape. Something else listening on this port does not get
    # to be treated as a degraded PolyShield.
    return reply if isinstance(reply, dict) else None


#: Feed states PolyShield's own classification treats as needing attention.
#: Not PolyScour inventing a severity ordering from raw ages -- these are the
#: exact words ``intel_updater.get_staleness()`` already uses, just filtered.
_FEED_NEEDS_ATTENTION = {"stale", "error", "auth_required"}


@dataclass(frozen=True)
class Posture:
    """What the dashboard tile renders. Every field optional and honest."""
    available: bool
    realtime_protection: bool | None = None
    watcher_running: bool | None = None
    #: PolyShield's separate process-behaviour monitor. Distinct from the
    #: filesystem watcher: a machine can have one running without the other.
    process_monitor_running: bool | None = None
    #: The scheduled background updater thread, from STATUS. Whether an
    #: update is actively in flight right now is a separate, narrower fact
    #: (GET_INTEL_STATUS's own ``running_now``) this tile does not surface --
    #: "is it kept up to date" matters more here than "is it updating this
    #: instant".
    intel_updater_running: bool | None = None
    #: None means "PolyShield did not answer with a readable feed list", never
    #: "zero feeds" -- those are different facts. Zero is a real, sayable
    #: value (no feed enabled at all).
    intel_feeds_enabled: int | None = None
    intel_feeds_stale_or_error: int | None = None
    events_count: int | None = None
    uptime_seconds: int | None = None
    detail: str = ""


def is_available() -> bool:
    """Whether PolyShield's service is present, running and answering us."""
    reply = _send("PING")
    return bool(reply) and reply.get("ok") is True


def _feed_summary(intel: dict) -> tuple[int | None, int | None]:
    """(enabled feed count, of those needing attention) from GET_INTEL_STATUS.

    ``feeds`` is keyed by feed name; each entry carries ``enabled`` and
    PolyShield's own ``state``. Anything not shaped as expected -- absent,
    not a dict -- yields ``(None, None)``: unreadable, not "no feeds".
    """
    feeds = intel.get("feeds")
    if not isinstance(feeds, dict):
        return None, None
    enabled = [f for f in feeds.values()
              if isinstance(f, dict) and f.get("enabled")]
    needs_attention = sum(1 for f in enabled
                          if f.get("state") in _FEED_NEEDS_ATTENTION)
    return len(enabled), needs_attention


def security_posture() -> Posture:
    """The tile's content, or an unavailable marker.

    Never raises. An integration that can throw would be a way for an optional
    component to take the dashboard down with it.
    """
    reply = _send("STATUS")
    if not reply or reply.get("ok") is not True:
        return Posture(available=False, detail="PolyShield is not running.")

    intel = _send("GET_INTEL_STATUS") or {}
    feeds_enabled, feeds_needing_attention = _feed_summary(intel)
    watcher = _as_bool(reply.get("watcher_running"))

    return Posture(
        available=True,
        realtime_protection=watcher,
        watcher_running=watcher,
        process_monitor_running=_as_bool(reply.get("process_monitor_running")),
        intel_updater_running=_as_bool(reply.get("intel_updater_running")),
        intel_feeds_enabled=feeds_enabled,
        intel_feeds_stale_or_error=feeds_needing_attention,
        events_count=_as_int(reply.get("events_count")),
        uptime_seconds=_as_int(reply.get("uptime_seconds")),
        detail="PolyShield is running.",
    )


def _as_bool(value) -> bool | None:
    return value if isinstance(value, bool) else None


def _as_int(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
