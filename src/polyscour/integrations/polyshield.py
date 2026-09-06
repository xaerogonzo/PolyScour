r"""Optional, read-only integration with PolyShield.

PolyScour is a complete application without PolyShield. If PolyShield happens
to be installed and running, one dashboard tile gains real security posture
instead of being absent. That is the entire relationship in 0.1.

Three questions, and no more
----------------------------

    is_available()      PING
    security_posture()  STATUS
    intel_freshness()   GET_INTEL_STATUS

Richer capabilities -- ``SCAN_PATH``, hash reputation, shared quarantine -- get
added only when a concrete, committed feature needs them. ``SCAN_PATH`` does not
exist on PolyShield's service today, and inventing it now would mean building an
IPC API before anything consumes it.

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


@dataclass(frozen=True)
class Posture:
    """What the dashboard tile renders. Every field optional and honest."""
    available: bool
    realtime_protection: bool | None = None
    watcher_running: bool | None = None
    intel_age_days: int | None = None
    detail: str = ""


def is_available() -> bool:
    """Whether PolyShield's service is present, running and answering us."""
    reply = _send("PING")
    return bool(reply) and reply.get("ok") is True


def security_posture() -> Posture:
    """The tile's content, or an unavailable marker.

    Never raises. An integration that can throw would be a way for an optional
    component to take the dashboard down with it.
    """
    reply = _send("STATUS")
    if not reply or reply.get("ok") is not True:
        return Posture(available=False, detail="PolyShield is not running.")

    intel = _send("GET_INTEL_STATUS") or {}

    return Posture(
        available=True,
        realtime_protection=_as_bool(reply.get("watcher_running")),
        watcher_running=_as_bool(reply.get("watcher_running")),
        intel_age_days=_as_int(intel.get("age_days")),
        detail="PolyShield is running.",
    )


def intel_freshness() -> int | None:
    """Age in days of PolyShield's threat intelligence, if it will tell us."""
    reply = _send("GET_INTEL_STATUS")
    return _as_int(reply.get("age_days")) if reply else None


def _as_bool(value) -> bool | None:
    return value if isinstance(value, bool) else None


def _as_int(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
