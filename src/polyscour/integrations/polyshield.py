r"""Optional, read-only integration with PolyShield.

PolyScour is a complete application without PolyShield. If PolyShield happens
to be installed and running, one dashboard tile gains real security posture
instead of being absent. That is the entire relationship in 0.1.

Four questions, and no more
---------------------------

    is_available()      PING
    security_posture()  STATUS, GET_INTEL_STATUS
    path_status(path)   PATH_STATUS      (one path -> watched? flagged?)

Richer capabilities -- hash reputation, shared quarantine -- get added only
when a concrete, committed feature needs them. ``PATH_STATUS`` was the first,
and it was added on PolyShield's side (its PR #35) *before* any code here
asked for it, shaped by what this side needed: a read-only, string-only answer
of two booleans, with a malformed request refused rather than answered.

Three outcomes, kept apart
--------------------------

"Fail closed" meant two different things in earlier drafts of this design, so
they are named separately:

* **A reply of the wrong shape is rejected.** Something else listening on the
  port is not a degraded PolyShield (``_send``'s long-standing behaviour).
* **No reply at all is UNKNOWN** -- not installed, not running, no token.
* **UNKNOWN grants nothing and blocks nothing.** PolyScour carries on under its
  own guard chain exactly as it did before PolyShield existed. An optional
  integration that could stop the cleaner would no longer be optional.

``flagged: False`` is not "safe". PolyShield answers from a capped event log, so
it means "no recorded detection", and nothing here may word it as a clearance.
Only ``flagged: True`` ever changes what PolyScour does, and then only by
doing *less*.

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
import time
from dataclasses import dataclass
from pathlib import Path

_HOST = "127.0.0.1"
_PORT = 52614
_CONNECT_TIMEOUT = 0.4      # a closed port on Windows can burn the full timeout
_CMD_TIMEOUT = 3.0
#: Far above any real reply (STATUS is a few hundred bytes), far below a
#: problem. See ``_send``.
_MAX_REPLY = 64 * 1024


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


def _send(cmd: str, timeout: float = _CMD_TIMEOUT, **fields) -> dict | None:
    """One command, one response. None for every transport-level failure.

    Deliberately undistinguished: "not installed", "not running", "refused us"
    and "answered nonsense" all mean the same thing to PolyScour -- UNKNOWN --
    so reporting them differently would only invite a caller to treat one of
    them as a partial yes. (``PathAdvisor`` does use the difference between
    *no reply* and *an unusable reply*, but only to stop asking, never to
    change what an answer means.)

    ``fields`` are extra request keys. The token and command are set last so a
    caller cannot override them.

    The reply is bounded in size and in total time. Once a privileged process
    (the elevated helper) can ask, "whatever is listening on this port" can
    reach it, and a listener that never sends a newline, or drips one byte at a
    time, must cost a bounded wait rather than a hung helper or unbounded
    memory. A per-``recv`` timeout alone resets on every byte.
    """
    token = _read_token()
    if not token:
        return None
    payload = json.dumps({**fields, "cmd": cmd, "token": token}).encode() + b"\n"
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((_HOST, _PORT), timeout=_CONNECT_TIMEOUT) as s:
            s.sendall(payload)
            buf = b""
            while b"\n" not in buf:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                s.settimeout(remaining)
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > _MAX_REPLY:
                    return None
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


# ── PATH_STATUS ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PathStatus:
    """What PolyShield says about one path. ``None`` is UNKNOWN, never False.

    ``flagged=False`` is deliberately a different thing from ``flagged=None``
    and from "safe": it means PolyShield answered and has no recorded
    detection there, from an event log it caps. See the module docstring.
    """
    watched: bool | None = None
    flagged: bool | None = None


UNKNOWN_PATH = PathStatus()


def _ask_path(path: str) -> PathStatus | None:
    """One ``PATH_STATUS`` round trip.

    ``None`` means no reply at all (not installed, not running, no token,
    timed out). ``UNKNOWN_PATH`` means PolyShield *did* reply, but not with a
    usable answer -- ``ok: false`` (it refuses an empty, relative, NUL-bearing or
    oversized path rather than guessing) or two values that are not booleans.
    Both are UNKNOWN to the caller; the difference only tells
    :class:`PathAdvisor` whether it is worth asking again.
    """
    reply = _send("PATH_STATUS", path=path)
    if reply is None:
        return None
    watched, flagged = reply.get("watched"), reply.get("flagged")
    if (reply.get("ok") is True and isinstance(watched, bool)
            and isinstance(flagged, bool)):
        return PathStatus(watched=watched, flagged=flagged)
    return UNKNOWN_PATH


def path_status(path: Path | str) -> PathStatus:
    """Ask once. Never raises, never caches -- see :class:`PathAdvisor`."""
    reply = _ask_path(str(path))
    return UNKNOWN_PATH if reply is None else reply


class PathAdvisor:
    """Asks PolyShield about paths for the length of **one operation**.

    A scan walks tens of thousands of files and the guard looks at every one, so
    one socket round trip per file is not an option. Two things keep the number
    of questions small:

    * **A cache that lives exactly one operation.** ``Guard.begin()`` calls
      :meth:`begin` at the top of every scan and every execution, so an answer
      never outlives the operation it was asked in. That is what makes a plain
      path key enough: the one way a path-keyed cache goes stale -- a file at
      that path deleted and a different one created in its place -- cannot
      span a scan *and* the delete that follows it, because the delete asks
      afresh.
    * **A latch.** The first time PolyShield gives no reply at all, the rest of
      the operation does not ask again. Without it a machine with no PolyShield
      would pay a lookup per file for an answer that cannot change mid-scan.

    And :meth:`flagged_within` asks about *directories* before files, which is
    what keeps the question count proportional to the part of the tree that
    matters rather than to its size.
    """

    def __init__(self, ask=None, enabled=None) -> None:
        #: The person's switch (``polyshield_path_checks``), as a callable so
        #: it is read at the moment of each question and a change takes effect
        #: immediately. ``None`` means always on. When it says no, nothing is
        #: asked and the answer is UNKNOWN -- which, by design, blocks and
        #: clears nothing, so "off" is exactly "PolyShield is not installed".
        self._enabled = enabled
        #: Injected by tests; ``None`` resolves ``_ask_path`` at call time so
        #: patching the module attribute works too.
        self._ask = ask
        self._cache: dict[str, PathStatus] = {}
        self._down = False
        #: Questions actually put to PolyShield since the last ``begin()``.
        #: Public so a test can assert a scan stayed cheap.
        self.queries = 0

    def begin(self) -> None:
        self._cache.clear()
        self._down = False
        self.queries = 0

    def status(self, path: Path | str) -> PathStatus:
        key = os.path.normcase(str(path))
        if self._enabled is not None and not self._enabled():
            return UNKNOWN_PATH
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        if self._down:
            return UNKNOWN_PATH
        self.queries += 1
        reply = (self._ask or _ask_path)(str(path))
        if reply is None:
            self._down = True
            return UNKNOWN_PATH
        self._cache[key] = reply
        return reply

    def flagged_within(self, root: Path, target: Path) -> bool | None:
        """Whether ``target`` has a recorded detection, asking top-down.

        ``flagged`` means "a detection at this path *or beneath it*", so it is
        monotonic: a flagged file makes every directory above it flagged. That
        gives a sound shortcut -- ask about ``root`` first, and if PolyShield
        says no, nothing below it can be flagged, so one question answers the
        whole tree. Only along a chain of "yes" answers does the walk continue
        down towards ``target``.

        ``True``  every level said yes, including ``target`` itself.
        ``False`` some level said no (so ``target`` is not flagged).
        ``None``  UNKNOWN at the first level that could not be answered --
                  which the caller treats as "carry on".
        """
        try:
            relative = target.relative_to(root)
        except ValueError:
            chain = [target]
        else:
            chain = [root]
            walked = root
            for part in relative.parts:
                walked = walked / part
                chain.append(walked)

        for level in chain:
            flagged = self.status(level).flagged
            if flagged is None:
                return None
            if not flagged:
                return False
        return True


def describe_path(status: PathStatus, *, folder: bool) -> str:
    """The informational label Storage and Startup show, or "".

    Facts only, in PolyShield's own terms, and nothing that reads as advice:
    no "suspicious", no "remove", no colour. ``flagged=False`` and UNKNOWN both
    produce no label at all -- a screen must not say "PolyShield found nothing
    here" about something it only has a capped log for.
    """
    bits: list[str] = []
    if status.flagged:
        bits.append("PolyShield has a recorded detection "
                    + ("in or beneath this folder" if folder
                       else "for this file"))
    if status.watched:
        bits.append("PolyShield monitors this location")
    return "  ·  ".join(bits)
