r"""Asking for one elevated operation, and waiting for the answer.

The GUI launches the helper rather than connecting to something already
listening. That direction is a security property, not a convenience: there is
no port and no pipe for another process to claim first, so there is nothing to
impersonate. See ``docs/THREAT_MODEL.md`` T16.

One prompt per operation
------------------------

Each call is a separate ``ShellExecute("runas")`` and therefore a separate UAC
prompt. That is the bargain the threat model accepted: elevation is not
retained, there is no resident helper, and no "stay elevated" option.

What an *operation* covers is therefore the decision that matters, and it is
made in the protocol rather than here.
``DELETE_APPROVED_PATHS_FOR_RULE`` is one operation covering a whole rule —
because per-file elevation makes ``windows-temp`` several hundred prompts, and
a prompt nobody can read is a habit rather than consent. It earns that by being
*narrower* than the per-file form: the caller supplies no path at all. See
``THREAT_MODEL.md`` T19 and ``docs/adr/0004``.

:func:`is_elevation_available` exists so a caller can say *"this needs
administrator rights"* up front rather than surprising someone with a prompt.

Waiting for an answer
---------------------

The timeout is a **silence** timeout. A batched delete can legitimately run
longer than any fixed limit, and calling that a dead helper causes the one
genuinely dangerous failure available here: the GUI concluding the operation
failed, and re-scanning, while an elevated process is still deleting. So the
helper reports progress and the clock resets on it.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

from polyscour.elevation.protocol import Operation, Request, Response

#: How long to wait for the helper. Generous: the clock starts before the UAC
#: prompt appears, and a person deciding whether to consent is not a hung
#: process. A timeout is still needed -- a user who walks away should not leave
#: a PolyScour thread blocked forever.
_TIMEOUT_S = 120.0
_POLL_S = 0.2

#: How long to keep listening after asking the helper to stop. Short, because
#: it stops between items and the wait is only for the item in flight.
_GRACE_S = 10.0


def is_elevation_available() -> bool:
    """Whether asking for elevation could work at all on this machine.

    Not "are we elevated" -- we deliberately are not. This answers whether the
    machinery exists, so a caller can say up front that something needs
    administrator rights instead of offering a button that cannot work.
    """
    return sys.platform == "win32"


def request(operation: Operation, cancel: "threading.Event | None" = None,
            **params) -> Response:
    """Run one operation elevated and return what the helper reported.

    Never raises. Every failure — the user declining the prompt, the helper
    crashing, a timeout — is a :class:`Response` with ``ok=False``, because they
    are indistinguishable to the caller and all mean the same thing: the
    privileged work did not verifiably happen.

    ``cancel`` is the executor's existing stop event, if there is one. Asking
    the helper to stop is best effort by construction: it is a file the helper
    checks between items, so a helper already inside a syscall finishes it.
    """
    if not is_elevation_available():
        return Response(False, "elevation is only available on Windows", "client")

    req = Request(operation=operation, params=params)

    tmp = Path(tempfile.mkdtemp(prefix="polyscour-elev-"))
    try:
        return _run(req, tmp, cancel)
    finally:
        # Every exit path, including the ones that gave up. Without this the
        # directory accumulates one entry per elevated operation, forever,
        # which is the kind of leak nobody notices until it is thousands.
        shutil.rmtree(tmp, ignore_errors=True)


def _run(req: Request, tmp: Path, cancel: "threading.Event | None") -> Response:
    request_path = tmp / "request.json"
    response_path = request_path.with_suffix(".json.response")
    progress_path = tmp / "progress"
    cancel_path = tmp / "cancel"

    try:
        request_path.write_text(req.to_json(), encoding="utf-8")
    except OSError as exc:
        return Response(False, f"could not stage the request: {exc}", "client")

    try:
        started = _launch(request_path)
    except Exception as exc:
        return Response(False, f"could not start the helper: {exc}", "client")
    if not started:
        # The overwhelmingly common case: the user said no. Worth its own
        # message, because "failed" would suggest something went wrong.
        return Response(False, "administrator rights were not granted", "user")

    # A *silence* deadline, not a duration one. A batched delete over
    # C:\Windows\Temp can legitimately outlast any fixed timeout, and treating
    # that as a dead helper produces the one genuinely bad failure here: the
    # GUI reports failure and re-scans while an elevated process is still
    # deleting files. So the clock resets whenever the helper says it is alive.
    deadline = time.monotonic() + _TIMEOUT_S
    seen_progress = None
    asked_to_stop = False

    while time.monotonic() < deadline:
        answer = _read_response(response_path)
        if answer is not None:
            return answer

        if cancel is not None and cancel.is_set() and not asked_to_stop:
            asked_to_stop = True
            try:
                cancel_path.write_text("1", encoding="utf-8")
            except OSError:
                pass          # best effort; the helper simply finishes
            # Do not return yet. The helper stops between items and still
            # writes a response saying what it managed, and discarding that
            # would lose the record of privileged work that did happen.
            deadline = min(deadline, time.monotonic() + _GRACE_S)

        progress = _read_progress(progress_path)
        if progress is not None and progress != seen_progress:
            seen_progress = progress
            if not asked_to_stop:
                deadline = time.monotonic() + _TIMEOUT_S

        time.sleep(_POLL_S)

    # One last look: the helper may have answered inside the final interval.
    answer = _read_response(response_path)
    if answer is not None:
        return answer

    if asked_to_stop:
        return Response(False, "the helper was asked to stop and did not "
                               "answer in time", "client")
    return Response(False, "the helper did not answer in time", "client")


def _read_response(path: Path) -> "Response | None":
    """The response, or None if it is not there yet.

    The helper publishes atomically, so a file that exists is whole. This still
    tolerates a read failure rather than treating it as an answer: on Windows a
    file can be briefly unopenable for reasons that are not about its content.
    """
    try:
        return Response.from_json(path.read_text(encoding="utf-8"))
    except OSError:
        return None


def _read_progress(path: Path) -> "str | None":
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _launch(request_path: Path) -> bool:
    """ShellExecute the helper with ``runas``. False if the user declined.

    ``runas`` is what raises the UAC prompt. There is no way to do this with
    ``subprocess`` -- CreateProcess cannot elevate -- which is why this reaches
    for the shell API directly.
    """
    import ctypes

    executable, args = _helper_command(request_path)

    # SW_HIDE: the helper has no UI, and a console window flashing up during a
    # clean looks like something went wrong.
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, args, None, 0)

    # ShellExecuteW returns >32 on success. 5 is ERROR_ACCESS_DENIED, which is
    # what a declined UAC prompt looks like from here.
    return int(result) > 32


def _helper_command(request_path: Path) -> tuple[str, str]:
    """The executable and arguments that run the helper.

    Frozen and source builds differ, and getting this wrong is the trap
    PolyShield already documented: in a compiled build ``sys.executable`` names
    a python.exe beside the real binary that does not exist.
    """
    if getattr(sys, "frozen", False):
        return sys.executable, f'--elevated-helper "{request_path}"'
    return (sys.executable,
            f'-m polyscour.elevation.helper "{request_path}"')
