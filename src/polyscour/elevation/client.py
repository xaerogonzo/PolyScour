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

It is also genuinely inconvenient, which is why :func:`is_elevation_available`
exists — a caller should be able to say *"3 items need administrator rights"*
once, up front, rather than surprising someone with three prompts in a row.
Batching them behind a single prompt is a real future request and needs its own
threat-model entry first: "one prompt, many deletes" is a different bargain
from "one prompt, one delete".
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

from polyscour.elevation.protocol import Operation, Request, Response

#: How long to wait for the helper. Generous: the clock starts before the UAC
#: prompt appears, and a person deciding whether to consent is not a hung
#: process. A timeout is still needed -- a user who walks away should not leave
#: a PolyScour thread blocked forever.
_TIMEOUT_S = 120.0
_POLL_S = 0.2


def is_elevation_available() -> bool:
    """Whether asking for elevation could work at all on this machine.

    Not "are we elevated" -- we deliberately are not. This answers whether the
    machinery exists, so a caller can say up front that something needs
    administrator rights instead of offering a button that cannot work.
    """
    return sys.platform == "win32"


def request(operation: Operation, **params) -> Response:
    """Run one operation elevated and return what the helper reported.

    Never raises. Every failure -- the user declining the prompt, the helper
    crashing, a timeout -- is a :class:`Response` with ``ok=False``, because
    they are indistinguishable to the caller and all mean the same thing: the
    privileged work did not verifiably happen.
    """
    if not is_elevation_available():
        return Response(False, "elevation is only available on Windows", "client")

    req = Request(operation=operation, params=params)

    tmp = Path(tempfile.mkdtemp(prefix="polyscour-elev-"))
    request_path = tmp / "request.json"
    response_path = request_path.with_suffix(".json.response")
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

    deadline = time.monotonic() + _TIMEOUT_S
    while time.monotonic() < deadline:
        if response_path.exists():
            try:
                return Response.from_json(
                    response_path.read_text(encoding="utf-8"))
            except OSError:
                pass          # still being written; try again
        time.sleep(_POLL_S)
    return Response(False, "the helper did not answer in time", "client")


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
