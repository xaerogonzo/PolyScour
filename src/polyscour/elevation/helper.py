r"""The elevated half. Assumes whatever asked it is lying.

Runs as administrator, does exactly one operation, and exits. Specified in
``docs/THREAT_MODEL.md`` under "The elevated helper" before it was written; this
module is the implementation of that specification and should be read against it.

The one rule everything else follows from
-----------------------------------------

**Nothing the caller says is believed.** Not the path, not the rule id, not
that the GUI already checked. An unelevated process is easier to compromise
than an elevated one, so a helper that trusts its caller has moved the
attacker's target rather than raised the bar.

Concretely: the request arrives as a file the *unelevated* user can write, so
by construction it is attacker-controlled input. That is fine, and it is why
:func:`handle` re-runs the entire guard chain from :mod:`polyscour.safety` — in
this process, at full privilege, against the path as it exists at this instant.
The GUI's earlier check kept a bad request off the wire. This one is the
security boundary.

That is the same reasoning that already makes ``authorize()`` run twice inside
the unelevated app, taken one step further: different time, different process,
*different privilege level*, and only the last one matters.

What it will not do
-------------------

It does not loop, does not listen, does not stay resident, and does not accept
a second request. It takes a request path on the command line, answers it, and
exits — so it is a target only while it runs, rather than a standing one. There
is no code path here that runs a command, a script, or anything named by the
caller.
"""
from __future__ import annotations

import sys
import winreg
from pathlib import Path

from polyscour.elevation.protocol import (MalformedRequest, Operation, Request,
                                          Response)
from polyscour.safety.guard import Guard, GuardRefusal
from polyscour.safety.policy import Operation as PolicyOperation

#: The HKLM approval key. Named here rather than imported from
#: ``startup.manager`` because that module is about the *user's* hive; the
#: machine hive is a different privilege story and deserves its own constant
#: in the file that is allowed to write it.
_MACHINE_APPROVED = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")


def handle(request: Request) -> Response:
    """Perform one validated operation. Never raises.

    Every refusal names which link said no, so a user reading the result
    learns something they can act on rather than "access denied".
    """
    try:
        if request.operation is Operation.DELETE_APPROVED_PATH:
            return _delete_approved_path(request.params)
        if request.operation is Operation.SET_MACHINE_STARTUP_APPROVAL:
            return _set_machine_startup_approval(request.params)
    except Exception as exc:                      # pragma: no cover - belt
        # An unexpected failure at full privilege must not surface as a
        # traceback on stdout that a caller might parse as success.
        return Response(False, f"unhandled failure: {exc!r}", "helper")
    return Response(False, f"unhandled operation {request.operation}", "helper")


def _delete_approved_path(params: dict) -> Response:
    """Delete one path, having re-authorised it here.

    The rule id travels with the request so this process can look up what that
    rule is permitted to touch. It is *not* taken as evidence of anything: an
    unknown rule id is a refusal, and a known one only narrows what is allowed.
    """
    rule_id = params["rule_id"]
    target = Path(params["path"])

    guard = Guard()
    guard.begin()
    try:
        # The whole chain: policy lookup, permitted roots, component-wise
        # reparse inspection, containment, denylist, exclusions. Run here, at
        # privilege, against the path as it is now -- not as it was when the
        # GUI looked at it.
        canonical = guard.authorize(rule_id, target, PolicyOperation.DELETE)
    except GuardRefusal as exc:
        return Response(False, str(exc), "guard")

    try:
        if canonical.is_dir():
            # Directories are refused rather than walked. A recursive delete at
            # administrator privilege driven by a path from an untrusted caller
            # is the single most dangerous thing this helper could offer, and
            # nothing needs it: the executor sends individual files.
            return Response(False, "the helper does not delete directories",
                            "helper")
        canonical.unlink()
    except FileNotFoundError:
        # Already gone is the outcome the caller wanted. Reporting failure
        # would make a successful clean look broken.
        return Response(True, "already absent", data={"path": str(canonical)})
    except OSError as exc:
        return Response(False, f"could not delete: {exc}", "filesystem")

    return Response(True, "deleted", data={"path": str(canonical)})


def _set_machine_startup_approval(params: dict) -> Response:
    """Flip one HKLM StartupApproved byte.

    Refuses to *create* an entry: the value must already exist, because writing
    an approval record for a name with no matching ``Run`` value produces the
    orphan records that already litter real machines, and doing it at
    administrator privilege on a caller-supplied name would let a compromised
    GUI write arbitrary value names into a machine-wide key.
    """
    from polyscour.startup.manager import _approval_blob

    value_name = params["value_name"]
    enabled = params["enabled"]

    run_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, run_key) as key:
            winreg.QueryValueEx(key, value_name)
    except OSError:
        return Response(False,
                        f"{value_name!r} is not a machine-wide startup entry",
                        "policy")

    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, _MACHINE_APPROVED) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY,
                              _approval_blob(enabled))
    except OSError as exc:
        return Response(False, f"the registry refused the write: {exc}",
                        "registry")

    return Response(True, "enabled" if enabled else "disabled",
                    data={"value_name": value_name})


def main(argv: list[str] | None = None) -> int:
    """Read one request from a file, answer it beside that file, exit.

    The response is written to ``<request>.response`` rather than stdout: a
    process launched with ``ShellExecute("runas")`` has no inherited pipes, so
    stdout goes nowhere a caller can read.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: helper <request.json>", file=sys.stderr)
        return 2

    request_path = Path(args[0])
    response_path = request_path.with_suffix(request_path.suffix + ".response")

    try:
        text = request_path.read_text(encoding="utf-8")
    except OSError as exc:
        _write(response_path, Response(False, f"could not read request: {exc}",
                                       "helper"))
        return 1

    try:
        request = Request.from_json(text)
    except MalformedRequest as exc:
        _write(response_path, Response(False, str(exc), "protocol"))
        return 1

    response = handle(request)
    _write(response_path, response)
    return 0 if response.ok else 1


def _write(path: Path, response: Response) -> None:
    try:
        path.write_text(response.to_json(), encoding="utf-8")
    except OSError:                               # pragma: no cover - defensive
        pass          # the caller will treat a missing response as a failure


if __name__ == "__main__":                        # pragma: no cover
    raise SystemExit(main())
