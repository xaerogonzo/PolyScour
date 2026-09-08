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

import os
import sys
import time
import winreg
from datetime import datetime, timedelta, timezone
from pathlib import Path

from polyscour.elevation.protocol import (MalformedRequest, Operation, Request,
                                          Response)
from polyscour.contracts import SkipReason, classify_os_error
from polyscour.safety.guard import Guard, GuardRefusal
from polyscour.safety.policy import Operation as PolicyOperation
from polyscour.safety.policy import PolicyViolation, entry_for, permitted_roots

#: The HKLM approval key. Named here rather than imported from
#: ``startup.manager`` because that module is about the *user's* hive; the
#: machine hive is a different privilege story and deserves its own constant
#: in the file that is allowed to write it.
_MACHINE_APPROVED = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")

#: How many individually-named skips a response carries before it starts
#: summarising. A response is read by a human through the UI, and a rule that
#: refuses two hundred thousand files does not become clearer by listing them.
#: The counts stay exact either way — only the naming is capped.
_MAX_NAMED_SKIPS = 500

#: Seconds between progress heartbeats. The client's timeout is a
#: *silence* timeout, so this only has to be comfortably shorter than it.
_BEAT_S = 2.0


class _Control:
    """The cancel sentinel and the progress heartbeat, as sibling files.

    A batched delete can run for longer than any sensible fixed timeout, and
    the failure that produces is the dangerous one: the GUI concludes the
    helper is dead and moves on while an elevated process is still deleting.
    So the helper says "still here, N done" as it goes, and the client's
    deadline resets on that rather than on the total duration.

    Files rather than a pipe or an event, for the same reason the response is a
    file: a process launched with ``ShellExecute("runas")`` inherits no handles
    from its caller. Both are advisory — a missing heartbeat costs a spurious
    timeout, and a cancel that never arrives costs a completed operation.
    """

    def __init__(self, request_path: Path | None = None) -> None:
        self._cancel = (request_path.with_name("cancel")
                        if request_path is not None else None)
        self._progress = (request_path.with_name("progress")
                          if request_path is not None else None)
        self._last = 0.0

    def cancelled(self) -> bool:
        if self._cancel is None:
            return False
        try:
            return self._cancel.exists()
        except OSError:          # pragma: no cover - defensive
            return False

    def beat(self, done: int) -> None:
        """Report progress, at most every :data:`_BEAT_S`.

        Failures are swallowed. A helper that aborted a privileged operation
        halfway because it could not write a progress file would be trading a
        completed piece of work for a diagnostic.
        """
        if self._progress is None:
            return
        now = time.monotonic()
        if now - self._last < _BEAT_S:
            return
        self._last = now
        try:
            self._progress.write_text(str(done), encoding="utf-8")
        except OSError:          # pragma: no cover - defensive
            pass


def handle(request: Request, control: "_Control | None" = None) -> Response:
    """Perform one validated operation. Never raises.

    Every refusal names which link said no, so a user reading the result
    learns something they can act on rather than "access denied".

    ``control`` is optional so a caller — a test, most often — can run an
    operation without the sibling files. Absent, nothing is cancellable and
    nothing reports progress; neither is a security property.
    """
    control = control or _Control()
    try:
        if request.operation is Operation.DELETE_APPROVED_PATH:
            return _delete_approved_path(request.params)
        if request.operation is Operation.DELETE_APPROVED_PATHS_FOR_RULE:
            return _delete_approved_paths_for_rule(request.params, control)
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


def _walk(root: Path, max_depth: int):
    """Depth-limited file walk that never follows a directory link.

    Deliberately a local eight lines rather than an import from
    ``cleaning.scanner``. Everything this module does runs as administrator, so
    its import graph is part of what a reviewer has to read; pulling in the
    scanner would bring rules, threading and progress callbacks into an
    elevated process to save writing ``os.walk``.

    ``followlinks=False`` is the default and is relied on: the guard would
    refuse anything reached through a junction anyway, but declining to descend
    means a planted link cannot make an elevated walk take an hour.
    """
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        if len(here.parts) - root_depth >= max_depth:
            dirnames.clear()
        for name in filenames:
            yield here / name


def _delete_approved_paths_for_rule(params: dict, control: _Control) -> Response:
    r"""Delete what one rule is permitted to delete. One consent, many files.

    Exists because per-file elevation makes ``windows-temp`` several hundred
    UAC prompts, and a prompt nobody can realistically read is a habit rather
    than consent — which T18 already says nothing here can repair.

    Why this is *narrower* than :func:`_delete_approved_path`
    --------------------------------------------------------

    It takes no path. The caller names a rule; this function resolves that
    rule's permitted roots from :mod:`polyscour.safety.policy` — code, in this
    process — and enumerates them itself. So a compromised GUI's best available
    move is to name a rule that was already in the reviewed policy table and
    ask for exactly what an honest GUI would have asked for.

    The batch is not a transaction
    ------------------------------

    ``authorize()`` runs immediately before *each* ``unlink()``, never once for
    the group. This is the invariant most likely to look like a pointless
    repetition to a later reader, so: hoisting it would turn several hundred
    re-checks into a single check with a long window behind it, which is the
    TOCTOU protection of T3 spent for nothing measurable. See docs/adr/0004.

    Nothing here forces. A locked file is a fact about a live machine, not an
    obstacle, and least of all at administrator privilege.
    """
    rule_id = params["rule_id"]

    try:
        entry = entry_for(rule_id)
        roots = permitted_roots(rule_id)
    except PolicyViolation as exc:
        return Response(False, str(exc), "policy")

    if PolicyOperation.DELETE not in entry.operations:
        # A rule whose policy grants VAULT is not permitted to have things
        # deleted out from under it by the elevated path either.
        return Response(
            False,
            f"rule {rule_id!r} is not permitted to delete anything",
            "policy")

    # The caller's exclusions. Safe to accept from an untrusted source for one
    # reason and only that reason: an exclusion can never widen what is
    # deleted. A caller that lies about them causes fewer deletions.
    #
    # Necessary, not merely allowed: this process cannot read the invoking
    # user's settings, because under `runas` its %LOCALAPPDATA% need not be the
    # same profile. Without them a path the user protected would be honoured
    # unelevated and deleted here.
    guard = Guard(exclusions=[Path(e) for e in params["exclusions"]])
    guard.begin()

    # The age floor comes from the policy entry, never from the rule file. The
    # rule file is data the caller could have rewritten; `C:\Windows\Temp` is a
    # working directory for installers, and "delete everything, including what
    # was written a minute ago" is a materially different operation from the
    # one the user was shown.
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=entry.min_age_days)).timestamp()

    deleted = 0
    freed = 0
    candidates = 0
    named: list[dict] = []
    counts: dict[str, int] = {}
    stopped = ""

    def note(path: Path, reason: SkipReason, detail: str) -> None:
        counts[reason.value] = counts.get(reason.value, 0) + 1
        if len(named) < _MAX_NAMED_SKIPS:
            named.append({"path": str(path), "reason": reason.value,
                          "detail": detail})

    for root in roots:
        if stopped:
            break
        for path in _walk(root, entry.max_depth):
            if control.cancelled():
                stopped = "cancelled"
                break
            control.beat(deleted)

            try:
                st = path.stat()
            except OSError as exc:
                note(path, *classify_os_error(exc))
                continue

            if entry.min_age_days and st.st_mtime > cutoff:
                continue

            candidates += 1
            if candidates > entry.max_candidates:
                stopped = (f"stopped after {entry.max_candidates:,} files, the "
                           f"most this rule may consider")
                break

            try:
                canonical = guard.authorize(rule_id, path,
                                            PolicyOperation.DELETE)
            except GuardRefusal as exc:
                note(path, SkipReason.REFUSED_BY_GUARD, str(exc))
                continue

            try:
                if canonical.is_dir():
                    # The walk yields files, so a directory here means the
                    # target changed under us between the walk and now. Loud,
                    # not silent: it is exactly what a refusal is for.
                    note(canonical, SkipReason.ERROR,
                         "became a directory between the walk and the delete")
                    continue
                size = canonical.stat().st_size
                canonical.unlink()
            except OSError as exc:
                note(canonical, *classify_os_error(exc))
                continue

            deleted += 1
            freed += size
            if freed > entry.max_bytes:
                stopped = (f"stopped after {freed:,} bytes, above the "
                           f"{entry.max_bytes:,} this rule may free")
                break

    detail = f"deleted {deleted:,} of {candidates:,}"
    if stopped:
        detail = f"{detail}; {stopped}"
    return Response(True, detail, data={
        "rule_id": rule_id,
        "deleted": deleted,
        "bytes_freed": freed,
        "candidates": candidates,
        "skips": named,
        "skip_counts": counts,
        "stopped": stopped,
    })

def _set_machine_startup_approval(params: dict) -> Response:
    """Flip one HKLM StartupApproved byte, having re-checked everything.

    The validation order matters and is the specification, not an accident:

        resolve the mechanism  ->  absolute veto  ->  expected state  ->
        write  ->  read back  ->  verify

    Refuses to *create* an entry: the value must already exist, because writing
    an approval record for a name with no matching ``Run`` value produces the
    orphan records that already litter real machines, and doing it at
    administrator privilege on a caller-supplied name would let a compromised
    GUI write arbitrary value names into a machine-wide key.
    """
    from polyscour.startup.manager import _approval_blob
    from polyscour.startup.policy import is_own_entry

    value_name = params["value_name"]
    enabled = params["enabled"]
    expected_raw_value = params["expected_raw_value"]

    # 1. The mechanism must exist. This is what bounds the operation: a name
    #    with no machine-wide Run value is not a startup entry, whatever the
    #    caller called it.
    run_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, run_key) as key:
            current_raw, _ = winreg.QueryValueEx(key, value_name)
    except OSError:
        return Response(False,
                        f"{value_name!r} is not a machine-wide startup entry",
                        "policy")

    # 2. The absolute veto, re-applied here. The GUI already greys this row
    #    out; the GUI is not believed.
    if is_own_entry(value_name):
        return Response(False,
                        "PolyScour will not disable its own startup entry",
                        "policy")

    # 3. The entry must still launch what it launched when the caller looked.
    #    Between a change and its undo an installer can rewrite the Run value,
    #    and acting then would apply a decision nobody made, with PolyScour's
    #    name on it. This check lives here as well as in the GUI because only
    #    the copy running at privilege is a boundary.
    #
    #    Accepting the expected value from an untrusted caller is safe for the
    #    same reason exclusions are: it can only ever cause a refusal.
    if str(current_raw) != expected_raw_value:
        return Response(
            False,
            "what this entry launches has changed since PolyScour looked at "
            "it, so it has been left alone",
            "policy")

    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, _MACHINE_APPROVED) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY,
                              _approval_blob(enabled))
    except OSError as exc:
        return Response(False, f"the registry refused the write: {exc}",
                        "registry")

    # 4. Read it back rather than trusting the write. SetValueEx returning
    #    without error is not evidence that the value is what was asked for --
    #    virtualisation, policy and a racing writer can all intervene -- and
    #    "verify, do not assume" is what the rest of this product already does
    #    when it re-scans after a clean.
    observed = _read_machine_approval(value_name)
    if observed is None:
        return Response(False,
                        "the value could not be read back after writing, so "
                        "the change is not confirmed", "registry")
    if observed != enabled:
        return Response(False,
                        f"the registry reported success but the entry is still "
                        f"{'enabled' if observed else 'disabled'}", "registry")

    return Response(True, "enabled" if enabled else "disabled",
                    data={"value_name": value_name, "enabled": enabled})


def _read_machine_approval(value_name: str) -> bool | None:
    """The current approval state of one HKLM entry, or None if unreadable.

    Absent means enabled: Windows treats a missing approval record as "not
    disabled", and so must anything reading it back.
    """
    from polyscour.startup.manager import _DISABLED_BYTE

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _MACHINE_APPROVED) as key:
            blob, _ = winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        return True
    except OSError:
        return None
    if not isinstance(blob, bytes) or not blob:
        return None
    return blob[0] != _DISABLED_BYTE


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

    response = handle(request, _Control(request_path))
    _write(response_path, response)
    return 0 if response.ok else 1


def _write(path: Path, response: Response) -> None:
    """Publish the response atomically, or not at all.

    The client polls for this file, so a partially written one could be read as
    a complete answer. ``os.replace`` is atomic on Windows for a same-directory
    rename, which makes the file either absent or whole -- and a helper killed
    mid-write leaves the temporary behind rather than a truncated response that
    happens to parse.
    """
    tmp = path.with_name(path.name + ".partial")
    try:
        tmp.write_text(response.to_json(), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:                               # pragma: no cover - defensive
        pass          # the caller will treat a missing response as a failure


if __name__ == "__main__":                        # pragma: no cover
    raise SystemExit(main())
