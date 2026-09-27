r"""Windows Task Scheduler: the delivery mechanism for a scheduled clean.

Per-user, unelevated, and interactive-token-only (``/it``) -- the task runs
only while the person is logged on, never as a hidden background job, and
never requests its own elevation (``/rl LIMITED``). ``polyscour.exe
--scheduled-clean <schedule-id>`` is the only thing it is ever told to run;
the schedule id is the only argument, and the schedule file itself (never the
task) is what actually constrains what runs -- see ``scheduling/consent.py``.

Ownership, not name-matching
-----------------------------

Cleanup (disabling a schedule, uninstalling PolyScour) acts on the exact task
path a ``Schedule`` recorded when it was created (``scheduling/store.py``),
never a pattern match against Task Scheduler's live task list. A user can
have an unrelated task that happens to contain "PolyScour" in its name; only
the path PolyScour itself wrote down is ever touched.

``schtasks /query /xml`` is not used here
-------------------------------------------

Measured directly: piping ``schtasks /query /tn <name> /xml`` through
``subprocess`` can silently corrupt element text for a task whose command line
is long enough -- a real run produced ``<Command>"C:\Windows\System32\r\r\
otepad.exe"</Command>``, losing the backslash and the leading ``n`` of
``notepad.exe`` to an inserted ``CR CR LF``, reproducibly, writing to a real
file as well as a pipe. This is not whitespace noise to strip; the tool's own
XML text rendering drops bytes. Verification therefore goes through
``Get-ScheduledTask`` via PowerShell (``ConvertTo-Json``, structured output,
no text rendering to corrupt) using the shared ``polybedrock.ps_run`` runner,
and only creation and deletion -- whose success is a plain exit code, not
parsed text -- go through ``schtasks.exe`` directly. See
``docs/gotchas/windows-subprocess.md``.
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess

from polybedrock.ps_run import run_ps

_TASK_FOLDER = "PolyScour"
_TIMEOUT_S = 30


def _oem_encoding() -> str:
    """schtasks writes console (OEM) codepage text, not the ANSI codepage.

    Only used for an error message a person may read, so "replace" rather
    than raising is the right failure mode either way.
    """
    try:
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except (AttributeError, OSError):                      # pragma: no cover
        return "utf-8"


def _schtasks_exe() -> str:
    windows = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    return os.path.join(windows, "System32", "schtasks.exe")


def task_name(schedule_id: str) -> str:
    r"""The exact Task Scheduler path a schedule's task lives at.

    Stored on the ``Schedule`` itself as the ownership record (see the module
    docstring); this function is how both the creator and the record agree on
    the same string.
    """
    return rf"\{_TASK_FOLDER}\ScheduledClean-{schedule_id}"


def _task_path_and_name(schedule_id: str) -> tuple[str, str]:
    """(TaskPath, TaskName) the way `Get-ScheduledTask` wants them, split from
    the single path string schtasks uses for `/tn`."""
    return "\\" + _TASK_FOLDER + "\\", f"ScheduledClean-{schedule_id}"


def _run_schtasks(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_schtasks_exe(), *args], capture_output=True, shell=False,
        timeout=_TIMEOUT_S,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)


def _quote_if_needed(token: str) -> str:
    return f'"{token}"' if " " in token else token


def _schedule_flags(trigger) -> list[str]:
    from polyscour.scheduling.consent import Frequency
    if trigger.frequency is Frequency.DAILY:
        return ["/sc", "DAILY", "/st", trigger.time]
    return ["/sc", "WEEKLY", "/d", trigger.day_of_week, "/st", trigger.time]


def create(schedule_id: str, trigger) -> tuple[bool, str]:
    """Create the task. ``/rl LIMITED`` (never elevated) and ``/it``
    (logged-on users only) are not optional flags -- they are the two
    properties this feature promises and cannot be created without.
    """
    from polyscour import entry

    argv = entry.child_argv(entry.SCHEDULED_CLEAN_FLAG, schedule_id)
    command_line = " ".join(_quote_if_needed(a) for a in argv)

    args = ["/create", "/tn", task_name(schedule_id), "/tr", command_line,
           "/rl", "LIMITED", "/it", "/f", *_schedule_flags(trigger)]
    try:
        result = _run_schtasks(args)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if result.returncode != 0:
        return False, result.stderr.decode(_oem_encoding(), "replace").strip()[:300]
    return True, ""


def remove(schedule_id: str) -> tuple[bool, str]:
    """Delete the task. A task that is already gone is success, not failure --
    the goal is "this schedule owns no task", which is already true."""
    try:
        result = _run_schtasks(["/delete", "/tn", task_name(schedule_id), "/f"])
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if result.returncode != 0:
        stderr = result.stderr.decode(_oem_encoding(), "replace")
        if "cannot find" in stderr.lower():
            return True, ""
        return False, stderr.strip()[:300]
    return True, ""


def set_enabled(schedule_id: str, enabled: bool) -> tuple[bool, str]:
    """Enable or disable the task itself, not only PolyScour's own record.

    Best-effort: the runner also checks the stored ``Schedule.enabled`` flag
    before doing anything, so a failure here does not by itself let a
    disabled schedule run.
    """
    flag = "/enable" if enabled else "/disable"
    try:
        result = _run_schtasks(["/change", "/tn", task_name(schedule_id), flag])
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if result.returncode != 0:
        return False, result.stderr.decode(_oem_encoding(), "replace").strip()[:300]
    return True, ""


def verify(schedule_id: str) -> tuple[bool, str]:
    """Confirm the live Task Scheduler task still runs exactly what PolyScour
    created it to run, before a scheduled run acts on anything.

    Not a privilege boundary -- the task is unelevated either way -- but an
    integrity check: a task altered outside PolyScour is treated as untrusted
    rather than assumed to still be what PolyScour created.
    """
    from polyscour import entry, paths

    task_path, bare_name = _task_path_and_name(schedule_id)
    escaped_path = task_path.replace("'", "''")
    escaped_name = bare_name.replace("'", "''")
    script = f"""
try {{
    $t = Get-ScheduledTask -TaskPath '{escaped_path}' -TaskName '{escaped_name}' -ErrorAction Stop
    $a = $t.Actions[0]
    [PSCustomObject]@{{
        found = $true
        execute = $a.Execute
        arguments = $a.Arguments
        runLevel = $t.Principal.RunLevel.ToString()
        logonType = $t.Principal.LogonType.ToString()
    }} | ConvertTo-Json -Compress
}} catch {{
    [PSCustomObject]@{{ found = $false }} | ConvertTo-Json -Compress
}}
"""
    ok, output = run_ps(script, timeout=_TIMEOUT_S)
    if not ok or not output:
        return False, "could not read the scheduled task's definition"

    try:
        data = json.loads(output)
    except ValueError:
        return False, "the scheduled task's definition could not be parsed"

    if not data.get("found"):
        return False, "the scheduled task could not be found"

    expected_exe = str(paths.running_executable())
    actual_exe = str(data.get("execute") or "").strip('"')
    if os.path.normcase(actual_exe) != os.path.normcase(expected_exe):
        return False, ("the scheduled task points at a different program "
                       "than PolyScour installed")

    arguments = str(data.get("arguments") or "")
    if entry.SCHEDULED_CLEAN_FLAG not in arguments or schedule_id not in arguments:
        return False, "the scheduled task's arguments do not match this schedule"

    if str(data.get("runLevel") or "") != "Limited":
        return False, "the scheduled task is no longer set to run unelevated"

    if str(data.get("logonType") or "") != "Interactive":
        return False, "the scheduled task is no longer restricted to logged-on use"

    return True, ""
