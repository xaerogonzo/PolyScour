r"""The second process, and the smallest one that can exist.

Specified in ``docs/THREAT_MODEL.md`` under "The Game Mode supervisor", written
before this file existed. Read that first; this is the implementation of it.

What it is for
--------------

T12's residual: a hard kill with no subsequent launch leaves suspended
processes frozen until reboot. A frozen process does not exit, keeps its
memory, and presents to the user as an application that has hung for no reason.

So: an unprivileged child that waits for its parent to be gone and then runs
the same recovery the next launch would have run.

What it is not
--------------

**Not elevated.** Suspending and resuming the user's own processes needs no
administrator rights at all, so asking for them would buy a standing elevated
target to pay for a convenience.

**Not persistent.** It waits on one handle and exits. It does not install, does
not listen, does not poll for PolyScour coming back, and there is nothing to
uninstall.

**Not a second implementation of recovery.** It calls
:func:`polyscour.gamemode.session.recover`, the same function
``Services.__init__`` calls at startup. A second copy would be a second place
for the PID-reuse guard to be forgotten, and the guard is the only thing
standing between "resume what we froze" and "resume a stranger".

Its authority is the ledger
---------------------------

It replays what the session recorded. It never enumerates the system looking
for suspended processes -- that would touch things PolyScour never froze
(someone's debugger, an installer mid-operation, a program a user deliberately
paused) with no record that anything had been suspended in the first place.

Why a handle and not a pid
--------------------------

PIDs are recycled. Waiting on "the process with pid N" would, after a recycle,
mean waiting on a stranger -- and then either never cleaning up, or cleaning up
while PolyScour is still running and resuming processes the user is still
playing over.

A handle names a process *object*. Once opened it cannot be redirected by a
recycle, and ``GetProcessTimes`` on it answers about the object we hold rather
than about whatever currently owns that number. So: open, verify the creation
time, then wait. A mismatch means this was aimed at the wrong process, and the
correct response to that is to exit without doing anything.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading

#: Windows constants. Named rather than inlined because a wrong access mask
#: produces a handle that works until the day it does not.
_SYNCHRONIZE = 0x00100000
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_INFINITE = 0xFFFFFFFF
_WAIT_OBJECT_0 = 0x00000000
_WAIT_FAILED = 0xFFFFFFFF

#: 100-nanosecond intervals between 1601-01-01 (FILETIME) and the Unix epoch.
_EPOCH_DELTA_100NS = 116444736000000000

#: How far apart two readings of the same process's start time may be and still
#: be considered the same reading. psutil and GetProcessTimes derive from the
#: same FILETIME, so this is slack for float rounding rather than for drift --
#: if it ever has to be widened, something else is wrong.
_START_TIME_TOLERANCE_S = 1.0

#: Set once a supervisor has been started for this process. Game Mode can be
#: entered and left repeatedly in one run, and one watcher per parent is
#: enough -- they would all be waiting on the same handle for the same reason.
_started = threading.Lock()
_running: "subprocess.Popen | None" = None


# ── the parent side ─────────────────────────────────────────────────────────

def ensure_running() -> bool:
    """Start a supervisor for this process, unless one already is.

    Idempotent and never raises: a supervisor is an improvement on the failure
    path, not a precondition for Game Mode. If it cannot start, the feature
    still works and recovery still happens -- at the next launch, which is
    exactly where it happened before this file existed.

    Returns whether a supervisor is running, so a caller can say so honestly
    rather than implying a guarantee it does not have.
    """
    global _running

    if sys.platform != "win32":
        return False

    with _started:
        if _running is not None and _running.poll() is None:
            return True
        _running = _spawn()
        return _running is not None


def _spawn() -> "subprocess.Popen | None":
    try:
        import psutil

        from polyscour.entry import SUPERVISOR_FLAG, child_argv

        me = psutil.Process()
        argv = child_argv(SUPERVISOR_FLAG, str(me.pid), repr(me.create_time()))

        # DETACHED_PROCESS so it does not die with our console, and
        # CREATE_NO_WINDOW so nothing flashes up during a game. Both are
        # Windows-only flags; this function has already refused to run
        # anywhere else.
        creationflags = 0x00000008 | 0x08000000
        return subprocess.Popen(
            argv,
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True)
    except Exception:
        # Deliberately broad. Every failure here means the same thing to the
        # caller -- no supervisor, fall back to resume-at-next-launch -- and
        # none of them is worth taking Game Mode down for.
        return None


def stop() -> None:
    """Let go of the supervisor. For tests, and for an orderly shutdown.

    Terminating it is safe at any moment: it holds nothing, and its only job is
    to run a recovery that would be a no-op once the GUI has resumed
    everything itself.
    """
    global _running

    with _started:
        if _running is None:
            return
        try:
            if _running.poll() is None:
                _running.terminate()
        except Exception:
            pass
        _running = None


# ── the child side ──────────────────────────────────────────────────────────

def _open_parent(pid: int) -> "int | None":
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(
        _SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    return handle or None


def _start_time(handle: int) -> "float | None":
    """The creation time of the process this handle names, as a Unix timestamp.

    Asked of the *handle* rather than of the pid on purpose. A second lookup by
    pid would be answerable by whatever owns that number now, which is the
    exact confusion this check exists to detect.
    """
    import ctypes
    import ctypes.wintypes as wintypes

    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()

    ok = ctypes.windll.kernel32.GetProcessTimes(
        ctypes.c_void_p(handle),
        ctypes.byref(created), ctypes.byref(exited),
        ctypes.byref(kernel), ctypes.byref(user))
    if not ok:
        return None

    ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
    return (ticks - _EPOCH_DELTA_100NS) / 10_000_000.0


def _wait(handle: int) -> bool:
    """Block until the process is gone. False if the wait itself failed."""
    import ctypes

    result = ctypes.windll.kernel32.WaitForSingleObject(
        ctypes.c_void_p(handle), _INFINITE)
    return result == _WAIT_OBJECT_0


def _close(handle: int) -> None:
    import ctypes
    try:
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
    except Exception:          # pragma: no cover - defensive
        pass


def watch(pid: int, expected_start: float) -> int:
    """Wait for one process, then recover what it left frozen.

    Every refusal is silent and non-zero rather than raising: this runs with no
    console and nobody to read a traceback, and the outcomes a caller could act
    on are already recorded in the ledger by :func:`recover`.
    """
    handle = _open_parent(pid)
    if handle is None:
        # The parent is already gone. Recovery is still the right thing to do:
        # this is precisely the case the supervisor exists for, and the ledger
        # says what needs resuming regardless of who is left to ask.
        return _recover()

    try:
        observed = _start_time(handle)
        if observed is None:
            return 2
        if abs(observed - expected_start) > _START_TIME_TOLERANCE_S:
            # Aimed at the wrong process: this pid was recycled before the
            # handle was opened. Do nothing at all -- resuming what some other
            # PolyScour's ledger describes is not this supervisor's business.
            return 3

        if not _wait(handle):
            return 4
    finally:
        _close(handle)

    return _recover()


def _recover() -> int:
    """Run the same recovery the next launch would have run.

    Imported here rather than at module scope so that a supervisor which exits
    early -- wrong process, failed wait -- never opens the ledger at all.
    """
    try:
        from polyscour import paths
        from polyscour.gamemode.session import recover
        from polyscour.ledger import Ledger

        ledger = Ledger(paths.ledger_path())
        ledger.initialise()
        recover(ledger)
    except Exception:
        return 5
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print(f"usage: {os.path.basename(sys.argv[0])} "
              f"--supervise-game-mode <pid> <start-time>", file=sys.stderr)
        return 2

    try:
        pid = int(args[0])
        expected_start = float(args[1])
    except ValueError:
        print("pid must be an integer and start-time a float", file=sys.stderr)
        return 2

    if pid <= 0:
        return 2

    return watch(pid, expected_start)
