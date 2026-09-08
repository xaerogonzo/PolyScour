r"""tests/test_supervisor.py — the second process, and what it refuses to do.

Specified in ``docs/THREAT_MODEL.md`` under "The Game Mode supervisor", written
before the code. These are that section turned into assertions.

The one that matters most is the last: a real supervisor, watching a real
parent, resuming a really-suspended process after that parent is really killed.
Everything above it is a refusal, and refusals are only worth anything if the
thing also works.
"""
from __future__ import annotations

import subprocess
import sys
import time

import pytest

from polyscour.gamemode import supervisor

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="the supervisor is Windows-only")

#: Long enough that it is still alive when the test looks, short enough that a
#: leaked one is gone before it matters.
_VICTIM = "import time; time.sleep(90)"


@pytest.fixture
def spawned():
    """Processes this test started, killed on the way out however it ends."""
    started: list[subprocess.Popen] = []

    def start(code: str) -> subprocess.Popen:
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            creationflags=0x08000000,          # CREATE_NO_WINDOW
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        started.append(proc)
        return proc

    yield start

    for proc in started:
        try:
            # Resume first: a suspended process cannot always be killed, and a
            # leaked frozen python is exactly the thing this feature exists to
            # prevent.
            from polybedrock.proc_control import resume_pid
            resume_pid(proc.pid)
            proc.kill()
            proc.wait(timeout=10)
        except Exception:
            pass


# ── the parent must be the process it was told about ────────────────────────

def test_a_mismatched_start_time_does_nothing_at_all(spawned, monkeypatch):
    """The PID-reuse guard, pointed at the parent.

    Waiting on "the process with pid N" would, after a recycle, mean waiting
    on a stranger — and then cleaning up either never, or while PolyScour is
    still running and resuming processes the user is still playing over.

    Doing nothing is the correct response to being aimed at the wrong process.
    """
    victim = spawned(_VICTIM)
    recovered = []
    monkeypatch.setattr(supervisor, "_recover",
                        lambda: recovered.append(True) or 0)

    code = supervisor.watch(victim.pid, expected_start=1.0)

    assert code == 3
    assert recovered == [], "it recovered against a process it had misidentified"


def test_the_matching_start_time_is_accepted(spawned, monkeypatch):
    """The control. Without it, the test above passes against a supervisor
    that refuses everything."""
    import psutil

    victim = spawned(_VICTIM)
    started = psutil.Process(victim.pid).create_time()

    recovered = []
    monkeypatch.setattr(supervisor, "_recover",
                        lambda: recovered.append(True) or 0)
    # Return immediately rather than blocking for the process lifetime; the
    # wait itself is exercised end-to-end at the bottom of this file.
    monkeypatch.setattr(supervisor, "_wait", lambda handle: True)

    assert supervisor.watch(victim.pid, expected_start=started) == 0
    assert recovered == [True]


def test_a_parent_that_is_already_gone_still_triggers_recovery(monkeypatch):
    """The case the supervisor exists for.

    If the parent died before the handle could be opened, that is not a reason
    to skip recovery — it is the exact situation recovery is for, and the
    ledger says what needs resuming regardless of who is left to ask.
    """
    recovered = []
    monkeypatch.setattr(supervisor, "_recover",
                        lambda: recovered.append(True) or 0)
    monkeypatch.setattr(supervisor, "_open_parent", lambda pid: None)

    assert supervisor.watch(999_999, expected_start=1.0) == 0
    assert recovered == [True]


# ── arguments ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("args", [
    [],
    ["123"],
    ["123", "1.0", "extra"],
    ["notapid", "1.0"],
    ["123", "notatime"],
    ["-1", "1.0"],
    ["0", "1.0"],
])
def test_bad_arguments_are_refused_without_recovering(args, monkeypatch):
    """Its two parameters can only narrow what it does. An argument that fails
    to describe a running process means exit without acting."""
    monkeypatch.setattr(supervisor, "_recover",
                        lambda: pytest.fail("recovered on a bad argument"))

    assert supervisor.main(args) == 2


# ── starting one ────────────────────────────────────────────────────────────

def test_ensure_running_is_idempotent(monkeypatch):
    """Game Mode can be entered and left repeatedly in one run, and one watcher
    per parent is enough — they would all wait on the same handle."""
    spawns = []

    class _Fake:
        def poll(self):
            return None

    monkeypatch.setattr(supervisor, "_running", None)
    monkeypatch.setattr(supervisor, "_spawn",
                        lambda: spawns.append(True) or _Fake())

    assert supervisor.ensure_running() is True
    assert supervisor.ensure_running() is True
    assert len(spawns) == 1


def test_a_supervisor_that_cannot_start_is_not_fatal(monkeypatch):
    """It is an improvement on the failure path, not a precondition.

    Without one, recovery still happens at the next launch — which is where it
    happened before this existed. Taking Game Mode down over it would trade a
    working feature for a better failure mode.
    """
    monkeypatch.setattr(supervisor, "_running", None)
    monkeypatch.setattr(supervisor, "_spawn", lambda: None)

    assert supervisor.ensure_running() is False


def test_the_session_reports_whether_it_is_supervised(monkeypatch, tmp_path):
    """A claim about recovery that is not checked is invented reassurance."""
    from polyscour.gamemode import session as gm
    from polyscour.gamemode.policy import Candidate
    from polyscour.ledger import Ledger

    ledger = Ledger(tmp_path / "l.db")
    ledger.initialise()
    monkeypatch.setattr(gm, "suspend_pid", lambda pid: True)
    monkeypatch.setattr(supervisor, "ensure_running", lambda: False)

    import getpass
    cand = Candidate(pid=4321, name="game.exe", username=getpass.getuser(),
                     memory_bytes=1, create_time=1.0)

    session = gm.GameSession(ledger)
    session.suspend([cand], current_user=getpass.getuser(),
                    protected_pids=frozenset())

    assert session.supervised is False, (
        "the session claimed supervision it does not have")


# ── the whole thing, for real ───────────────────────────────────────────────

@pytest.mark.allows_supervisor
def test_a_killed_parent_leaves_nothing_frozen(spawned, tmp_path, monkeypatch):
    r"""End to end: real child, real parent, real suspension, real kill.

    This is T12's residual being closed as far as it closes. Everything else in
    this file is a refusal; refusals are only worth something if the thing also
    does its job.

    Deliberately not mocked anywhere. The parts that have gone wrong in this
    project were all in the seams between processes — a flag Nuitka does not
    set, a path resolved one level too high — and a test that stubs the seam
    would have found none of them.
    """
    import psutil
    from polybedrock.proc_control import suspend_pid

    from polyscour.entry import SUPERVISOR_FLAG, child_argv
    from polyscour.ledger import Ledger

    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path / "data"))

    victim = spawned(_VICTIM)
    parent = spawned("import time; time.sleep(120)")
    parent_started = psutil.Process(parent.pid).create_time()

    ledger = Ledger(tmp_path / "data" / "history.sqlite")
    ledger.initialise()
    row = ledger.record_suspension(
        "supervised-session", victim.pid, "victim.py",
        psutil.Process(victim.pid).create_time())

    assert suspend_pid(victim.pid), "could not suspend the victim"
    assert psutil.Process(victim.pid).status() == psutil.STATUS_STOPPED

    watcher = subprocess.Popen(
        child_argv(SUPERVISOR_FLAG, str(parent.pid), repr(parent_started)),
        creationflags=0x08000000,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True)
    try:
        # It must still be waiting: nothing has happened to the parent yet, and
        # a supervisor that recovers early would resume processes mid-session.
        time.sleep(2.0)
        assert watcher.poll() is None, "the supervisor exited before its parent"
        assert psutil.Process(victim.pid).status() == psutil.STATUS_STOPPED, (
            "the victim was resumed while the parent was still alive")

        parent.kill()
        out, err = watcher.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        watcher.kill()
        pytest.fail("the supervisor did not exit after its parent was killed")

    assert watcher.returncode == 0, f"supervisor failed: {err}"

    assert psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED, (
        "the victim is still frozen; T12's residual is not narrowed at all")

    open_rows = [dict(r) for r in ledger.open_suspensions()]
    assert open_rows == [], "a row left open would be retried forever"
    closed = [dict(r) for r in ledger.all_suspensions()] \
        if hasattr(ledger, "all_suspensions") else []
    if closed:
        assert any(r["id"] == row for r in closed)
