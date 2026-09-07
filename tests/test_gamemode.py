r"""tests/test_gamemode.py — the refusals, and what survives a crash.

Two properties carry this feature and neither is visible from a happy path.

**The veto is structural, not just a list.** A denylist only refuses what
somebody thought of. The rule that refuses everything not owned by the current
user is what covers the processes nobody named, so it is tested as its own
property rather than through a sample of names.

**The ledger row exists before the freeze.** If PolyScour dies between the two,
the recoverable state must be "we may have frozen this" rather than "something
is frozen and nothing knows". A test that only checked the happy path would
pass against an implementation that suspended first and recorded second — so
the ordering is asserted directly.
"""
from __future__ import annotations

import pytest

from polyscour.gamemode import session as gm
from polyscour.gamemode.policy import Candidate, NEVER_SUSPEND, veto
from polyscour.ledger import Ledger


ME = "DESK\\alex"


def make(pid=4321, name="notepad.exe", user=ME, mem=100, created=1000.0):
    return Candidate(pid=pid, name=name, username=user,
                     memory_bytes=mem, create_time=created)


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    led.initialise()
    return led


# ── the veto ────────────────────────────────────────────────────────────────

def test_an_ordinary_process_of_mine_is_permitted():
    """The control. Without this, every refusal below could be a veto that
    simply refuses everything."""
    assert veto(make(), current_user=ME, protected_pids=frozenset()) is None


@pytest.mark.parametrize("name", ["csrss.exe", "lsass.exe", "winlogon.exe",
                                  "explorer.exe", "audiodg.exe", "svchost.exe",
                                  "MsMpEng.exe", "PolyShield.exe"])
def test_named_system_processes_are_refused(name):
    reason = veto(make(name=name), current_user=ME, protected_pids=frozenset())
    assert reason and "never be suspended" in reason


def test_the_denylist_is_matched_case_insensitively():
    """Process names arrive from the OS in whatever case it feels like."""
    assert veto(make(name="CSRSS.EXE"), current_user=ME,
                protected_pids=frozenset()) is not None


def test_a_process_owned_by_someone_else_is_refused_even_if_unnamed():
    """The structural rule, which is the one that covers what the list misses.

    `sshd.exe` is not on any denylist here and never will be; running as
    SYSTEM is what refuses it.
    """
    reason = veto(make(name="sshd.exe", user="NT AUTHORITY\\SYSTEM"),
                  current_user=ME, protected_pids=frozenset())
    assert reason and "not to you" in reason


def test_an_unreadable_owner_is_refused_rather_than_assumed_safe():
    """AccessDenied reading an owner is itself evidence it is not ours."""
    reason = veto(make(user=None), current_user=ME, protected_pids=frozenset())
    assert reason and "system" in reason


def test_not_knowing_who_we_are_refuses_everything():
    reason = veto(make(), current_user=None, protected_pids=frozenset())
    assert reason and "running as" in reason


def test_an_unreadable_name_is_refused():
    reason = veto(make(name=""), current_user=ME, protected_pids=frozenset())
    assert reason and "cannot be judged" in reason


@pytest.mark.parametrize("pid", [0, 4])
def test_kernel_pids_are_refused_by_number_not_by_name(pid):
    """Refusing by number means never depending on a name we may not read."""
    reason = veto(make(pid=pid, name="anything.exe"), current_user=ME,
                  protected_pids=frozenset())
    assert reason == "kernel process"


def test_polyscour_will_not_suspend_itself():
    reason = veto(make(pid=999), current_user=ME,
                  protected_pids=frozenset({999}))
    assert reason and "itself" in reason


def test_the_denylist_entries_are_all_lower_case():
    """They are compared against `.lower()`; an upper-case entry would be a
    rule that silently never fires."""
    assert all(n == n.lower() for n in NEVER_SUSPEND)


# ── the ordering that makes a crash survivable ──────────────────────────────

class _Recorder:
    """A ledger that records the ORDER of what happened to it."""

    def __init__(self):
        self.events: list[str] = []
        self.rows: dict[int, dict] = {}
        self._next = 1

    def record_suspension(self, session_id, pid, name, create_time):
        rid = self._next
        self._next += 1
        self.rows[rid] = dict(id=rid, session_id=session_id, pid=pid,
                              process_name=name, create_time=create_time,
                              resumed_at=None)
        self.events.append(f"record:{pid}")
        return rid

    def mark_resumed(self, row_id, note=""):
        self.rows[row_id]["resumed_at"] = "now"
        self.events.append(f"mark_resumed:{row_id}")

    def open_suspensions(self):
        return [r for r in self.rows.values() if r["resumed_at"] is None]


def test_the_ledger_row_is_written_before_the_process_is_frozen(monkeypatch):
    """The property the whole recovery model rests on."""
    rec = _Recorder()
    monkeypatch.setattr(gm, "suspend_pid",
                        lambda pid: rec.events.append(f"suspend:{pid}") or True)

    gm.GameSession(rec).suspend([make(pid=42)],
                                current_user=ME, protected_pids=frozenset())

    assert rec.events == ["record:42", "suspend:42"], (
        "a freeze recorded after the fact is a freeze nothing can recover")


def test_a_refused_process_is_never_recorded_and_never_frozen(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(gm, "suspend_pid",
                        lambda pid: rec.events.append(f"suspend:{pid}") or True)

    out = gm.GameSession(rec).suspend([make(name="lsass.exe")],
                                      current_user=ME,
                                      protected_pids=frozenset())

    assert rec.events == []
    assert out[0].suspended is False


def test_a_failed_suspend_closes_its_own_row(monkeypatch):
    """Otherwise the row claims a freeze that never happened, and the next
    launch reports resuming something it never suspended."""
    rec = _Recorder()
    monkeypatch.setattr(gm, "suspend_pid", lambda pid: False)

    out = gm.GameSession(rec).suspend([make(pid=7)], current_user=ME,
                                      protected_pids=frozenset())

    assert out[0].suspended is False
    assert rec.open_suspensions() == []


def test_the_veto_runs_again_at_suspend_time(monkeypatch):
    """The UI already filtered. Between building a list and acting on it a PID
    can be recycled onto something the policy refuses — the same reason the
    cleaner calls authorize() twice."""
    rec = _Recorder()
    monkeypatch.setattr(gm, "suspend_pid", lambda pid: True)

    # A candidate that looked fine when listed, but is now the shell.
    out = gm.GameSession(rec).suspend([make(name="explorer.exe")],
                                      current_user=ME,
                                      protected_pids=frozenset())
    assert out[0].suspended is False
    assert rec.events == []


def test_resume_all_closes_every_row_and_reports_the_stubborn(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(gm, "suspend_pid", lambda pid: True)
    sess = gm.GameSession(rec)
    # PIDs above the kernel range: 1 and 2 would be refused as kernel
    # processes, and the test would pass for the wrong reason.
    sess.suspend([make(pid=101, name="a.exe"), make(pid=102, name="b.exe")],
                 current_user=ME, protected_pids=frozenset())

    monkeypatch.setattr(gm, "resume_pid", lambda pid: pid != 102)
    stubborn = sess.resume_all()

    assert stubborn == ["b.exe"]
    assert rec.open_suspensions() == [], "a row left open would be retried forever"
    assert sess.held_count == 0
    assert sess.resume_all() == [], "resume_all must be safe to call twice"


# ── recovery after a crash ──────────────────────────────────────────────────

def test_recovery_resumes_what_a_dead_session_left_frozen(ledger, monkeypatch):
    ledger.record_suspension("dead-session", 1234, "game.exe", 500.0)

    monkeypatch.setattr(gm, "_identify", lambda pid, start: "same")
    resumed: list[int] = []
    monkeypatch.setattr(gm, "resume_pid",
                        lambda pid: resumed.append(pid) or True)

    report = gm.recover(ledger)

    assert resumed == [1234]
    assert report.resumed == ["game.exe"]
    assert ledger.open_suspensions() == []


def test_recovery_does_not_touch_a_recycled_pid(ledger, monkeypatch):
    """PID 1234 is somebody else now. Resuming it would be a no-op performed
    on a stranger, and a repair the ledger would falsely claim."""
    ledger.record_suspension("dead-session", 1234, "game.exe", 500.0)

    monkeypatch.setattr(gm, "_identify", lambda pid, start: "recycled")
    monkeypatch.setattr(gm, "resume_pid",
                        lambda pid: pytest.fail("resumed a recycled PID"))

    report = gm.recover(ledger)

    assert report.recycled == ["game.exe"]
    assert ledger.open_suspensions() == [], "the row must still be closed"


def test_recovery_closes_rows_for_processes_that_have_gone(ledger, monkeypatch):
    ledger.record_suspension("dead-session", 1234, "game.exe", 500.0)
    monkeypatch.setattr(gm, "_identify", lambda pid, start: "gone")

    report = gm.recover(ledger)

    assert report.vanished == ["game.exe"]
    assert ledger.open_suspensions() == []


def test_recovery_closes_the_row_even_when_the_resume_fails(ledger, monkeypatch):
    """An open row would make every future launch retry a process that may
    have been gone for weeks, and keep reporting work nobody needs done."""
    ledger.record_suspension("dead-session", 1234, "game.exe", 500.0)
    monkeypatch.setattr(gm, "_identify", lambda pid, start: "same")
    monkeypatch.setattr(gm, "resume_pid", lambda pid: False)

    report = gm.recover(ledger)

    assert report.failed == ["game.exe"]
    assert ledger.open_suspensions() == []


def test_recovery_on_a_clean_ledger_says_so(ledger):
    report = gm.recover(ledger)
    assert not report.anything_found
    assert report.summary() == "No processes were left suspended."


def test_recovery_reads_rows_from_previous_sessions_not_just_this_one(ledger,
                                                                     monkeypatch):
    """Rows left by a PolyScour that died are exactly the ones that matter."""
    ledger.record_suspension("session-a", 11, "one.exe", 1.0)
    ledger.record_suspension("session-b", 22, "two.exe", 2.0)
    monkeypatch.setattr(gm, "_identify", lambda pid, start: "same")
    monkeypatch.setattr(gm, "resume_pid", lambda pid: True)

    report = gm.recover(ledger)
    assert sorted(report.resumed) == ["one.exe", "two.exe"]


# ── enumeration fails closed ────────────────────────────────────────────────

def test_enumeration_reports_none_rather_than_an_empty_list(monkeypatch):
    """An empty list would tell the UI "nothing is running", which is never
    true — it would render a harmless-looking empty screen when enumeration is
    what actually broke."""
    import builtins
    real_import = builtins.__import__

    def no_psutil(name, *a, **kw):
        if name == "psutil":
            raise ImportError("no psutil")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_psutil)
    assert gm.enumerate_candidates() is None


def test_enumeration_finds_this_very_process():
    """A real call, so the shape of what psutil returns is actually exercised
    rather than assumed."""
    import os
    cands = gm.enumerate_candidates()
    if cands is None:
        pytest.skip("psutil unavailable")
    assert any(c.pid == os.getpid() for c in cands)
