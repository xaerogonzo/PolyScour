r"""Freezing processes, and being able to unfreeze them after a crash.

Game Mode suspends background processes while you play and resumes them
afterwards. The whole design problem is the second half: a suspended process
stays suspended after the thing that suspended it is gone. It does not exit, it
does not time out, and it presents to the user as an application that has hung
for no reason.

The order is the guarantee
--------------------------

Every suspension is written to the ledger **before** the process is frozen::

    record intent  ->  suspend  ->  (later) resume  ->  mark resumed

Same shape as the vault: the reversal exists before the destructive step. If
PolyScour dies between the record and the freeze, recovery resumes a process
that was never suspended, which is a documented no-op. If it dies between the
freeze and the record -- which this ordering makes impossible -- a frozen
process would exist that nothing knows how to release. One of those failure
modes is harmless and the other is not, so the order is not an implementation
detail.

What this does not survive
--------------------------

A supervisor narrows this and does not remove it. :mod:`polyscour.gamemode.supervisor`
is an unprivileged child, started at the first suspension, that waits on a
handle to this process and then runs :func:`recover` -- so the window becomes
"until PolyScour's process ends" rather than "until the user next opens
PolyScour, which may be never".

**A kill that takes both leaves things exactly as this paragraph describes
them.** That is T20, it is stated as a non-mitigation, and nothing here should
be written as though recovery were guaranteed.

PID reuse
---------

A PID is a short-lived name. Between a crash and the next launch, PID 1234 may
belong to something else entirely, so every record carries the process's
creation time and recovery checks it. Resuming a stranger would be a harmless
no-op in practice -- and a repair the ledger would then falsely claim to have
made, which is the part that matters.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from polybedrock.proc_control import resume_pid, suspend_pid

from polyscour.gamemode import supervisor
from polyscour.gamemode.policy import Candidate, veto


@dataclass(frozen=True)
class SuspendOutcome:
    """What happened to one target, in a shape the UI can render directly."""
    candidate: Candidate
    suspended: bool
    reason: str = ""


@dataclass(frozen=True)
class RecoveryReport:
    """What a fresh launch found still frozen, and what it did about it."""
    resumed: list[str] = field(default_factory=list)
    vanished: list[str] = field(default_factory=list)
    recycled: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def anything_found(self) -> bool:
        return bool(self.resumed or self.vanished or self.recycled or self.failed)

    def summary(self) -> str:
        if not self.anything_found:
            return "No processes were left suspended."
        bits = []
        if self.resumed:
            bits.append(f"resumed {len(self.resumed)}")
        if self.vanished:
            bits.append(f"{len(self.vanished)} had already exited")
        if self.recycled:
            bits.append(f"{len(self.recycled)} PIDs had been reused")
        if self.failed:
            bits.append(f"{len(self.failed)} could not be resumed")
        return "Game Mode recovery: " + ", ".join(bits) + "."


def enumerate_candidates() -> list[Candidate] | None:
    """Every running process, as facts. ``None`` if that cannot be established.

    ``None`` rather than an empty list, and the distinction is load-bearing:
    ``scanner.condition_met`` already established that an unknown answer must
    not read as a safe one. An empty list would tell the UI "nothing is
    running", which is never true and would present an empty, harmless-looking
    screen when enumeration is what actually broke.
    """
    try:
        import psutil
    except ImportError:
        return None

    out: list[Candidate] = []
    try:
        procs = psutil.process_iter(["pid", "name", "username", "create_time"])
    except Exception:
        return None

    for proc in procs:
        try:
            info = proc.info
            try:
                rss = proc.memory_info().rss
            except Exception:
                rss = 0
            out.append(Candidate(
                pid=int(info["pid"]),
                name=info.get("name") or "",
                username=info.get("username"),
                memory_bytes=int(rss),
                create_time=float(info.get("create_time") or 0.0),
            ))
        except Exception:
            continue          # a process that exited mid-walk is not an error
    return out


class GameSession:
    """One Game Mode session: what it froze, and how to let it go again.

    Holds no lock for the duration. The mutation lock exists to serialise
    *changes to the vault and ledger*, and a Game Mode session lasts as long as
    someone is playing -- holding it across that would block every other
    PolyScour operation for hours. Each ledger write takes it briefly instead.
    """

    def __init__(self, ledger, *, session_id: str | None = None) -> None:
        self._ledger = ledger
        self.session_id = session_id or uuid.uuid4().hex
        #: row id -> (pid, name)
        self._held: dict[int, tuple[int, str]] = {}
        #: Whether a recovery supervisor is watching this process. Recorded
        #: rather than assumed, so the interface can say "a supervisor is
        #: running" only when one is -- a claim about recovery that is not
        #: checked is the kind of reassurance this product refuses to invent.
        self.supervised = False

    @property
    def held_count(self) -> int:
        return len(self._held)

    def suspend(self, candidates: list[Candidate], **veto_kw) -> list[SuspendOutcome]:
        """Freeze what policy permits. Refusals are reported, never raised.

        The veto runs here even though the UI already filtered -- the same
        reason ``authorize()`` is called twice in the cleaner. Between building
        a list and acting on it, a PID can be recycled onto something the
        policy would refuse, and the second check is what makes that race lose.
        """
        results: list[SuspendOutcome] = []
        for cand in candidates:
            refusal = veto(cand, **veto_kw)
            if refusal:
                results.append(SuspendOutcome(cand, False, refusal))
                continue

            row_id = self._ledger.record_suspension(
                self.session_id, cand.pid, cand.name, cand.create_time)

            if suspend_pid(cand.pid):
                self._held[row_id] = (cand.pid, cand.name)
                results.append(SuspendOutcome(cand, True))
                # After the first real suspension, and not before: there is
                # nothing to recover until something is frozen, and a watcher
                # started speculatively is a process running for no reason.
                # Never fatal -- without it, recovery still happens at the
                # next launch, which is where it happened before.
                if not self.supervised:
                    self.supervised = supervisor.ensure_running()
            else:
                # The record already exists; close it rather than leaving a row
                # claiming a freeze that never happened.
                self._ledger.mark_resumed(row_id, "suspend failed")
                results.append(SuspendOutcome(
                    cand, False, "the process refused to suspend"))
        return results

    def resume_all(self) -> list[str]:
        """Release everything this session froze. Safe to call twice.

        Returns the names it could not resume, which the caller should show:
        silently leaving a process frozen is the one outcome this feature must
        never produce quietly.
        """
        stubborn: list[str] = []
        for row_id, (pid, name) in list(self._held.items()):
            if resume_pid(pid):
                self._ledger.mark_resumed(row_id)
            else:
                self._ledger.mark_resumed(row_id, "resume failed")
                stubborn.append(name or f"pid {pid}")
            del self._held[row_id]
        return stubborn


def recover(ledger) -> RecoveryReport:
    """Resume anything a previous run left frozen. Call once, at startup.

    Every open row is closed, whatever the outcome. A row that stays open
    forever would make the next launch retry a process that has been gone for
    weeks, and the report would keep describing work nobody needs done.
    """
    report = RecoveryReport()
    for row in ledger.open_suspensions():
        pid = int(row["pid"])
        name = row["process_name"] or f"pid {pid}"
        recorded_start = float(row["create_time"])

        state = _identify(pid, recorded_start)
        if state == "gone":
            ledger.mark_resumed(row["id"], "process had already exited")
            report.vanished.append(name)
        elif state == "recycled":
            ledger.mark_resumed(row["id"], "PID belonged to another process")
            report.recycled.append(name)
        elif resume_pid(pid):
            ledger.mark_resumed(row["id"], "resumed at startup")
            report.resumed.append(name)
        else:
            ledger.mark_resumed(row["id"], "could not be resumed at startup")
            report.failed.append(name)
    return report


def _identify(pid: int, recorded_start: float) -> str:
    """'same', 'recycled' or 'gone' — is this still the process we froze?

    Without psutil the honest answer is "assume it is the same one". Resuming a
    process that was not suspended is a no-op, so the cost of being wrong here
    is nil, whereas skipping the resume would leave something frozen.
    """
    try:
        import psutil
    except ImportError:
        return "same"
    try:
        proc = psutil.Process(pid)
        # A second of tolerance: create_time is a float from the OS and is not
        # guaranteed to round-trip through SQLite bit-for-bit.
        return "same" if abs(proc.create_time() - recorded_start) < 1.0 else "recycled"
    except psutil.NoSuchProcess:
        return "gone"
    except Exception:
        return "same"
