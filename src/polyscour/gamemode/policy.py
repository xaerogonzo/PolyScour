r"""What Game Mode is *permitted* to suspend. This file is the authority.

Same shape as ``polyscour.safety.policy``, for the same reason: the user's
selection is input, and input is untrusted. A list of ticked checkboxes arrives
from a UI, and a UI can be wrong -- a stale row, a PID recycled between the scan
and the click, a user who ticked ``lsass.exe`` because it was using memory. So
the selection proposes and this module disposes, in code, in the repository,
where a change to it is reviewed.

Freezing the wrong thing is not a small mistake
-----------------------------------------------

Suspending ``csrss.exe`` or ``winlogon.exe`` wedges the session; there is no
undo dialog for a machine that has stopped drawing. Suspending ``lsass.exe``
stops authentication. Suspending the running antivirus mid-write leaves a file
locked for as long as the freeze lasts. None of these announce themselves --
``NtSuspendProcess`` reports success and the machine simply stops working
properly, with nothing on screen saying PolyScour did it.

So the veto is a denylist **plus** structural rules, and the structural rules
are the ones that matter. A denylist alone only refuses what somebody thought
of; "must belong to me, in my session" refuses the entire category of
system-owned processes including the ones nobody has named yet.

Unknown is treated as refused
-----------------------------

If a process's name or owner cannot be read, that is not permission to proceed.
``scanner.condition_met`` already establishes this convention for the cleaner --
an unknown answer behaves like the dangerous one -- and the reasoning is
stronger here, because ``AccessDenied`` reading a process's owner is itself
usually evidence that it belongs to SYSTEM.

**Game Mode never proposes.** It shows what a process is using and lets a person
decide. Sorting a list by memory is a fact; pre-ticking the top of that list
would be a recommendation, and "using 2 GB" is not evidence that freezing
something is a good idea. Detection, diagnosis, recommendation and modification
stay four separate decisions, and this feature deliberately performs only two
of them.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


#: Reviewed refusals, lower-cased. Every entry is here because freezing it
#: breaks the machine in a way the user cannot easily connect back to PolyScour.
#:
#: This list is the *second* line of defence, not the first -- the structural
#: rules below refuse anything not owned by the current user, which already
#: covers most of these. They are named anyway because a process running as the
#: user is not automatically safe (``explorer.exe`` is the obvious one), and
#: because being explicit is what makes the refusal reviewable.
NEVER_SUSPEND: frozenset[str] = frozenset({
    # Session and kernel plumbing. Freezing any of these ends the session.
    "system", "registry", "idle", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "fontdrvhost.exe", "dwm.exe", "conhost.exe",
    # Service hosts and brokers. Generic containers -- freezing one stops an
    # unknowable set of services, which is exactly why they cannot be judged
    # individually.
    "svchost.exe", "runtimebroker.exe", "dllhost.exe", "wmiprvse.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe",
    # The shell. Recoverable, but the taskbar and desktop stop responding and
    # the user has no way to know why.
    "explorer.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "searchhost.exe", "searchindexer.exe", "textinputhost.exe",
    # Audio. A frozen audio graph takes sound out with it, which in a feature
    # aimed at gaming would be a memorable bug.
    "audiodg.exe",
    # Security. Freezing an antivirus mid-scan leaves files locked, and doing
    # it from a maintenance tool is indistinguishable from malware behaviour.
    "msmpeng.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
    "nissrv.exe", "mpdefendercoreservice.exe", "polyshield.exe",
    "polyshieldservice.exe",
    # Ourselves. Belt and braces -- the structural rule below catches this too.
    "polyscour.exe",
})


#: Distinct from ``None``, which is a real answer here: "we could not
#: establish who we are", and therefore a refusal. Without a separate sentinel
#: a caller cannot express that state, and passing None would silently mean
#: "go and detect it" instead.
_DETECT = object()


@dataclass(frozen=True)
class Candidate:
    """One running process, described in facts rather than judgements.

    ``memory_bytes`` is shown so a person can decide. It carries no opinion:
    nothing here ranks, scores, or recommends.
    """
    pid: int
    name: str
    username: str | None
    memory_bytes: int
    create_time: float

    @property
    def display_name(self) -> str:
        return self.name or f"pid {self.pid}"


class SuspensionRefused(Exception):
    """A target the policy will not permit, with the reason it refused."""


def veto(candidate: Candidate, *, current_user: "str | None" = _DETECT,
         protected_pids: "frozenset[int] | None" = None) -> str | None:
    r"""Why this process may not be suspended, or ``None`` if it may.

    Checks run cheapest first -- set membership before the psutil call that
    resolves the current user -- which also means a *named* refusal wins over
    the generic ownership one. That ordering is deliberate: told that
    ``MsMpEng.exe`` is "on the reviewed list of processes that must never be
    suspended", a user learns PolyScour protects it on purpose. Told it
    "belongs to NT AUTHORITY\SYSTEM", they learn only that this attempt
    failed. Both are true; the first is worth more.
    """
    protected = protected_pids if protected_pids is not None else _own_pids()

    if candidate.pid in protected:
        return "PolyScour will not suspend itself or the process that started it"

    if candidate.pid <= 4:
        # 0 is System Idle, 4 is System. Neither is openable for suspend anyway;
        # refusing by number means never relying on a name we may not be able
        # to read.
        return "kernel process"

    if not candidate.name:
        return "could not read the process name, so it cannot be judged"

    if candidate.name.lower() in NEVER_SUSPEND:
        return "on the reviewed list of processes that must never be suspended"

    me = _current_username() if current_user is _DETECT else current_user
    if candidate.username is None:
        return ("could not read the owner, which usually means it belongs to "
                "the system")
    if me is None:
        return "could not establish who PolyScour is running as"
    if candidate.username.lower() != me.lower():
        return f"belongs to {candidate.username}, not to you"

    return None


def permitted(candidates: list[Candidate], **kw) -> list[Candidate]:
    """The subset that may be suspended. Never raises on a refusal."""
    return [c for c in candidates if veto(c, **kw) is None]


def _own_pids() -> frozenset[int]:
    """This process and its parent.

    The parent matters: PolyScour launched from a terminal must not freeze the
    terminal it is reporting into, and launched from Explorer it must not
    freeze the shell -- though ``NEVER_SUSPEND`` catches that one too.
    """
    pids = {os.getpid()}
    try:
        pids.add(os.getppid())
    except (OSError, AttributeError):       # pragma: no cover - not on Windows
        pass
    return frozenset(pids)


def _current_username() -> str | None:
    """Who PolyScour is running as, or None if that cannot be established.

    None is a refusal upstream rather than a fallback: if we cannot say who we
    are, we cannot say that a process belongs to us.
    """
    try:
        import psutil
        return psutil.Process(os.getpid()).username()
    except Exception:
        return None
