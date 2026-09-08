r"""What the Startup Manager is *permitted* to change. This file is the authority.

The third policy in this codebase, and the same shape as the other two:
``safety/policy.py`` for paths, ``gamemode/policy.py`` for processes, this one
for startup entries. The selection proposes; reviewed code disposes.

The trap this feature is most likely to fall into
-------------------------------------------------

It is not deleting the wrong key. It is the reasoning that goes *"this hasn't
been used in months, so disable it"*. Startup impact is usually negligible, and
"unused" is not evidence that turning something off helps anyone. So this module
answers only **may this be changed**, never **should it be**. Nothing here
scores, ranks, or produces a recommended set, and the interface above it does
not pre-select.

Two different refusals, kept apart
----------------------------------

There are entries this module will **never** let anything change, and entries
it will change **only at administrator privilege**. Collapsing those into one
string was right while nothing could elevate, and became wrong the moment
something could.

    veto()                may this be changed at all?     absolute
    requires_elevation()  what would it take?             a cost, not a refusal

``HKLM`` Run values affect every account on the machine. They are listed --
hiding them would make the screen a misleading account of what starts up -- and
now they can be changed, through the narrow, named, server-validated operation
the earlier version of this docstring said the job wanted. It is
``SET_MACHINE_STARTUP_APPROVAL``, and it re-checks everything here for itself.

PolyScour's own entry and unnamed entries stay in ``veto()``, because neither
becomes acceptable at higher privilege. A product that can switch off its own
autorun has a way to make itself un-restorable by a user who then cannot find
it, and that is as true with administrator rights as without.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from polyscour.startup.manager import StartupItem

#: PolyScour's own startup entry, if it ever has one. Named rather than
#: detected: a product that can switch off its own autorun has a way to make
#: itself un-restorable by a user who then cannot find it.
_OWN_NAMES = frozenset({"polyscour"})


def is_own_entry(value_name: str) -> bool:
    """Whether this names PolyScour's own autorun.

    Public because the elevated helper re-applies it. The helper assumes the
    GUI lies, and "PolyScour will not switch itself off" is a rule that should
    not stop being true merely because the request arrived at administrator
    privilege. Same reasoning as calling ``authorize()`` twice.
    """
    return value_name.strip().lower() in _OWN_NAMES


def veto(item: StartupItem) -> str | None:
    """Why this entry may not be changed, or ``None`` if it may.

    Reports the most fundamental refusal first, so the reason shown is the one
    that would still apply if the others were resolved.
    """
    if is_own_entry(item.entry.value_name):
        return "PolyScour will not disable its own startup entry"

    if not item.entry.value_name:
        return "the entry has no name, so it cannot be addressed reliably"

    return None


def requires_elevation(item: StartupItem) -> str | None:
    """What it would cost to change this, or ``None`` if nothing.

    Deliberately not part of :func:`veto`. A cost is something a user can
    choose to pay; a refusal is not, and showing them as the same thing either
    hides an available action or offers an impossible one.

    The string is shown next to the switch rather than in place of it, because
    "affects every account on this machine" is a fact worth reading *before*
    flipping it, not merely an explanation for why it is greyed out.
    """
    if item.scope != "user":
        return ("machine-wide: affects every account, and needs "
                "administrator rights")
    return None


def changeable(items: list[StartupItem]) -> list[StartupItem]:
    """The subset whose switch may be flipped. Never raises.

    Says nothing about privilege — an entry needing administrator rights is
    still changeable, it just costs a prompt.
    """
    return [i for i in items if veto(i) is None]


def describe_target(item: StartupItem) -> str:
    """A factual line about what this entry launches. No verdict.

    Deliberately phrased as observation. "Its file is missing" is a fact;
    "safe to remove" would be a recommendation, and a missing target is
    frequently an installer that will put the file back.
    """
    from polyscour.startup.manager import TargetState

    if item.target is TargetState.PRESENT:
        return item.entry.target_path
    if item.target is TargetState.MISSING:
        return f"{item.entry.target_path} — not on disk"
    return f"{item.entry.raw_value} — could not work out what this launches"


def _own_executable_names() -> frozenset[str]:
    """Best-effort names for the running PolyScour, lower-cased.

    Unused by :func:`veto` today, which matches on the *entry name* instead --
    kept because an installed PolyScour will register its autorun under a name
    worth matching, and the reasoning belongs next to the rule it will serve.
    """
    names = set(_OWN_NAMES)
    try:
        names.add(Path(sys.executable).stem.lower())
        names.add(Path(sys.argv[0]).stem.lower())
    except (OSError, IndexError):    # pragma: no cover - defensive
        pass
    return frozenset(n for n in names if n)
