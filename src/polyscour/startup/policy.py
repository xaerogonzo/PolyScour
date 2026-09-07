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

Machine-wide entries are read, reported, and refused
----------------------------------------------------

``HKLM`` Run values affect every account on the machine, and writing that hive
needs administrator rights that 0.1 does not have. They are still listed --
hiding them would make the screen a misleading account of what starts up -- but
the switch is refused with a reason, rather than offered and then failing with
an access error the user has to interpret.

That refusal is a **policy** decision, not a capability one. When the elevated
helper arrives it will not simply lift this: raising privilege to change what
runs for every user on a machine is precisely the operation that wants a
narrow, named, server-validated API rather than a flag flipped here.
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


def veto(item: StartupItem) -> str | None:
    """Why this entry may not be changed, or ``None`` if it may.

    Reports the most fundamental refusal first, so the reason shown is the one
    that would still apply if the others were resolved.
    """
    if item.scope != "user":
        return ("machine-wide entries affect every account and need "
                "administrator rights, which PolyScour 0.1 does not use")

    if item.entry.value_name.strip().lower() in _OWN_NAMES:
        return "PolyScour will not disable its own startup entry"

    if not item.entry.value_name:
        return "the entry has no name, so it cannot be addressed reliably"

    return None


def changeable(items: list[StartupItem]) -> list[StartupItem]:
    """The subset whose switch may be flipped. Never raises."""
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
