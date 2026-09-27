r"""What the uninstaller runs before it removes ``PolyScour.exe``.

Removes every Task Scheduler task a ``Schedule`` in ``schedules.json``
records owning, by that exact recorded path -- never a name-pattern sweep of
Task Scheduler's live list, which could catch a task someone else created
that merely happens to be named similarly. This is the same ownership
discipline ``scheduling/task.py`` states for every other removal: cleanup
acts on PolyScour's own record, not on what Task Scheduler's namespace
happens to contain.

Ordering matters and is the entire reason this is a separate step rather than
something the installer script tries to do itself: it must run **before**
the installer deletes ``PolyScour.exe``, or a task that survived would try to
launch a program that is no longer there on its next trigger.

Best-effort by design. An uninstall must not be blocked by a schedule that
fails to remove cleanly -- the installer's next step deletes the binary
regardless, and a task pointed at a now-missing executable simply fails
silently the next time Windows tries to fire it, which is a cosmetic problem,
not a safety one.
"""
from __future__ import annotations

import sys

from polyscour.scheduling import service, store


def remove_all() -> int:
    """Remove every recorded schedule's task and its record. Returns the
    count of schedules that failed to remove cleanly (0 means all clean, or
    there was nothing to remove)."""
    failures = 0
    for schedule in store.load_all():
        result = service.remove_schedule(schedule.id)
        if not result.ok:
            failures += 1
    return failures


def main(args: list[str]) -> int:
    remove_all()
    # Always 0: this runs from the uninstaller, and a nonzero exit here must
    # never be read as "uninstall failed" for something this cosmetic.
    return 0


if __name__ == "__main__":                                  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
