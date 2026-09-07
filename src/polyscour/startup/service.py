r"""Changing a startup entry: the veto, the record, and the write.

Kept apart from ``manager`` (which knows the registry) and ``policy`` (which
knows what is allowed) because it is the only place that does all three, and
because ``policy`` imports ``manager`` -- putting the orchestration in either
would make the pair circular.

The order, and why it is this way round
---------------------------------------

    veto  ->  record  ->  write

The record goes in **before** the registry write, for the same reason a vault
object exists before a delete and a suspension is logged before the freeze. If
PolyScour dies between the record and the write, History shows a change that
did not happen -- visible, checkable, and correctable by looking. Dying between
a write and a record would leave the machine altered with nothing to say so,
which is the failure this product exists not to have.

What "undo" has to check
------------------------

Flipping the switch back is not enough. Between disabling an entry and undoing
it, an installer may have rewritten the ``Run`` value to launch something else.
Re-enabling then restores a decision the user never made, using PolyScour's
name. So the recorded ``raw_value`` is compared against what is there now, and
a mismatch is reported rather than silently overwritten.
"""
from __future__ import annotations

from dataclasses import dataclass

from polyscour.startup.manager import StartupItem, list_items, set_enabled
from polyscour.startup.policy import veto


@dataclass(frozen=True)
class ChangeResult:
    """What happened to one entry, in a shape the UI renders directly."""
    item: StartupItem
    changed: bool
    reason: str = ""
    row_id: int | None = None


@dataclass(frozen=True)
class UndoResult:
    identity: str
    name: str
    undone: bool
    reason: str = ""


def apply_change(item: StartupItem, enabled: bool, ledger) -> ChangeResult:
    """Set one entry's switch, having checked that we may.

    The veto runs here even though the interface already greyed the row out.
    The list a user is looking at was built at some earlier moment, and the
    registry is shared: an entry can have moved hive, been renamed, or vanished
    since. Same reasoning as calling ``authorize()`` twice.
    """
    refusal = veto(item)
    if refusal:
        return ChangeResult(item, False, refusal)

    if item.enabled == enabled:
        return ChangeResult(item, False, "already in that state")

    row_id = ledger.record_startup_change(
        item.identity, item.name, item.entry.raw_value,
        was_enabled=item.enabled, now_enabled=enabled)

    try:
        set_enabled(item, enabled)
    except OSError as exc:
        # The row exists and describes a change that did not happen. Close it
        # rather than leaving History asserting something false.
        ledger.mark_startup_reverted(row_id)
        return ChangeResult(item, False, f"the registry refused the write: {exc}")

    return ChangeResult(item, True, row_id=row_id)


def undo(row, ledger) -> UndoResult:
    """Put one recorded change back, if the entry still looks like itself.

    ``row`` is a ledger row from ``startup_changes``.
    """
    identity = row["identity"]
    name = row["value_name"]

    current = _find(identity)
    if current is None:
        ledger.mark_startup_reverted(row["id"])
        return UndoResult(identity, name, False,
                          "the entry no longer exists, so there is nothing to "
                          "put back")

    if current.entry.raw_value != row["raw_value"]:
        # Deliberately not undone. Re-enabling a value that now launches
        # something else would restore a decision nobody made.
        return UndoResult(identity, name, False,
                          "what this entry launches has changed since "
                          "PolyScour touched it, so it has been left alone")

    try:
        set_enabled(current, bool(row["was_enabled"]))
    except OSError as exc:
        return UndoResult(identity, name, False,
                          f"the registry refused the write: {exc}")

    ledger.mark_startup_reverted(row["id"])
    return UndoResult(identity, name, True)


def _find(identity: str) -> StartupItem | None:
    for item in list_items():
        if item.identity == identity:
            return item
    return None
