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
from polyscour.startup.policy import requires_elevation, veto


class ElevationRefused(Exception):
    """The elevated helper did not make the change, and said why."""


@dataclass(frozen=True)
class ChangeResult:
    """What happened to one entry, in a shape the UI renders directly."""
    item: StartupItem
    changed: bool
    reason: str = ""
    row_id: int | None = None
    #: Whether administrator rights were involved. Recorded rather than
    #: inferred from the hive: a machine-wide entry that failed before the
    #: prompt is a different event from one that was changed after it.
    elevated: bool = False


@dataclass(frozen=True)
class UndoResult:
    identity: str
    name: str
    undone: bool
    reason: str = ""
    elevated: bool = False


def _write(item: StartupItem, enabled: bool) -> bool:
    """Flip one switch, elevating only where the hive requires it.

    Returns whether administrator rights were used. Raises
    :class:`ElevationRefused` if they were needed and the change did not
    happen — including when the user simply declined, which is not a failure
    of anything and is reported in those words.

    What is sent is the entry's name and what it currently launches. Not a
    decision, not "the veto passed": the helper re-checks the machine-wide Run
    value exists, re-applies the absolute vetoes, compares what the entry
    launches against what we saw, writes, and reads back. See T13 and T19.
    """
    if requires_elevation(item) is None:
        set_enabled(item, enabled)
        return False

    from polyscour.elevation.client import request
    from polyscour.elevation.protocol import Operation

    response = request(Operation.SET_MACHINE_STARTUP_APPROVAL,
                       value_name=item.entry.value_name,
                       enabled=enabled,
                       expected_raw_value=item.entry.raw_value)
    if not response.ok:
        raise ElevationRefused(response.detail)
    return True


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
        elevated = _write(item, enabled)
    except ElevationRefused as exc:
        # The row exists and describes a change that did not happen. Close it
        # rather than leaving History asserting something false. Identical
        # handling to a registry error, deliberately: a declined prompt and a
        # refused write differ in cause, not in what is now true.
        ledger.mark_startup_reverted(row_id)
        return ChangeResult(item, False, str(exc))
    except OSError as exc:
        ledger.mark_startup_reverted(row_id)
        return ChangeResult(item, False, f"the registry refused the write: {exc}")

    return ChangeResult(item, True, row_id=row_id, elevated=elevated)


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
        #
        # Checked here *and* in the helper. This copy keeps a pointless prompt
        # off the screen; the helper's copy is the one that matters, because
        # only it runs somewhere a compromised GUI cannot reach.
        return UndoResult(identity, name, False,
                          "what this entry launches has changed since "
                          "PolyScour touched it, so it has been left alone")

    refusal = veto(current)
    if refusal:
        # An entry that has become un-changeable since the change was made --
        # renamed to PolyScour's own, say. Undo is a write like any other.
        return UndoResult(identity, name, False, refusal)

    try:
        elevated = _write(current, bool(row["was_enabled"]))
    except ElevationRefused as exc:
        return UndoResult(identity, name, False, str(exc))
    except OSError as exc:
        return UndoResult(identity, name, False,
                          f"the registry refused the write: {exc}")

    ledger.mark_startup_reverted(row["id"])
    return UndoResult(identity, name, True, elevated=elevated)


def _find(identity: str) -> StartupItem | None:
    for item in list_items():
        if item.identity == identity:
            return item
    return None
