r"""Reading and changing what runs when Windows starts.

The exact mechanism
-------------------

Enabling and disabling go through **the same mechanism Task Manager uses**:

    HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run

a ``REG_BINARY`` value per entry, named after the ``Run`` value it governs.
Byte 0 is ``0x02`` for enabled and ``0x03`` for disabled; the remaining bytes
carry a FILETIME of when the state last changed.

Using Windows' own switch rather than inventing one is the whole design.
The alternative -- delete the ``Run`` value and keep a copy somewhere -- would
mean the entry vanishes from Task Manager rather than showing as *Disabled*,
and that a user who uninstalled PolyScour would lose it permanently. Toggling
the approval byte leaves the ``Run`` value untouched, so every other tool on
the machine still sees the truth and can undo what PolyScour did.

**A disable is therefore a state transition, not a deletion.** Nothing is
removed, so "restore" is a matter of writing one byte back rather than
reconstructing something from a backup that may itself be gone.

Three facts observed on a real machine, each of which a guess gets wrong
--------------------------------------------------------------------------

1. **Absence means enabled.** Most ``Run`` values have no approval record at
   all; Windows treats that as enabled, so a reader that requires a record
   reports healthy entries as unknown.
2. **Orphan approval records exist.** ``StartupApproved`` outlives the ``Run``
   value it named -- a machine here had records for ``MicrosoftEdgeAutoLaunch``
   and ``CCleaner Smart Cleaning`` with no matching entry. They are not startup
   items and must not be listed as such.
3. **The record is per-hive.** The HKCU approval key governs HKCU ``Run``
   values only. There is an HKLM equivalent, and writing it needs elevation,
   which 0.1 does not have.

What this refuses to conclude
-----------------------------

Nothing here scores, ranks or recommends. An entry that has not been launched
in months, or whose target is missing, is *reported as that* -- it is not
labelled "safe to disable", because startup impact is usually negligible and
"unused" is not evidence that turning something off helps. Detection and
diagnosis; the decision stays with the person.
"""
from __future__ import annotations

import struct
import winreg
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from polybedrock.startup import RunEntry, iter_run_entries

#: The approval key, per hive. HKLM is listed so its entries can be *read* and
#: reported; writing it is refused by policy until there is an elevated helper.
_APPROVED = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"

_HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

_ENABLED_BYTE = 0x02
_DISABLED_BYTE = 0x03


class TargetState(Enum):
    """What we can say about the thing an entry launches.

    ``UNRESOLVED`` is not a tidy-up value. A registry value whose target cannot
    be worked out -- a malformed command line, an environment variable that
    expands to nothing -- is a real and fairly common thing, and forcing it into
    "present" or "missing" would be inventing a fact. The product's whole claim
    is that it says what it does not know.
    """
    PRESENT = "present"
    MISSING = "missing"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class StartupItem:
    """One startup entry: what it is, and whether it is switched on.

    ``enabled`` and ``target`` are deliberately separate. A disabled entry whose
    file is gone is both of those things, and collapsing them into one status
    would force a choice about which to show.
    """
    entry: RunEntry
    enabled: bool
    has_approval_record: bool
    target: TargetState

    @property
    def identity(self) -> str:
        return self.entry.identity

    @property
    def name(self) -> str:
        return self.entry.value_name

    @property
    def scope(self) -> str:
        return self.entry.scope


def read_approvals(hive_name: str) -> dict[str, bool]:
    """``{value_name: enabled}`` from one hive's approval key.

    Only names actually recorded appear. A caller must treat a missing name as
    **enabled** -- see the module docstring; that is Windows' default and most
    entries never get a record at all.
    """
    hive = _HIVES.get(hive_name.split("_")[0])
    if hive is None:
        return {}
    out: dict[str, bool] = {}
    try:
        with winreg.OpenKey(hive, _APPROVED) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if isinstance(value, bytes) and value:
                    out[name] = value[0] != _DISABLED_BYTE
    except OSError:
        pass          # no approval key on this machine yet: everything enabled
    return out


def list_items() -> list[StartupItem]:
    """Every Run entry, with its switch position and what it points at.

    Orphan approval records are **not** included: a record naming a ``Run``
    value that no longer exists is not a startup item, and listing it would
    offer the user a switch that governs nothing.
    """
    approvals_by_hive: dict[str, dict[str, bool]] = {}
    items: list[StartupItem] = []

    for entry in iter_run_entries():
        approvals = approvals_by_hive.get(entry.hive_name)
        if approvals is None:
            approvals = read_approvals(entry.hive_name)
            approvals_by_hive[entry.hive_name] = approvals

        recorded = entry.value_name in approvals
        items.append(StartupItem(
            entry=entry,
            enabled=approvals.get(entry.value_name, True),
            has_approval_record=recorded,
            target=_target_state(entry),
        ))
    return items


def _target_state(entry: RunEntry) -> TargetState:
    if not entry.target_path:
        return TargetState.UNRESOLVED
    try:
        return (TargetState.PRESENT if Path(entry.target_path).exists()
                else TargetState.MISSING)
    except OSError:
        # A path the OS refuses to stat is not a missing file, and saying so
        # would be a claim we cannot support.
        return TargetState.UNRESOLVED


def set_enabled(item: StartupItem, enabled: bool) -> None:
    """Flip the approval byte. Raises ``OSError`` if the write is refused.

    Writes the same 12-byte shape Windows writes, so Task Manager and every
    other tool read the result correctly. **Callers must have cleared policy
    first** -- this function performs the change and makes no judgement about
    whether it should happen.
    """
    hive = _HIVES[item.entry.hive_name.split("_")[0]]
    with winreg.CreateKey(hive, _APPROVED) as key:
        winreg.SetValueEx(key, item.entry.value_name, 0, winreg.REG_BINARY,
                          _approval_blob(enabled))


def _approval_blob(enabled: bool) -> bytes:
    """The 12 bytes Windows stores: a state byte, padding, and a FILETIME.

    Enabled records carry a zero timestamp, which is what Task Manager writes --
    the time something was switched *on* is not information Windows keeps.
    """
    if enabled:
        return bytes([_ENABLED_BYTE]) + b"\x00" * 11
    delta = datetime.now(timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc)
    filetime = int(delta.total_seconds() * 10_000_000)
    return bytes([_DISABLED_BYTE, 0, 0, 0]) + struct.pack("<Q", filetime)
