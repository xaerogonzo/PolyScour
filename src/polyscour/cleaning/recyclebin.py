r"""The Recycle Bin: a Shell operation, not a filesystem cleaning rule.

Every other cleaning rule names a symbolic root family in ``safety/policy.py``
and is authorised path by path, because a glob-based rule could otherwise be
pointed anywhere. The Recycle Bin has no such rule to write: ``$Recycle.Bin\
<SID>`` is Windows' own bookkeeping, not a location a rule chooses, and the
Shell API -- not the filesystem -- is the authority on what is "in" it. Asking
``SHQueryRecycleBinW`` and ``SHEmptyRecycleBinW`` is therefore both simpler and
safer than treating the on-disk folder as an ordinary directory to glob and
unlink: manipulating that folder's contents directly risks corrupting the
index the Shell itself relies on, especially if a run is interrupted partway
by a locked item. See docs/adr/0012.

**This operation is `moderate` risk and explicitly irreversible.** The user
already decided to delete these files once; the Recycle Bin is what lets that
first decision be undone. The Recycle Bin provides recovery *before* this
operation runs -- emptying it permanently removes that recovery path. It is
not a second, PolyScour-controlled undo layer.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from polyscour.contracts import Evidence, Finding, RiskLevel, RuleOutcome
from polyscour.storage import volumes

#: Not a `safety.policy` rule id -- there is no `PolicyEntry` for this, and
#: there should never be one. It exists purely as a tag the executor and UI
#: use to recognise a Recycle Bin finding among ordinary ones.
RULE_ID = "recycle-bin"

_SHERB_NOCONFIRMATION = 0x00000001
_SHERB_NOPROGRESSUI = 0x00000002
_SHERB_NOSOUND = 0x00000004

_S_OK = 0
_S_FALSE = 1   # "nothing to do" -- an empty bin is not a failure to empty it


class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("i64Size", ctypes.c_longlong),
        ("i64NumItems", ctypes.c_longlong),
    ]


@dataclass(frozen=True)
class RecycleBinInfo:
    """What the Shell says is in one volume's Recycle Bin, right now."""
    volume: str          # e.g. "C:\\"
    items: int
    bytes: int

    @property
    def empty(self) -> bool:
        return self.items <= 0 and self.bytes <= 0


def query(volume_root: str) -> RecycleBinInfo | None:
    """Ask the Shell about one volume's Recycle Bin.

    ``None`` means the Shell could not answer -- an unreadable or vanished
    volume -- which is treated the same as "nothing to report" by callers,
    never as "empty": those are different facts, the same distinction Storage
    already draws between an unreadable folder and one that is genuinely small.
    """
    try:
        info = _SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
        hresult = ctypes.windll.shell32.SHQueryRecycleBinW(
            volume_root, ctypes.pointer(info))
        if hresult != _S_OK:
            return None
        return RecycleBinInfo(volume=volume_root,
                              items=max(0, int(info.i64NumItems)),
                              bytes=max(0, int(info.i64Size)))
    except OSError:
        return None


def empty(volume_root: str) -> bool:
    """Empty one volume's Recycle Bin. True if the Shell reports success.

    Its own confirmation, progress dialog and sound are suppressed --
    PolyScour's own confirmation is the single consent surface for this
    operation, and a second, Windows-drawn confirmation stacked on top of it
    would be noise, not an extra safeguard. Never forced: a locked item is
    simply left behind, and the caller finds that out by re-querying
    afterward with :func:`query`, not from this call's return value alone.
    """
    try:
        flags = _SHERB_NOCONFIRMATION | _SHERB_NOPROGRESSUI | _SHERB_NOSOUND
        hresult = ctypes.windll.shell32.SHEmptyRecycleBinW(
            None, volume_root, flags)
        return hresult in (_S_OK, _S_FALSE)
    except OSError:
        return False


def scan() -> RuleOutcome:
    """One Finding per fixed volume whose Recycle Bin has something in it.

    Deliberately outside the JSON-rule / ``RootFamily`` pipeline in
    ``cleaning/rules.py`` and ``safety/policy.py``: there is no glob-scanned
    path here for the guard to authorise, and inventing a ``RootFamily`` that
    resolves to a per-user ``$Recycle.Bin`` folder would misrepresent the
    Shell API as an ordinary directory rule when it is not one.
    """
    outcome = RuleOutcome(rule_id=RULE_ID)
    for vol in volumes.fixed_volumes():
        root = f"{vol.label}\\"
        info = query(root)
        if info is None or info.empty:
            continue
        outcome.findings.append(Finding(
            rule_id=RULE_ID,
            title=f"Recycle Bin on {vol.label}",
            path=Path(root),
            size_bytes=info.bytes,
            risk=RiskLevel.MODERATE,
            reversible=False,
            evidence=Evidence(
                mechanism="SHQueryRecycleBinW / SHEmptyRecycleBinW",
                observation=f"{info.items:,} item(s), {info.bytes:,} bytes",
                rationale=(
                    "The Recycle Bin provides recovery before this operation; "
                    "emptying it permanently removes that recovery path. "
                    "This cannot be undone by PolyScour."),
            ),
        ))
    return outcome
