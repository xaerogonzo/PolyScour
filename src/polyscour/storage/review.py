r"""After a scan: snapshot it, compare it with the last one, then keep it.

The order is the point, and it lives here so it is decided once. The comparison
is made **before** the save: saving first would make the scan its own baseline,
and every comparison would report that nothing changed.

Changes nothing on the machine -- it reads the store and writes PolyScour's own
measurements. ``docs/adr/0008``.

**A finished scan is never lost to a history fault.** A two-minute walk that
completed is more valuable than the comparison built on it, so anything going
wrong in the store is captured in :attr:`Review.error` and shown, and the report
survives. That is deliberately the one broad ``except`` in this package; the
alternative is a screen that says "scan failed" over a scan that succeeded. The
error is reported as text and never as "nothing changed".
"""
from __future__ import annotations

from dataclasses import dataclass

from polyscour.storage.analyser import VolumeReport
from polyscour.storage.comparison import Comparison, Refusal, compare
from polyscour.storage.history import SaveOutcome, SnapshotStore
from polyscour.storage.snapshots import Snapshot


@dataclass(frozen=True)
class Review:
    snapshot: Snapshot
    #: The newest earlier scan of this volume that was kept. ``None`` means
    #: there was none -- which is not the same as "nothing changed".
    baseline: Snapshot | None
    #: ``None`` only when there was no baseline to compare with.
    comparison: Comparison | Refusal | None
    #: ``None`` only when the store failed before it could say.
    saved: SaveOutcome | None
    #: Saved scans that could not be read and were skipped.
    unreadable: int = 0
    #: The store's failure, as text. Set means history was not fully usable.
    error: str | None = None


def review_scan(report: VolumeReport, store: SnapshotStore) -> Review:
    """Snapshot ``report``, compare it with the newest kept scan, then keep it."""
    snapshot = Snapshot.from_report(report)
    baseline: Snapshot | None = None
    comparison: Comparison | Refusal | None = None
    saved: SaveOutcome | None = None
    unreadable = 0
    error: str | None = None

    try:
        if snapshot.volume_id is not None:
            past = store.history(snapshot.volume_id)
            unreadable = past.unreadable
            if past.snapshots:
                baseline = past.snapshots[0]
                comparison = compare(baseline, snapshot)
        # After the comparison, never before.
        saved = store.save(snapshot)
    except Exception as exc:                          # noqa: BLE001 - see module docstring
        error = f"{type(exc).__name__}: {exc}"

    return Review(snapshot=snapshot, baseline=baseline, comparison=comparison,
                  saved=saved, unreadable=unreadable, error=error)
